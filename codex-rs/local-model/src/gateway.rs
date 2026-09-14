use crate::adapter::Adapter;
use crate::resources;
use crate::session::Session;
use crate::stream;
use crate::transport;
use anyhow::Result;
use anyhow::ensure;
use axum::Router;
use axum::body::Body;
use axum::body::Bytes;
use axum::extract::DefaultBodyLimit;
use axum::extract::Request;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::post;
use codex_app_server_protocol::LocalModelPhase;
use codex_app_server_protocol::LocalModelStatusResponse;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::OwnedMutexGuard;
use tokio::sync::mpsc;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

#[derive(Clone)]
pub(crate) struct Gateway {
    pub session: Arc<Mutex<Session>>,
    pub view: Arc<StdMutex<LocalModelStatusResponse>>,
    pub bearer: Arc<Zeroizing<String>>,
    pub cancel: CancellationToken,
}

pub(crate) fn router(gateway: Gateway) -> Router {
    Router::new()
        .route("/v1/responses", post(responses))
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(gateway)
}

struct Lease {
    session: OwnedMutexGuard<Session>,
    view: Arc<StdMutex<LocalModelStatusResponse>>,
    completed: bool,
}

impl Drop for Lease {
    fn drop(&mut self) {
        if !self.completed {
            self.session.fail();
        }
        let mut view = self.view.lock().unwrap_or_else(|p| p.into_inner());
        view.phase = if self.session.failed {
            LocalModelPhase::Failed
        } else {
            LocalModelPhase::Ready
        };
        view.plan = self.session.plan.clone();
    }
}

async fn responses(State(gateway): State<Gateway>, request: Request) -> Response {
    let token = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    if !token.is_some_and(|token| {
        token.len() == gateway.bearer.len()
            && transport::token_matches(gateway.bearer.as_bytes(), token.as_bytes()).is_ok()
    }) {
        return (
            StatusCode::UNAUTHORIZED,
            "invalid local model authorization",
        )
            .into_response();
    }
    let Ok(session) = gateway.session.clone().try_lock_owned() else {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            "local model is already generating",
        )
            .into_response();
    };
    if session.failed || gateway.cancel.is_cancelled() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "local model requires an explicit restart",
        )
            .into_response();
    }
    let body = tokio::select! {
        _ = gateway.cancel.cancelled() => return (StatusCode::SERVICE_UNAVAILABLE, "local model stopped").into_response(),
        body = timeout(Duration::from_secs(15), axum::body::to_bytes(request.into_body(), 8 * 1024 * 1024)) => body,
    };
    let Ok(Ok(body)) = body else {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            "local model request exceeds its size or time bound",
        )
            .into_response();
    };
    let adapted = validate_request(&body, &session.model_id).and_then(Adapter::request);
    let Ok((body, adapter)) = adapted else {
        return (
            StatusCode::BAD_REQUEST,
            "expected a bounded, stateless Responses request for the configured model",
        )
            .into_response();
    };
    let mut lease = Lease {
        session,
        view: Arc::clone(&gateway.view),
        completed: false,
    };
    gateway.view.lock().unwrap_or_else(|p| p.into_inner()).phase = LocalModelPhase::Generating;
    let result = tokio::select! {
        _ = gateway.cancel.cancelled() => return (StatusCode::SERVICE_UNAVAILABLE, "local model stopped").into_response(),
        result = timeout(Duration::from_secs(600), prepare(&mut lease.session, body)) => result,
    };
    let Ok(Ok(upstream)) = result else {
        return (
            StatusCode::BAD_GATEWAY,
            "local inference or helper connection failed; restart explicitly",
        )
            .into_response();
    };
    if !upstream.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            "local engine rejected the model request",
        )
            .into_response();
    }
    if !upstream
        .headers()
        .get("content-type")
        .is_some_and(|v| v.as_bytes().starts_with(b"text/event-stream"))
    {
        return (
            StatusCode::BAD_GATEWAY,
            "local engine did not provide a Responses event stream",
        )
            .into_response();
    }
    gateway.view.lock().unwrap_or_else(|p| p.into_inner()).plan = lease.session.plan.clone();
    let (sender, receiver) = mpsc::channel(/*buffer*/ 2);
    tokio::spawn(async move {
        let mut lease = lease;
        let pid = lease
            .session
            .engine
            .as_ref()
            .and_then(|engine| engine.child.id());
        let result = if let Some(pid) = pid {
            tokio::select! {
                _ = resources::wait_for_over_budget(pid, lease.session.budget) => Err(std::io::Error::other("local model exceeded its memory budget")),
                result = stream::forward(upstream.bytes_stream(), &sender, &gateway.cancel, adapter) => result,
            }
        } else {
            Err(std::io::Error::other("local model process unavailable"))
        };
        match result {
            Ok(()) => lease.completed = true,
            Err(error) => {
                let _ = sender.try_send(Err(error));
            }
        }
    });
    let streamed = futures::stream::unfold(receiver, |mut receiver| async move {
        receiver.recv().await.map(|chunk| (chunk, receiver))
    });
    (
        [
            ("content-type", "text/event-stream"),
            ("cache-control", "no-store"),
        ],
        Body::from_stream(streamed),
    )
        .into_response()
}

fn validate_request(body: &[u8], model: &str) -> Result<serde_json::Value> {
    let request: serde_json::Value = serde_json::from_slice(body)?;
    ensure!(
        request.get("model").and_then(serde_json::Value::as_str) == Some(model),
        "model does not match"
    );
    ensure!(
        request
            .get("previous_response_id")
            .is_none_or(serde_json::Value::is_null),
        "server-side history is unsupported"
    );
    ensure!(request.get("input").is_some(), "input missing");
    ensure!(
        request.get("stream").and_then(serde_json::Value::as_bool) == Some(true),
        "streaming is required"
    );
    Ok(request)
}

async fn prepare(session: &mut Session, body: Bytes) -> Result<reqwest::Response> {
    session.refresh().await?;
    let engine = session
        .engine
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("local engine unavailable"))?;
    let pid = engine
        .child
        .id()
        .ok_or_else(|| anyhow::anyhow!("local engine exited"))?;
    let port = engine.port;
    let request = session
        .http
        .post(format!("http://127.0.0.1:{port}/v1/responses"))
        .bearer_auth(session.engine_token.as_str())
        .header("content-type", "application/json")
        .body(body)
        .send();
    tokio::select! {
        _ = resources::wait_for_over_budget(pid, session.budget) => anyhow::bail!("local model exceeded its memory budget"),
        result = request => Ok(result?),
    }
}

#[cfg(test)]
#[path = "gateway_tests.rs"]
mod tests;
