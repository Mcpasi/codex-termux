use crate::MAX_DEVICES;
use crate::MAX_MEMORY_BYTES;
use crate::artifact::VerifiedArtifact;
use crate::gateway;
use crate::gguf;
use crate::resources;
use crate::session::Session;
use crate::transport::PeerClient;
use anyhow::Result;
use anyhow::ensure;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codex_app_server_protocol::LocalModelPhase;
use codex_app_server_protocol::LocalModelStartParams;
use codex_app_server_protocol::LocalModelStartResponse;
use codex_app_server_protocol::LocalModelStatusResponse;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(crate) struct Coordinator {
    cancel: CancellationToken,
    task: JoinHandle<()>,
    state: Arc<StdMutex<LocalModelStatusResponse>>,
    session: Arc<Mutex<Session>>,
}

impl Coordinator {
    pub async fn start(
        params: LocalModelStartParams,
        private_parent: &Path,
    ) -> Result<(Self, LocalModelStartResponse)> {
        resources::validate_budget(params.memory_budget_bytes, params.threads)?;
        ensure!(
            params.peers.len() < MAX_DEVICES,
            "at most nine helpers may join one coordinator"
        );
        ensure!(
            cfg!(unix) || params.peers.is_empty(),
            "native device pooling requires Unix sockets"
        );
        ensure!(
            (256..=32768).contains(&params.context_tokens),
            "context exceeds limits"
        );
        ensure!(
            !params.model_id.is_empty()
                && params.model_id.len() <= 128
                && params
                    .model_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b)),
            "invalid model id"
        );
        let mut endpoints = std::collections::HashSet::new();
        let mut certificates = std::collections::HashSet::new();
        let mut peers = Vec::new();
        let coordinator_id = rand::random::<[u8; 16]>();
        for invitation in params.peers {
            let certificate = invitation.certificate.clone();
            let peer = PeerClient::new(invitation, coordinator_id)?;
            ensure!(endpoints.insert(peer.endpoint), "duplicate helper address");
            ensure!(
                certificates.insert(certificate),
                "helper identity supplied more than once"
            );
            peers.push(Arc::new(peer));
        }
        let (artifact, model, shape) = timeout(
            Duration::from_secs(600),
            tokio::task::spawn_blocking(move || {
                let artifact =
                    VerifiedArtifact::open(&params.engine, /*limit*/ 1024 * 1024 * 1024)?;
                let model = VerifiedArtifact::open(&params.model, MAX_MEMORY_BYTES)?;
                let shape = gguf::inspect(&model, params.context_tokens)?;
                anyhow::Ok((artifact, model, shape))
            }),
        )
        .await???;
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .build()?;
        let mut session = Session {
            private_parent: private_parent.to_owned(),
            artifact,
            model,
            shape,
            peers,
            http,
            model_id: params.model_id.clone(),
            context: params.context_tokens,
            threads: params.threads,
            budget: params.memory_budget_bytes,
            engine: None,
            bridges: Vec::new(),
            plan: None,
            failed: false,
            transport_failed: Arc::new(AtomicBool::new(false)),
            engine_token: Zeroizing::new(STANDARD.encode(rand::random::<[u8; 32]>())),
        };
        session.refresh().await?;
        let plan = session
            .plan
            .clone()
            .ok_or_else(|| anyhow::anyhow!("local model plan missing"))?;
        let state = Arc::new(StdMutex::new(LocalModelStatusResponse {
            phase: LocalModelPhase::Ready,
            plan: Some(plan.clone()),
        }));
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let base_url = format!("http://{}/v1", listener.local_addr()?);
        let bearer_token = STANDARD.encode(rand::random::<[u8; 32]>());
        let cancel = CancellationToken::new();
        let session = Arc::new(Mutex::new(session));
        let app = gateway::router(gateway::Gateway {
            session: Arc::clone(&session),
            view: Arc::clone(&state),
            cancel: cancel.clone(),
            bearer: Arc::new(Zeroizing::new(bearer_token.clone())),
        });
        let cancelled = cancel.clone();
        let session_for_shutdown = Arc::clone(&session);
        let task = tokio::spawn(async move {
            tokio::select! {
                _ = cancelled.cancelled() => {},
                _ = async { axum::serve(listener, app).await } => {},
            }
            let mut session = session_for_shutdown.lock().await;
            session.fail();
            if let Some(mut engine) = session.engine.take() {
                let _ = engine.stop().await;
            }
        });
        Ok((
            Self {
                cancel,
                task,
                state,
                session,
            },
            LocalModelStartResponse {
                base_url,
                model: params.model_id,
                bearer_token,
                plan,
            },
        ))
    }

    pub fn status(&self) -> LocalModelStatusResponse {
        if let Ok(mut session) = self.session.try_lock() {
            let dead = session
                .engine
                .as_mut()
                .is_some_and(|engine| !matches!(engine.child.try_wait(), Ok(None)));
            if dead
                && !session
                    .transport_failed
                    .load(std::sync::atomic::Ordering::Acquire)
            {
                session.fail();
                self.state.lock().unwrap_or_else(|p| p.into_inner()).phase =
                    LocalModelPhase::Failed;
            }
        }
        let mut status = self.state.lock().unwrap_or_else(|p| p.into_inner()).clone();
        if self.task.is_finished() {
            status.phase = LocalModelPhase::Failed;
        }
        status
    }

    pub async fn stop(&mut self) {
        self.cancel.cancel();
        if timeout(Duration::from_secs(12), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
        }
    }
}

impl Drop for Coordinator {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Ok(mut session) = self.session.try_lock() {
            session.fail();
        }
    }
}
