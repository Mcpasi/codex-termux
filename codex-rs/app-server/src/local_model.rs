use crate::error_code::invalid_params;
use crate::outgoing_message::ConnectionId;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::ClientResponsePayload;
use codex_app_server_protocol::JSONRPCErrorError;
use codex_app_server_protocol::LocalModelStopResponse;
use codex_local_model::LocalModelRuntime;
use std::path::PathBuf;
use std::sync::Mutex as StdMutex;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

pub(crate) struct LocalModelProcessor {
    owner: StdMutex<Option<(ConnectionId, CancellationToken)>>,
    runtime: Mutex<LocalModelRuntime>,
}

impl LocalModelProcessor {
    pub fn new(private_parent: PathBuf) -> Self {
        Self {
            owner: StdMutex::new(None),
            runtime: Mutex::new(LocalModelRuntime::new(private_parent)),
        }
    }

    pub async fn request(
        &self,
        connection: ConnectionId,
        connection_cancel: &CancellationToken,
        request: ClientRequest,
    ) -> Result<Option<ClientResponsePayload>, JSONRPCErrorError> {
        let cancel = {
            let mut owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
            if connection_cancel.is_cancelled() {
                return Err(invalid_params("local model connection closed"));
            }
            if let Some((current, _)) = &*owner
                && *current != connection
            {
                return Err(invalid_params("local model belongs to another connection"));
            }
            let (_, cancel) = owner.get_or_insert_with(|| (connection, CancellationToken::new()));
            cancel.clone()
        };
        if matches!(request, ClientRequest::LocalModelStop { .. }) {
            cancel.cancel();
            timeout(Duration::from_secs(15), self.runtime.lock())
                .await
                .map_err(|_| invalid_params("local model stop timed out"))?
                .stop()
                .await;
            let mut owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((id, token)) = &mut *owner
                && *id == connection
            {
                *token = CancellationToken::new();
            }
            return Ok(Some(LocalModelStopResponse::default().into()));
        }
        let result = tokio::select! {
            _ = connection_cancel.cancelled() => return Err(invalid_params("local model connection closed")),
            _ = cancel.cancelled() => return Err(invalid_params("local model connection closed")),
            result = timeout(Duration::from_secs(930), async {
                let mut runtime = self.runtime.try_lock().map_err(|_| invalid_params("local model operation already in progress"))?;
                let response = match request {
                    ClientRequest::LocalModelStart { params, .. } => runtime.start(params).await.map(ClientResponsePayload::from),
                    ClientRequest::LocalModelWorkerStart { params, .. } => runtime.start_worker(params).await.map(ClientResponsePayload::from),
                    ClientRequest::LocalModelStatus { .. } => Ok(runtime.status().into()),
                    ClientRequest::LocalModelStop { .. } => {
                        runtime.stop().await;
                        Ok(LocalModelStopResponse::default().into())
                    }
                    _ => return Err(invalid_params("unsupported local model operation")),
                }.map_err(|_| invalid_params("local model operation failed: check installed artifact hashes, model support, memory budget and paired devices"))?;
                Ok(Some(response))
            }) => result,
        };
        result.map_err(|_| invalid_params("local model operation timed out"))?
    }

    pub async fn connection_closed(&self, connection: ConnectionId) {
        let cancel = {
            let owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
            if owner.as_ref().is_none_or(|(id, _)| *id != connection) {
                return;
            }
            owner.as_ref().map(|(_, token)| token.clone())
        };
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
        self.runtime.lock().await.stop().await;
        let mut owner = self.owner.lock().unwrap_or_else(|p| p.into_inner());
        if owner.as_ref().is_some_and(|(id, _)| *id == connection) {
            owner.take();
        }
    }
}

#[cfg(test)]
#[path = "local_model_tests.rs"]
mod tests;
