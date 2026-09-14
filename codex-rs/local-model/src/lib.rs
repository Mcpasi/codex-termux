//! Local GGUF inference and a bounded, explicitly paired CPU device pool.
//! The host owns installation and UI; this crate never downloads executable content.

mod adapter;
mod artifact;
mod coordinator;
mod engine;
mod gateway;
mod gguf;
mod local_rpc;
mod planner;
mod pool;
mod resources;
mod session;
mod stream;
mod transport;
mod worker;

use anyhow::Result;
use anyhow::ensure;
use codex_app_server_protocol::LocalModelPhase;
use codex_app_server_protocol::LocalModelStartParams;
use codex_app_server_protocol::LocalModelStartResponse;
use codex_app_server_protocol::LocalModelStatusResponse;
use codex_app_server_protocol::LocalModelWorkerStartParams;
use codex_app_server_protocol::LocalModelWorkerStartResponse;
use coordinator::Coordinator;
use std::path::PathBuf;
use worker::Worker;

pub const MAX_DEVICES: usize = 10;
pub(crate) const RESERVE_BYTES: u64 = 256 * 1024 * 1024;
pub(crate) const MAX_MEMORY_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// Own one role per app-server connection. Dropping it cancels connections and children.
pub struct LocalModelRuntime {
    private_parent: PathBuf,
    coordinator: Option<Coordinator>,
    worker: Option<Worker>,
}

impl LocalModelRuntime {
    /// The host supplies a canonical private parent outside all tool/workspace roots.
    pub fn new(private_parent: PathBuf) -> Self {
        Self {
            private_parent,
            coordinator: None,
            worker: None,
        }
    }

    pub async fn start(
        &mut self,
        params: LocalModelStartParams,
    ) -> Result<LocalModelStartResponse> {
        ensure!(
            self.coordinator.is_none() && self.worker.is_none(),
            "stop the existing local model role first"
        );
        let (coordinator, response) = Coordinator::start(params, &self.private_parent).await?;
        self.coordinator = Some(coordinator);
        Ok(response)
    }

    pub async fn start_worker(
        &mut self,
        params: LocalModelWorkerStartParams,
    ) -> Result<LocalModelWorkerStartResponse> {
        ensure!(
            self.coordinator.is_none() && self.worker.is_none(),
            "stop the existing local model role first"
        );
        let (worker, invitation) = Worker::start(params, &self.private_parent).await?;
        self.worker = Some(worker);
        Ok(LocalModelWorkerStartResponse { invitation })
    }

    pub fn status(&self) -> LocalModelStatusResponse {
        if let Some(coordinator) = &self.coordinator {
            coordinator.status()
        } else {
            LocalModelStatusResponse {
                phase: match &self.worker {
                    Some(worker) if worker.is_running() => LocalModelPhase::Worker,
                    Some(_) => LocalModelPhase::Failed,
                    None => LocalModelPhase::Stopped,
                },
                plan: None,
            }
        }
    }

    pub async fn stop(&mut self) {
        if let Some(mut coordinator) = self.coordinator.take() {
            coordinator.stop().await;
        }
        if let Some(mut worker) = self.worker.take() {
            worker.stop().await;
        }
    }
}
