use crate::artifact::VerifiedArtifact;
use crate::engine;
use crate::engine::Engine;
use crate::gguf::ModelShape;
use crate::planner;
use crate::planner::Capacity;
use crate::pool::Bridge;
use crate::resources;
use crate::transport::PeerClient;
use anyhow::Result;
use anyhow::ensure;
use codex_app_server_protocol::LocalModelPlan;
use futures::future::join_all;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::Instant;
use tokio::time::timeout;
use zeroize::Zeroizing;

pub(crate) struct Session {
    pub private_parent: PathBuf,
    pub artifact: VerifiedArtifact,
    pub model: VerifiedArtifact,
    pub shape: ModelShape,
    pub model_id: String,
    pub context: u32,
    pub threads: u32,
    pub budget: u64,
    pub peers: Vec<Arc<PeerClient>>,
    pub engine: Option<Engine>,
    pub bridges: Vec<Bridge>,
    pub plan: Option<LocalModelPlan>,
    pub failed: bool,
    pub transport_failed: Arc<AtomicBool>,
    pub http: reqwest::Client,
    pub engine_token: Zeroizing<String>,
}

impl Session {
    pub async fn refresh(&mut self) -> Result<()> {
        ensure!(
            !self.failed,
            "local inference failed; explicitly stop and restart it"
        );
        // Only idle state is replaced here. The next request supplies a new explicit prompt.
        if self.transport_failed.swap(false, Ordering::AcqRel) {
            if let Some(mut engine) = self.engine.take() {
                engine.stop().await?;
            }
            self.bridges.clear();
            self.plan = None;
        }
        self.artifact.validate()?;
        self.model.validate()?;
        if let Some(engine) = &mut self.engine {
            ensure!(
                engine.child.try_wait()?.is_none(),
                "local inference process exited"
            );
        }
        let capacities = join_all(
            self.peers
                .iter()
                .enumerate()
                .map(|(index, peer)| async move {
                    let start = Instant::now();
                    peer.status().await.ok().map(|status| Capacity {
                        index: index as u32 + 1,
                        bytes: status.available_bytes,
                        latency_micros: start.elapsed().as_micros().min(u128::from(u64::MAX))
                            as u64,
                    })
                }),
        )
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let local_bytes =
            resources::available(self.budget, self.engine.as_ref().and_then(|e| e.child.id()));
        let proposed = planner::plan(&self.shape, local_bytes, &capacities)?;
        if let Some(current) = &self.plan {
            let fits = current.assignments.iter().all(|a| {
                let bytes = if a.device_index == 0 {
                    local_bytes
                } else {
                    capacities
                        .iter()
                        .find(|p| p.index == a.device_index)
                        .map_or(0, |p| p.bytes)
                };
                a.estimated_bytes <= bytes
            });
            let local_gain = proposed.assignments[0]
                .end_layer
                .saturating_sub(current.assignments[0].end_layer);
            if fits
                && proposed.assignments.len() >= current.assignments.len()
                && local_gain < self.shape.layers.div_ceil(10).max(2)
            {
                return Ok(());
            }
        }
        if let Some(mut engine) = self.engine.take() {
            engine.stop().await?;
        }
        self.bridges.clear();
        // Retired connections must not report their shutdown against a new engine.
        self.transport_failed = Arc::new(AtomicBool::new(false));
        // A replacement always rebuilds KV state from the next complete Responses request.
        let mut bridges = Vec::new();
        for assignment in proposed.assignments.iter().skip(1) {
            bridges.push(
                Bridge::start(
                    Arc::clone(&self.peers[assignment.device_index as usize - 1]),
                    Arc::clone(&self.transport_failed),
                    &self.private_parent,
                )
                .await?,
            );
        }
        let port = engine::free_port().await?;
        let mut command = engine::command(&self.artifact, &[&self.model])?;
        command.env("LLAMA_API_KEY", self.engine_token.as_str());
        command.args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--alias",
            &self.model_id,
            "--ctx-size",
            &self.context.to_string(),
            "--threads",
            &self.threads.to_string(),
            "--parallel",
            "1",
            "--batch-size",
            "32",
            "--ubatch-size",
            "32",
            "--fit",
            "off",
            "--cache-type-k",
            "f16",
            "--cache-type-v",
            "f16",
            "--flash-attn",
            "off",
            "--jinja",
            "--no-webui",
            "--no-context-shift",
        ]);
        command.arg("--model").arg(self.model.child_path());
        let remote_layers = self.shape.layers - proposed.assignments[0].end_layer;
        command.args(["--n-gpu-layers", &remote_layers.to_string()]);
        if bridges.is_empty() {
            command.args(["--device", "none"]);
        } else {
            let endpoints = bridges
                .iter()
                .map(|bridge| bridge.endpoint.clone())
                .collect::<Vec<_>>();
            let devices = endpoints
                .iter()
                .map(|e| format!("RPC0[{e}]"))
                .collect::<Vec<_>>()
                .join(",");
            let split = planner::split_weights(&proposed)
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(",");
            command.args([
                "--rpc",
                &endpoints.join(","),
                "--device",
                &devices,
                "--tensor-split",
                &split,
                "--split-mode",
                "layer",
            ]);
        }
        let mut engine = Engine {
            child: command.spawn()?,
            port,
        };
        timeout(Duration::from_secs(300), async {
            loop {
                ensure!(
                    !self.transport_failed.load(Ordering::Acquire),
                    "helper transport failed while loading model"
                );
                ensure!(
                    engine.child.try_wait()?.is_none(),
                    "local model process exited during startup"
                );
                ensure!(
                    engine
                        .child
                        .id()
                        .and_then(resources::resident_bytes)
                        .is_none_or(|bytes| bytes <= self.budget),
                    "local model exceeded its memory budget during startup"
                );
                if let Ok(Ok(response)) = timeout(
                    Duration::from_secs(2),
                    self.http
                        .get(format!("http://127.0.0.1:{port}/health"))
                        .bearer_auth(self.engine_token.as_str())
                        .send(),
                )
                .await
                    && response.status().is_success()
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            anyhow::Ok(())
        })
        .await??;
        self.artifact.validate()?;
        self.model.validate()?;
        self.bridges = bridges;
        self.engine = Some(engine);
        self.plan = Some(proposed);
        Ok(())
    }

    pub fn fail(&mut self) {
        self.failed = true;
        if let Some(engine) = &mut self.engine {
            let _ = engine.child.start_kill();
        }
        self.bridges.clear();
    }
}
