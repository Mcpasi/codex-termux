use crate::local_rpc::LocalRpc;
use crate::transport::OP_RPC;
use crate::transport::PeerClient;
use crate::transport::relay;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;

pub(crate) struct Bridge {
    pub endpoint: String,
    task: JoinHandle<()>,
}

impl Bridge {
    pub async fn start(
        peer: Arc<PeerClient>,
        failed: Arc<AtomicBool>,
        private_parent: &Path,
    ) -> Result<Self> {
        let rpc = LocalRpc::new(private_parent)?;
        let listener = rpc.bind()?;
        let endpoint = rpc.endpoint();
        let task = tokio::spawn(async move {
            let _rpc = rpc;
            let slots = Arc::new(Semaphore::new(8));
            let mut connections = JoinSet::new();
            loop {
                tokio::select! {
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((mut local, _)) = accepted else { break; };
                        let Ok(permit) = slots.clone().try_acquire_owned() else {
                            failed.store(true, Ordering::Release);
                            continue;
                        };
                        let peer = Arc::clone(&peer);
                        let failed = Arc::clone(&failed);
                        connections.spawn(async move {
                            let _permit = permit;
                            let result = async {
                                let mut remote = peer.connect(OP_RPC).await?;
                                relay(&mut local, &mut remote).await
                            }.await;
                            if result.is_err() { failed.store(true, Ordering::Release); }
                        });
                    }
                }
            }
            failed.store(true, Ordering::Release);
        });
        Ok(Self { endpoint, task })
    }
}

impl Drop for Bridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}
