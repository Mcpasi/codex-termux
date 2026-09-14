use crate::MAX_MEMORY_BYTES;
use crate::artifact::VerifiedArtifact;
use crate::engine::Engine;
use crate::local_rpc::LocalRpc;
use crate::resources;
use crate::transport;
use crate::transport::CONNECT_TIMEOUT;
use crate::transport::OP_RPC;
use crate::transport::OP_STATUS;
use crate::transport::TLS_NAME;
use crate::transport::Telemetry;
use anyhow::Result;
use anyhow::ensure;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codex_app_server_protocol::LocalModelPeer;
use codex_app_server_protocol::LocalModelWorkerStartParams;
use rustls::ServerConfig;
use rustls::pki_types::PrivatePkcs8KeyDer;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinHandle;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

pub(crate) struct Worker {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl Worker {
    pub async fn start(
        params: LocalModelWorkerStartParams,
        private_parent: &Path,
    ) -> Result<(Self, LocalModelPeer)> {
        resources::validate_budget(params.memory_budget_bytes, params.threads)?;
        let address = transport::address(&params.listen_address)?;
        let artifact = timeout(
            Duration::from_secs(120),
            tokio::task::spawn_blocking(move || {
                VerifiedArtifact::open(&params.engine, /*limit*/ 1024 * 1024 * 1024)
            }),
        )
        .await???;
        let rpc = LocalRpc::new(private_parent)?;
        let engine = Engine::worker(&artifact, params.threads, &rpc).await?;
        let pid = engine.child.id();
        let rpc_path = rpc.path().to_owned();
        let listener = TcpListener::bind(address).await?;
        let identity = rcgen::generate_simple_self_signed(vec![TLS_NAME.to_owned()])?;
        let certificate = identity.cert.der().clone();
        let key = PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
        let config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![certificate.clone()], key.into())?;
        let token = Arc::new(Zeroizing::new(rand::random::<[u8; 32]>()));
        let invitation = LocalModelPeer {
            endpoint: listener.local_addr()?.to_string(),
            certificate: STANDARD.encode(certificate),
            token: STANDARD.encode(&**token),
        };
        let cancel = CancellationToken::new();
        let cancelled = cancel.clone();
        let task = tokio::spawn(async move {
            let mut engine = engine;
            let _artifact = artifact;
            let _rpc = rpc;
            let slots = Arc::new(Semaphore::new(16));
            let service = Arc::new(Service {
                acceptor: TlsAcceptor::from(Arc::new(config)),
                token,
                rpc_path,
                budget: params.memory_budget_bytes,
                threads: params.threads,
                pid,
                lease: Arc::new(Mutex::new(LeaseState::default())),
            });
            let mut connections = JoinSet::new();
            let mut memory_tick = tokio::time::interval(Duration::from_millis(250));
            loop {
                tokio::select! {
                    _ = cancelled.cancelled() => break,
                    _ = engine.child.wait() => break,
                    _ = memory_tick.tick() => {
                        if pid.and_then(resources::resident_bytes).is_some_and(|bytes| bytes > params.memory_budget_bytes) {
                            break;
                        }
                    },
                    Some(_) = connections.join_next(), if !connections.is_empty() => {},
                    accepted = listener.accept() => {
                        let Ok((socket, _)) = accepted else { break; };
                        let Ok(permit) = slots.clone().try_acquire_owned() else { continue; };
                        let service = Arc::clone(&service);
                        connections.spawn(async move {
                            let _permit = permit;
                            let _ = serve(socket, service).await;
                        });
                    }
                }
            }
            connections.abort_all();
            let _ = engine.stop().await;
        });
        Ok((Self { cancel, task }, invitation))
    }

    pub fn is_running(&self) -> bool {
        !self.task.is_finished()
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

impl Drop for Worker {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

struct Service {
    acceptor: TlsAcceptor,
    token: Arc<Zeroizing<[u8; 32]>>,
    rpc_path: PathBuf,
    budget: u64,
    threads: u32,
    pid: Option<u32>,
    lease: Arc<Mutex<LeaseState>>,
}

async fn serve(socket: TcpStream, service: Arc<Service>) -> Result<()> {
    socket.set_nodelay(true)?;
    let (mut tls, operation, _guard) = timeout(CONNECT_TIMEOUT, async {
        let mut tls = service.acceptor.accept(socket).await?;
        let mut offered = Zeroizing::new([0_u8; 32]);
        tls.read_exact(offered.as_mut()).await?;
        transport::token_matches(service.token.as_ref().as_ref(), offered.as_ref())?;
        let mut coordinator_id = [0; 16];
        tls.read_exact(&mut coordinator_id).await?;
        let operation = tls.read_u8().await?;
        ensure!(
            matches!(operation, OP_STATUS | OP_RPC),
            "unsupported device operation"
        );
        let guard = PoolLease::acquire(Arc::clone(&service.lease), coordinator_id)?;
        tls.write_u8(0).await?;
        tls.flush().await?;
        anyhow::Ok((tls, operation, guard))
    })
    .await??;
    if operation == OP_STATUS {
        let telemetry = Telemetry {
            available_bytes: resources::available(
                service.budget.min(MAX_MEMORY_BYTES),
                service.pid,
            ),
            threads: service.threads,
        };
        let bytes = serde_json::to_vec(&telemetry)?;
        timeout(CONNECT_TIMEOUT, async {
            tls.write_u32(bytes.len() as u32).await?;
            tls.write_all(&bytes).await?;
            tls.shutdown().await
        })
        .await??;
    } else {
        let mut rpc = timeout(CONNECT_TIMEOUT, LocalRpc::connect(&service.rpc_path)).await??;
        transport::relay(&mut tls, &mut rpc).await?;
    }
    Ok(())
}

#[derive(Default)]
struct LeaseState {
    owner: [u8; 16],
    connections: usize,
}

struct PoolLease(Arc<Mutex<LeaseState>>);

impl PoolLease {
    fn acquire(state: Arc<Mutex<LeaseState>>, owner: [u8; 16]) -> Result<Self> {
        {
            let mut lease = state.lock().unwrap_or_else(|p| p.into_inner());
            ensure!(
                lease.connections == 0 || lease.owner == owner,
                "helper is already leased to another coordinator"
            );
            lease.owner = owner;
            lease.connections += 1;
        }
        Ok(Self(state))
    }
}

impl Drop for PoolLease {
    fn drop(&mut self) {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).connections -= 1;
    }
}

#[cfg(test)]
#[path = "worker_tests.rs"]
mod tests;
