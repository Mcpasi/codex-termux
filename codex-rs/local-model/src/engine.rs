use crate::artifact::VerifiedArtifact;
use crate::local_rpc::LocalRpc;
use anyhow::Result;
use anyhow::ensure;
use std::net::Ipv4Addr;
use std::process::Stdio;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::process::Child;
use tokio::process::Command;
use tokio::time::timeout;

pub(crate) struct Engine {
    pub child: Child,
    pub port: u16,
}

pub(crate) async fn free_port() -> Result<u16> {
    Ok(TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await?
        .local_addr()?
        .port())
}

pub(crate) fn command(
    engine: &VerifiedArtifact,
    inherited: &[&VerifiedArtifact],
) -> Result<Command> {
    engine.validate()?;
    for artifact in inherited {
        artifact.validate()?;
    }
    let mut command = Command::new(engine.child_path());
    command
        .env_clear()
        .env("GGML_RPC_NO_RDMA", "1")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        use std::os::fd::AsRawFd;
        let fds: Vec<_> = std::iter::once(engine)
            .chain(inherited.iter().copied())
            .map(|a| a.file.as_raw_fd())
            .collect();
        // This only affects the dedicated inference child, not Codex's sandbox or JIT hosts.
        unsafe {
            command.pre_exec(move || {
                for fd in &fds {
                    let flags = libc::fcntl(*fd, libc::F_GETFD);
                    if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }
    Ok(command)
}

impl Engine {
    pub async fn worker(artifact: &VerifiedArtifact, threads: u32, rpc: &LocalRpc) -> Result<Self> {
        let mut command = command(artifact, &[])?;
        command.arg("--host").arg(rpc.path());
        command.args([
            "--device",
            "CPU",
            "--port",
            "1",
            "--threads",
            &threads.to_string(),
        ]);
        let child = command.spawn()?;
        let mut engine = Self { child, port: 0 };
        timeout(Duration::from_secs(15), async {
            loop {
                ensure!(
                    engine.child.try_wait()?.is_none(),
                    "local inference worker exited during startup"
                );
                if LocalRpc::connect(rpc.path()).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            anyhow::Ok(())
        })
        .await??;
        artifact.validate()?;
        Ok(engine)
    }

    pub async fn stop(&mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.start_kill()?;
            timeout(Duration::from_secs(10), self.child.wait()).await??;
        }
        Ok(())
    }
}
