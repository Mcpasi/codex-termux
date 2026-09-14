use anyhow::Result;
use anyhow::ensure;
use std::path::Path;
use std::path::PathBuf;

#[cfg(unix)]
type Listener = tokio::net::UnixListener;
#[cfg(unix)]
type Stream = tokio::net::UnixStream;
// Non-Unix constructors fail before opening any socket; these aliases keep shared callers portable.
#[cfg(not(unix))]
type Listener = tokio::net::TcpListener;
#[cfg(not(unix))]
type Stream = tokio::net::TcpStream;

/// Raw native RPC remains inside a private directory, never on a TCP port.
pub(crate) struct LocalRpc {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl LocalRpc {
    pub fn new(private_parent: &Path) -> Result<Self> {
        ensure!(cfg!(unix), "native device pooling requires Unix sockets");
        ensure!(
            private_parent.is_absolute() && private_parent.canonicalize()? == private_parent,
            "RPC parent must be canonical and absolute"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(private_parent)?;
            ensure!(
                metadata.is_dir() && metadata.mode() & 0o022 == 0,
                "RPC parent must not be shared-writable"
            );
        }
        let directory = tempfile::Builder::new()
            .prefix("clm-")
            .tempdir_in(private_parent)?;
        let root = directory.path().canonicalize()?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                std::fs::metadata(&root)?.permissions().mode() & 0o077 == 0,
                "RPC directory must be owner-only"
            );
        }
        let path = root.join("rpc.sock");
        let text = path
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("invalid RPC socket path"))?;
        ensure!(
            text.len() < 100 && !text.contains([',', ':', '[', ']']),
            "private temporary path is too long or unsupported for native RPC"
        );
        Ok(Self {
            _directory: directory,
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn bind(&self) -> Result<Listener> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let listener = Listener::bind(&self.path)?;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600))?;
            Ok(listener)
        }
        #[cfg(not(unix))]
        anyhow::bail!("native device pooling requires Unix sockets")
    }

    pub async fn connect(path: &Path) -> Result<Stream> {
        #[cfg(unix)]
        {
            Ok(Stream::connect(path).await?)
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            anyhow::bail!("native device pooling requires Unix sockets")
        }
    }

    pub fn endpoint(&self) -> String {
        // The pinned parser still requires a numeric port suffix; Unix transport ignores it.
        format!("{}:1", self.path.display())
    }
}

#[cfg(all(test, unix))]
#[path = "local_rpc_tests.rs"]
mod tests;
