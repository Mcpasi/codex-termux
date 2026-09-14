use anyhow::Result;
use anyhow::ensure;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use codex_app_server_protocol::LocalModelPeer;
use hmac::Hmac;
use hmac::Mac;
use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use serde::Serialize;
use sha2::Sha256;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWrite;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;
use zeroize::Zeroizing;

pub(crate) const TLS_NAME: &str = "codex-local-model";
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(90);
pub(crate) const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const OP_STATUS: u8 = 1;
pub(crate) const OP_RPC: u8 = 2;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Telemetry {
    pub available_bytes: u64,
    pub threads: u32,
}

pub(crate) fn address(value: &str) -> Result<SocketAddr> {
    ensure!(value.len() <= 64, "invalid device address");
    let address: SocketAddr = value.parse()?;
    let private = match address.ip() {
        IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local(),
    };
    ensure!(
        private,
        "device address must name a private, link-local, or loopback interface"
    );
    Ok(address)
}

pub(crate) struct PeerClient {
    pub endpoint: SocketAddr,
    connector: TlsConnector,
    token: Zeroizing<Vec<u8>>,
    coordinator_id: [u8; 16],
}

impl PeerClient {
    pub fn new(mut invitation: LocalModelPeer, coordinator_id: [u8; 16]) -> Result<Self> {
        use zeroize::Zeroize;
        let token_text = Zeroizing::new(std::mem::take(&mut invitation.token));
        ensure!(
            invitation.certificate.len() <= 8192 && token_text.len() <= 64,
            "device invitation exceeds limits"
        );
        let token = Zeroizing::new(STANDARD.decode(token_text.as_bytes())?);
        invitation.token.zeroize();
        ensure!(token.len() == 32, "invalid pairing token");
        let endpoint = address(&invitation.endpoint)?;
        ensure!(endpoint.port() != 0, "helper port must be nonzero");
        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(
            STANDARD.decode(invitation.certificate)?,
        ))?;
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            endpoint,
            connector: TlsConnector::from(Arc::new(config)),
            token,
            coordinator_id,
        })
    }

    pub async fn connect(&self, operation: u8) -> Result<TlsStream<TcpStream>> {
        timeout(CONNECT_TIMEOUT, async {
            let socket = TcpStream::connect(self.endpoint).await?;
            socket.set_nodelay(true)?;
            let mut tls = self
                .connector
                .connect(ServerName::try_from(TLS_NAME)?, socket)
                .await?;
            tls.write_all(&self.token).await?;
            tls.write_all(&self.coordinator_id).await?;
            tls.write_u8(operation).await?;
            tls.flush().await?;
            ensure!(tls.read_u8().await? == 0, "helper rejected the request");
            Ok(tls)
        })
        .await?
    }

    pub async fn status(&self) -> Result<Telemetry> {
        timeout(CONNECT_TIMEOUT, async {
            let mut stream = self.connect(OP_STATUS).await?;
            let length = stream.read_u32().await?;
            ensure!(length <= 1024, "helper telemetry exceeds limits");
            let mut bytes = vec![0; length as usize];
            stream.read_exact(&mut bytes).await?;
            let telemetry: Telemetry = serde_json::from_slice(&bytes)?;
            crate::resources::validate_budget(
                telemetry.available_bytes.max(crate::RESERVE_BYTES * 2),
                telemetry.threads,
            )?;
            Ok(telemetry)
        })
        .await?
    }
}

pub(crate) fn token_matches(expected: &[u8], received: &[u8]) -> Result<()> {
    let mut actual = Hmac::<Sha256>::new_from_slice(received)?;
    actual.update(b"codex-local-model-pairing-v1");
    let mut verifier = Hmac::<Sha256>::new_from_slice(expected)?;
    verifier.update(b"codex-local-model-pairing-v1");
    verifier.verify_slice(&actual.finalize().into_bytes())?;
    Ok(())
}

pub(crate) async fn relay<A, B>(left: &mut A, right: &mut B) -> Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (lr, lw) = tokio::io::split(left);
    let (rr, rw) = tokio::io::split(right);
    timeout(Duration::from_secs(3600), async {
        tokio::try_join!(pump(lr, rw), pump(rr, lw))?;
        anyhow::Ok(())
    })
    .await?
}

async fn pump(
    mut reader: impl AsyncRead + Unpin,
    mut writer: impl AsyncWrite + Unpin,
) -> Result<()> {
    let mut buffer = Zeroizing::new(vec![0; 64 * 1024]);
    let mut transferred = 0_u64;
    loop {
        let count = timeout(IO_TIMEOUT, reader.read(&mut buffer)).await??;
        if count == 0 {
            timeout(IO_TIMEOUT, writer.shutdown()).await??;
            return Ok(());
        }
        transferred += count as u64;
        ensure!(
            transferred <= 128 * 1024 * 1024 * 1024,
            "device transfer exceeds session bound"
        );
        timeout(IO_TIMEOUT, writer.write_all(&buffer[..count])).await??;
        timeout(IO_TIMEOUT, writer.flush()).await??;
    }
}

#[cfg(test)]
#[path = "transport_tests.rs"]
mod tests;
