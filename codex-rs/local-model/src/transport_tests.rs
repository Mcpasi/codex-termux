use super::*;
use pretty_assertions::assert_eq;
use rustls::ServerConfig;
use rustls::pki_types::PrivatePkcs8KeyDer;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

#[test]
fn rejects_public_wildcard_dns_and_malformed_endpoints() {
    for value in [
        "0.0.0.0:5000",
        "[::]:5000",
        "8.8.8.8:5000",
        "example.com:5000",
        "http://192.168.1.2:5000",
        "192.168.1.2:65536",
    ] {
        assert!(address(value).is_err(), "{value}");
    }
    for value in ["127.0.0.1:0", "192.168.1.2:5000", "[fd00::1]:5000"] {
        assert!(address(value).is_ok(), "{value}");
    }
}

#[test]
fn pairing_verifies_the_entire_secret() -> Result<()> {
    let secret = rand::random::<[u8; 32]>();
    token_matches(&secret, &secret)?;
    for index in 0..32 {
        let mut wrong = secret;
        wrong[index] ^= 1;
        assert!(token_matches(&secret, &wrong).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn relay_preserves_bytes_in_both_directions_and_closes() -> Result<()> {
    let (mut left_client, mut left_relay) = tokio::io::duplex(128);
    let (mut right_relay, mut right_client) = tokio::io::duplex(128);
    let task = tokio::spawn(async move { relay(&mut left_relay, &mut right_relay).await });
    left_client.write_all(b"activation").await?;
    let mut received = [0; 10];
    right_client.read_exact(&mut received).await?;
    assert_eq!(&received, b"activation");
    right_client.write_all(b"logits").await?;
    let mut output = [0; 6];
    left_client.read_exact(&mut output).await?;
    assert_eq!(&output, b"logits");
    left_client.shutdown().await?;
    right_client.shutdown().await?;
    timeout(CONNECT_TIMEOUT, task).await???;
    Ok(())
}

fn server_identity() -> Result<(CertificateDer<'static>, ServerConfig)> {
    let identity = rcgen::generate_simple_self_signed(vec![TLS_NAME.to_owned()])?;
    let cert = identity.cert.der().clone();
    let key = PrivatePkcs8KeyDer::from(identity.signing_key.serialize_der());
    let config = ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![cert.clone()], key.into())?;
    Ok((cert, config))
}

#[tokio::test]
async fn certificate_pinned_channel_authenticates_before_telemetry() -> Result<()> {
    let (cert, config) = server_identity()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let secret = rand::random::<[u8; 32]>();
    let coordinator_id = rand::random::<[u8; 16]>();
    let invitation = LocalModelPeer {
        endpoint: listener.local_addr()?.to_string(),
        certificate: STANDARD.encode(cert),
        token: STANDARD.encode(secret),
    };
    let client = PeerClient::new(invitation.clone(), coordinator_id)?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let mut tls = TlsAcceptor::from(Arc::new(config)).accept(socket).await?;
        let mut token = [0; 32];
        tls.read_exact(&mut token).await?;
        token_matches(&secret, &token)?;
        let mut owner = [0; 16];
        tls.read_exact(&mut owner).await?;
        assert_eq!(owner, coordinator_id);
        assert_eq!(tls.read_u8().await?, OP_STATUS);
        tls.write_u8(0).await?;
        let bytes = serde_json::to_vec(&Telemetry {
            available_bytes: 1024 * 1024 * 1024,
            threads: 2,
        })?;
        tls.write_u32(bytes.len() as u32).await?;
        tls.write_all(&bytes).await?;
        tls.shutdown().await?;
        anyhow::Ok(())
    });
    let telemetry = client.status().await?;
    assert_eq!(
        (telemetry.available_bytes, telemetry.threads),
        (1024 * 1024 * 1024, 2)
    );
    timeout(CONNECT_TIMEOUT, server).await???;
    assert!(!format!("{invitation:?}").contains(&invitation.token));
    Ok(())
}

#[tokio::test]
async fn a_different_certificate_cannot_receive_the_pairing_secret() -> Result<()> {
    let (_, config) = server_identity()?;
    let (wrong_cert, _) = server_identity()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = PeerClient::new(
        LocalModelPeer {
            endpoint: listener.local_addr()?.to_string(),
            certificate: STANDARD.encode(wrong_cert),
            token: STANDARD.encode(rand::random::<[u8; 32]>()),
        },
        rand::random(),
    )?;
    let server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let accepted = TlsAcceptor::from(Arc::new(config)).accept(socket).await;
        assert!(accepted.is_err());
        anyhow::Ok(())
    });
    assert!(client.status().await.is_err());
    timeout(CONNECT_TIMEOUT, server).await???;
    Ok(())
}
