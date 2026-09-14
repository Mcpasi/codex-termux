use super::*;
use pretty_assertions::assert_eq;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn raw_rpc_socket_is_private_and_removed_with_its_owner() -> Result<()> {
    let storage = tempfile::tempdir()?;
    let rpc = LocalRpc::new(&storage.path().canonicalize()?)?;
    let path = rpc.path().to_owned();
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("RPC parent missing"))?;
    assert_eq!(
        std::fs::metadata(parent)?.permissions().mode() & 0o777,
        0o700
    );
    let listener = rpc.bind()?;
    let _client = LocalRpc::connect(&path).await?;
    let (_server, _) = listener.accept().await?;
    drop(listener);
    drop(rpc);
    assert!(!path.exists());
    Ok(())
}
