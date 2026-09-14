use super::*;
use std::io::Write;

fn fixture() -> Result<(tempfile::NamedTempFile, LocalModelArtifact)> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(b"local model fixture")?;
    let spec = LocalModelArtifact {
        path: file.path().canonicalize()?.to_string_lossy().into_owned(),
        sha256: format!("{:x}", Sha256::digest(b"local model fixture")),
    };
    Ok((file, spec))
}

#[test]
fn verifies_exact_bytes_and_rejects_changed_file() -> Result<()> {
    let (file, spec) = fixture()?;
    let artifact = VerifiedArtifact::open(&spec, /*limit*/ 1024)?;
    artifact.validate()?;
    std::fs::write(file.path(), b"local model changed")?;
    assert!(artifact.validate().is_err());
    assert!(VerifiedArtifact::open(&spec, /*limit*/ 1024).is_err());
    Ok(())
}

#[test]
fn wrong_hash_and_oversized_artifact_are_rejected() -> Result<()> {
    let (_file, mut spec) = fixture()?;
    assert!(VerifiedArtifact::open(&spec, /*limit*/ 4).is_err());
    spec.sha256 = "00".repeat(32);
    assert!(VerifiedArtifact::open(&spec, /*limit*/ 1024).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn links_and_shared_writable_files_are_rejected() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let (file, spec) = fixture()?;
    let directory = tempfile::tempdir()?;
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(file.path(), &link)?;
    assert!(
        VerifiedArtifact::open(
            &LocalModelArtifact {
                path: link.to_string_lossy().into_owned(),
                sha256: spec.sha256.clone()
            },
            /*limit*/ 1024
        )
        .is_err()
    );
    std::fs::hard_link(file.path(), directory.path().join("hard"))?;
    assert!(VerifiedArtifact::open(&spec, /*limit*/ 1024).is_err());
    std::fs::remove_file(directory.path().join("hard"))?;
    std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o666))?;
    assert!(VerifiedArtifact::open(&spec, /*limit*/ 1024).is_err());
    Ok(())
}
