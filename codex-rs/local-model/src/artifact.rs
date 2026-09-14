use anyhow::Context;
use anyhow::Result;
use anyhow::ensure;
use codex_app_server_protocol::LocalModelArtifact;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::fs::Metadata;
use std::io::Read;
use std::path::PathBuf;

pub(crate) struct VerifiedArtifact {
    pub file: File,
    pub path: PathBuf,
    metadata: Metadata,
}

impl VerifiedArtifact {
    pub fn open(spec: &LocalModelArtifact, limit: u64) -> Result<Self> {
        ensure!(
            spec.path.len() <= 4096 && !spec.path.contains('\0'),
            "invalid artifact path"
        );
        ensure!(
            spec.sha256.len() == 64 && spec.sha256.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid artifact SHA-256"
        );
        let path = PathBuf::from(&spec.path);
        ensure!(
            path.is_absolute() && path.canonicalize()? == path,
            "artifact must use its absolute canonical path"
        );
        let metadata = std::fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && metadata.len() > 0 && metadata.len() <= limit,
            "artifact must be a bounded regular file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ensure!(
                metadata.nlink() == 1 && metadata.mode() & 0o022 == 0,
                "artifact must have one link and no group/other write access"
            );
        }
        let mut file = File::open(&path).context("open local artifact")?;
        ensure!(
            same_file(&metadata, &file.metadata()?),
            "artifact changed while opening"
        );
        let mut digest = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut remaining = metadata.len();
        while remaining > 0 {
            let count = file.read(&mut buffer)?;
            ensure!(
                count > 0 && count as u64 <= remaining,
                "artifact changed while hashing"
            );
            remaining -= count as u64;
            digest.update(&buffer[..count]);
        }
        ensure!(
            format!("{:x}", digest.finalize()).eq_ignore_ascii_case(&spec.sha256),
            "artifact SHA-256 mismatch"
        );
        let verified = Self {
            file,
            path,
            metadata,
        };
        verified.validate()?;
        Ok(verified)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            same_file(&self.metadata, &self.file.metadata()?),
            "verified artifact changed"
        );
        ensure!(
            same_file(&self.metadata, &std::fs::symlink_metadata(&self.path)?),
            "verified artifact was replaced"
        );
        ensure!(
            self.path.canonicalize()? == self.path,
            "verified artifact path changed"
        );
        Ok(())
    }

    pub fn length(&self) -> u64 {
        self.metadata.len()
    }

    // Linux/Android children inherit these already verified handles, preventing path replacement
    // between verification and exec/model loading. Other hosts revalidate the canonical path.
    pub fn child_path(&self) -> PathBuf {
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            use std::os::fd::AsRawFd;
            PathBuf::from(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
        }
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        self.path.clone()
    }
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    let common = right.is_file()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        common
            && left.dev() == right.dev()
            && left.ino() == right.ino()
            && left.ctime() == right.ctime()
            && left.ctime_nsec() == right.ctime_nsec()
            && left.mode() == right.mode()
            && right.nlink() == 1
    }
    #[cfg(not(unix))]
    common
}

#[cfg(test)]
#[path = "artifact_tests.rs"]
mod tests;
