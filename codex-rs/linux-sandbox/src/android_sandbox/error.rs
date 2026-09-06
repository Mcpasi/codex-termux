//! Errors raised while setting up or running the Android sandbox.
//!
//! Every one of these is fatal by design. The helper never reports a partially
//! applied sandbox as success: if a layer cannot be installed, the command is
//! refused rather than run with a weaker boundary than the caller asked for.

use std::fmt;
use std::io;

#[derive(Debug)]
pub(crate) enum SandboxError {
    /// No register layout is implemented for this architecture, so the
    /// supervisor cannot read syscall arguments.
    UnsupportedArchitecture,
    /// A seccomp filter could not be built or installed.
    Seccomp(String),
    /// A `ptrace` request failed.
    Ptrace {
        operation: &'static str,
        source: io::Error,
    },
    Io(io::Error),
    Other(String),
}

impl fmt::Display for SandboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedArchitecture => write!(
                f,
                "the Android sandbox supervisor does not support this CPU architecture"
            ),
            Self::Seccomp(message) => write!(f, "seccomp setup failed: {message}"),
            Self::Ptrace { operation, source } => {
                write!(f, "ptrace {operation} failed: {source}")
            }
            Self::Io(source) => write!(f, "{source}"),
            Self::Other(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SandboxError {}

impl From<io::Error> for SandboxError {
    fn from(source: io::Error) -> Self {
        Self::Io(source)
    }
}

impl From<seccompiler::Error> for SandboxError {
    fn from(source: seccompiler::Error) -> Self {
        Self::Seccomp(source.to_string())
    }
}

impl From<seccompiler::BackendError> for SandboxError {
    fn from(source: seccompiler::BackendError) -> Self {
        Self::Seccomp(source.to_string())
    }
}

pub(crate) type Result<T> = std::result::Result<T, SandboxError>;

/// Wraps the return of a `ptrace` request, turning `-1` into an error carrying
/// the failing operation's name.
pub(crate) fn ptrace_result(operation: &'static str, ret: libc::c_long) -> Result<libc::c_long> {
    if ret == -1 {
        let source = io::Error::last_os_error();
        // `PTRACE_PEEK*` legitimately returns -1 on success; those callers use
        // a different helper, so any -1 here is a real failure.
        if source.raw_os_error() != Some(0) {
            return Err(SandboxError::Ptrace { operation, source });
        }
    }
    Ok(ret)
}
