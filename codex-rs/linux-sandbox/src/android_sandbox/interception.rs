//! Verify syscall cancellation before executing any sandboxed command.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum InterceptMode {
    SeccompDirected,
    AllSyscalls,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProbeAction {
    Ready,
    RetryAllSyscalls,
    Refuse,
}

pub(super) const PROBE_READY: u8 = 2;
pub(super) const PROBE_RETRY: u8 = 3;

pub(super) fn probe_action(mode: InterceptMode, observed: bool) -> ProbeAction {
    match (mode, observed) {
        (_, true) => ProbeAction::Ready,
        (InterceptMode::SeccompDirected, false) => ProbeAction::RetryAllSyscalls,
        (InterceptMode::AllSyscalls, false) => ProbeAction::Refuse,
    }
}

/// This impossible open touches no file even without interception.
pub(super) fn is_probe(nr: i64, fd: u64, path: u64, flags: u64) -> bool {
    nr == libc::SYS_openat && fd as i32 == -1 && path == 0 && flags == libc::O_WRONLY as u64
}

#[cfg(target_os = "android")]
pub(super) fn verify_child(
    mut read_ack: impl FnMut() -> super::error::Result<u8>,
) -> super::error::Result<()> {
    for _ in 0..2 {
        // SAFETY: null with an invalid dirfd always fails; it touches no file.
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat,
                -1,
                std::ptr::null::<libc::c_char>(),
                libc::O_WRONLY,
                0,
            )
        };
        let cancelled =
            result == -1 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EACCES);
        // SAFETY: the supervisor consumes this setup stop before command exec.
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
        match read_ack()? {
            PROBE_READY if cancelled => return Ok(()),
            PROBE_RETRY => continue,
            _ => break,
        }
    }
    Err(super::error::SandboxError::Other(
        "filesystem syscall interception could not be verified".to_string(),
    ))
}

#[cfg(test)]
#[path = "interception_tests.rs"]
mod tests;
