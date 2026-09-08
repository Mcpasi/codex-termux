//! Optional Landlock hardening.
//!
//! Android's inherited app seccomp policy may deliver SIGSYS for a Landlock
//! syscall instead of returning ENOSYS. Probe the complete installation in a
//! disposable child before starting the supervised command. Neither an absent
//! LSM nor a forbidden syscall may kill that command during optional setup.
//! The ptrace supervisor remains the mandatory filesystem boundary.

use std::io;
use std::time::Duration;
use std::time::Instant;

use codex_utils_absolute_path::AbsolutePathBuf;
use landlock::ABI;
use landlock::Access;
use landlock::AccessFs;
use landlock::CompatLevel;
use landlock::Compatible;
use landlock::Ruleset;
use landlock::RulesetAttr;
use landlock::RulesetCreatedAttr;
use landlock::RulesetStatus;

const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Called by the single-threaded sandbox launcher before it creates tracees.
/// Check all installation steps, including add_rule and restrict_self: an ABI
/// query alone does not prove that the inherited filter permits those calls.
pub(crate) fn is_supported(writable_roots: &[AbsolutePathBuf]) -> bool {
    probe(|| install(writable_roots).is_ok_and(|status| status != RulesetStatus::NotEnforced))
}

extern "C" fn probe_denied(_signal: libc::c_int) {
    // SAFETY: the probe has no user command or state to preserve. _exit is
    // async-signal-safe and avoids a crash dump for an expected seccomp TRAP.
    unsafe { libc::_exit(1) }
}

fn probe(operation: impl FnOnce() -> bool) -> bool {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    // SAFETY: production calls this from the single-threaded sandbox launcher.
    // The child installs only the optional ruleset and always exits; it never
    // executes a user command, changes the parent's policy, or rejoins Rust.
    let child = unsafe { libc::fork() };
    if child == -1 {
        return false;
    }
    if child == 0 {
        // SAFETY: change signal handling only in this disposable child. The
        // alarm also bounds its lifetime if the launcher disappears.
        unsafe {
            if libc::signal(libc::SIGSYS, probe_denied as libc::sighandler_t) == libc::SIG_ERR
                || libc::signal(libc::SIGALRM, probe_denied as libc::sighandler_t) == libc::SIG_ERR
            {
                libc::_exit(1);
            }
            let mut signals = std::mem::zeroed();
            libc::sigemptyset(&mut signals);
            libc::sigaddset(&mut signals, libc::SIGSYS);
            libc::sigaddset(&mut signals, libc::SIGALRM);
            if libc::sigprocmask(libc::SIG_UNBLOCK, &signals, std::ptr::null_mut()) != 0 {
                libc::_exit(1);
            }
            libc::alarm(PROBE_TIMEOUT.as_secs() as libc::c_uint);
            libc::_exit(if operation() { 0 } else { 1 });
        }
    }

    loop {
        let mut status = 0;
        // SAFETY: wait only for our own probe; never consume a tracee's status.
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        if waited == child {
            return libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
        }
        if waited == -1 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return false;
        }
        if Instant::now() >= deadline {
            // SAFETY: the probe is still our unreaped child. Kill and reap it
            // so a stopped probe cannot survive the finite setup deadline.
            unsafe {
                libc::kill(child, libc::SIGKILL);
                while libc::waitpid(child, &mut status, 0) == -1
                    && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
                {
                }
            }
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Restricts writes after `is_supported` verified this exact installation.
///
/// Reads stay unrestricted here even when the policy narrows them: the legacy
/// Landlock ruleset shape cannot express read narrowing, and this layer must
/// never be *more* permissive or *less* permissive than the supervisor in a way
/// that changes observed behaviour. Read narrowing is enforced by the
/// supervisor.
pub(crate) fn apply_best_effort(writable_roots: &[AbsolutePathBuf]) {
    if let Err(err) = install(writable_roots) {
        // Not a failure: this layer is optional by design.
        let _ = err;
    }
}

fn install(writable_roots: &[AbsolutePathBuf]) -> Result<RulesetStatus, landlock::RulesetError> {
    let abi = ABI::V5;
    let access_rw = AccessFs::from_all(abi);
    let access_ro = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(access_rw)?
        .create()?
        .add_rules(landlock::path_beneath_rules(&["/"], access_ro))?
        .add_rules(landlock::path_beneath_rules(
            &["/dev/null", "/dev/tty"],
            access_rw,
        ))?
        .set_no_new_privs(true);

    if !writable_roots.is_empty() {
        ruleset = ruleset.add_rules(landlock::path_beneath_rules(writable_roots, access_rw))?;
    }

    Ok(ruleset.restrict_self()?.ruleset)
}

#[cfg(test)]
#[path = "landlock_layer_tests.rs"]
mod tests;
