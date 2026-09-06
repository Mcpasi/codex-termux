//! The Android sandbox backend.
//!
//! Android has neither bubblewrap (no unprivileged user namespaces) nor a
//! guaranteed Landlock LSM, so neither of the mechanisms the Linux backend
//! relies on can be promised on arbitrary hardware. This backend is built only
//! on features every Android kernel is required to have — `seccomp` and
//! `ptrace` — and enforces the session's [`FileSystemSandboxPolicy`] itself,
//! syscall by syscall, in [`supervisor`].
//!
//! Layout:
//!
//! | module | role |
//! | --- | --- |
//! | [`syscalls`] | which syscalls carry paths, and where |
//! | [`resolve`] | turning syscall arguments into absolute paths |
//! | [`decision`] | answering those paths from the policy |
//! | [`seccomp`] | the deny-lists and the trace filter |
//! | [`supervisor`] | the ptrace loop that ties them together |
//! | [`landlock_layer`] | optional extra hardening when the kernel has it |
//! | [`arch`], [`mem`] | register and memory access for the supervisor |

pub(crate) mod decision;
pub(crate) mod error;
pub(crate) mod resolve;
pub(crate) mod seccomp;
pub(crate) mod syscalls;

#[cfg(target_os = "android")]
mod arch;
#[cfg(target_os = "android")]
mod landlock_layer;
#[cfg(target_os = "android")]
mod mem;
#[cfg(target_os = "android")]
mod supervisor;

#[cfg(target_os = "android")]
use std::path::Path;

#[cfg(target_os = "android")]
use codex_protocol::models::PermissionProfile;

#[cfg(target_os = "android")]
pub(crate) use supervisor::SANDBOX_SETUP_FAILURE_EXIT_CODE;

/// Runs `command` under the Android sandbox and exits with its status.
///
/// Never returns: either the sandboxed command's status is propagated, or the
/// sandbox could not be established and the command is refused. There is no
/// path through this function that runs the command unconfined.
#[cfg(target_os = "android")]
pub(crate) fn run(
    permission_profile: &PermissionProfile,
    sandbox_policy_cwd: &Path,
    command: Vec<String>,
) -> ! {
    let (file_system_sandbox_policy, network_sandbox_policy) =
        permission_profile.to_runtime_permissions();

    let network = if network_sandbox_policy.is_enabled() {
        seccomp::NetworkMode::Allowed
    } else {
        seccomp::NetworkMode::Denied
    };

    // Landlock, when the kernel has it, adds a second write boundary behind the
    // supervisor. It is skipped for policies that grant full disk write access,
    // where it would have nothing to enforce.
    let landlock_writable_roots = if file_system_sandbox_policy.has_full_disk_write_access() {
        None
    } else {
        Some(
            file_system_sandbox_policy
                .get_writable_roots_with_cwd(sandbox_policy_cwd)
                .into_iter()
                .map(|writable_root| writable_root.root)
                .collect(),
        )
    };

    let proc_root = supervisor::default_proc_root().to_path_buf();
    let policy = decision::PolicyEngine::new(
        file_system_sandbox_policy,
        sandbox_policy_cwd.to_path_buf(),
        &proc_root,
        std::process::id() as i32,
    );

    supervisor::run(
        supervisor::SupervisorConfig {
            policy,
            network,
            proc_root,
            landlock_writable_roots,
        },
        command,
    )
}
