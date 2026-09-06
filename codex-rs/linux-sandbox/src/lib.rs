//! Linux sandbox helper entry point.
//!
//! On Linux, `codex-linux-sandbox` applies:
//! - in-process restrictions (`no_new_privs` + seccomp), and
//! - bubblewrap for filesystem isolation.
//!
//! On Android (Termux, and app-embedded builds) neither is available:
//! bubblewrap needs unprivileged user namespaces and Landlock is absent from
//! most device kernels. The helper therefore runs the command as a traced child
//! and enforces the permission profile itself. See [`android_sandbox`].
#[cfg(target_os = "linux")]
mod bazel_bwrap;
#[cfg(target_os = "linux")]
mod bundled_bwrap;
#[cfg(target_os = "linux")]
mod bwrap;
#[cfg(target_os = "linux")]
mod exec_util;
#[cfg(target_os = "linux")]
mod fd_mount;
#[cfg(target_os = "linux")]
mod landlock;
#[cfg(target_os = "linux")]
mod launcher;
#[cfg(target_os = "linux")]
mod linux_run_main;
#[cfg(target_os = "linux")]
mod proxy_lifecycle;
#[cfg(target_os = "linux")]
mod proxy_routing;

// The policy-decision half of the Android backend is architecture independent
// and free of `ptrace`, so it is built (and unit tested) on Linux hosts as
// well; only the supervisor itself is Android-only.
#[cfg(any(target_os = "linux", target_os = "android"))]
#[cfg_attr(target_os = "linux", allow(dead_code))]
mod android_sandbox;

#[cfg(target_os = "android")]
mod android_run_main;

/// Exit status returned when bundled bubblewrap fails digest verification.
#[cfg(target_os = "linux")]
pub const BUNDLED_BWRAP_DIGEST_VERIFICATION_FAILURE_EXIT_CODE: i32 = 8;

/// Exit status returned when the Android sandbox could not be established.
///
/// The helper never falls back to running the command unconfined, so callers
/// can treat this as "the command did not run" rather than "the command ran
/// without a sandbox".
#[cfg(target_os = "android")]
pub const ANDROID_SANDBOX_SETUP_FAILURE_EXIT_CODE: i32 =
    android_sandbox::SANDBOX_SETUP_FAILURE_EXIT_CODE;

#[cfg(target_os = "linux")]
pub fn run_main() -> ! {
    linux_run_main::run_main();
}

#[cfg(target_os = "android")]
pub fn run_main() -> ! {
    android_run_main::run_main();
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn run_main() -> ! {
    panic!("codex-linux-sandbox is only supported on Linux and Android");
}
