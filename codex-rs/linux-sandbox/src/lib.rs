//! Linux sandbox helper entry point.
//!
//! On Linux, `codex-linux-sandbox` applies:
//! - in-process restrictions (`no_new_privs` + seccomp), and
//! - bubblewrap for filesystem isolation.
//!
//! On Android (Termux) there is no bubblewrap: the helper applies the Landlock
//! LSM filesystem rules plus the network seccomp filter, then execs the command.
#[cfg(target_os = "linux")]
mod bazel_bwrap;
#[cfg(target_os = "linux")]
mod bundled_bwrap;
#[cfg(target_os = "linux")]
mod bwrap;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod exec_util;
#[cfg(target_os = "linux")]
mod fd_mount;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod landlock;
#[cfg(target_os = "linux")]
mod launcher;
#[cfg(target_os = "linux")]
mod linux_run_main;
#[cfg(target_os = "linux")]
mod proxy_lifecycle;
#[cfg(target_os = "linux")]
mod proxy_routing;

#[cfg(target_os = "android")]
mod android_run_main;

/// Exit status returned when bundled bubblewrap fails digest verification.
#[cfg(target_os = "linux")]
pub const BUNDLED_BWRAP_DIGEST_VERIFICATION_FAILURE_EXIT_CODE: i32 = 8;

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
