//! Android (Termux) entry point for `codex-linux-sandbox`.
//!
//! There is no bubblewrap on Android: this applies the Landlock LSM filesystem
//! rules (writable roots, full read) plus the network seccomp filter to the
//! current process, then execs the requested command. It mirrors the legacy
//! Landlock tail of [`crate::linux_run_main::run_main`].

use clap::Parser;
use std::path::PathBuf;

use codex_protocol::models::PermissionProfile;

use crate::exec_util::exec_or_panic;
use crate::landlock::apply_permission_profile_to_current_thread;

/// CLI surface for the Android sandbox helper.
///
/// The accepted flags are the subset of the Linux helper's `LandlockCommand`
/// that [`codex_sandboxing::landlock::create_linux_sandbox_command_args_for_permission_profile`]
/// emits with `use_legacy_landlock = true` and no managed-network routing.
#[derive(Debug, Parser)]
struct AndroidSandboxCommand {
    /// cwd used to resolve `:workspace`-relative rules in the permission profile.
    #[arg(long = "sandbox-policy-cwd")]
    sandbox_policy_cwd: PathBuf,

    /// Logical working directory of the command being sandboxed. Accepted for
    /// parity with the Linux helper; the child inherits this process's cwd.
    #[arg(long = "command-cwd", hide = true)]
    command_cwd: Option<PathBuf>,

    /// Canonical runtime permissions for the command (JSON).
    #[arg(long = "permission-profile", hide = true, value_parser = parse_permission_profile)]
    permission_profile: Option<PermissionProfile>,

    /// Accepted and ignored: the Android backend is always legacy Landlock.
    #[arg(long = "use-legacy-landlock", hide = true, default_value_t = false)]
    use_legacy_landlock: bool,

    /// Accepted for CLI parity; unsupported on Android (no network namespace).
    #[arg(long = "allow-network-for-proxy", hide = true, default_value_t = false)]
    allow_network_for_proxy: bool,

    /// Full command args to run under the sandbox.
    #[arg(trailing_var_arg = true)]
    command: Vec<String>,
}

fn parse_permission_profile(value: &str) -> Result<PermissionProfile, String> {
    serde_json::from_str(value).map_err(|err| format!("invalid permission profile JSON: {err}"))
}

pub fn run_main() -> ! {
    let AndroidSandboxCommand {
        sandbox_policy_cwd,
        command_cwd: _,
        permission_profile,
        use_legacy_landlock,
        allow_network_for_proxy,
        command,
    } = AndroidSandboxCommand::parse();
    // The Android backend has no bubblewrap pipeline, so it is always the
    // "legacy" Landlock path regardless of this flag.
    let _ = use_legacy_landlock;

    if allow_network_for_proxy {
        panic!("managed-network proxy routing is not supported by the Android sandbox");
    }
    if command.is_empty() {
        panic!("No command specified to execute.");
    }

    let permission_profile =
        permission_profile.unwrap_or_else(|| panic!("missing permission profile configuration"));

    if let Err(err) = apply_permission_profile_to_current_thread(
        &permission_profile,
        &sandbox_policy_cwd,
        /*apply_landlock_fs*/ true,
        /*allow_network_for_proxy*/ false,
        /*proxy_routed_network*/ false,
    ) {
        panic!("error applying Android sandbox restrictions: {err:?}");
    }

    exec_or_panic(command);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_linux_helper_argv() {
        let profile = PermissionProfile::workspace_write();
        let project = std::path::Path::new("/data/data/com.termux/files/home/project");
        let argv = codex_sandboxing::landlock::create_linux_sandbox_command_args_for_permission_profile(
            vec!["/bin/echo".to_string(), "hi".to_string()],
            project,
            &profile,
            project,
            /*use_legacy_landlock*/ true,
            /*allow_network_for_proxy*/ false,
        );

        let mut full = vec!["codex-linux-sandbox".to_string()];
        full.extend(argv);
        let parsed = AndroidSandboxCommand::try_parse_from(full).expect("parse android argv");

        assert_eq!(parsed.command, vec!["/bin/echo".to_string(), "hi".to_string()]);
        assert_eq!(parsed.permission_profile, Some(profile));
        assert_eq!(parsed.sandbox_policy_cwd.as_path(), project);
    }
}
