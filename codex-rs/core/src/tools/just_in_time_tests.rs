use super::*;
use crate::environment_selection::EnvironmentConfigOrigin;
use crate::session::turn_context::TurnEnvironment;
use crate::tools::sandboxing::SandboxOverride;
use crate::tools::sandboxing::sandbox_override_for_first_attempt;
use crate::tools::sandboxing::unsandboxed_execution_allowed;
use codex_exec_server::Environment;
use codex_exec_server::LOCAL_ENVIRONMENT_ID;
use codex_protocol::config_types::WindowsSandboxLevel;
use codex_protocol::models::ActivePermissionProfile;
use codex_protocol::models::AdditionalPermissionProfile;
use codex_protocol::models::FileSystemPermissions;
use codex_protocol::models::SandboxPermissions;
use codex_protocol::permissions::NetworkSandboxPolicy;
use codex_protocol::permissions::ReadDenyMatcher;
use codex_protocol::protocol::EnvironmentConfig;
use codex_protocol::protocol::GranularApprovalConfig;
use codex_protocol::protocol::TurnEnvironmentSelection;
use codex_sandboxing::policy_transforms::effective_permission_profile;
use pretty_assertions::assert_eq;
use std::sync::Arc;

fn local_environments(
    cwd: &AbsolutePathBuf,
    permissions: PermissionProfile,
) -> TurnEnvironmentSnapshot {
    let mut environment = TurnEnvironment::new(
        TurnEnvironmentSelection {
            environment_id: LOCAL_ENVIRONMENT_ID.to_string(),
            cwd: cwd.clone().into(),
            workspace_roots: Vec::new(),
            config: EnvironmentConfigState::Ready(EnvironmentConfig {
                allow_login_shell: true,
                workspace_roots: vec![cwd.clone().into()],
                windows_sandbox_level: WindowsSandboxLevel::Disabled,
                windows_sandbox_private_desktop: true,
                use_legacy_landlock: false,
                permission_profile: PermissionProfileSnapshot::active_with_profile_workspace_roots(
                    permissions,
                    ActivePermissionProfile::new("jit-test"),
                    vec![cwd.clone()],
                ),
                shell_environment_policy: Default::default(),
                exec_policy: None,
                mcp_policy: None,
                network_policy: None,
                selected_capability_roots: Vec::new(),
            }),
        },
        EnvironmentConfigOrigin::Thread,
        Arc::new(Environment::default_for_tests()),
        /*shell*/ None,
    );
    environment.shell_snapshot_v2_supported = true;
    TurnEnvironmentSnapshot {
        environments: vec![TurnEnvironmentState::Ready(environment)],
    }
}

#[test]
fn codex_home_denial_survives_grants_and_disables_unsandboxed_attempts() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = AbsolutePathBuf::from_absolute_path(temp.path())
        .expect("absolute root")
        .canonicalize()
        .expect("canonical root");
    let home = root.join("codex-home");
    let workspace = root.join("workspace");
    std::fs::create_dir_all(&home).expect("create home");
    std::fs::create_dir_all(&workspace).expect("create workspace");
    let baseline = PermissionProfile::workspace_write();
    let mut environments = local_environments(&workspace, baseline.clone());
    protect_codex_home(&mut environments, &home).expect("protect home");
    protect_codex_home(&mut environments, &home).expect("protection is idempotent");
    let environment = environments.primary().expect("local environment");
    let mut expected_policy = baseline.file_system_sandbox_policy();
    expected_policy.entries.push(FileSystemSandboxEntry::new(
        home.clone().into(),
        FileSystemAccessMode::Deny,
    ));
    assert_eq!(
        environment.config().permission_profile,
        PermissionProfileSnapshot::active_with_profile_workspace_roots(
            PermissionProfile::from_runtime_permissions(
                &expected_policy,
                baseline.network_sandbox_policy(),
            ),
            ActivePermissionProfile::new("jit-test"),
            vec![workspace.clone()],
        )
    );
    assert!(!environment.shell_snapshot_v2_supported);
    let file = home.join("auth.json");
    for grant in [&root, &home, &file] {
        let additional = AdditionalPermissionProfile {
            file_system: Some(FileSystemPermissions::from_read_write_roots(
                Some(vec![grant.clone()]),
                Some(vec![grant.clone()]),
            )),
            ..Default::default()
        };
        let policy =
            effective_permission_profile(environment.permission_profile(), Some(&additional))
                .file_system_sandbox_policy();
        let deny = ReadDenyMatcher::new(&policy, &workspace).expect("home deny matcher");
        assert!(deny.is_read_denied(&file));
        assert!(!deny.is_read_denied(&workspace.join("result")));
        assert_eq!(
            policy.get_unreadable_roots_with_cwd(&workspace),
            vec![home.clone()]
        );
        assert!(!unsandboxed_execution_allowed(&policy));
        assert_eq!(
            sandbox_override_for_first_attempt(
                SandboxPermissions::RequireEscalated,
                &approval_requirement(
                    AskForApproval::OnRequest,
                    ExecApprovalRequirement::Skip {
                        bypass_sandbox: true,
                        proposed_execpolicy_amendment: None,
                    },
                ),
                &policy,
                /*sandbox_unavailable_by_construction*/ false,
            ),
            SandboxOverride::NoOverride,
        );
    }
}

#[test]
fn managed_full_access_keeps_home_denied_and_other_paths_writable() {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = AbsolutePathBuf::from_absolute_path(temp.path()).expect("absolute home");
    let mut environments = local_environments(
        &home,
        PermissionProfile::Managed {
            file_system: ManagedFileSystemPermissions::Unrestricted,
            network: NetworkSandboxPolicy::Enabled,
        },
    );
    protect_codex_home(&mut environments, &home).expect("protect unrestricted managed profile");
    let environment = environments.primary().expect("local environment");
    let permissions = environment.permission_profile();
    let policy = permissions.file_system_sandbox_policy();
    assert_eq!(
        permissions.network_sandbox_policy(),
        NetworkSandboxPolicy::Enabled
    );
    assert!(!policy.has_full_disk_write_access());
    assert!(
        ReadDenyMatcher::new(&policy, &home)
            .expect("home denial")
            .is_read_denied(&home.join("auth.json"))
    );
    assert!(policy.can_write_path_with_cwd(&home.parent().expect("parent").join("outside"), &home));
}

#[test]
fn unresolvable_home_and_unmanaged_profiles_fail_closed() {
    let temp = tempfile::tempdir().expect("temp dir");
    let home = AbsolutePathBuf::from_absolute_path(temp.path()).expect("absolute home");
    for permissions in [
        PermissionProfile::Disabled,
        PermissionProfile::External {
            network: NetworkSandboxPolicy::Enabled,
        },
    ] {
        let mut environments = local_environments(&home, permissions.clone());
        assert!(protect_codex_home(&mut environments, &home).is_err());
        assert_eq!(
            environments
                .primary()
                .expect("local environment")
                .permission_profile(),
            &permissions
        );
    }
    let mut environments = local_environments(&home, PermissionProfile::workspace_write());
    assert!(protect_codex_home(&mut environments, &home.join("missing")).is_err());
}

#[cfg(unix)]
#[test]
fn home_symlink_protects_both_spellings_and_workspace_aliases() {
    let temp = tempfile::tempdir().expect("temp dir");
    let root = AbsolutePathBuf::from_absolute_path(temp.path()).expect("absolute root");
    let home = root.join("private-home");
    std::fs::create_dir(&home).expect("create home");
    let alias = root.join("configured-home");
    std::os::unix::fs::symlink(&home, &alias).expect("home symlink");
    let mut environments = local_environments(&root, PermissionProfile::workspace_write());
    protect_codex_home(&mut environments, &alias).expect("protect canonical home");
    let policy = environments
        .primary()
        .expect("local environment")
        .permission_profile()
        .file_system_sandbox_policy();
    let canonical = home.canonicalize().expect("canonical home");
    for home in [&alias, &canonical] {
        assert!(policy.entries.contains(&FileSystemSandboxEntry::new(
            home.clone().into(),
            FileSystemAccessMode::Deny
        )));
    }
    let workspace_alias = root.join("workspace-alias");
    std::os::unix::fs::symlink(&home, &workspace_alias).expect("workspace symlink");
    let deny = ReadDenyMatcher::new(&policy, &root).expect("home denial");
    let resolved = workspace_alias
        .canonicalize()
        .expect("resolve workspace alias");
    assert!(deny.is_read_denied_with_canonical_path(
        &workspace_alias.join("auth.json"),
        &resolved.join("auth.json"),
    ));
}

#[test]
fn persistent_command_allow_becomes_a_sandboxed_one_action_request() {
    assert_eq!(
        approval_requirement(
            AskForApproval::OnRequest,
            ExecApprovalRequirement::Skip {
                bypass_sandbox: true,
                proposed_execpolicy_amendment: None,
            }
        ),
        ExecApprovalRequirement::NeedsApproval {
            reason: Some(REASON.to_string()),
            proposed_execpolicy_amendment: None,
        }
    );
}

#[test]
fn policy_prohibitions_remain_authoritative() {
    let forbidden = ExecApprovalRequirement::Forbidden {
        reason: "blocked by policy".to_string(),
    };
    assert_eq!(
        approval_requirement(AskForApproval::OnRequest, forbidden.clone()),
        forbidden
    );
    let no_prompts = AskForApproval::Granular(GranularApprovalConfig {
        sandbox_approval: false,
        rules: true,
        skill_approval: true,
        request_permissions: true,
        mcp_elicitations: true,
    });
    assert!(matches!(
        approval_requirement(
            no_prompts,
            ExecApprovalRequirement::Skip {
                bypass_sandbox: false,
                proposed_execpolicy_amendment: None,
            }
        ),
        ExecApprovalRequirement::Forbidden { .. }
    ));
}
