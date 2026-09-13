//! One-action human approvals shared by the Android sandbox's callers and
//! app-server clients. The feature is inherited through ordinary session config.
//! It never grants paths and keeps the runtime's private home outside tool access.

use super::approvals::ApprovalAction;
use super::sandboxing::ExecApprovalRequirement;
use crate::environment_selection::TurnEnvironmentSnapshot;
use crate::environment_selection::TurnEnvironmentState;
use crate::exec_policy::prompt_is_rejected_by_policy;
use codex_protocol::models::ManagedFileSystemPermissions;
use codex_protocol::models::PermissionProfile;
use codex_protocol::models::PermissionProfileSnapshot;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::EnvironmentConfigState;
use codex_protocol::protocol::ReviewDecision;
use codex_utils_absolute_path::AbsolutePathBuf;
use futures::FutureExt;
use std::io;

pub(crate) const REASON: &str =
    "Just-in-time permissions: the agent is paused. Allow or deny this action only.";

/// Protect the controller's home in the local step snapshot before tools can
/// inspect files, prepare patch previews, or launch processes. Runtime-owned
/// authentication and storage keep using the original configuration.
pub(crate) fn protect_codex_home(
    environments: &mut TurnEnvironmentSnapshot,
    codex_home: &AbsolutePathBuf,
) -> io::Result<()> {
    let canonical_home = codex_home.canonicalize().map_err(|_| {
        io::Error::other("just-in-time permissions cannot resolve CODEX_HOME safely")
    })?;
    if canonical_home.parent().is_none() {
        return Err(io::Error::other(
            "just-in-time permissions require CODEX_HOME below the filesystem root",
        ));
    }
    for environment in &mut environments.environments {
        let TurnEnvironmentState::Ready(environment) = environment else {
            continue;
        };
        // Controller-native paths must never be projected into a foreign executor.
        if environment.environment.is_remote() {
            continue;
        }
        let EnvironmentConfigState::Ready(config) = &mut environment.selection.config else {
            unreachable!("ready turn environments always carry resolved configuration");
        };
        let snapshot = &config.permission_profile;
        let mut permissions = snapshot.permission_profile().clone();
        let PermissionProfile::Managed { file_system, .. } = &mut permissions else {
            return Err(io::Error::other(
                "just-in-time permissions require a managed filesystem sandbox to protect CODEX_HOME",
            ));
        };
        if matches!(file_system, ManagedFileSystemPermissions::Unrestricted) {
            *file_system = ManagedFileSystemPermissions::Restricted {
                entries: vec![FileSystemSandboxEntry::new(
                    FileSystemPath::Special {
                        value: FileSystemSpecialPath::Root,
                    },
                    FileSystemAccessMode::Write,
                )],
                glob_scan_max_depth: None,
            };
        }
        let ManagedFileSystemPermissions::Restricted { entries, .. } = file_system else {
            unreachable!("unrestricted managed permissions were materialized above");
        };
        // Deny both the configured spelling and the canonical target, including
        // every descendant. Additional grants cannot remove these deny entries;
        // they also make unsandboxed first attempts and retries ineligible.
        for home in [codex_home, &canonical_home] {
            let denial =
                FileSystemSandboxEntry::new(home.clone().into(), FileSystemAccessMode::Deny);
            if !entries.contains(&denial) {
                entries.push(denial);
            }
        }
        config.permission_profile = match snapshot.active_permission_profile() {
            Some(active) => PermissionProfileSnapshot::active_with_profile_workspace_roots(
                permissions,
                active,
                snapshot.profile_workspace_roots().to_vec(),
            ),
            None => PermissionProfileSnapshot::legacy(permissions),
        };
        // Snapshots are runtime files under CODEX_HOME. Do not grant a carveout
        // just to source them inside an otherwise protected command.
        environment.shell_snapshot = futures::future::ready(None).boxed().shared();
        environment.shell_snapshot_v2_supported = false;
    }
    Ok(())
}

pub(crate) fn approval_requirement(
    policy: AskForApproval,
    requirement: ExecApprovalRequirement,
) -> ExecApprovalRequirement {
    if matches!(requirement, ExecApprovalRequirement::Forbidden { .. }) {
        return requirement;
    }
    if let Some(reason) = prompt_is_rejected_by_policy(policy, /*prompt_is_rule*/ false) {
        return ExecApprovalRequirement::Forbidden {
            reason: format!("just-in-time permissions require a human decision: {reason}"),
        };
    }
    let reason = match requirement {
        ExecApprovalRequirement::NeedsApproval { reason, .. } => reason,
        ExecApprovalRequirement::Skip { .. } => None,
        ExecApprovalRequirement::Forbidden { .. } => unreachable!("handled above"),
    };
    ExecApprovalRequirement::NeedsApproval {
        reason: reason.or_else(|| Some(REASON.to_string())),
        proposed_execpolicy_amendment: None,
    }
}

impl ApprovalAction {
    pub(crate) fn requires_just_in_time_approval(&self) -> bool {
        match self {
            Self::ExecCommand { .. } | Self::ApplyPatch { .. } | Self::WriteStdin { .. } => true,
            #[cfg(unix)]
            Self::Execve { .. } => true,
            Self::McpToolCall { .. }
            | Self::NetworkAccess { .. }
            | Self::RequestPermissions { .. } => false,
        }
    }
}

/// Older clients may still offer session/rule grants. Consume those as an
/// approval of this action only. Command handlers also prevent persistence.
pub(crate) fn one_action_decision(decision: ReviewDecision) -> ReviewDecision {
    match decision {
        ReviewDecision::ApprovedForSession | ReviewDecision::ApprovedExecpolicyAmendment { .. } => {
            ReviewDecision::Approved
        }
        ReviewDecision::Approved | ReviewDecision::Denied { .. } | ReviewDecision::Abort => {
            decision
        }
        ReviewDecision::ApprovedMcpPolicyAmendment
        | ReviewDecision::NetworkPolicyAmendment { .. }
        | ReviewDecision::TimedOut => {
            ReviewDecision::denied("invalid just-in-time approval decision")
        }
    }
}

#[cfg(test)]
#[path = "just_in_time_tests.rs"]
mod tests;
