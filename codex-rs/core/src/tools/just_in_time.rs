//! One-action human approvals shared by the Android sandbox's callers and
//! app-server clients. The feature is inherited through ordinary session config.
//! It never grants paths and keeps the runtime's private home outside tool access.

use super::approvals::ApprovalAction;
use super::sandboxing::ExecApprovalRequirement;
use crate::environment_selection::TurnEnvironmentSnapshot;
use crate::environment_selection::TurnEnvironmentState;
use crate::exec_policy::prompt_is_rejected_by_policy;
use crate::session::turn_context::TurnEnvironment;
use codex_protocol::models::AdditionalPermissionProfile;
use codex_protocol::models::ManagedFileSystemPermissions;
use codex_protocol::models::PermissionProfile;
use codex_protocol::models::PermissionProfileSnapshot;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_protocol::permissions::ReadDenyMatcher;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::EnvironmentConfigState;
use codex_protocol::protocol::ReviewDecision;
use codex_utils_absolute_path::AbsolutePathBuf;
use codex_utils_path_uri::PathUri;
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
        // every descendant. The JIT grant validator prevents narrower grants
        // from reopening them; these entries also forbid unsandboxed retries.
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

/// A platform sandbox may reopen a more specific grant beneath a denied root.
/// Reject that authority before approval or execution, including stored grants.
pub(crate) fn validate_additional_permissions(
    environment: &TurnEnvironment,
    cwd: &PathUri,
    permissions: Option<&AdditionalPermissionProfile>,
) -> io::Result<()> {
    if environment.environment.is_remote() {
        return Ok(());
    }
    let Some(file_system) = permissions.and_then(|permissions| permissions.file_system.as_ref())
    else {
        return Ok(());
    };
    let cwd = cwd.to_abs_path()?;
    let policy = environment
        .permission_profile_with_workspace_roots()
        .file_system_sandbox_policy();
    let Some(deny) = ReadDenyMatcher::new(&policy, &cwd) else {
        return Ok(());
    };
    for entry in file_system
        .entries
        .iter()
        .filter(|entry| entry.access.can_read())
    {
        // Resolve each grant separately so a broad parent grant cannot hide a
        // second, more specific grant when the root list is deduplicated.
        let grant = FileSystemSandboxPolicy::restricted(vec![entry.clone()])
            .materialize_project_roots_with_path_uris(environment.workspace_roots());
        if grant.has_full_disk_read_access() {
            // A root-wide grant remains constrained by the existing deny roots.
            continue;
        }
        let roots = grant.get_readable_roots_with_cwd(&cwd);
        if roots.is_empty() {
            return Err(io::Error::other(
                "just-in-time permissions cannot resolve an additional permission safely",
            ));
        }
        for root in roots {
            // New paths still have an existing ancestor. Resolve that ancestor
            // to catch both existing aliases and missing children below aliases.
            let mut ancestor = root.as_path();
            let canonical = loop {
                match dunce::canonicalize(ancestor) {
                    Ok(canonical) => {
                        break canonical.join(root.strip_prefix(ancestor).expect("grant ancestor"));
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {
                        ancestor = ancestor.parent().ok_or(error)?;
                    }
                    Err(error) => return Err(error),
                }
            };
            if deny.is_read_denied_with_canonical_path(&root, &canonical) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "just-in-time permissions cannot grant access to protected paths",
                ));
            }
        }
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
