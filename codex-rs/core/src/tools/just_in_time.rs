//! One-action human approvals shared by the Android sandbox's callers and
//! app-server clients. The feature is inherited through ordinary session config.
//! It neither grants paths nor replaces the executor's sandbox policy.

use super::approvals::ApprovalAction;
use super::sandboxing::ExecApprovalRequirement;
use crate::exec_policy::prompt_is_rejected_by_policy;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::ReviewDecision;

pub(crate) const REASON: &str =
    "Just-in-time permissions: the agent is paused. Allow or deny this action only.";

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
