//! The one-action choices for the shared just-in-time approval gate.

use super::ApprovalDecision;
use super::ApprovalKeymap;
use super::ApprovalOption;
use super::ApprovalRequest;
use super::CommandExecutionApprovalDecision;
use super::FileChangeApprovalDecision;

pub(super) fn approval_options(
    request: &ApprovalRequest,
    keymap: &ApprovalKeymap,
) -> Option<Vec<ApprovalOption>> {
    let (allow, deny) = match request {
        ApprovalRequest::Exec(request) if request.network_approval_context.is_none() => (
            ApprovalDecision::Command(CommandExecutionApprovalDecision::Accept),
            ApprovalDecision::Command(CommandExecutionApprovalDecision::Decline),
        ),
        ApprovalRequest::ApplyPatch(_) => (
            ApprovalDecision::FileChange(FileChangeApprovalDecision::Accept),
            ApprovalDecision::FileChange(FileChangeApprovalDecision::Decline),
        ),
        ApprovalRequest::Exec(_)
        | ApprovalRequest::Permissions(_)
        | ApprovalRequest::McpElicitation(_) => return None,
    };
    Some(vec![
        ApprovalOption {
            label: "Allow".to_string(),
            decision: allow,
            shortcuts: keymap.approve.clone(),
        },
        ApprovalOption {
            label: "Deny".to_string(),
            decision: deny,
            shortcuts: keymap.deny.clone(),
        },
    ])
}
