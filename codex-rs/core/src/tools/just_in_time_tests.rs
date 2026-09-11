use super::*;
use codex_protocol::protocol::GranularApprovalConfig;
use pretty_assertions::assert_eq;

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
