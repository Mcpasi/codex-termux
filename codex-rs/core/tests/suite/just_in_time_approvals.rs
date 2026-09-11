//! Behavioral coverage: pause before side effects, deny without writing,
//! approve repeated commands/patches afresh, and reject incompatible no-prompt
//! policies. Uses the same approval events consumed by app-server clients.

use anyhow::Result;
use codex_config::types::ApprovalsReviewer;
use codex_core::TurnInputRequest;
use codex_core::config::Constrained;
use codex_features::Feature;
use codex_protocol::approvals::ExecApprovalRequestEvent;
use codex_protocol::models::PermissionProfile;
use codex_protocol::protocol::AskForApproval;
use codex_protocol::protocol::EventMsg;
use codex_protocol::protocol::FileChange;
use codex_protocol::protocol::Op;
use codex_protocol::protocol::ReviewDecision;
use codex_protocol::user_input::UserInput;
use core_test_support::responses::ev_apply_patch_custom_tool_call;
use core_test_support::responses::ev_completed;
use core_test_support::responses::mount_function_call_agent_response;
use core_test_support::responses::mount_sse_once;
use core_test_support::responses::sse;
use core_test_support::skip_if_no_network;
use core_test_support::skip_if_target_windows;
use core_test_support::test_codex::TestCodexHarness;
use core_test_support::test_codex::test_codex;
use pretty_assertions::assert_eq;
use serde_json::json;
use std::collections::HashMap;
use test_case::test_case;

/// `mode` selects how `exec_command` is exposed. Disabling unified exec keeps the
/// same tool name and registers it one-shot: no resumable session, no
/// `write_stdin`, and `timeout_ms` in place of `yield_time_ms`.
async fn harness(mode: &'static str, policy: AskForApproval) -> Result<TestCodexHarness> {
    TestCodexHarness::with_auto_env_builder(test_codex().with_config(move |config| {
        config.features.enable(Feature::JustInTimeApprovals).expect("enable just-in-time approvals");
        config.features.disable(Feature::WriteStdinApproval).expect("disable ordinary stdin reviews");
        if mode == "one_shot" {
            config.features.disable(Feature::UnifiedExec).expect("use one-shot exec_command");
        } else {
            config.features.enable(Feature::UnifiedExec).expect("use unified exec");
        }
        // JIT must ask the human even when the ordinary reviewer is automated.
        config.approvals_reviewer = ApprovalsReviewer::AutoReview;
        config.permissions.approval_policy = Constrained::allow_any(policy);
        config.permissions.set_permission_profile(PermissionProfile::workspace_write()).expect("set workspace permissions");
    }).with_pre_build_hook(|home| {
        // Exercise both persistent command allows and hook allows. Neither may
        // authorize an action on behalf of the user in just-in-time mode.
        std::fs::create_dir_all(home.join("rules")).expect("create rules directory");
        std::fs::write(home.join("rules/default.rules"), "prefix_rule(pattern=[\"printf\"], decision=\"allow\")\n").expect("write allow rule");
        #[cfg(unix)]
        std::fs::write(home.join("hooks.json"), json!({"hooks":{"PermissionRequest":[{"hooks":[{
            "type":"command",
            "command":"printf '%s' '{\"hookSpecificOutput\":{\"hookEventName\":\"PermissionRequest\",\"decision\":{\"behavior\":\"allow\"}}}'"
        }]}]}}).to_string()).expect("write allow hook");
    })).await
}

async fn start(harness: &TestCodexHarness) -> Result<()> {
    harness
        .test()
        .codex
        .start_or_steer_turn(TurnInputRequest::user_input(vec![UserInput::Text {
            text: "perform the next action".to_string(),
            text_elements: Vec::new(),
        }]))
        .await?;
    Ok(())
}

async fn next_exec_approval(harness: &TestCodexHarness) -> ExecApprovalRequestEvent {
    match next_approval(harness).await {
        EventMsg::ExecApprovalRequest(request) => request,
        event => panic!("expected command approval, got {event:?}"),
    }
}

async fn next_approval(harness: &TestCodexHarness) -> EventMsg {
    loop {
        match next_event(harness).await {
            event @ (EventMsg::ExecApprovalRequest(_) | EventMsg::ApplyPatchApprovalRequest(_)) => {
                return event;
            }
            event @ (EventMsg::TurnComplete(_) | EventMsg::TurnAborted(_)) => {
                panic!("turn ended before the expected approval: {event:?}");
            }
            _ => {}
        }
    }
}

async fn next_event(harness: &TestCodexHarness) -> EventMsg {
    // Let the runner own cancellation; host startup speed is not a test deadline.
    let event = harness
        .test()
        .codex
        .next_event()
        .await
        .expect("event stream ended")
        .msg;
    if let EventMsg::Error(error) = &event {
        panic!("unexpected session error: {error:?}");
    }
    event
}

enum Completion<'a> {
    Turn,
    Command(&'a str),
    Interrupted,
}

async fn finish_turn(harness: &TestCodexHarness, expected: Completion<'_>) {
    let mut command_finished = !matches!(expected, Completion::Command(_));
    let mut turn_finished = false;
    loop {
        match next_event(harness).await {
            EventMsg::ExecCommandEnd(end) if matches!(expected, Completion::Command(id) if end.call_id == id) =>
            {
                assert_eq!(end.exit_code, 0, "command failed: {end:?}");
                command_finished = true;
            }
            EventMsg::TurnComplete(_) => {
                assert!(
                    !matches!(expected, Completion::Interrupted),
                    "expected interruption"
                );
                turn_finished = true;
            }
            EventMsg::TurnAborted(_) if matches!(expected, Completion::Interrupted) => return,
            event @ (EventMsg::TurnAborted(_)
            | EventMsg::ExecApprovalRequest(_)
            | EventMsg::ApplyPatchApprovalRequest(_)) => {
                panic!("unexpected event while waiting for completion: {event:?}");
            }
            _ => {}
        }
        if turn_finished && command_finished {
            return;
        }
    }
}

async fn decide_and_finish(
    harness: &TestCodexHarness,
    request: ExecApprovalRequestEvent,
    decision: ReviewDecision,
    completion: Completion<'_>,
) -> Result<()> {
    let codex = &harness.test().codex;
    codex
        .submit(Op::ExecApproval {
            id: request.approval_id.unwrap_or(request.call_id),
            turn_id: Some(request.turn_id),
            decision,
        })
        .await?;
    finish_turn(harness, completion).await;
    Ok(())
}

#[test_case("one_shot")]
#[test_case("session")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn repeated_commands_wait_for_a_human_and_denial_has_no_side_effect(
    mode: &'static str,
) -> Result<()> {
    skip_if_target_windows!(Ok(()), "uses a POSIX shell command");
    skip_if_no_network!(Ok(()));
    let harness = harness(mode, AskForApproval::OnRequest).await?;
    let rules_path = harness.test().codex_home_path().join("rules/default.rules");
    let original_rules = std::fs::read_to_string(&rules_path)?;
    let args = json!({"cmd":"printf x >> result"});
    for (id, decision, before, after) in [
        ("deny", ReviewDecision::denied("leave it alone"), "", ""),
        ("allow", ReviewDecision::ApprovedForSession, "", "x"),
        ("repeat", ReviewDecision::Approved, "x", "xx"),
        (
            "legacy_rule",
            ReviewDecision::ApprovedExecpolicyAmendment {
                proposed_execpolicy_amendment: codex_protocol::approvals::ExecPolicyAmendment::new(
                    vec!["node".to_string(), "checks".to_string()],
                ),
            },
            "xx",
            "xxx",
        ),
    ] {
        let mock = mount_function_call_agent_response(
            harness.server(),
            id,
            &args.to_string(),
            "exec_command",
        )
        .await;
        start(&harness).await?;
        let request = next_exec_approval(&harness).await;
        // The tool's output request and filesystem effect must both wait.
        assert!(mock.completion.requests().is_empty());
        let contents = if harness.path_exists("result").await? {
            harness.read_file_text("result").await?
        } else {
            String::new()
        };
        assert_eq!(contents, before);
        assert_eq!(
            request.available_decisions,
            Some(vec![
                ReviewDecision::Approved,
                ReviewDecision::denied("rejected by user")
            ])
        );
        assert_eq!(request.proposed_execpolicy_amendment, None);
        // A yielded command can finish after the model turn. Observe the real
        // process-exit event before checking its writes, regardless of ordering.
        let completion = if id == "deny" {
            Completion::Turn
        } else {
            Completion::Command(id)
        };
        decide_and_finish(&harness, request, decision, completion).await?;
        let contents = if harness.path_exists("result").await? {
            harness.read_file_text("result").await?
        } else {
            String::new()
        };
        assert_eq!(contents, after);
        assert_eq!(mock.function_call.requests().len(), 1);
        let output = mock.completion.single_request().function_call_output(id);
        if id == "deny" {
            assert!(output.to_string().contains("leave it alone"));
        }
    }
    assert_eq!(std::fs::read_to_string(rules_path)?, original_rules);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn patches_show_all_files_and_wait_again_after_session_approval() -> Result<()> {
    skip_if_no_network!(Ok(()));
    let harness = harness("session", AskForApproval::OnRequest).await?;
    for (id, decision) in [
        ("deny", ReviewDecision::denied("do not write")),
        ("allow", ReviewDecision::ApprovedForSession),
        ("repeat", ReviewDecision::denied("keep existing files")),
    ] {
        let patch = "*** Begin Patch\n*** Add File: index.js\n+hello\n*** Add File: docs/notice.md\n+notice\n*** End Patch";
        let mock = mount_sse_once(
            harness.server(),
            sse(vec![
                ev_apply_patch_custom_tool_call(id, patch),
                ev_completed(id),
            ]),
        )
        .await;
        let completion = mount_sse_once(harness.server(), sse(vec![ev_completed("done")])).await;
        start(&harness).await?;
        let request = match next_approval(&harness).await {
            EventMsg::ApplyPatchApprovalRequest(request) => request,
            event => panic!("expected patch approval, got {event:?}"),
        };
        assert_eq!(
            request.changes,
            HashMap::from([
                (
                    harness.test().workspace_path_uri("index.js")?.to_path_buf(),
                    FileChange::Add {
                        content: "hello\n".to_string()
                    }
                ),
                (
                    harness
                        .test()
                        .workspace_path_uri("docs/notice.md")?
                        .to_path_buf(),
                    FileChange::Add {
                        content: "notice\n".to_string()
                    }
                ),
            ])
        );
        assert_eq!(harness.path_exists("index.js").await?, id == "repeat");
        assert_eq!(harness.path_exists("docs/notice.md").await?, id == "repeat");
        assert!(completion.requests().is_empty());
        harness
            .test()
            .codex
            .submit(Op::PatchApproval {
                id: request.call_id,
                decision,
            })
            .await?;
        finish_turn(&harness, Completion::Turn).await;
        assert_eq!(mock.requests().len(), 1);
        assert_eq!(completion.requests().len(), 1);
    }
    assert_eq!(harness.read_file_text("index.js").await?, "hello\n");
    assert_eq!(harness.read_file_text("docs/notice.md").await?, "notice\n");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_prompt_policy_refuses_execution_instead_of_auto_approving() -> Result<()> {
    skip_if_target_windows!(Ok(()), "uses a POSIX shell command");
    skip_if_no_network!(Ok(()));
    let harness = harness("session", AskForApproval::Never).await?;
    let mock = mount_function_call_agent_response(
        harness.server(),
        "blocked",
        &json!({"cmd":"printf x > result"}).to_string(),
        "exec_command",
    )
    .await;
    start(&harness).await?;
    finish_turn(&harness, Completion::Turn).await;
    assert!(!harness.path_exists("result").await?);
    assert!(
        mock.completion
            .single_request()
            .function_call_output("blocked")
            .to_string()
            .contains("human decision")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupt_discards_a_pending_action_and_its_late_approval() -> Result<()> {
    skip_if_target_windows!(Ok(()), "uses a POSIX shell command");
    skip_if_no_network!(Ok(()));
    let harness = harness("session", AskForApproval::OnRequest).await?;
    let mock = mount_function_call_agent_response(
        harness.server(),
        "interrupted",
        &json!({"cmd":"printf x > result"}).to_string(),
        "exec_command",
    )
    .await;
    start(&harness).await?;
    let request = next_exec_approval(&harness).await;
    harness.test().codex.submit(Op::Interrupt).await?;
    finish_turn(&harness, Completion::Interrupted).await;
    harness
        .test()
        .codex
        .submit(Op::ExecApproval {
            id: request.call_id,
            turn_id: Some(request.turn_id),
            decision: ReviewDecision::Approved,
        })
        .await?;
    assert!(!harness.path_exists("result").await?);
    assert!(mock.completion.requests().is_empty());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn terminal_input_waits_even_without_the_stdin_approval_feature() -> Result<()> {
    skip_if_target_windows!(Ok(()), "uses a POSIX interactive shell");
    skip_if_no_network!(Ok(()));
    let harness = harness("session", AskForApproval::OnRequest).await?;
    let opened = mount_function_call_agent_response(
        harness.server(),
        "open",
        &json!({"cmd":"/bin/bash --noprofile --norc", "tty":true, "yield_time_ms":200}).to_string(),
        "exec_command",
    )
    .await;
    start(&harness).await?;
    let request = next_exec_approval(&harness).await;
    decide_and_finish(
        &harness,
        request,
        ReviewDecision::Approved,
        Completion::Turn,
    )
    .await?;
    assert!(
        opened
            .completion
            .single_request()
            .function_call_output("open")
            .to_string()
            .contains("session ID 1000")
    );
    let poll = mount_function_call_agent_response(
        harness.server(),
        "poll",
        &json!({"session_id":1000, "chars":"", "yield_time_ms":1000}).to_string(),
        "write_stdin",
    )
    .await;
    start(&harness).await?;
    finish_turn(&harness, Completion::Turn).await;
    assert_eq!(poll.completion.requests().len(), 1);
    let input = mount_function_call_agent_response(
        harness.server(),
        "input",
        &json!({"session_id":1000, "chars":"printf bypass > result\n"}).to_string(),
        "write_stdin",
    )
    .await;
    start(&harness).await?;
    let request = next_exec_approval(&harness).await;
    assert_eq!(
        request.kind,
        codex_protocol::approvals::ExecApprovalKind::WriteStdin
    );
    assert!(!harness.path_exists("result").await?);
    decide_and_finish(
        &harness,
        request,
        ReviewDecision::denied("blocked input"),
        Completion::Turn,
    )
    .await?;
    assert!(!harness.path_exists("result").await?);
    assert!(
        input
            .completion
            .single_request()
            .function_call_output("input")
            .to_string()
            .contains("blocked input")
    );
    Ok(())
}
