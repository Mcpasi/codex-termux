use anyhow::Result;
use app_test_support::TestAppServer;
use codex_app_server_protocol::ClientRequest;
use codex_app_server_protocol::LocalModelArtifact;
use codex_app_server_protocol::LocalModelPhase;
use codex_app_server_protocol::LocalModelStartParams;
use codex_app_server_protocol::LocalModelStartResponse;
use codex_app_server_protocol::LocalModelStatusParams;
use codex_app_server_protocol::LocalModelStatusResponse;
use codex_app_server_protocol::LocalModelStopParams;
use codex_app_server_protocol::LocalModelStopResponse;
use pretty_assertions::assert_eq;

#[tokio::test]
async fn local_model_lifecycle_is_available_over_initialized_json_rpc() -> Result<()> {
    let mut server = TestAppServer::builder().build_initialized().await?;
    let initial: LocalModelStatusResponse = server
        .request(|request_id| ClientRequest::LocalModelStatus {
            request_id,
            params: LocalModelStatusParams::default(),
        })
        .await?;
    assert_eq!(
        initial,
        LocalModelStatusResponse {
            phase: LocalModelPhase::Stopped,
            plan: None
        }
    );

    // Validation happens before any artifact is opened or executable is launched.
    let result: Result<LocalModelStartResponse> = server
        .request(|request_id| ClientRequest::LocalModelStart {
            request_id,
            params: LocalModelStartParams {
                engine: LocalModelArtifact {
                    path: String::new(),
                    sha256: String::new(),
                },
                model: LocalModelArtifact {
                    path: String::new(),
                    sha256: String::new(),
                },
                model_id: "fixture".to_string(),
                context_tokens: 1024,
                threads: 0,
                memory_budget_bytes: 1024 * 1024 * 1024,
                peers: Vec::new(),
            },
        })
        .await;
    assert!(result.is_err());
    let _: LocalModelStopResponse = server
        .request(|request_id| ClientRequest::LocalModelStop {
            request_id,
            params: LocalModelStopParams::default(),
        })
        .await?;
    let final_state: LocalModelStatusResponse = server
        .request(|request_id| ClientRequest::LocalModelStatus {
            request_id,
            params: LocalModelStatusParams::default(),
        })
        .await?;
    assert_eq!(final_state, initial);
    Ok(())
}
