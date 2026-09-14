use super::*;
use codex_app_server_protocol::LocalModelStatusParams;
use codex_app_server_protocol::RequestId;

#[tokio::test]
async fn local_model_ownership_is_released_on_disconnect() {
    let processor = LocalModelProcessor::new(std::env::temp_dir());
    let first_connection = CancellationToken::new();
    let second_connection = CancellationToken::new();
    let status = || ClientRequest::LocalModelStatus {
        request_id: RequestId::Integer(1),
        params: LocalModelStatusParams::default(),
    };
    assert!(
        processor
            .request(ConnectionId(1), &first_connection, status())
            .await
            .is_ok()
    );
    assert!(
        processor
            .request(ConnectionId(2), &second_connection, status())
            .await
            .is_err()
    );
    processor.connection_closed(ConnectionId(2)).await;
    assert!(
        processor
            .request(ConnectionId(2), &second_connection, status())
            .await
            .is_err()
    );
    first_connection.cancel();
    processor.connection_closed(ConnectionId(1)).await;
    // A handler that already passed the RPC gate must not reclaim a disconnected role.
    assert!(
        processor
            .request(ConnectionId(1), &first_connection, status())
            .await
            .is_err()
    );
    assert!(
        processor
            .request(ConnectionId(2), &second_connection, status())
            .await
            .is_ok()
    );
}
