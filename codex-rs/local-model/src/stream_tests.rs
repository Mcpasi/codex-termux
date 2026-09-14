use super::*;

#[test]
fn completion_survives_every_chunk_boundary() -> Result<()> {
    let event = b"event: response.completed\r\ndata: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\r\n\r\ndata: [DONE]\n\n";
    for index in 0..=event.len() {
        let mut tracker = CompletionTracker::default();
        tracker.push(&event[..index], &Adapter::default())?;
        tracker.push(&event[index..], &Adapter::default())?;
        tracker.finish()?;
    }
    Ok(())
}

#[test]
fn partial_malformed_and_failed_streams_cannot_be_reused() -> Result<()> {
    let mut tracker = CompletionTracker::default();
    tracker.push(
        b"data: {\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}\n\n",
        &Adapter::default(),
    )?;
    assert!(tracker.finish().is_err());
    assert!(
        tracker
            .push(
                b"data: {\"type\":\"response.failed\"}\n\n",
                &Adapter::default()
            )
            .is_err()
    );
    assert!(
        CompletionTracker::default()
            .push(b"data: invalid\n\n", &Adapter::default())
            .is_err()
    );
    assert!(
        CompletionTracker::default()
            .push(&vec![b'x'; 1024 * 1024 + 1], &Adapter::default())
            .is_err()
    );
    Ok(())
}

#[test]
fn terminal_data_without_event_delimiter_is_incomplete() -> Result<()> {
    let mut tracker = CompletionTracker::default();
    tracker.push(
        b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n",
        &Adapter::default(),
    )?;
    assert!(tracker.finish().is_err());
    Ok(())
}

#[tokio::test]
async fn authoritative_completion_does_not_require_upstream_eof() -> Result<()> {
    let terminal = Bytes::from_static(
        b"data: {\"type\":\"response.completed\",\"response\":{\"status\":\"completed\"}}\n\n",
    );
    let upstream = futures::stream::once(std::future::ready(Ok(terminal.clone())))
        .chain(futures::stream::pending());
    let (sender, mut receiver) = mpsc::channel(2);
    timeout(
        Duration::from_secs(2),
        forward(
            upstream,
            &sender,
            &CancellationToken::new(),
            Adapter::default(),
        ),
    )
    .await??;
    let output = receiver
        .recv()
        .await
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("terminal event missing"))?;
    pretty_assertions::assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output[b"data: ".len()..])?,
        serde_json::json!({"type":"response.completed", "response":{"status":"completed"}})
    );
    Ok(())
}

#[tokio::test]
async fn cancellation_releases_a_response_with_blocked_downstream() -> Result<()> {
    let (sender, _receiver) = mpsc::channel(1);
    sender
        .send(Ok(Bytes::from_static(b"already queued")))
        .await?;
    let upstream = futures::stream::iter([Ok(Bytes::from_static(b": keepalive\n\n"))]);
    let cancel = CancellationToken::new();
    let stopped = cancel.clone();
    let task =
        tokio::spawn(async move { forward(upstream, &sender, &stopped, Adapter::default()).await });
    tokio::task::yield_now().await;
    cancel.cancel();
    assert!(timeout(Duration::from_secs(2), task).await??.is_err());
    Ok(())
}
