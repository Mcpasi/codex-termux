use crate::adapter::Adapter;
use anyhow::Result;
use anyhow::ensure;
use axum::body::Bytes;
use futures::Stream;
use futures::StreamExt;
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

/// Verify the terminal Responses event before considering a generation reusable.
#[derive(Default)]
pub(crate) struct CompletionTracker {
    line: Vec<u8>,
    event: Option<serde_json::Value>,
    completed: bool,
}

impl CompletionTracker {
    pub fn push(&mut self, bytes: &[u8], adapter: &Adapter) -> Result<Vec<u8>> {
        let mut output = Vec::new();
        if self.completed {
            return Ok(output);
        }
        for &byte in bytes {
            if byte != b'\n' {
                ensure!(
                    self.line.len() < 1024 * 1024,
                    "inference event exceeds its bound"
                );
                self.line.push(byte);
                continue;
            }
            let line = self.line.strip_suffix(b"\r").unwrap_or(&self.line);
            if let Some(data) = line.strip_prefix(b"data:") {
                let data = data.strip_prefix(b" ").unwrap_or(data);
                ensure!(
                    data != b"[DONE]" && self.event.is_none(),
                    "unexpected or multiline inference event"
                );
                self.event = Some(serde_json::from_slice(data)?);
            } else if line.is_empty() {
                if let Some(mut event) = self.event.take() {
                    let kind = event.get("type").and_then(serde_json::Value::as_str);
                    ensure!(
                        kind.is_some()
                            && !matches!(
                                kind,
                                Some("error" | "response.failed" | "response.incomplete")
                            ),
                        "inference failed"
                    );
                    if kind == Some("response.completed") {
                        ensure!(
                            event
                                .pointer("/response/status")
                                .and_then(serde_json::Value::as_str)
                                == Some("completed"),
                            "inference completion has no successful status"
                        );
                        self.completed = true;
                    }
                    adapter.event(&mut event)?;
                    output.extend_from_slice(b"data: ");
                    serde_json::to_writer(&mut output, &event)?;
                    output.extend_from_slice(b"\n\n");
                } else {
                    output.extend_from_slice(b":\n\n");
                }
            }
            self.line.clear();
            ensure!(
                output.len() <= 16 * 1024 * 1024,
                "adapted inference stream exceeds its bound"
            );
            if self.completed {
                break;
            }
        }
        Ok(output)
    }

    pub fn finish(&self) -> Result<()> {
        ensure!(
            self.completed,
            "inference stream ended before a complete terminal event"
        );
        Ok(())
    }
}

/// Keep cancellation independent of HTTP backpressure, and stop at the authoritative event.
pub(crate) async fn forward(
    mut upstream: impl Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
    sender: &mpsc::Sender<Result<Bytes, io::Error>>,
    cancel: &CancellationToken,
    adapter: Adapter,
) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(1800);
    let mut tracker = CompletionTracker::default();
    let mut received = 0_usize;
    let mut sent_bytes = 0_usize;
    loop {
        let next = tokio::select! {
            _ = cancel.cancelled() => return Err(io::Error::other("local model stopped")),
            _ = sender.closed() => return Err(io::Error::other("local model response disconnected")),
            _ = tokio::time::sleep_until(deadline) => return Err(io::Error::other("local model response deadline exceeded")),
            next = timeout(Duration::from_secs(90), upstream.next()) => next,
        };
        let chunk = match next {
            Ok(Some(Ok(chunk))) if chunk.len() <= 16 * 1024 * 1024 - received => chunk,
            _ => {
                return Err(io::Error::other(
                    "local model stream failed or exceeded its bound",
                ));
            }
        };
        received += chunk.len();
        let chunk = tracker
            .push(&chunk, &adapter)
            .map_err(|_| io::Error::other("invalid local inference stream"))?;
        if chunk.len() > 16 * 1024 * 1024 - sent_bytes {
            return Err(io::Error::other(
                "adapted inference stream exceeds its bound",
            ));
        }
        sent_bytes += chunk.len();
        if chunk.is_empty() {
            continue;
        }
        tokio::select! {
            _ = cancel.cancelled() => return Err(io::Error::other("local model stopped")),
            _ = tokio::time::sleep_until(deadline) => return Err(io::Error::other("local model response deadline exceeded")),
            sent = timeout(Duration::from_secs(90), sender.send(Ok(Bytes::from(chunk)))) => {
                if !matches!(sent, Ok(Ok(()))) {
                    return Err(io::Error::other("local model response disconnected or stalled"));
                }
            }
        }
        if tracker.completed {
            tracker
                .finish()
                .map_err(|_| io::Error::other("incomplete local inference event"))?;
            return Ok(());
        }
    }
}

#[cfg(test)]
#[path = "stream_tests.rs"]
mod tests;
