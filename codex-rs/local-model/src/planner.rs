use crate::MAX_DEVICES;
use crate::MAX_MEMORY_BYTES;
use crate::RESERVE_BYTES;
use crate::gguf::ModelShape;
use anyhow::Result;
use anyhow::ensure;
use codex_app_server_protocol::LocalModelLayerAssignment;
use codex_app_server_protocol::LocalModelPlan;

#[derive(Clone, Debug)]
pub(crate) struct Capacity {
    pub index: u32,
    pub bytes: u64,
    pub latency_micros: u64,
}

pub(crate) fn plan(
    shape: &ModelShape,
    local_bytes: u64,
    peers: &[Capacity],
) -> Result<LocalModelPlan> {
    ensure!(
        peers.len() < MAX_DEVICES && local_bytes <= MAX_MEMORY_BYTES,
        "device pool exceeds limits"
    );
    ensure!(
        shape.layers > 0 && shape.layer_bytes > 0 && local_bytes >= shape.fixed_bytes,
        "coordinator lacks memory for tokenizer, output and runtime"
    );
    let mut seen = std::collections::HashSet::new();
    ensure!(
        peers.iter().all(|p| p.index > 0
            && p.index < MAX_DEVICES as u32
            && p.bytes <= MAX_MEMORY_BYTES
            && seen.insert(p.index)),
        "invalid or duplicate device capacity"
    );
    let local_layers =
        ((local_bytes - shape.fixed_bytes) / shape.layer_bytes).min(u64::from(shape.layers)) as u32;
    let mut assignments = vec![LocalModelLayerAssignment {
        device_index: 0,
        start_layer: 0,
        end_layer: local_layers,
        estimated_bytes: shape.fixed_bytes + u64::from(local_layers) * shape.layer_bytes,
    }];
    let mut next = local_layers;
    let mut candidates = peers.to_vec();
    // Prefer fewer network boundaries, then the lower measured handshake latency.
    candidates.sort_by_key(|p| {
        (
            std::cmp::Reverse(p.bytes.saturating_sub(RESERVE_BYTES) / shape.layer_bytes),
            p.latency_micros,
            p.index,
        )
    });
    for peer in candidates {
        if next == shape.layers {
            break;
        }
        let count = (peer.bytes.saturating_sub(RESERVE_BYTES) / shape.layer_bytes)
            .min(u64::from(shape.layers - next)) as u32;
        if count == 0 {
            continue;
        }
        assignments.push(LocalModelLayerAssignment {
            device_index: peer.index,
            start_layer: next,
            end_layer: next + count,
            estimated_bytes: u64::from(count) * shape.layer_bytes + RESERVE_BYTES,
        });
        next += count;
    }
    ensure!(
        next == shape.layers,
        "insufficient memory across available paired devices; use a smaller model or context"
    );
    Ok(LocalModelPlan {
        layers: shape.layers,
        assignments,
    })
}

pub(crate) fn split_weights(plan: &LocalModelPlan) -> Vec<u32> {
    let mut weights: Vec<_> = plan
        .assignments
        .iter()
        .skip(1)
        .map(|assignment| (assignment.end_layer - assignment.start_layer) * 2)
        .collect();
    if weights.len() > 1 {
        // llama.cpp uses upper_bound on normalized f32 split points. Put each boundary
        // halfway between layer indices so rounding cannot move a layer to the wrong budget.
        weights[0] -= 1;
        if let Some(last) = weights.last_mut() {
            *last += 1;
        }
    }
    weights
}

#[cfg(test)]
#[path = "planner_tests.rs"]
mod tests;
