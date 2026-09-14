use super::*;
use pretty_assertions::assert_eq;

fn shape() -> ModelShape {
    ModelShape {
        layers: 12,
        layer_bytes: RESERVE_BYTES,
        fixed_bytes: RESERVE_BYTES * 2,
    }
}

#[test]
fn fitting_model_uses_only_coordinator() -> Result<()> {
    assert_eq!(
        plan(&shape(), RESERVE_BYTES * 14, &[])?,
        LocalModelPlan {
            layers: 12,
            assignments: vec![LocalModelLayerAssignment {
                device_index: 0,
                start_layer: 0,
                end_layer: 12,
                estimated_bytes: RESERVE_BYTES * 14
            }],
        }
    );
    Ok(())
}

#[test]
fn assigns_contiguous_ranges_to_fewest_capable_helpers() -> Result<()> {
    let peers = vec![
        Capacity {
            index: 1,
            bytes: RESERVE_BYTES * 3,
            latency_micros: 10,
        },
        Capacity {
            index: 2,
            bytes: RESERVE_BYTES * 9,
            latency_micros: 20,
        },
    ];
    assert_eq!(
        plan(&shape(), RESERVE_BYTES * 6, &peers)?,
        LocalModelPlan {
            layers: 12,
            assignments: vec![
                LocalModelLayerAssignment {
                    device_index: 0,
                    start_layer: 0,
                    end_layer: 4,
                    estimated_bytes: RESERVE_BYTES * 6
                },
                LocalModelLayerAssignment {
                    device_index: 2,
                    start_layer: 4,
                    end_layer: 12,
                    estimated_bytes: RESERVE_BYTES * 9
                },
            ],
        }
    );
    Ok(())
}

#[test]
fn planner_reacts_to_lost_capacity_without_overcommitting() -> Result<()> {
    let peers = vec![Capacity {
        index: 1,
        bytes: RESERVE_BYTES * 13,
        latency_micros: 1,
    }];
    let result = plan(&shape(), RESERVE_BYTES * 2, &peers)?;
    assert_eq!(
        result.assignments[1],
        LocalModelLayerAssignment {
            device_index: 1,
            start_layer: 0,
            end_layer: 12,
            estimated_bytes: RESERVE_BYTES * 13
        }
    );
    assert!(plan(&shape(), RESERVE_BYTES * 2, &[]).is_err());
    assert!(plan(&shape(), RESERVE_BYTES, &peers).is_err());
    Ok(())
}

#[test]
fn ten_devices_cover_all_layers_and_an_eleventh_is_rejected() -> Result<()> {
    let shape = ModelShape {
        layers: 10,
        layer_bytes: RESERVE_BYTES,
        fixed_bytes: RESERVE_BYTES,
    };
    let mut peers: Vec<_> = (1..10)
        .map(|index| Capacity {
            index,
            bytes: RESERVE_BYTES * 2,
            latency_micros: u64::from(index),
        })
        .collect();
    let result = plan(&shape, RESERVE_BYTES * 2, &peers)?;
    assert_eq!(result.assignments.len(), 10);
    for (index, assignment) in result.assignments.iter().enumerate() {
        assert_eq!(
            (assignment.start_layer, assignment.end_layer),
            (index as u32, index as u32 + 1)
        );
    }
    peers.push(Capacity {
        index: 10,
        bytes: RESERVE_BYTES * 2,
        latency_micros: 0,
    });
    assert!(plan(&shape, RESERVE_BYTES * 2, &peers).is_err());
    Ok(())
}

#[test]
fn duplicate_and_out_of_range_devices_fail_closed() {
    let peer = Capacity {
        index: 1,
        bytes: RESERVE_BYTES * 2,
        latency_micros: 0,
    };
    assert!(plan(&shape(), MAX_MEMORY_BYTES, &[peer.clone(), peer]).is_err());
    assert!(
        plan(
            &shape(),
            MAX_MEMORY_BYTES,
            &[Capacity {
                index: 0,
                bytes: MAX_MEMORY_BYTES,
                latency_micros: 0
            }]
        )
        .is_err()
    );
}

#[test]
fn native_split_rounding_keeps_every_layer_on_its_budgeted_helper() {
    for counts in [
        vec![1, 1, 1],
        vec![3, 7],
        vec![1, 4, 2, 6],
        vec![1; 9],
        vec![251, 1, 250],
    ] {
        let mut plan = LocalModelPlan {
            layers: counts.iter().sum(),
            assignments: vec![LocalModelLayerAssignment {
                device_index: 0,
                start_layer: 0,
                end_layer: 0,
                estimated_bytes: RESERVE_BYTES,
            }],
        };
        let mut start = 0;
        for (index, &count) in counts.iter().enumerate() {
            plan.assignments.push(LocalModelLayerAssignment {
                device_index: index as u32 + 1,
                start_layer: start,
                end_layer: start + count,
                estimated_bytes: u64::from(count) * RESERVE_BYTES,
            });
            start += count;
        }
        let weights = split_weights(&plan);
        let total = weights.iter().sum::<u32>() as f32;
        let mut sum = 0_f32;
        let thresholds: Vec<_> = weights
            .iter()
            .map(|&weight| {
                sum += weight as f32;
                sum / total
            })
            .collect();
        for assignment in plan.assignments.iter().skip(1) {
            for layer in assignment.start_layer..assignment.end_layer {
                let native_index =
                    thresholds.partition_point(|point| *point <= layer as f32 / plan.layers as f32);
                assert_eq!(native_index as u32 + 1, assignment.device_index);
            }
        }
    }
}
