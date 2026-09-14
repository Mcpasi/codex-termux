use super::*;
use pretty_assertions::assert_eq;
use std::io::Cursor;

fn string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend((value.len() as u64).to_le_bytes());
    bytes.extend(value.as_bytes());
}

fn fixture() -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend(0x4655_4747_u32.to_le_bytes());
    bytes.extend(3_u32.to_le_bytes());
    bytes.extend(3_u64.to_le_bytes());
    bytes.extend(4_u64.to_le_bytes());
    string(&mut bytes, "general.architecture");
    bytes.extend(8_u32.to_le_bytes());
    string(&mut bytes, "llama");
    for (key, value) in [
        ("llama.block_count", 2_u32),
        ("llama.embedding_length", 16_u32),
        ("llama.attention.head_count", 4_u32),
    ] {
        string(&mut bytes, key);
        bytes.extend(4_u32.to_le_bytes());
        bytes.extend(value.to_le_bytes());
    }
    for (index, name) in [
        "token_embd.weight",
        "blk.0.attn.weight",
        "blk.1.attn.weight",
    ]
    .iter()
    .enumerate()
    {
        string(&mut bytes, name);
        bytes.extend(1_u32.to_le_bytes());
        bytes.extend(8_u64.to_le_bytes());
        bytes.extend(0_u32.to_le_bytes());
        bytes.extend((index as u64 * 32).to_le_bytes());
    }
    bytes.resize(bytes.len().div_ceil(32) * 32 + 96, 0);
    bytes
}

#[test]
fn projects_layer_weights_plus_context_and_coordinator_overhead() -> Result<()> {
    let bytes = fixture();
    let length = bytes.len() as u64;
    assert_eq!(
        parse(&mut Cursor::new(bytes), length, /*context*/ 256)?,
        ModelShape {
            layers: 2,
            layer_bytes: 32 + 256 * 16 * 4,
            fixed_bytes: length - 64 + RESERVE_BYTES,
        }
    );
    Ok(())
}

#[test]
fn truncated_and_oversized_headers_fail_before_allocation() {
    let bytes = fixture();
    for length in [0, 4, 16, 24, 30, bytes.len() - 80] {
        assert!(
            parse(
                &mut Cursor::new(&bytes[..length]),
                length as u64,
                /*context*/ 256
            )
            .is_err()
        );
    }
    let mut bad = fixture();
    bad[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(
        parse(
            &mut Cursor::new(&bad),
            bad.len() as u64,
            /*context*/ 256
        )
        .is_err()
    );
    assert!(
        parse(
            &mut Cursor::new(&bytes),
            bytes.len() as u64,
            /*context*/ u32::MAX
        )
        .is_err()
    );
}
