use crate::RESERVE_BYTES;
use crate::artifact::VerifiedArtifact;
use anyhow::Result;
use anyhow::bail;
use anyhow::ensure;
use std::collections::BTreeMap;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

const MAX_HEADER: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ModelShape {
    pub layers: u32,
    pub layer_bytes: u64,
    pub fixed_bytes: u64,
}

pub(crate) fn inspect(artifact: &VerifiedArtifact, context: u32) -> Result<ModelShape> {
    let mut file = artifact.file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let result = parse(&mut file, artifact.length(), context)?;
    artifact.validate()?;
    Ok(result)
}

fn parse(reader: &mut (impl Read + Seek), length: u64, context: u32) -> Result<ModelShape> {
    ensure!(
        (256..=32768).contains(&context),
        "context must be between 256 and 32768 tokens"
    );
    let mut header = Header {
        reader,
        consumed: 0,
    };
    ensure!(
        header.u32()? == 0x4655_4747 && header.u32()? == 3,
        "only GGUF v3 models are supported"
    );
    let tensors = header.u64()?;
    let values = header.u64()?;
    ensure!(
        (1..=MAX_ENTRIES).contains(&tensors) && values <= MAX_ENTRIES,
        "GGUF metadata count exceeds limits"
    );
    let mut architecture = String::new();
    let mut scalars = BTreeMap::new();
    for _ in 0..values {
        let key = header.string(/*max*/ 256)?;
        let kind = header.u32()?;
        if key == "general.architecture" {
            ensure!(
                kind == 8 && architecture.is_empty(),
                "invalid GGUF architecture"
            );
            architecture = header.string(/*max*/ 128)?;
        } else if key.ends_with(".block_count")
            || key.ends_with(".embedding_length")
            || key.ends_with(".attention.head_count")
            || key.ends_with(".attention.head_count_kv")
            || key.ends_with(".attention.key_length")
            || key.ends_with(".attention.value_length")
            || key == "general.alignment"
            || key == "split.count"
        {
            let value = match kind {
                4 => u64::from(header.u32()?),
                10 => header.u64()?,
                _ => bail!("invalid GGUF dimension metadata"),
            };
            ensure!(
                scalars.insert(key, value).is_none(),
                "duplicate GGUF dimension"
            );
        } else {
            header.skip_value(kind, /*depth*/ 0)?;
        }
    }
    // A transformer-only contract: recurrent/hybrid state needs its own memory estimator.
    ensure!(
        matches!(
            architecture.as_str(),
            "llama" | "qwen2" | "qwen3" | "gemma" | "gemma2" | "gemma3" | "phi3" | "mistral"
        ),
        "unsupported GGUF architecture for bounded layer planning"
    );
    ensure!(
        scalars.get("split.count").copied().unwrap_or(1) == 1,
        "split GGUF files are not supported"
    );
    let layers = *scalars
        .get(&format!("{architecture}.block_count"))
        .ok_or_else(|| anyhow::anyhow!("GGUF has no block count"))?;
    let embedding = *scalars
        .get(&format!("{architecture}.embedding_length"))
        .ok_or_else(|| anyhow::anyhow!("GGUF has no embedding size"))?;
    ensure!(
        (1..=512).contains(&layers) && (1..=65536).contains(&embedding),
        "GGUF dimensions exceed limits"
    );
    let mut offsets = Vec::with_capacity(tensors as usize);
    for _ in 0..tensors {
        let name = header.string(/*max*/ 256)?;
        let dimensions = header.u32()?;
        ensure!((1..=4).contains(&dimensions), "invalid tensor rank");
        let mut elements = 1_u64;
        for _ in 0..dimensions {
            let dimension = header.u64()?;
            ensure!(dimension > 0, "empty GGUF tensor");
            elements = elements
                .checked_mul(dimension)
                .ok_or_else(|| anyhow::anyhow!("GGUF tensor overflow"))?;
        }
        ensure!(elements <= 1 << 40, "GGUF tensor exceeds limits");
        let _quantization = header.u32()?;
        let offset = header.u64()?;
        let layer = if let Some(suffix) = name.strip_prefix("blk.") {
            let index: u32 = suffix.split('.').next().unwrap_or_default().parse()?;
            ensure!(
                u64::from(index) < layers,
                "GGUF block index exceeds block count"
            );
            Some(index as usize)
        } else {
            None
        };
        offsets.push((offset, layer));
    }
    let alignment = scalars.get("general.alignment").copied().unwrap_or(32);
    ensure!(
        alignment.is_power_of_two() && alignment <= 4096,
        "invalid GGUF alignment"
    );
    let start = header.consumed.div_ceil(alignment) * alignment;
    ensure!(start < length, "GGUF tensor data missing");
    offsets.sort_unstable_by_key(|entry| entry.0);
    ensure!(offsets[0].0 == 0, "invalid first GGUF tensor offset");
    let mut sizes = vec![0_u64; layers as usize];
    let mut fixed = start + RESERVE_BYTES;
    for (index, &(offset, layer)) in offsets.iter().enumerate() {
        let end = offsets.get(index + 1).map_or(length - start, |next| next.0);
        ensure!(
            offset < end && end <= length - start && offset % alignment == 0,
            "invalid GGUF tensor extent"
        );
        match layer {
            Some(layer) => sizes[layer] += end - offset,
            None => fixed += end - offset,
        }
    }
    ensure!(
        sizes.iter().all(|size| *size > 0),
        "GGUF contains an empty layer"
    );
    let heads = scalars
        .get(&format!("{architecture}.attention.head_count"))
        .copied()
        .ok_or_else(|| anyhow::anyhow!("GGUF has no attention head count"))?;
    let kv_heads = scalars
        .get(&format!("{architecture}.attention.head_count_kv"))
        .copied()
        .unwrap_or(heads);
    ensure!(
        (1..=65536).contains(&heads) && (1..=heads).contains(&kv_heads),
        "invalid attention head counts"
    );
    let key_width = scalars
        .get(&format!("{architecture}.attention.key_length"))
        .copied()
        .unwrap_or(embedding.div_ceil(heads));
    let value_width = scalars
        .get(&format!("{architecture}.attention.value_length"))
        .copied()
        .unwrap_or(embedding.div_ceil(heads));
    ensure!(
        (1..=65536).contains(&key_width) && (1..=65536).contains(&value_width),
        "invalid attention head dimensions"
    );
    // Include explicit head dimensions when wider than the embedding, and cache padding.
    let kv_width = (kv_heads * (key_width + value_width)).max(embedding * 2);
    let kv = u64::from(context).div_ceil(256) * 256 * kv_width * 2;
    let layer_bytes = sizes.into_iter().max().unwrap_or_default() + kv;
    Ok(ModelShape {
        layers: layers as u32,
        layer_bytes,
        fixed_bytes: fixed,
    })
}

struct Header<'a, R> {
    reader: &'a mut R,
    consumed: u64,
}

impl<R: Read + Seek> Header<'_, R> {
    fn read<const N: usize>(&mut self) -> Result<[u8; N]> {
        self.consumed += N as u64;
        ensure!(self.consumed <= MAX_HEADER, "GGUF header exceeds limits");
        let mut bytes = [0; N];
        self.reader.read_exact(&mut bytes)?;
        Ok(bytes)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read()?))
    }
    fn skip(&mut self, bytes: u64) -> Result<()> {
        self.consumed = self
            .consumed
            .checked_add(bytes)
            .ok_or_else(|| anyhow::anyhow!("GGUF size overflow"))?;
        ensure!(self.consumed <= MAX_HEADER, "GGUF header exceeds limits");
        self.reader.seek(SeekFrom::Current(bytes as i64))?;
        Ok(())
    }
    fn string(&mut self, max: u64) -> Result<String> {
        let length = self.u64()?;
        ensure!(
            length <= max && self.consumed + length <= MAX_HEADER,
            "GGUF string exceeds limits"
        );
        let mut bytes = vec![0; length as usize];
        self.reader.read_exact(&mut bytes)?;
        self.consumed += length;
        Ok(String::from_utf8(bytes)?)
    }
    fn skip_value(&mut self, kind: u32, depth: u8) -> Result<()> {
        let size = match kind {
            0 | 1 | 7 => 1,
            2 | 3 => 2,
            4..=6 => 4,
            10..=12 => 8,
            8 => {
                let length = self.u64()?;
                return self.skip(length);
            }
            9 => {
                ensure!(depth == 0, "nested GGUF arrays are unsupported");
                let item_kind = self.u32()?;
                let count = self.u64()?;
                ensure!(
                    count <= MAX_ENTRIES && item_kind != 9,
                    "GGUF array exceeds limits"
                );
                for _ in 0..count {
                    self.skip_value(item_kind, depth + 1)?;
                }
                return Ok(());
            }
            _ => bail!("unknown GGUF metadata type"),
        };
        self.skip(size)
    }
}

#[cfg(test)]
#[path = "gguf_tests.rs"]
mod tests;
