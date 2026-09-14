use crate::MAX_MEMORY_BYTES;
use crate::RESERVE_BYTES;
use anyhow::Result;
use anyhow::ensure;

pub(crate) fn validate_budget(bytes: u64, threads: u32) -> Result<()> {
    ensure!(
        (RESERVE_BYTES * 2..=MAX_MEMORY_BYTES).contains(&bytes),
        "memory budget must be between 512 MiB and 64 GiB"
    );
    ensure!(
        (1..=64).contains(&threads),
        "thread count must be between 1 and 64"
    );
    Ok(())
}

pub(crate) fn available(budget: u64, child: Option<u32>) -> u64 {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let memory = std::fs::read_to_string("/proc/meminfo")
            .ok()
            .and_then(|text| kib_field(&text, "MemAvailable:"));
        let resident = child.and_then(resident_bytes).unwrap_or_default();
        // Reclaim our existing allocation when planning a replacement, never double-count it.
        memory.map_or(0, |bytes| {
            bytes
                .saturating_sub(RESERVE_BYTES)
                .saturating_add(resident)
                .min(budget)
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = child;
        budget
    }
}

pub(crate) fn resident_bytes(pid: u32) -> Option<u64> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .ok()
            .and_then(|text| kib_field(&text, "VmRSS:"))
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let _ = pid;
        None
    }
}

pub(crate) async fn wait_for_over_budget(pid: u32, budget: u64) {
    let mut tick = tokio::time::interval(std::time::Duration::from_millis(250));
    loop {
        tick.tick().await;
        if resident_bytes(pid).is_some_and(|bytes| bytes > budget) {
            return;
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "android", test))]
fn kib_field(text: &str, name: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let mut parts = line.split_ascii_whitespace();
        (parts.next()? == name).then_some(())?;
        let value = parts.next()?.parse::<u64>().ok()?;
        (parts.next()? == "kB").then_some(())?;
        value.checked_mul(1024)
    })
}

#[cfg(test)]
#[path = "resources_tests.rs"]
mod tests;
