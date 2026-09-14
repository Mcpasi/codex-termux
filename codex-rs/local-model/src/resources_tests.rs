use super::*;
use pretty_assertions::assert_eq;

#[test]
fn memory_telemetry_checks_units_and_overflow() {
    assert_eq!(
        kib_field("MemTotal: 1000 kB\nMemAvailable: 750 kB\n", "MemAvailable:"),
        Some(750 * 1024)
    );
    assert_eq!(kib_field("MemAvailable: 750 MB", "MemAvailable:"), None);
    assert_eq!(
        kib_field("MemAvailable: 18446744073709551615 kB", "MemAvailable:"),
        None
    );
    assert!(validate_budget(MAX_MEMORY_BYTES + 1, /*threads*/ 1).is_err());
    assert!(validate_budget(RESERVE_BYTES * 2, /*threads*/ 0).is_err());
}
