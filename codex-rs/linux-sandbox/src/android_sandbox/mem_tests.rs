use super::*;
use pretty_assertions::assert_eq;

#[test]
fn tracee_memory_reads_paths_and_open_how_and_writes_scratch() {
    let directory = tempfile::tempdir().unwrap();
    let tracee = directory.path().join("42");
    std::fs::create_dir(&tracee).unwrap();
    let mut bytes = vec![0u8; 8192];
    bytes[4092..4101].copy_from_slice(b"AGENTS.md");
    bytes[128..136].copy_from_slice(&0x1234_5678_9abc_def0u64.to_le_bytes());
    std::fs::write(tracee.join("mem"), bytes).unwrap();
    let memory = TraceeMemory::open(directory.path(), 42).unwrap();

    // Include the bionic heap tag (0xb4), MTE tags and untagged pointers. On
    // other architectures high bits are address bits and must stay intact.
    for tag in [0u64, 0x01, 0x0f, 0x7f, 0x80, 0xb4, 0xff] {
        let prefix = tag << 56;
        if cfg!(target_arch = "aarch64") || tag == 0 {
            assert_eq!(memory.read_c_string(prefix | 4092).unwrap(), b"AGENTS.md");
            assert_eq!(
                memory.read_u64(prefix | 128).unwrap(),
                0x1234_5678_9abc_def0
            );
            assert!(memory.is_readable(prefix | 4092, 10));
            memory.write_bytes(prefix | 256, b"workspace\0").unwrap();
            assert_eq!(memory.read_c_string(256).unwrap(), b"workspace");
        } else {
            assert!(memory.read_c_string(prefix | 4092).is_err());
            assert!(memory.read_u64(prefix | 128).is_err());
        }
    }
}

#[test]
fn invalid_or_unterminated_memory_is_still_rejected() {
    let file = tempfile::tempfile().unwrap();
    file.write_all_at(&vec![b'x'; PATH_MAX], 0).unwrap();
    let memory = TraceeMemory { file };
    assert_eq!(
        memory.read_c_string(0).unwrap_err().raw_os_error(),
        Some(libc::ENAMETOOLONG)
    );
    assert!(memory.read_u64(PATH_MAX as u64 - 1).is_err());
    assert!(!memory.is_readable(PATH_MAX as u64 - 1, 2));
    assert!(!memory.is_readable(u64::MAX, usize::MAX));
}
