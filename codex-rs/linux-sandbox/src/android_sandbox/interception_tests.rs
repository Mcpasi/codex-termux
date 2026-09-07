use super::*;
use pretty_assertions::assert_eq;

#[test]
fn accepted_seccomp_options_without_events_require_full_tracing() {
    assert_eq!(
        probe_action(InterceptMode::SeccompDirected, false),
        ProbeAction::RetryAllSyscalls
    );
    assert_eq!(
        probe_action(InterceptMode::AllSyscalls, false),
        ProbeAction::Refuse
    );
    assert_eq!(
        probe_action(InterceptMode::AllSyscalls, true),
        ProbeAction::Ready
    );
    assert_eq!(
        probe_action(InterceptMode::SeccompDirected, true),
        ProbeAction::Ready
    );
}

#[test]
fn only_the_impossible_setup_open_is_the_interception_probe() {
    let open = libc::SYS_openat;
    let fd = (-1i32) as u64;
    let write = libc::O_WRONLY as u64;
    assert!(is_probe(open, fd, 0, write));
    for (nr, fd, path, flags) in [
        (open, libc::AT_FDCWD as u64, 0, write),
        (open, fd, 4096, write),
        (open, fd, 0, libc::O_RDONLY as u64),
        (libc::SYS_execve, fd, 0, write),
    ] {
        assert!(!is_probe(nr, fd, path, flags));
    }
}
