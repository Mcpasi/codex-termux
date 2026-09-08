use super::*;
use pretty_assertions::assert_eq;

/// The escape list is what stops a sandboxed process from stepping out from
/// under the supervisor, so its contents are asserted rather than assumed.
#[test]
fn the_escape_list_covers_the_known_bypasses() {
    let denied = escape_denied_syscalls();
    for (nr, name) in [
        (libc::SYS_io_uring_setup, "io_uring_setup"),
        (libc::SYS_io_uring_enter, "io_uring_enter"),
        (libc::SYS_io_uring_register, "io_uring_register"),
        (libc::SYS_userfaultfd, "userfaultfd"),
        (libc::SYS_ptrace, "ptrace"),
        (libc::SYS_process_vm_readv, "process_vm_readv"),
        (libc::SYS_process_vm_writev, "process_vm_writev"),
        (libc::SYS_mount, "mount"),
        (libc::SYS_pivot_root, "pivot_root"),
        (libc::SYS_chroot, "chroot"),
        (libc::SYS_unshare, "unshare"),
        (libc::SYS_setns, "setns"),
        (libc::SYS_open_by_handle_at, "open_by_handle_at"),
    ] {
        assert!(denied.contains(&nr), "{name} must be denied");
    }
}

/// `socket`/`socketpair` are argument-conditional (AF_UNIX stays allowed), so
/// they must not appear in the unconditional list.
#[test]
fn unix_sockets_are_not_denied_unconditionally() {
    let denied = network_denied_syscalls();
    assert!(!denied.contains(&libc::SYS_socket));
    assert!(!denied.contains(&libc::SYS_socketpair));
    assert!(denied.contains(&libc::SYS_connect));
    assert!(denied.contains(&libc::SYS_bind));
}

#[test]
fn filters_compile_for_this_architecture() {
    assert!(build_deny_filter(NetworkMode::Denied).is_ok());
    assert!(build_deny_filter(NetworkMode::Allowed).is_ok());
    assert!(build_clone3_filter().is_ok());
    assert!(build_trace_filter(/*reads_restricted*/ false).is_ok());
    assert!(build_trace_filter(/*reads_restricted*/ true).is_ok());
}

/// Allowing the network must not weaken the escape list.
#[test]
fn the_escape_list_applies_even_with_the_network_allowed() {
    let allowed = build_deny_filter(NetworkMode::Allowed).expect("filter");
    let denied = build_deny_filter(NetworkMode::Denied).expect("filter");
    assert!(!allowed.is_empty());
    assert!(denied.len() > allowed.len());
}

/// A read-restricted policy has to intercept strictly more than an unrestricted
/// one; a smaller program would mean read probes were being skipped.
#[test]
fn read_restricted_policies_trace_more_syscalls() {
    let unrestricted = build_trace_filter(/*reads_restricted*/ false).expect("filter");
    let restricted = build_trace_filter(/*reads_restricted*/ true).expect("filter");
    assert!(restricted.len() > unrestricted.len());
}

#[test]
fn open_flag_narrowing_only_applies_to_the_flag_carrying_syscalls() {
    assert_eq!(open_flags_argument(libc::SYS_openat), Some(2));
    // `openat2` hides its flags behind a pointer, so it is always traced.
    assert_eq!(open_flags_argument(libc::SYS_openat2), None);
    assert_eq!(open_flags_argument(libc::SYS_unlinkat), None);
}

#[test]
fn prctl_installs_enforcing_filters_when_seccomp_syscall_is_forbidden() {
    // Keep irreversible filters out of the test runner and other tests.
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let test = || -> Result<()> {
            let forbidden = SeccompFilter::new(
                BTreeMap::from([(libc::SYS_seccomp, Vec::new())]),
                SeccompAction::Allow,
                SeccompAction::Trap,
                target_arch()?,
            )?;
            let program: BpfProgram = forbidden.try_into()?;
            apply_filter(&program)?;
            install_deny_filters(NetworkMode::Denied)?;
            // All three filter shapes must use prctl. getpid is a harmless
            // probe that the third filter can turn into a distinctive errno.
            let filtered = SeccompFilter::new(
                BTreeMap::from([(libc::SYS_getpid, Vec::new())]),
                SeccompAction::Allow,
                SeccompAction::Errno(libc::EACCES as u32),
                target_arch()?,
            )?;
            let program: BpfProgram = filtered.try_into()?;
            apply_filter(&program)?;
            for (nr, expected) in [
                (libc::SYS_getpid, libc::EACCES),
                (libc::SYS_io_uring_setup, libc::EPERM),
                (libc::SYS_clone3, libc::ENOSYS),
                (libc::SYS_socket, libc::EPERM),
            ] {
                let result = unsafe { libc::syscall(nr, libc::AF_INET, libc::SOCK_STREAM, 0) };
                if result != -1 || std::io::Error::last_os_error().raw_os_error() != Some(expected)
                {
                    return Err(SandboxError::Other("filter was not enforced".to_string()));
                }
            }
            Ok(())
        };
        unsafe { libc::_exit(if test().is_ok() { 0 } else { 1 }) }
    }
    let mut status = 0;
    loop {
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
    assert_eq!(
        status, 0,
        "filter installation must survive and still deny syscalls"
    );
}
