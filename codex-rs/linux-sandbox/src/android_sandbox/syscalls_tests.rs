use super::*;
use pretty_assertions::assert_eq;

#[test]
fn open_flags_map_to_the_access_they_imply() {
    assert_eq!(need_from_open_flags(libc::O_RDONLY as u64), Need::Read);
    assert_eq!(need_from_open_flags(libc::O_WRONLY as u64), Need::Write);
    assert_eq!(need_from_open_flags(libc::O_RDWR as u64), Need::Write);
    assert_eq!(
        need_from_open_flags((libc::O_WRONLY | libc::O_TRUNC) as u64),
        Need::Write
    );
    // Creating a name changes the directory entry, not just the file.
    assert_eq!(
        need_from_open_flags((libc::O_WRONLY | libc::O_CREAT) as u64),
        Need::WriteName
    );
    assert_eq!(
        need_from_open_flags((libc::O_RDWR | libc::O_TMPFILE) as u64),
        Need::WriteName
    );
}

/// `O_TMPFILE` contains `O_DIRECTORY`, so a naive bit test would classify every
/// directory open as a write.
#[test]
fn opening_a_directory_read_only_is_not_a_write() {
    assert_eq!(
        need_from_open_flags((libc::O_RDONLY | libc::O_DIRECTORY) as u64),
        Need::Read
    );
}

#[test]
fn read_probes_are_only_intercepted_when_reads_are_restricted() {
    let unrestricted = intercepted_syscalls(/*reads_restricted*/ false);
    let restricted = intercepted_syscalls(/*reads_restricted*/ true);

    assert!(unrestricted.contains(&libc::SYS_openat));
    assert!(unrestricted.contains(&libc::SYS_unlinkat));
    assert!(!unrestricted.contains(&libc::SYS_readlinkat));
    assert!(restricted.contains(&libc::SYS_readlinkat));
    assert!(restricted.len() > unrestricted.len());
}

#[test]
fn every_write_syscall_is_intercepted_regardless_of_read_policy() {
    let unrestricted = intercepted_syscalls(/*reads_restricted*/ false);
    for nr in [
        libc::SYS_openat,
        libc::SYS_openat2,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_renameat2,
        libc::SYS_linkat,
        libc::SYS_symlinkat,
        libc::SYS_fchmodat,
        libc::SYS_fchownat,
        libc::SYS_utimensat,
        libc::SYS_setxattr,
        libc::SYS_fsetxattr,
    ] {
        assert!(unrestricted.contains(&nr), "syscall {nr} is not intercepted");
    }
}

/// `renameat2` moves a name in both directions, so both arguments have to be
/// checked as name mutations.
#[test]
fn renameat2_checks_both_names() {
    let spec = lookup(libc::SYS_renameat2).expect("renameat2 spec");
    assert_eq!(spec.paths.len(), 2);
    for path in &spec.paths {
        assert_eq!(path.need, Need::WriteName);
        assert_eq!(path.follow, Follow::Never);
    }
}

/// `linkat`'s source is only read, but its destination creates a name.
#[test]
fn linkat_reads_the_source_and_writes_the_destination() {
    let spec = lookup(libc::SYS_linkat).expect("linkat spec");
    assert_eq!(spec.paths[0].need, Need::Read);
    assert_eq!(spec.paths[1].need, Need::WriteName);
}

/// Rewriting an `openat2` path to an absolute one would break the `RESOLVE_*`
/// restrictions the caller asked for.
#[test]
fn openat2_paths_are_not_rewritten() {
    let spec = lookup(libc::SYS_openat2).expect("openat2 spec");
    assert!(!spec.paths[0].rewritable);
    assert!(lookup(libc::SYS_openat).expect("openat spec").paths[0].rewritable);
}

#[test]
fn descriptor_only_syscalls_have_no_path_argument() {
    for nr in [libc::SYS_fchmod, libc::SYS_fchown, libc::SYS_fsetxattr] {
        let spec = lookup(nr).expect("descriptor spec");
        assert_eq!(spec.paths[0].path_arg, None);
        assert_eq!(spec.paths[0].need, Need::Write);
    }
}

#[test]
fn symlink_flags_are_read_from_the_documented_argument() {
    assert!(at_flags_nofollow(libc::AT_SYMLINK_NOFOLLOW as u64));
    assert!(!at_flags_nofollow(0));
    assert!(at_flags_follow(libc::AT_SYMLINK_FOLLOW as u64));
    assert!(!at_flags_follow(0));
    assert!(open_flags_nofollow(libc::O_NOFOLLOW as u64));
    assert!(!open_flags_nofollow(libc::O_RDONLY as u64));
}
