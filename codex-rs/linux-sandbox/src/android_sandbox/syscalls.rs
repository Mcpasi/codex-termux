//! Table of syscalls the Android supervisor has to inspect.
//!
//! The supervisor cannot rely on an LSM to resolve paths for it, so it has to
//! know, for every filesystem-touching syscall, *where* the path arguments are
//! and *what* access they need. This module is pure data plus the few helpers
//! needed to interpret the flag arguments; it has no ptrace dependency so it
//! compiles (and is unit tested) on ordinary Linux hosts too.
//!
//! Only syscalls that take a path (or act on a descriptor in a way that a
//! read-only `open` would not have authorized) appear here. Everything else is
//! either irrelevant to the filesystem boundary or hard-denied by the seccomp
//! filter in [`crate::android_sandbox::seccomp`].

use std::collections::HashMap;
use std::sync::OnceLock;

/// Access a path argument needs before the syscall may proceed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Need {
    /// The syscall only reads the object.
    Read,
    /// The syscall modifies the object itself (contents, mode, owner, times).
    Write,
    /// The syscall creates or removes a *name*. Both the object and the
    /// directory that holds the name have to be writable, because the
    /// directory entry is what actually changes.
    WriteName,
    /// `open`-family: derive the need from the flags in this argument.
    OpenFlags(usize),
    /// `openat2`: derive the need from `open_how.flags` behind this pointer.
    OpenHow(usize),
}

/// Whether the final path component is followed before the check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Follow {
    /// Resolve the final component through symlinks (`stat`-like).
    Always,
    /// Leave the final component alone (`lstat`-like); the name itself is the
    /// object being acted on.
    Never,
    /// Follow unless `AT_SYMLINK_NOFOLLOW` is set in this argument.
    UnlessAtNoFollow(usize),
    /// Follow only when `AT_SYMLINK_FOLLOW` is set in this argument (`linkat`).
    OnlyIfAtFollow(usize),
    /// Follow unless `O_NOFOLLOW` is set in this `open`-flags argument.
    UnlessOpenNoFollow(usize),
    /// Follow unless `O_NOFOLLOW` is set in `open_how.flags` behind this
    /// pointer.
    UnlessOpenHowNoFollow(usize),
}

/// Where a checked path starts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Base {
    /// Relative paths resolve against the tracee's current directory.
    Cwd,
    /// Relative paths resolve against the descriptor in this argument, which
    /// may also be `AT_FDCWD`. When the path argument is absent, empty or
    /// `NULL`, the descriptor itself is the target (`AT_EMPTY_PATH`,
    /// `futimens`, `fchmod`, ...).
    Fd(usize),
}

/// One path (or descriptor) a syscall touches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PathArg {
    /// Register index holding the `const char *`, or `None` when the syscall
    /// only acts on `base`.
    pub(crate) path_arg: Option<usize>,
    pub(crate) base: Base,
    pub(crate) need: Need,
    pub(crate) follow: Follow,
    /// Whether the supervisor may replace the argument with the canonical path
    /// it validated. Disabled where rewriting would change the syscall's
    /// meaning (`openat2` honours `RESOLVE_*` restrictions that an absolute
    /// path would violate).
    pub(crate) rewritable: bool,
}

impl PathArg {
    const fn path(path_arg: usize, base: Base, need: Need, follow: Follow) -> Self {
        Self {
            path_arg: Some(path_arg),
            base,
            need,
            follow,
            rewritable: true,
        }
    }

    const fn no_rewrite(mut self) -> Self {
        self.rewritable = false;
        self
    }

    /// A syscall that acts on an already-open descriptor.
    const fn descriptor(fd_arg: usize, need: Need) -> Self {
        Self {
            path_arg: None,
            base: Base::Fd(fd_arg),
            need,
            follow: Follow::Never,
            rewritable: false,
        }
    }
}

/// A syscall the supervisor intercepts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SyscallSpec {
    pub(crate) nr: i64,
    pub(crate) name: &'static str,
    pub(crate) paths: Vec<PathArg>,
    /// Interception is only needed when the policy narrows *read* access.
    /// Profiles such as `workspace-write` keep full read access, and skipping
    /// these keeps `stat`/`access`-heavy tooling at native speed.
    pub(crate) read_probe_only: bool,
}

impl SyscallSpec {
    fn write_op(nr: i64, name: &'static str, paths: Vec<PathArg>) -> Self {
        Self {
            nr,
            name,
            paths,
            read_probe_only: false,
        }
    }

    fn read_op(nr: i64, name: &'static str, paths: Vec<PathArg>) -> Self {
        Self {
            nr,
            name,
            paths,
            read_probe_only: true,
        }
    }
}

/// Syscall numbers.
///
/// `libc` does not expose every number we need on every architecture (the
/// arm64 `asm-generic` table is missing `truncate`, `statfs` and friends in the
/// crate), so the handful of gaps are spelled out from the UAPI table, which is
/// frozen for these syscalls.
mod nr {
    #[cfg(target_arch = "aarch64")]
    pub(super) const TRUNCATE: i64 = 45;
    #[cfg(target_arch = "aarch64")]
    pub(super) const FTRUNCATE: i64 = 46;
    #[cfg(target_arch = "aarch64")]
    pub(super) const NEWFSTATAT: i64 = 79;
    #[cfg(target_arch = "aarch64")]
    pub(super) const STATFS: i64 = 43;

    #[cfg(target_arch = "x86_64")]
    pub(super) const TRUNCATE: i64 = libc::SYS_truncate;
    #[cfg(target_arch = "x86_64")]
    pub(super) const FTRUNCATE: i64 = libc::SYS_ftruncate;
    #[cfg(target_arch = "x86_64")]
    pub(super) const NEWFSTATAT: i64 = libc::SYS_newfstatat;
    #[cfg(target_arch = "x86_64")]
    pub(super) const STATFS: i64 = libc::SYS_statfs;

    // The supervisor refuses to start on architectures it has no register
    // layout for (see `arch::supported`), so an unmatchable number is enough to
    // keep the crate compiling for them.
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) const TRUNCATE: i64 = -1;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) const FTRUNCATE: i64 = -1;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) const NEWFSTATAT: i64 = -1;
    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(super) const STATFS: i64 = -1;
}

/// Builds the interception table for this architecture.
fn build_table() -> Vec<SyscallSpec> {
    use Base::Cwd;
    use Base::Fd;
    use Follow::Always;
    use Follow::Never;
    use Follow::OnlyIfAtFollow;
    use Follow::UnlessAtNoFollow;
    use Follow::UnlessOpenHowNoFollow;
    use Follow::UnlessOpenNoFollow;
    use Need::OpenFlags;
    use Need::OpenHow;
    use Need::Read;
    use Need::Write;
    use Need::WriteName;

    // `mut` is only needed on architectures that add legacy syscalls below.
    #[allow(unused_mut)]
    let mut table = vec![
        // ---- open family -------------------------------------------------
        SyscallSpec::write_op(
            libc::SYS_openat,
            "openat",
            vec![PathArg::path(
                1,
                Fd(0),
                OpenFlags(2),
                UnlessOpenNoFollow(2),
            )],
        ),
        SyscallSpec::write_op(
            libc::SYS_openat2,
            "openat2",
            vec![
                PathArg::path(1, Fd(0), OpenHow(2), UnlessOpenHowNoFollow(2)).no_rewrite(),
            ],
        ),
        // ---- name creation / removal ------------------------------------
        SyscallSpec::write_op(
            libc::SYS_unlinkat,
            "unlinkat",
            vec![PathArg::path(1, Fd(0), WriteName, Never)],
        ),
        SyscallSpec::write_op(
            libc::SYS_mkdirat,
            "mkdirat",
            vec![PathArg::path(1, Fd(0), WriteName, Never)],
        ),
        SyscallSpec::write_op(
            libc::SYS_mknodat,
            "mknodat",
            vec![PathArg::path(1, Fd(0), WriteName, Never)],
        ),
        // `symlinkat(target, newdirfd, linkpath)`: `target` is the link's
        // contents, not a path that gets resolved now.
        SyscallSpec::write_op(
            libc::SYS_symlinkat,
            "symlinkat",
            vec![PathArg::path(2, Fd(1), WriteName, Never)],
        ),
        SyscallSpec::write_op(
            libc::SYS_linkat,
            "linkat",
            vec![
                PathArg::path(1, Fd(0), Read, OnlyIfAtFollow(4)),
                PathArg::path(3, Fd(2), WriteName, Never),
            ],
        ),
        SyscallSpec::write_op(
            libc::SYS_renameat,
            "renameat",
            vec![
                PathArg::path(1, Fd(0), WriteName, Never),
                PathArg::path(3, Fd(2), WriteName, Never),
            ],
        ),
        SyscallSpec::write_op(
            libc::SYS_renameat2,
            "renameat2",
            vec![
                PathArg::path(1, Fd(0), WriteName, Never),
                PathArg::path(3, Fd(2), WriteName, Never),
            ],
        ),
        // ---- metadata / content mutation --------------------------------
        SyscallSpec::write_op(
            libc::SYS_fchmodat,
            "fchmodat",
            vec![PathArg::path(1, Fd(0), Write, UnlessAtNoFollow(3))],
        ),
        SyscallSpec::write_op(
            libc::SYS_fchmod,
            "fchmod",
            vec![PathArg::descriptor(0, Write)],
        ),
        SyscallSpec::write_op(
            libc::SYS_fchownat,
            "fchownat",
            vec![PathArg::path(1, Fd(0), Write, UnlessAtNoFollow(4))],
        ),
        SyscallSpec::write_op(
            libc::SYS_fchown,
            "fchown",
            vec![PathArg::descriptor(0, Write)],
        ),
        // `utimensat(fd, NULL, ...)` is `futimens` and acts on the descriptor;
        // the resolver falls back to `base` for a NULL path.
        SyscallSpec::write_op(
            libc::SYS_utimensat,
            "utimensat",
            vec![PathArg::path(1, Fd(0), Write, UnlessAtNoFollow(3))],
        ),
        SyscallSpec::write_op(
            nr::TRUNCATE,
            "truncate",
            vec![PathArg::path(0, Cwd, Write, Always)],
        ),
        SyscallSpec::write_op(
            nr::FTRUNCATE,
            "ftruncate",
            vec![PathArg::descriptor(0, Write)],
        ),
        SyscallSpec::write_op(
            libc::SYS_fallocate,
            "fallocate",
            vec![PathArg::descriptor(0, Write)],
        ),
        // ---- extended attributes ----------------------------------------
        SyscallSpec::write_op(
            libc::SYS_setxattr,
            "setxattr",
            vec![PathArg::path(0, Cwd, Write, Always)],
        ),
        SyscallSpec::write_op(
            libc::SYS_lsetxattr,
            "lsetxattr",
            vec![PathArg::path(0, Cwd, Write, Never)],
        ),
        SyscallSpec::write_op(
            libc::SYS_fsetxattr,
            "fsetxattr",
            vec![PathArg::descriptor(0, Write)],
        ),
        SyscallSpec::write_op(
            libc::SYS_removexattr,
            "removexattr",
            vec![PathArg::path(0, Cwd, Write, Always)],
        ),
        SyscallSpec::write_op(
            libc::SYS_lremovexattr,
            "lremovexattr",
            vec![PathArg::path(0, Cwd, Write, Never)],
        ),
        SyscallSpec::write_op(
            libc::SYS_fremovexattr,
            "fremovexattr",
            vec![PathArg::descriptor(0, Write)],
        ),
        // ---- read probes -------------------------------------------------
        SyscallSpec::read_op(
            libc::SYS_execve,
            "execve",
            vec![PathArg::path(0, Cwd, Read, Always)],
        ),
        SyscallSpec::read_op(
            libc::SYS_execveat,
            "execveat",
            vec![PathArg::path(1, Fd(0), Read, UnlessAtNoFollow(4))],
        ),
        SyscallSpec::read_op(
            libc::SYS_faccessat,
            "faccessat",
            vec![PathArg::path(1, Fd(0), Read, Always)],
        ),
        SyscallSpec::read_op(
            libc::SYS_faccessat2,
            "faccessat2",
            vec![PathArg::path(1, Fd(0), Read, UnlessAtNoFollow(3))],
        ),
        SyscallSpec::read_op(
            libc::SYS_readlinkat,
            "readlinkat",
            vec![PathArg::path(1, Fd(0), Read, Never)],
        ),
        SyscallSpec::read_op(
            nr::NEWFSTATAT,
            "newfstatat",
            vec![PathArg::path(1, Fd(0), Read, UnlessAtNoFollow(3))],
        ),
        SyscallSpec::read_op(
            libc::SYS_statx,
            "statx",
            vec![PathArg::path(1, Fd(0), Read, UnlessAtNoFollow(2))],
        ),
        SyscallSpec::read_op(
            nr::STATFS,
            "statfs",
            vec![PathArg::path(0, Cwd, Read, Always)],
        ),
        SyscallSpec::read_op(
            libc::SYS_chdir,
            "chdir",
            vec![PathArg::path(0, Cwd, Read, Always)],
        ),
        SyscallSpec::read_op(
            libc::SYS_getxattr,
            "getxattr",
            vec![PathArg::path(0, Cwd, Read, Always)],
        ),
        SyscallSpec::read_op(
            libc::SYS_lgetxattr,
            "lgetxattr",
            vec![PathArg::path(0, Cwd, Read, Never)],
        ),
        SyscallSpec::read_op(
            libc::SYS_listxattr,
            "listxattr",
            vec![PathArg::path(0, Cwd, Read, Always)],
        ),
        SyscallSpec::read_op(
            libc::SYS_llistxattr,
            "llistxattr",
            vec![PathArg::path(0, Cwd, Read, Never)],
        ),
        SyscallSpec::read_op(
            libc::SYS_inotify_add_watch,
            "inotify_add_watch",
            vec![PathArg::path(1, Cwd, Read, Always)],
        ),
    ];

    // x86_64 (emulators, `x86_64` Android images) still exposes the pre-`*at`
    // syscalls, and a static binary can call them directly.
    #[cfg(target_arch = "x86_64")]
    {
        table.extend([
            SyscallSpec::write_op(
                libc::SYS_open,
                "open",
                vec![PathArg::path(0, Cwd, OpenFlags(1), UnlessOpenNoFollow(1))],
            ),
            SyscallSpec::write_op(
                libc::SYS_creat,
                "creat",
                vec![PathArg::path(0, Cwd, WriteName, Always)],
            ),
            SyscallSpec::write_op(
                libc::SYS_unlink,
                "unlink",
                vec![PathArg::path(0, Cwd, WriteName, Never)],
            ),
            SyscallSpec::write_op(
                libc::SYS_rmdir,
                "rmdir",
                vec![PathArg::path(0, Cwd, WriteName, Never)],
            ),
            SyscallSpec::write_op(
                libc::SYS_mkdir,
                "mkdir",
                vec![PathArg::path(0, Cwd, WriteName, Never)],
            ),
            SyscallSpec::write_op(
                libc::SYS_mknod,
                "mknod",
                vec![PathArg::path(0, Cwd, WriteName, Never)],
            ),
            SyscallSpec::write_op(
                libc::SYS_symlink,
                "symlink",
                vec![PathArg::path(1, Cwd, WriteName, Never)],
            ),
            SyscallSpec::write_op(
                libc::SYS_link,
                "link",
                vec![
                    PathArg::path(0, Cwd, Read, Never),
                    PathArg::path(1, Cwd, WriteName, Never),
                ],
            ),
            SyscallSpec::write_op(
                libc::SYS_rename,
                "rename",
                vec![
                    PathArg::path(0, Cwd, WriteName, Never),
                    PathArg::path(1, Cwd, WriteName, Never),
                ],
            ),
            SyscallSpec::write_op(
                libc::SYS_chmod,
                "chmod",
                vec![PathArg::path(0, Cwd, Write, Always)],
            ),
            SyscallSpec::write_op(
                libc::SYS_chown,
                "chown",
                vec![PathArg::path(0, Cwd, Write, Always)],
            ),
            SyscallSpec::write_op(
                libc::SYS_lchown,
                "lchown",
                vec![PathArg::path(0, Cwd, Write, Never)],
            ),
            SyscallSpec::write_op(
                libc::SYS_utime,
                "utime",
                vec![PathArg::path(0, Cwd, Write, Always)],
            ),
            SyscallSpec::write_op(
                libc::SYS_utimes,
                "utimes",
                vec![PathArg::path(0, Cwd, Write, Always)],
            ),
            SyscallSpec::write_op(
                libc::SYS_futimesat,
                "futimesat",
                vec![PathArg::path(1, Fd(0), Write, Always)],
            ),
            SyscallSpec::read_op(
                libc::SYS_stat,
                "stat",
                vec![PathArg::path(0, Cwd, Read, Always)],
            ),
            SyscallSpec::read_op(
                libc::SYS_lstat,
                "lstat",
                vec![PathArg::path(0, Cwd, Read, Never)],
            ),
            SyscallSpec::read_op(
                libc::SYS_access,
                "access",
                vec![PathArg::path(0, Cwd, Read, Always)],
            ),
            SyscallSpec::read_op(
                libc::SYS_readlink,
                "readlink",
                vec![PathArg::path(0, Cwd, Read, Never)],
            ),
        ]);
    }

    table
}

fn table() -> &'static HashMap<i64, SyscallSpec> {
    static TABLE: OnceLock<HashMap<i64, SyscallSpec>> = OnceLock::new();
    TABLE.get_or_init(|| {
        build_table()
            .into_iter()
            // Placeholder numbers for architectures without a register layout.
            .filter(|spec| spec.nr >= 0)
            .map(|spec| (spec.nr, spec))
            .collect()
    })
}

/// Returns the spec for `nr`, or `None` when the syscall does not touch a path.
pub(crate) fn lookup(nr: i64) -> Option<&'static SyscallSpec> {
    table().get(&nr)
}

/// Syscall numbers that must stop in the supervisor for the given policy shape.
///
/// When reads are unrestricted, the read probes are left running at full speed:
/// their check could only ever return "allowed".
pub(crate) fn intercepted_syscalls(reads_restricted: bool) -> Vec<i64> {
    let mut numbers: Vec<i64> = table()
        .values()
        .filter(|spec| reads_restricted || !spec.read_probe_only)
        .map(|spec| spec.nr)
        .collect();
    numbers.sort_unstable();
    numbers
}

/// Access implied by `open`-style flags.
pub(crate) fn need_from_open_flags(flags: u64) -> Need {
    let flags = flags as i64;
    let tmpfile = flags & i64::from(libc::O_TMPFILE) == i64::from(libc::O_TMPFILE);
    let accmode = flags & i64::from(libc::O_ACCMODE);
    let writes = accmode == i64::from(libc::O_WRONLY)
        || accmode == i64::from(libc::O_RDWR)
        || flags & i64::from(libc::O_TRUNC) != 0;

    // `O_CREAT` and `O_TMPFILE` both add an inode to the directory named by the
    // path, so the directory entry — not just the object — has to be writable.
    if flags & i64::from(libc::O_CREAT) != 0 || tmpfile {
        Need::WriteName
    } else if writes {
        Need::Write
    } else {
        Need::Read
    }
}

/// `__O_TMPFILE` on its own. `libc::O_TMPFILE` also carries `O_DIRECTORY`,
/// which would make a plain directory open look like a write.
const RAW_O_TMPFILE: i64 = 0o20_000_000;

/// Bits that make an `open` write-capable. Used by the seccomp filter to keep
/// read-only opens out of the supervisor entirely.
pub(crate) const OPEN_WRITE_INTENT_BITS: &[i64] = &[
    libc::O_WRONLY as i64,
    libc::O_RDWR as i64,
    libc::O_CREAT as i64,
    libc::O_TRUNC as i64,
    RAW_O_TMPFILE,
];

pub(crate) fn open_flags_nofollow(flags: u64) -> bool {
    flags as i64 & i64::from(libc::O_NOFOLLOW) != 0
}

pub(crate) fn at_flags_nofollow(flags: u64) -> bool {
    flags as i64 & i64::from(libc::AT_SYMLINK_NOFOLLOW) != 0
}

pub(crate) fn at_flags_follow(flags: u64) -> bool {
    flags as i64 & i64::from(libc::AT_SYMLINK_FOLLOW) != 0
}

#[cfg(test)]
#[path = "syscalls_tests.rs"]
mod tests;
