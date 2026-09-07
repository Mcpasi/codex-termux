//! Turning a tracee's syscall arguments into an absolute path the policy can
//! answer questions about.
//!
//! The supervisor sees exactly what the kernel would see — a descriptor plus a
//! byte string — so it has to redo the kernel's own resolution: apply the
//! working directory or the `*at` directory descriptor, expand `/proc/self`
//! from the *tracee's* point of view, and follow symlinks the same way the
//! syscall would.
//!
//! This module only builds paths; it never decides anything. It has no ptrace
//! dependency so the resolution rules can be unit tested on an ordinary host.

use std::io;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;

/// How the final component is treated during resolution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FinalComponent {
    /// Resolve it through symlinks (`stat`-like syscalls).
    Follow,
    /// Leave it as a name in its (fully resolved) parent directory
    /// (`lstat`/`unlink`-like syscalls).
    Keep,
}

/// Where the descriptor referenced by a syscall points.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DescriptorTarget {
    /// A path in the filesystem.
    Path(PathBuf),
    /// A socket, pipe, epoll instance, ... — nothing the filesystem policy
    /// governs.
    NotAFile,
}

/// Reads where `/proc/<pid>/fd/<fd>` points.
///
/// `readlink` reports deleted files as `"<path> (deleted)"`; the suffix is
/// stripped so an operation on an unlinked-but-open file is still judged
/// against the directory it came from.
pub(crate) fn descriptor_target(
    proc_root: &Path,
    pid: i32,
    fd: i32,
) -> io::Result<DescriptorTarget> {
    let link = if fd == libc::AT_FDCWD {
        proc_root.join(pid.to_string()).join("cwd")
    } else if fd < 0 {
        return Err(io::Error::from_raw_os_error(libc::EBADF));
    } else {
        proc_root
            .join(pid.to_string())
            .join("fd")
            .join(fd.to_string())
    };

    let target = std::fs::read_link(link)?;
    Ok(classify_descriptor_target(&target))
}

fn classify_descriptor_target(target: &Path) -> DescriptorTarget {
    let Some(text) = target.to_str() else {
        // Non-UTF-8 paths are still real paths.
        return DescriptorTarget::Path(target.to_path_buf());
    };
    if !text.starts_with('/') {
        // "socket:[12345]", "pipe:[678]", "anon_inode:[eventfd]", ...
        return DescriptorTarget::NotAFile;
    }
    match text.strip_suffix(" (deleted)") {
        Some(stripped) => DescriptorTarget::Path(PathBuf::from(stripped)),
        None => DescriptorTarget::Path(target.to_path_buf()),
    }
}

/// Recognizes one direct descriptor link of the stopped tracee, never another
/// process or a path below an fd link.
pub(crate) fn tracee_fd(path: &Path, proc_root: &Path, pid: i32) -> Option<i32> {
    let root = proc_root.join(pid.to_string()).join("fd");
    let name = path.strip_prefix(root).ok()?.to_str()?;
    if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    name.parse::<i32>().ok().filter(|fd| *fd >= 0)
}

/// Rewrites the `/proc/self` and `/proc/thread-self` magic links so they mean
/// what they mean *inside the tracee*.
///
/// Without this the supervisor would canonicalize `/proc/self/fd/3` against its
/// own descriptor table and validate a completely different file.
pub(crate) fn rebind_proc_self(path: &Path, proc_root: &Path, pid: i32) -> PathBuf {
    // `..` segments are collapsed first so `/proc/x/../self/fd/3` is caught
    // too. The normalized form is only adopted when the path really is a
    // `/proc/self` reference; everything else is returned untouched, because
    // collapsing `..` lexically is not generally sound in the presence of
    // symlinks.
    let normalized = lexically_normalize(path);
    let Ok(rest) = normalized.strip_prefix(proc_root) else {
        return path.to_path_buf();
    };
    let mut components = rest.components();
    let Some(Component::Normal(first)) = components.next() else {
        return path.to_path_buf();
    };
    if first != "self" && first != "thread-self" {
        return path.to_path_buf();
    }

    let mut rebound = proc_root.join(pid.to_string());
    rebound.extend(components.map(|component| component.as_os_str()));
    rebound
}

/// Resolves a raw syscall path argument into an absolute path.
///
/// * `base` is the directory the path is relative to — the tracee's cwd for
///   `AT_FDCWD`, otherwise the `*at` directory descriptor's target.
/// * An empty `path` means the descriptor itself (`AT_EMPTY_PATH`).
pub(crate) fn resolve_path(
    base: &Path,
    path: &Path,
    proc_root: &Path,
    pid: i32,
    final_component: FinalComponent,
) -> PathBuf {
    let joined = if path.as_os_str().is_empty() {
        base.to_path_buf()
    } else if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    let joined = rebind_proc_self(&joined, proc_root, pid);

    match final_component {
        FinalComponent::Follow => resolve_following_final(&joined, proc_root, pid),
        FinalComponent::Keep => resolve_keeping_final(&joined),
    }
}

/// The kernel's limit on symlink hops during one resolution.
const MAX_SYMLINK_HOPS: usize = 40;

/// Resolves everything up to the final component, leaving the last name intact.
///
/// This is `lstat` semantics, and it is also the right answer for `unlink`,
/// `rename` and the other syscalls that act on a *name*: what changes is the
/// directory entry, not whatever it points at.
fn resolve_keeping_final(path: &Path) -> PathBuf {
    // A trailing `/`, `.` or `..` always names a directory, which the kernel
    // resolves fully even for the `lstat`-style syscalls.
    let names_directory = matches!(
        path.components().next_back(),
        Some(Component::CurDir) | Some(Component::ParentDir) | Some(Component::RootDir) | None
    ) || path.to_str().is_some_and(|text| text.ends_with('/'));

    if names_directory {
        return canonicalize_best_effort(path);
    }
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => canonicalize_best_effort(parent).join(name),
        _ => canonicalize_best_effort(path),
    }
}

/// Resolves the final component through symlinks, the way `stat` or a plain
/// `open` would.
///
/// [`canonicalize_best_effort`] alone is not enough here: it gives up on the
/// final component as soon as the path does not fully exist, which is exactly
/// the case of a *dangling* symlink. A link pointing at a file that has not been
/// created yet would then be judged as the link's own path — so
/// `open("workspace/link", O_CREAT|O_WRONLY)` with `link -> /etc/newfile` would
/// look like a write inside the workspace while the kernel created a file
/// outside it. The link is therefore expanded explicitly.
fn resolve_following_final(path: &Path, proc_root: &Path, pid: i32) -> PathBuf {
    let mut current = resolve_keeping_final(path);
    for _ in 0..MAX_SYMLINK_HOPS {
        // `read_link` fails with `EINVAL` for anything that is not a symlink,
        // and with `ENOENT` when the name does not exist: both mean there is
        // nothing left to follow.
        let Ok(target) = std::fs::read_link(&current) else {
            return current;
        };
        // procfs anonymous descriptors are magic links, not relative names
        // such as /proc/<pid>/fd/pipe:[123]. Keep the link for the supervisor
        // to validate against this tracee's descriptor table.
        if tracee_fd(&current, proc_root, pid).is_some()
            && classify_descriptor_target(&target) == DescriptorTarget::NotAFile
        {
            return current;
        }
        let next = if target.is_absolute() {
            target
        } else {
            match current.parent() {
                Some(parent) => parent.join(target),
                None => target,
            }
        };
        current = resolve_keeping_final(&next);
    }
    current
}

/// Canonicalizes as much of `path` as exists and resolves the rest lexically.
///
/// Creation syscalls name files that do not exist yet, so a plain
/// [`std::fs::canonicalize`] would fail exactly where the check matters most.
/// Every component that *does* exist is resolved through the kernel, which is
/// what defeats symlink games; only the non-existent tail is handled textually,
/// where there is nothing left to point somewhere else.
pub(crate) fn canonicalize_best_effort(path: &Path) -> PathBuf {
    if let Ok(canonical) = std::fs::canonicalize(path) {
        return canonical;
    }

    let mut existing = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match (existing.parent(), existing.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => break,
        }
        if let Ok(canonical) = std::fs::canonicalize(&existing) {
            let mut resolved = canonical;
            for name in tail.iter().rev() {
                push_lexical(&mut resolved, Path::new(name));
            }
            return resolved;
        }
    }

    // Nothing on the path exists (or the tracee handed us a relative path we
    // could not anchor): fall back to a purely lexical normalization.
    lexically_normalize(path)
}

fn push_lexical(base: &mut PathBuf, component: &Path) {
    match component.as_os_str().to_str() {
        Some(".") => {}
        Some("..") => {
            base.pop();
        }
        _ => base.push(component),
    }
}

/// Collapses `.` and `..` without touching the filesystem.
pub(crate) fn lexically_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
#[path = "resolve_tests.rs"]
mod tests;
