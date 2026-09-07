//! Android's `:minimal` runtime paths. These are system image files and the
//! command's own process metadata; application data is never a platform default.

use std::path::Path;

use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSandboxPolicy;
use codex_utils_absolute_path::AbsolutePathBuf;

pub(super) fn add_defaults(policy: &mut FileSystemSandboxPolicy) {
    if !policy.include_platform_defaults() {
        return;
    }
    for root in [
        "/system",
        "/system_ext",
        "/apex",
        "/vendor",
        "/product",
        "/odm",
        "/linkerconfig",
        "/dev/__properties__",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/proc/version",
        "/proc/sys/kernel/osrelease",
        "/sys/devices/system/cpu",
    ] {
        policy.entries.push(FileSystemSandboxEntry::new(
            AbsolutePathBuf::try_from(root)
                .expect("absolute Android platform path")
                .into(),
            FileSystemAccessMode::Read,
        ));
    }
    for device in ["/dev/null", "/dev/tty"] {
        policy.entries.push(FileSystemSandboxEntry::new(
            AbsolutePathBuf::try_from(device)
                .expect("absolute Android device path")
                .into(),
            FileSystemAccessMode::Write,
        ));
    }
}

pub(super) fn add_tracee_reads(
    policy: &mut FileSystemSandboxPolicy,
    proc_root: &Path,
    tracee_pid: i32,
) {
    if !policy.include_platform_defaults() || tracee_pid <= 0 {
        return;
    }
    // Do not grant a process directory: mem, environ, root and other processes'
    // credentials remain outside the default. fd links are resolved separately.
    for name in [
        "exe", "cmdline", "maps", "stat", "statm", "status", "auxv", "limits",
    ] {
        if let Ok(path) =
            AbsolutePathBuf::from_absolute_path(proc_root.join(tracee_pid.to_string()).join(name))
        {
            policy.entries.push(FileSystemSandboxEntry::new(
                path.into(),
                FileSystemAccessMode::Read,
            ));
        }
    }
}

pub(super) fn is_writable_device(path: &Path) -> bool {
    path == Path::new("/dev/null") || path == Path::new("/dev/tty")
}
