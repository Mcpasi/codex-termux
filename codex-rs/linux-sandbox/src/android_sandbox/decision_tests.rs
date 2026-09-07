use super::*;
use codex_protocol::permissions::FileSystemAccessMode;
use codex_protocol::permissions::FileSystemPath;
use codex_protocol::permissions::FileSystemSandboxEntry;
use codex_protocol::permissions::FileSystemSpecialPath;
use codex_utils_absolute_path::AbsolutePathBuf;
use pretty_assertions::assert_eq;

/// Full read plus a single writable subtree — the shape `workspace-write`
/// produces, and the one the supervisor sees most often.
fn workspace_write_engine(workspace: &str) -> PolicyEngine {
    let workspace = AbsolutePathBuf::try_from(workspace).expect("absolute workspace");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(
            FileSystemPath::from(workspace.clone()),
            FileSystemAccessMode::Write,
        ),
    ]);
    PolicyEngine::new(
        policy,
        workspace.as_path().to_path_buf(),
        Path::new("/proc"),
        4242,
    )
}

#[test]
fn writes_inside_the_workspace_are_allowed() {
    let engine = workspace_write_engine("/workspace");

    assert_eq!(
        engine.check(Path::new("/workspace/src/main.rs"), Access::Write),
        Ok(())
    );
    assert_eq!(
        engine.check(Path::new("/workspace/src/new.rs"), Access::WriteName),
        Ok(())
    );
}

#[test]
fn writes_outside_the_workspace_are_refused() {
    let engine = workspace_write_engine("/workspace");

    let denial = engine
        .check(Path::new("/etc/passwd"), Access::Write)
        .expect_err("writing outside the workspace must be refused");
    assert_eq!(denial.reason, DenialReason::PolicyDenied);
    assert_eq!(denial.path, Path::new("/etc/passwd"));
}

/// The whole point of keeping read probes uninstrumented: with full read
/// access, every read is allowed anyway.
#[test]
fn reads_are_allowed_everywhere_under_workspace_write() {
    let engine = workspace_write_engine("/workspace");

    assert!(!engine.reads_restricted());
    assert_eq!(engine.check(Path::new("/etc/passwd"), Access::Read), Ok(()));
}

/// Landlock could only ever grant "full read"; the supervisor enforces the
/// narrowed policy that Codex was actually configured with.
#[test]
fn read_narrowing_is_enforced() {
    let workspace = AbsolutePathBuf::try_from("/workspace").expect("absolute workspace");
    let policy = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry::new(
        FileSystemPath::from(workspace.clone()),
        FileSystemAccessMode::Read,
    )]);
    let engine = PolicyEngine::new(
        policy,
        workspace.as_path().to_path_buf(),
        Path::new("/proc"),
        4242,
    );

    assert!(engine.reads_restricted());
    assert_eq!(
        engine.check(Path::new("/workspace/README.md"), Access::Read),
        Ok(())
    );
    assert!(
        engine
            .check(Path::new("/etc/passwd"), Access::Read)
            .is_err()
    );
    assert!(
        engine
            .check(Path::new("/workspace/README.md"), Access::Write)
            .is_err()
    );
}

/// Deleting or creating a name mutates the directory holding it, so a policy
/// that grants write to one file inside a read-only directory must not allow
/// that file to be removed or replaced.
#[test]
fn creating_a_name_requires_a_writable_parent() {
    let file = AbsolutePathBuf::try_from("/readonly/data.txt").expect("absolute file");
    let policy = FileSystemSandboxPolicy::restricted(vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Root,
            },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(FileSystemPath::from(file), FileSystemAccessMode::Write),
    ]);
    let engine = PolicyEngine::new(
        policy,
        std::path::PathBuf::from("/readonly"),
        Path::new("/proc"),
        4242,
    );

    // Rewriting the file's contents is what the policy granted.
    assert_eq!(
        engine.check(Path::new("/readonly/data.txt"), Access::Write),
        Ok(())
    );
    // Unlinking it would change the read-only directory.
    assert!(
        engine
            .check(Path::new("/readonly/data.txt"), Access::WriteName)
            .is_err()
    );
}

/// `/proc/self` inside the tracee resolves to the supervisor when the
/// supervisor canonicalizes it, so any path landing in the supervisor's own
/// process directory is refused outright.
#[test]
fn the_supervisors_own_proc_directory_is_off_limits() {
    let engine = workspace_write_engine("/workspace");

    let denial = engine
        .check(Path::new("/proc/4242/mem"), Access::Read)
        .expect_err("the supervisor's process directory must be refused");
    assert_eq!(denial.reason, DenialReason::SupervisorProcDirectory);
}

#[test]
fn denials_explain_themselves() {
    let engine = workspace_write_engine("/workspace");

    let denial = engine
        .check(Path::new("/etc/passwd"), Access::Write)
        .expect_err("denied");
    let message = denial.to_string();
    assert!(message.contains("write"), "{message}");
    assert!(message.contains("/etc/passwd"), "{message}");
}

fn android_minimal_engine(extra: Vec<FileSystemSandboxEntry>) -> PolicyEngine {
    let workspace = AbsolutePathBuf::try_from("/private/workspace").unwrap();
    let mut entries = vec![
        FileSystemSandboxEntry::new(
            FileSystemPath::Special {
                value: FileSystemSpecialPath::Minimal,
            },
            FileSystemAccessMode::Read,
        ),
        FileSystemSandboxEntry::new(workspace.into(), FileSystemAccessMode::Write),
    ];
    entries.extend(extra);
    PolicyEngine::new(
        FileSystemSandboxPolicy::restricted(entries),
        PathBuf::from("/private/workspace"),
        Path::new("/proc"),
        4242,
    )
}

#[test]
fn linker_fd_metadata_obeys_the_opened_files_read_permission() {
    let directory = tempfile::tempdir().unwrap();
    let root = std::fs::canonicalize(directory.path()).unwrap();
    let proc_root = root.join("proc");
    let fd_root = proc_root.join("4243/fd");
    std::fs::create_dir_all(&fd_root).unwrap();
    let library = root.join("native-library.so");
    let private = root.join("private-sibling");
    std::fs::write(&library, b"synthetic-library").unwrap();
    std::fs::write(&private, b"synthetic-private").unwrap();
    std::os::unix::fs::symlink(&library, fd_root.join("3")).unwrap();
    std::os::unix::fs::symlink(&private, fd_root.join("4")).unwrap();
    let policy = FileSystemSandboxPolicy::restricted(vec![FileSystemSandboxEntry::new(
        AbsolutePathBuf::try_from(library).unwrap().into(),
        FileSystemAccessMode::Read,
    )]);
    let engine = PolicyEngine::new(policy, root, &proc_root, 4242).for_tracee(4243);

    for (fd, tracee, allowed) in [(3, 4243, true), (4, 4243, false), (3, 4242, false)] {
        let link = fd_root.join(fd.to_string());
        let target =
            super::super::resolve::readlink_policy_target(&link, &proc_root, tracee).unwrap();
        assert_eq!(engine.check(&target, Access::Read).is_ok(), allowed);
        assert!(engine.check(&target, Access::Write).is_err());
    }
}

#[test]
fn android_minimal_allows_platform_reads_and_workspace_writes_only() {
    let engine = android_minimal_engine(vec![]);
    for (path, access, allowed) in [
        ("/system/bin/sh", Access::Read, true),
        (
            "/apex/com.android.runtime/lib64/bionic/libc.so",
            Access::Read,
            true,
        ),
        ("/linkerconfig/ld.config.txt", Access::Read, true),
        ("/dev/__properties__/properties_serial", Access::Read, true),
        ("/system/bin/sh", Access::Write, false),
        ("/private/workspace/new-file", Access::WriteOpen, true),
        ("/private/home/fixture", Access::Read, false),
        ("/private/codex-home/fixture", Access::Read, false),
        ("/data/app/pkg/lib/libnode.so", Access::Read, false),
        ("/data/user/0/other/files/fixture", Access::Write, false),
        ("/dev/null", Access::WriteOpen, true),
        ("/dev/null", Access::WriteName, false),
        ("/dev/new-device", Access::WriteOpen, false),
        ("/dev/urandom", Access::WriteOpen, false),
    ] {
        assert_eq!(
            engine.check(Path::new(path), access).is_ok(),
            allowed,
            "{path}"
        );
    }
}

#[test]
fn packaged_alias_target_needs_its_exact_native_payload_grant() {
    let native = AbsolutePathBuf::try_from("/data/app/pkg/lib").unwrap();
    let engine = android_minimal_engine(vec![FileSystemSandboxEntry::new(
        native.into(),
        FileSystemAccessMode::Read,
    )]);
    for (path, access, allowed) in [
        ("/data/app/pkg/lib/libnode.so", Access::Read, true),
        ("/data/app/pkg/lib/libnode.so", Access::Write, false),
        ("/data/app/other/lib/libnode.so", Access::Read, false),
    ] {
        assert_eq!(
            engine.check(Path::new(path), access).is_ok(),
            allowed,
            "{path}"
        );
    }
}

#[test]
fn minimal_tracee_metadata_never_grants_parent_process_or_environment() {
    let engine = android_minimal_engine(vec![]).for_tracee(4243);
    for (path, access, allowed) in [
        ("/proc/4243/exe", Access::Read, true),
        ("/proc/4243/cmdline", Access::Read, true),
        ("/proc/4243/maps", Access::Read, true),
        ("/proc/4243/status", Access::Read, true),
        ("/proc/4242/cmdline", Access::Read, false),
        ("/proc/4244/cmdline", Access::Read, false),
        ("/proc/4243/maps", Access::Write, false),
        ("/proc/4243/mem", Access::Read, false),
        ("/proc/4243/environ", Access::Read, false),
        ("/proc/4243/root", Access::Read, false),
        ("/proc/4243/fd/4", Access::Read, false),
    ] {
        assert_eq!(
            engine.check(Path::new(path), access).is_ok(),
            allowed,
            "{path}"
        );
    }
}

#[test]
fn explicit_denials_still_apply_to_android_platform_defaults() {
    let entries = ["/system/bin", "/dev/null", "/proc/4243/maps"]
        .into_iter()
        .map(|path| {
            FileSystemSandboxEntry::new(
                AbsolutePathBuf::try_from(path).unwrap().into(),
                FileSystemAccessMode::Deny,
            )
        })
        .collect();
    let engine = android_minimal_engine(entries).for_tracee(4243);
    for (path, access, allowed) in [
        ("/system/bin/sh", Access::Read, false),
        ("/dev/null", Access::WriteOpen, false),
        ("/proc/4243/maps", Access::Read, false),
        ("/system/etc/hosts", Access::Read, true),
    ] {
        assert_eq!(
            engine.check(Path::new(path), access).is_ok(),
            allowed,
            "{path}"
        );
    }
}
