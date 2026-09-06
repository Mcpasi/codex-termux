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
    assert!(engine.check(Path::new("/etc/passwd"), Access::Read).is_err());
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
