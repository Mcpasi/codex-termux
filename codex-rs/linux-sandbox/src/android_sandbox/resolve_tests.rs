use super::*;
use pretty_assertions::assert_eq;
use std::fs;

fn temp_dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

#[test]
fn anonymous_tracee_fd_links_remain_kernel_links_instead_of_fake_filenames() {
    let dir = temp_dir();
    let root = fs::canonicalize(dir.path()).unwrap();
    let proc_root = root.join("proc");
    let fd_root = proc_root.join("4243/fd");
    fs::create_dir_all(&fd_root).unwrap();
    std::os::unix::fs::symlink("pipe:[1234]", fd_root.join("7")).unwrap();
    let path = resolve_path(
        &root,
        &proc_root.join("self/fd/7"),
        &proc_root,
        4243,
        FinalComponent::Follow,
    );
    assert_eq!(path, fd_root.join("7"));
    assert_eq!(tracee_fd(&path, &proc_root, 4243), Some(7));
    assert_eq!(
        descriptor_target(&proc_root, 4243, 7).unwrap(),
        DescriptorTarget::NotAFile
    );
    assert_eq!(tracee_fd(&path, &proc_root, 4242), None);
    assert_eq!(tracee_fd(&fd_root.join("7/child"), &proc_root, 4243), None);
    assert_eq!(tracee_fd(&fd_root.join("-1"), &proc_root, 4243), None);
    assert_eq!(
        tracee_fd(&fd_root.join("999999999999999999"), &proc_root, 4243),
        None
    );
}

#[test]
fn regular_tracee_fd_links_still_resolve_to_the_real_file_for_policy_checks() {
    let dir = temp_dir();
    let root = fs::canonicalize(dir.path()).unwrap();
    let proc_root = root.join("proc");
    let fd_root = proc_root.join("4243/fd");
    fs::create_dir_all(&fd_root).unwrap();
    let private = root.join("synthetic-private-file");
    fs::write(&private, b"fixture").unwrap();
    std::os::unix::fs::symlink(&private, fd_root.join("7")).unwrap();
    assert_eq!(
        resolve_path(
            &root,
            &proc_root.join("self/fd/7"),
            &proc_root,
            4243,
            FinalComponent::Follow
        ),
        private
    );
}

#[test]
fn linker_readlink_checks_the_opened_file_without_rewriting_the_link_to_a_file() {
    let dir = temp_dir();
    let root = fs::canonicalize(dir.path()).unwrap();
    let proc_root = root.join("proc");
    let fd_root = proc_root.join("4243/fd");
    fs::create_dir_all(&fd_root).unwrap();
    let library = root.join("native-library.so");
    fs::write(&library, b"synthetic-library").unwrap();
    let link = fd_root.join("3");
    std::os::unix::fs::symlink(&library, &link).unwrap();
    let argument = resolve_path(
        &root,
        &proc_root.join("self/fd/3"),
        &proc_root,
        4243,
        FinalComponent::Keep,
    );
    assert_eq!(argument, link);
    assert_eq!(
        readlink_policy_target(&argument, &proc_root, 4243).unwrap(),
        library
    );
    assert_eq!(
        readlink_policy_target(&argument, &proc_root, 4242).unwrap(),
        link
    );

    // An inherited private fd is judged against its actual private target,
    // never against the allowed native-library root or the tracee's own pid.
    let private = root.join("private-sibling");
    fs::write(&private, b"synthetic-private").unwrap();
    std::os::unix::fs::symlink(&private, fd_root.join("4")).unwrap();
    assert_eq!(
        readlink_policy_target(&fd_root.join("4"), &proc_root, 4243).unwrap(),
        private
    );
    assert!(readlink_policy_target(&fd_root.join("99"), &proc_root, 4243).is_err());
}

/// `canonicalize` on the whole path fails for a file that is about to be
/// created, which is exactly the case a creation check has to answer.
#[test]
fn a_path_that_does_not_exist_yet_resolves_through_its_parent() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");

    let resolved = canonicalize_best_effort(&real.join("new-file.txt"));

    assert_eq!(resolved, real.join("new-file.txt"));
}

#[test]
fn dot_dot_in_a_non_existent_tail_is_collapsed() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");

    let resolved = canonicalize_best_effort(&real.join("a/b/../c"));

    assert_eq!(resolved, real.join("a/c"));
}

/// The point of resolving through the kernel: a symlink out of the workspace
/// has to be visible to the policy as the path it actually reaches.
#[test]
fn following_a_symlink_yields_the_target() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");
    let target = real.join("target");
    fs::write(&target, b"x").expect("write target");
    std::os::unix::fs::symlink(&target, real.join("link")).expect("symlink");

    let followed = resolve_path(
        &real,
        Path::new("link"),
        Path::new("/proc"),
        1,
        FinalComponent::Follow,
    );
    assert_eq!(followed, target);
}

/// `unlink`, `lstat` and friends act on the link itself, so the final component
/// must survive resolution.
#[test]
fn keeping_the_final_component_leaves_the_symlink_in_place() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");
    let target = real.join("target");
    fs::write(&target, b"x").expect("write target");
    std::os::unix::fs::symlink(&target, real.join("link")).expect("symlink");

    let kept = resolve_path(
        &real,
        Path::new("link"),
        Path::new("/proc"),
        1,
        FinalComponent::Keep,
    );
    assert_eq!(kept, real.join("link"));
}

/// The escape this guards against: `open("link", O_CREAT|O_WRONLY)` where
/// `link` points somewhere that does not exist yet. Resolving only the parent
/// would judge the link's own path, while the kernel would create the file at
/// the target.
#[test]
fn a_dangling_symlink_resolves_to_its_target() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");
    std::os::unix::fs::symlink("/etc/does-not-exist-yet", real.join("dangling")).expect("symlink");

    let followed = resolve_path(
        &real,
        Path::new("dangling"),
        Path::new("/proc"),
        1,
        FinalComponent::Follow,
    );

    assert_eq!(followed, Path::new("/etc/does-not-exist-yet"));
}

/// Chained links have to be walked to the end, but not forever.
#[test]
fn a_symlink_loop_terminates() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");
    std::os::unix::fs::symlink(real.join("b"), real.join("a")).expect("symlink a");
    std::os::unix::fs::symlink(real.join("a"), real.join("b")).expect("symlink b");

    let followed = resolve_path(
        &real,
        Path::new("a"),
        Path::new("/proc"),
        1,
        FinalComponent::Follow,
    );

    assert!(followed.starts_with(&real), "{followed:?}");
}

/// A symlinked *directory* on the way to the target is still resolved, even in
/// `Keep` mode: only the last component is exempt.
#[test]
fn intermediate_symlinks_are_resolved_in_keep_mode() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");
    fs::create_dir(real.join("actual")).expect("create dir");
    std::os::unix::fs::symlink(real.join("actual"), real.join("alias")).expect("symlink");

    let kept = resolve_path(
        &real,
        Path::new("alias/file"),
        Path::new("/proc"),
        1,
        FinalComponent::Keep,
    );
    assert_eq!(kept, real.join("actual/file"));
}

#[test]
fn absolute_paths_ignore_the_base_directory() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");

    let resolved = resolve_path(
        &real,
        Path::new("/definitely/not/here"),
        Path::new("/proc"),
        1,
        FinalComponent::Follow,
    );

    assert_eq!(resolved, Path::new("/definitely/not/here"));
}

#[test]
fn an_empty_path_means_the_base_descriptor() {
    let dir = temp_dir();
    let real = fs::canonicalize(dir.path()).expect("canonical dir");

    let resolved = resolve_path(
        &real,
        Path::new(""),
        Path::new("/proc"),
        1,
        FinalComponent::Follow,
    );

    assert_eq!(resolved, real);
}

/// Without this rebinding the supervisor would canonicalize `/proc/self`
/// against *its own* process and validate a completely different file.
#[test]
fn proc_self_is_rebound_to_the_tracee() {
    assert_eq!(
        rebind_proc_self(Path::new("/proc/self/fd/3"), Path::new("/proc"), 4242),
        Path::new("/proc/4242/fd/3")
    );
    assert_eq!(
        rebind_proc_self(Path::new("/proc/thread-self/cwd"), Path::new("/proc"), 7),
        Path::new("/proc/7/cwd")
    );
}

#[test]
fn proc_self_is_rebound_through_dot_dot_segments() {
    assert_eq!(
        rebind_proc_self(Path::new("/proc/1/../self/mem"), Path::new("/proc"), 9),
        Path::new("/proc/9/mem")
    );
}

#[test]
fn paths_outside_proc_are_left_alone() {
    for path in ["/tmp/self/fd/3", "/proc/1/fd/3", "/procself/fd/3"] {
        assert_eq!(
            rebind_proc_self(Path::new(path), Path::new("/proc"), 9),
            Path::new(path),
            "{path} should not be rewritten"
        );
    }
}

#[test]
fn descriptor_targets_distinguish_files_from_sockets() {
    assert_eq!(
        classify_descriptor_target(Path::new("socket:[12345]")),
        DescriptorTarget::NotAFile
    );
    assert_eq!(
        classify_descriptor_target(Path::new("anon_inode:[eventfd]")),
        DescriptorTarget::NotAFile
    );
    assert_eq!(
        classify_descriptor_target(Path::new("/home/user/file")),
        DescriptorTarget::Path(PathBuf::from("/home/user/file"))
    );
}

/// An unlinked-but-open file still has to be judged against the directory it
/// came from, so the kernel's " (deleted)" marker is stripped.
#[test]
fn deleted_descriptor_targets_keep_their_path() {
    assert_eq!(
        classify_descriptor_target(Path::new("/tmp/gone (deleted)")),
        DescriptorTarget::Path(PathBuf::from("/tmp/gone"))
    );
}

#[test]
fn lexical_normalization_collapses_dots() {
    assert_eq!(
        lexically_normalize(Path::new("/a/./b/../c/")),
        PathBuf::from("/a/c")
    );
}
