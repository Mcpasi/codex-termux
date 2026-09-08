use super::*;
use pretty_assertions::assert_eq;
use seccompiler::SeccompAction;
use seccompiler::SeccompFilter;
use seccompiler::TargetArch;
use std::collections::BTreeMap;

fn forbid_syscall(nr: i64, action: SeccompAction) {
    let arch = if cfg!(target_arch = "aarch64") {
        TargetArch::aarch64
    } else {
        TargetArch::x86_64
    };
    let filter = SeccompFilter::new(
        BTreeMap::from([(nr, Vec::new())]),
        SeccompAction::Allow,
        action,
        arch,
    )
    .unwrap();
    let program: seccompiler::BpfProgram = filter.try_into().unwrap();
    seccompiler::apply_filter(&program).unwrap();
}

#[test]
fn only_a_successful_probe_reports_support() {
    assert!(probe(|| true));
    assert!(!probe(|| false));
    assert!(!probe(|| unsafe { libc::_exit(17) }));
    assert!(!probe(|| unsafe {
        libc::raise(libc::SIGSYS);
        true
    }));
    assert!(!probe(|| unsafe {
        libc::raise(libc::SIGKILL);
        true
    }));
}

#[test]
fn a_stopped_probe_is_killed_at_the_deadline() {
    assert!(!probe(|| unsafe {
        libc::raise(libc::SIGSTOP);
        true
    }));
}

#[test]
fn inherited_trap_and_kill_rules_cannot_kill_the_launcher() {
    for nr in [
        libc::SYS_landlock_create_ruleset,
        libc::SYS_landlock_add_rule,
        libc::SYS_landlock_restrict_self,
    ] {
        for action in [SeccompAction::Trap, SeccompAction::KillProcess] {
            // The outer child inherits a simulated vendor policy. Only its
            // disposable inner probe may encounter the forbidden syscall.
            assert!(probe(|| {
                forbid_syscall(nr, action);
                !probe(|| unsafe {
                    libc::syscall(nr, -1, std::ptr::null::<libc::c_void>(), 0);
                    true
                })
            }));
        }
    }
}

#[test]
fn unavailable_landlock_never_runs_in_the_launcher() {
    for action in [
        SeccompAction::Trap,
        SeccompAction::KillProcess,
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Errno(libc::EOPNOTSUPP as u32),
        SeccompAction::Errno(libc::EPERM as u32),
    ] {
        assert!(probe(|| {
            forbid_syscall(libc::SYS_landlock_create_ruleset, action);
            !is_supported(&[])
        }));
    }
}

#[test]
fn successful_installation_does_not_restrict_the_launcher() {
    // Ruleset installation sets this irreversible flag in the probe. A
    // successful result must leave the calling process's privileges unchanged.
    let directory = tempfile::tempdir().unwrap();
    let before = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    let _supported = is_supported(&[]);
    let after = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    assert_eq!(before, after);
    std::fs::write(directory.path().join("launcher-write"), "probe fixture")
        .expect("the disposable ruleset must not restrict the launcher");
}
