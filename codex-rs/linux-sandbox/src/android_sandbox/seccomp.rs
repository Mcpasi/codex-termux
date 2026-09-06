//! The seccomp layer of the Android sandbox.
//!
//! Three filters are stacked on the sandboxed child. The kernel evaluates every
//! installed filter and takes the most restrictive result, so stacking is how a
//! single process gets different actions for different syscalls:
//!
//! 1. **Deny filter** (`EPERM`) — the network policy plus the syscalls that
//!    would let a process step around a ptrace supervisor entirely: `io_uring`
//!    (its submission queue performs file I/O without ever issuing a syscall),
//!    `userfaultfd` (lets a task stall a page fault and win path races),
//!    `ptrace`/`process_vm_*`, and every namespace/mount call.
//! 2. **`clone3` filter** (`ENOSYS`) — `clone3` takes its flags in a struct, so
//!    seccomp cannot inspect them. Reporting `ENOSYS` makes libc fall back to
//!    `clone`, whose flags *are* filterable.
//! 3. **Trace filter** (`SECCOMP_RET_TRACE`) — the path-carrying syscalls, which
//!    stop in the supervisor for a policy decision.
//!
//! Everything here relies only on `CONFIG_SECCOMP_FILTER`, which is mandatory
//! on every Android kernel (CTS requirement since Android 8.0), so unlike
//! Landlock there is no device where this layer silently does nothing.
//!
//! Note that `seccompiler` emits an architecture check in front of every
//! program that kills the process on a mismatch. That closes the classic
//! escape of issuing syscalls through a foreign ABI (a 32-bit ARM binary on an
//! arm64 kernel uses a different syscall table): such a process is killed
//! rather than let through unfiltered.

use std::collections::BTreeMap;

use seccompiler::BpfProgram;
use seccompiler::SeccompAction;
use seccompiler::SeccompCmpArgLen;
use seccompiler::SeccompCmpOp;
use seccompiler::SeccompCondition;
use seccompiler::SeccompFilter;
use seccompiler::SeccompRule;
use seccompiler::TargetArch;
use seccompiler::apply_filter;

use super::error::Result;
use super::error::SandboxError;
use super::syscalls;

type Rules = BTreeMap<i64, Vec<SeccompRule>>;

/// How the network policy is expressed in the deny filter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NetworkMode {
    /// The command may use the network; only the hardening deny-list applies.
    Allowed,
    /// Outbound and inbound sockets are refused; `AF_UNIX` stays available so
    /// tooling that uses `socketpair` for its own subprocesses keeps working.
    Denied,
}

fn target_arch() -> Result<TargetArch> {
    if cfg!(target_arch = "x86_64") {
        Ok(TargetArch::x86_64)
    } else if cfg!(target_arch = "aarch64") {
        Ok(TargetArch::aarch64)
    } else {
        Err(SandboxError::UnsupportedArchitecture)
    }
}

fn deny(rules: &mut Rules, nr: i64) {
    // An empty rule vector matches the syscall unconditionally.
    rules.insert(nr, Vec::new());
}

/// Syscalls that would let a sandboxed process get out from under the
/// supervisor, regardless of the filesystem policy in effect.
///
/// The supervisor reuses this list directly when it has to enforce the
/// deny-list itself (see [`super::supervisor`]), so the two paths cannot drift
/// apart.
pub(crate) fn escape_denied_syscalls() -> Vec<i64> {
    vec![
        // Bypasses ptrace interception: io_uring performs file I/O from a
        // kernel worker after a single setup syscall.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
        // Lets a task control when a page fault completes, which is the
        // standard way to widen a check-then-use race to an arbitrary window.
        libc::SYS_userfaultfd,
        // Reading or writing another process's memory, or attaching to it.
        libc::SYS_ptrace,
        libc::SYS_process_vm_readv,
        libc::SYS_process_vm_writev,
        // Re-rooting or re-mounting the filesystem would invalidate every path
        // the supervisor resolved.
        libc::SYS_mount,
        libc::SYS_umount2,
        libc::SYS_pivot_root,
        libc::SYS_chroot,
        libc::SYS_unshare,
        libc::SYS_setns,
        libc::SYS_mount_setattr,
        libc::SYS_open_tree,
        libc::SYS_move_mount,
        libc::SYS_fsopen,
        libc::SYS_fsconfig,
        libc::SYS_fsmount,
        libc::SYS_fspick,
        // Opening a file by handle skips path resolution entirely.
        libc::SYS_name_to_handle_at,
        libc::SYS_open_by_handle_at,
        // System-wide side effects that are never part of a sandboxed command.
        libc::SYS_swapon,
        libc::SYS_swapoff,
        libc::SYS_acct,
        libc::SYS_bpf,
        libc::SYS_init_module,
        libc::SYS_finit_module,
        libc::SYS_delete_module,
        libc::SYS_kexec_load,
    ]
}

/// Socket syscalls refused when the network policy is restricted.
///
/// `socket` and `socketpair` are deliberately absent: they are allowed for
/// `AF_UNIX` and handled by an argument-conditional rule, because tooling such
/// as `cargo clippy` uses `socketpair` to manage its own subprocesses.
pub(crate) fn network_denied_syscalls() -> Vec<i64> {
    vec![
        libc::SYS_connect,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_getpeername,
        libc::SYS_getsockname,
        libc::SYS_shutdown,
        libc::SYS_sendto,
        libc::SYS_sendmmsg,
        // `recvfrom` stays allowed for the same `socketpair` reason.
        libc::SYS_recvmmsg,
        libc::SYS_getsockopt,
        libc::SYS_setsockopt,
    ]
}

fn network_deny_rules(rules: &mut Rules) -> Result<()> {
    for nr in network_denied_syscalls() {
        deny(rules, nr);
    }

    let unix_only = SeccompRule::new(vec![SeccompCondition::new(
        0, // domain
        SeccompCmpArgLen::Dword,
        SeccompCmpOp::Ne,
        libc::AF_UNIX as u64,
    )?])?;
    rules.insert(libc::SYS_socket, vec![unix_only.clone()]);
    rules.insert(libc::SYS_socketpair, vec![unix_only]);
    Ok(())
}

/// Builds the `EPERM` deny filter.
pub(crate) fn build_deny_filter(network: NetworkMode) -> Result<BpfProgram> {
    let mut rules = Rules::new();
    for nr in escape_denied_syscalls() {
        deny(&mut rules, nr);
    }
    if network == NetworkMode::Denied {
        network_deny_rules(&mut rules)?;
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::EPERM as u32),
        target_arch()?,
    )?;
    Ok(filter.try_into()?)
}

/// Builds the `clone3` filter, which reports `ENOSYS` so libc retries with
/// `clone`.
pub(crate) fn build_clone3_filter() -> Result<BpfProgram> {
    let mut rules = Rules::new();
    deny(&mut rules, libc::SYS_clone3);

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
        target_arch()?,
    )?;
    Ok(filter.try_into()?)
}

/// Builds the filter that routes path-carrying syscalls to the supervisor.
///
/// When the policy leaves reads unrestricted, read-only `open` calls are left
/// running at full speed: seccomp can inspect the flags argument directly, and
/// a read-only open could only ever be allowed. `stat`, `access`, `readlink`
/// and the other pure read probes are omitted from the filter for the same
/// reason (see [`syscalls::intercepted_syscalls`]).
pub(crate) fn build_trace_filter(reads_restricted: bool) -> Result<BpfProgram> {
    let mut rules = Rules::new();
    for nr in syscalls::intercepted_syscalls(reads_restricted) {
        match open_flags_argument(nr) {
            Some(flags_arg) if !reads_restricted => {
                rules.insert(nr, write_intent_rules(flags_arg)?);
            }
            _ => deny(&mut rules, nr),
        }
    }

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Allow,
        SeccompAction::Trace(0),
        target_arch()?,
    )?;
    Ok(filter.try_into()?)
}

/// The argument index holding `open` flags, for the syscalls whose flags
/// seccomp can inspect. `openat2` keeps its flags behind a pointer, so it is
/// deliberately absent and always traced.
fn open_flags_argument(nr: i64) -> Option<usize> {
    if nr == libc::SYS_openat {
        return Some(2);
    }
    #[cfg(target_arch = "x86_64")]
    if nr == libc::SYS_open {
        return Some(1);
    }
    None
}

/// One rule per write-intent bit; seccomp ORs the rules for a syscall, so the
/// syscall is traced when any of them is set.
fn write_intent_rules(flags_arg: usize) -> Result<Vec<SeccompRule>> {
    let mut rules = Vec::with_capacity(syscalls::OPEN_WRITE_INTENT_BITS.len());
    for bit in syscalls::OPEN_WRITE_INTENT_BITS {
        let bit = *bit as u64;
        rules.push(SeccompRule::new(vec![SeccompCondition::new(
            flags_arg as u8,
            SeccompCmpArgLen::Dword,
            SeccompCmpOp::MaskedEq(bit),
            bit,
        )?])?);
    }
    Ok(rules)
}

/// Installs the two `errno` filters.
///
/// Split out from [`install_all`] because the full-syscall-tracing fallback
/// still wants them when it cannot use `SECCOMP_RET_TRACE`.
pub(crate) fn install_deny_filters(network: NetworkMode) -> Result<()> {
    apply_filter(&build_deny_filter(network)?)?;
    apply_filter(&build_clone3_filter()?)?;
    Ok(())
}

/// Installs all three filters on the current thread.
///
/// Order matters only for readability: the kernel combines installed filters by
/// taking the most restrictive action, so a syscall covered by both the deny
/// filter and the trace filter is denied.
pub(crate) fn install_all(network: NetworkMode, reads_restricted: bool) -> Result<()> {
    install_deny_filters(network)?;
    apply_filter(&build_trace_filter(reads_restricted)?)?;
    Ok(())
}

#[cfg(test)]
#[path = "seccomp_tests.rs"]
mod tests;
