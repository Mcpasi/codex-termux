//! The ptrace supervisor: the component that actually enforces the filesystem
//! boundary on Android.
//!
//! # Why not Landlock
//!
//! Landlock is a kernel LSM that has to be compiled into the running kernel.
//! Android does not require it, so on a large share of devices
//! `landlock_restrict_self` reports "not enforced" and the filesystem boundary
//! simply does not exist. A sandbox that depends on it is therefore not a
//! sandbox you can promise on arbitrary hardware.
//!
//! # What this uses instead
//!
//! `ptrace` plus `seccomp`, both of which are mandatory kernel features on
//! every Android device (`CONFIG_SECCOMP_FILTER` is a CTS requirement, and
//! `ptrace` of one's own descendants is what every in-process crash handler on
//! the platform relies on). The sandboxed command runs as a traced child; every
//! syscall that names a path stops in this supervisor, which resolves the path
//! exactly as the kernel would and answers it from the session's
//! [`FileSystemSandboxPolicy`]. Refused syscalls are cancelled before the
//! kernel executes them and return `EACCES`.
//!
//! Two interception modes exist so there is no device shape left without
//! enforcement:
//!
//! * **Seccomp-directed** (the normal path): a `SECCOMP_RET_TRACE` filter stops
//!   only the syscalls that matter, so ordinary reads and computation run at
//!   full speed.
//! * **Full syscall tracing** (fallback): if the kernel does not support
//!   `PTRACE_O_TRACESECCOMP`, every syscall stops instead, and the supervisor
//!   additionally applies the network and escape deny-lists itself. Slower, but
//!   it needs nothing beyond plain `ptrace`.
//!
//! Landlock is still applied on top when the kernel offers it. It is a bonus
//! layer, never the mechanism being relied on.
//!
//! # Known limitation
//!
//! A check-then-use race remains for a *multi-threaded* tracee: a sibling
//! thread could rewrite a path buffer between the check and the kernel's own
//! resolution. The supervisor narrows this as far as a ptrace design can, by
//! rewriting the validated, fully canonical path into per-thread scratch space
//! below the stopped thread's stack pointer, so what the kernel resolves is the
//! string that was approved rather than the one the tracee supplied. Closing
//! the window completely would require the kernel to do the path resolution and
//! the check together, which is exactly what an LSM does and what is not
//! available here. `userfaultfd`, the reliable way to widen such a race, is
//! denied outright by the seccomp layer.

use std::collections::HashMap;
use std::collections::HashSet;
use std::ffi::CString;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicI32;
use std::sync::atomic::Ordering;

use super::arch;
use super::arch::Regs;
use super::decision::Access;
use super::decision::PolicyEngine;
use super::error::Result;
use super::error::SandboxError;
use super::mem::TraceeMemory;
use super::resolve;
use super::resolve::DescriptorTarget;
use super::resolve::FinalComponent;
use super::seccomp;
use super::seccomp::NetworkMode;
use super::syscalls;
use super::syscalls::Base;
use super::syscalls::Follow;
use super::syscalls::Need;
use super::syscalls::PathArg;

const PTRACE_O_TRACESYSGOOD: libc::c_int = 0x0000_0001;
const PTRACE_O_TRACEFORK: libc::c_int = 0x0000_0002;
const PTRACE_O_TRACEVFORK: libc::c_int = 0x0000_0004;
const PTRACE_O_TRACECLONE: libc::c_int = 0x0000_0008;
const PTRACE_O_TRACEEXEC: libc::c_int = 0x0000_0010;
const PTRACE_O_TRACESECCOMP: libc::c_int = 0x0000_0080;
/// Kills every tracee if the supervisor dies. Without it, losing the supervisor
/// would release the sandboxed command to run unrestricted.
const PTRACE_O_EXITKILL: libc::c_int = 0x0010_0000;

const PTRACE_EVENT_EXEC: libc::c_int = 4;
const PTRACE_EVENT_SECCOMP: libc::c_int = 7;

/// `SIGTRAP | 0x80`, how syscall stops are reported once `TRACESYSGOOD` is set.
const SYSCALL_TRAP: libc::c_int = libc::SIGTRAP | 0x80;

/// Exit status used when the sandbox itself could not be established.
pub(crate) const SANDBOX_SETUP_FAILURE_EXIT_CODE: i32 = 9;

/// Upper bound on denial messages written to stderr, so a command that loops on
/// a denied path cannot flood the transcript.
const MAX_REPORTED_DENIALS: usize = 32;

/// How the supervisor learns about syscalls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InterceptMode {
    /// Only the syscalls selected by the `SECCOMP_RET_TRACE` filter stop.
    SeccompDirected,
    /// Every syscall stops; the supervisor also enforces the deny-lists that
    /// seccomp would normally handle.
    AllSyscalls,
}

/// Byte handed to the child so it knows whether to install the trace filter.
const MODE_SECCOMP: u8 = 0;
const MODE_ALL_SYSCALLS: u8 = 1;

/// Set before the supervisor loop starts so the signal handler can forward to
/// the sandboxed process.
static SANDBOXED_PID: AtomicI32 = AtomicI32::new(0);

pub(crate) struct SupervisorConfig {
    pub(crate) policy: PolicyEngine,
    pub(crate) network: NetworkMode,
    pub(crate) proc_root: PathBuf,
    /// Writable roots for the best-effort Landlock layer, already resolved
    /// against the policy cwd. Empty when Landlock cannot express the policy.
    pub(crate) landlock_writable_roots: Option<Vec<codex_utils_absolute_path::AbsolutePathBuf>>,
}

/// Per-tracee bookkeeping.
struct Tracee {
    /// Errno to install at the next syscall-exit stop, set when the entry stop
    /// cancelled the syscall.
    pending_errno: Option<i32>,
    /// Only meaningful in [`InterceptMode::AllSyscalls`], where entry and exit
    /// stops look identical and have to be counted.
    inside_syscall: bool,
    memory: Option<TraceeMemory>,
}

impl Tracee {
    fn new() -> Self {
        Self {
            pending_errno: None,
            inside_syscall: false,
            memory: None,
        }
    }
}

/// Runs `command` under the sandbox and exits with its status. Never returns.
pub(crate) fn run(config: SupervisorConfig, command: Vec<String>) -> ! {
    match supervise(config, command) {
        Ok(status) => exit_like(status),
        Err(err) => {
            eprintln!("codex-linux-sandbox: {err}");
            std::process::exit(SANDBOX_SETUP_FAILURE_EXIT_CODE);
        }
    }
}

/// How the sandboxed process finished.
enum ChildStatus {
    Exited(i32),
    Signalled(i32),
}

fn exit_like(status: ChildStatus) -> ! {
    match status {
        ChildStatus::Exited(code) => std::process::exit(code),
        ChildStatus::Signalled(signal) => {
            // Re-raise so the caller observes the same "killed by signal"
            // result it would have seen from an exec'd command.
            // SAFETY: restoring the default disposition and re-raising is the
            // documented way to propagate a signal death.
            unsafe {
                libc::signal(signal, libc::SIG_DFL);
                libc::raise(signal);
            }
            std::process::exit(128 + signal);
        }
    }
}

fn supervise(config: SupervisorConfig, command: Vec<String>) -> Result<ChildStatus> {
    if !arch::supported() {
        return Err(SandboxError::UnsupportedArchitecture);
    }

    let argv = to_cstrings(&command)?;

    // Child -> parent: setup failures. The write end is close-on-exec, so a
    // successful `execvp` closes it and the parent reads EOF.
    let mut status_pipe = Pipe::new()?;
    // Parent -> child: the interception mode, decided once the parent knows
    // whether the kernel supports `PTRACE_O_TRACESECCOMP`.
    let mut mode_pipe = Pipe::new()?;

    // SAFETY: the child branch below only calls async-signal-safe functions
    // before `execvp`.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(SandboxError::Io(io::Error::last_os_error())),
        0 => {
            // Child.
            status_pipe.close_read();
            mode_pipe.close_write();
            run_child(&config, &argv, &status_pipe, &mode_pipe)
        }
        pid => {
            status_pipe.close_write();
            mode_pipe.close_read();
            run_supervisor(config, pid, status_pipe, mode_pipe)
        }
    }
}

fn to_cstrings(command: &[String]) -> Result<Vec<CString>> {
    command
        .iter()
        .map(|arg| {
            CString::new(arg.as_str()).map_err(|_| {
                SandboxError::Other("command arguments must not contain NUL bytes".to_string())
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Child
// ---------------------------------------------------------------------------

/// Sets up the sandbox on the child side, then execs. Never returns.
fn run_child(
    config: &SupervisorConfig,
    argv: &[CString],
    status_pipe: &Pipe,
    mode_pipe: &Pipe,
) -> ! {
    if let Err(err) = prepare_child(config, mode_pipe) {
        status_pipe.report(&err.to_string());
        // SAFETY: `_exit` skips atexit handlers, which is what a failed fork
        // child must do.
        unsafe { libc::_exit(SANDBOX_SETUP_FAILURE_EXIT_CODE) }
    }

    let mut pointers: Vec<*const libc::c_char> = argv.iter().map(|arg| arg.as_ptr()).collect();
    pointers.push(std::ptr::null());
    // SAFETY: `argv` owns the strings and outlives this call; the array is
    // NULL-terminated.
    unsafe {
        libc::execvp(argv[0].as_ptr(), pointers.as_ptr());
    }

    let err = io::Error::last_os_error();
    status_pipe.report(&format!(
        "failed to execute {}: {err}",
        argv[0].to_string_lossy()
    ));
    // SAFETY: see above.
    unsafe { libc::_exit(127) }
}

fn prepare_child(config: &SupervisorConfig, mode_pipe: &Pipe) -> Result<()> {
    // Ask to be traced *before* anything else, so the parent can attach
    // options while this process is still stopped and has not yet run any of
    // the command's code.
    // SAFETY: `PTRACE_TRACEME` takes no arguments.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_TRACEME,
            0,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        )
    };
    super::error::ptrace_result("PTRACE_TRACEME", ret)?;

    // Stop so the parent can install its ptrace options. The parent replies
    // with the interception mode it managed to establish.
    // SAFETY: raising a signal on self.
    unsafe {
        libc::raise(libc::SIGSTOP);
    }
    let mode = mode_pipe.read_byte()?;

    set_no_new_privs()?;

    // Best effort only: this is the layer that is absent on many devices, and
    // the whole point of the supervisor is that nothing depends on it.
    if let Some(roots) = &config.landlock_writable_roots {
        super::landlock_layer::apply_best_effort(roots);
    }

    let reads_restricted = config.policy.reads_restricted();
    match mode {
        MODE_SECCOMP => seccomp::install_all(config.network, reads_restricted)?,
        _ => {
            // Without `SECCOMP_RET_TRACE` the errno filters may still work, and
            // they cost nothing to try. Whatever fails here is covered by the
            // supervisor's own deny-list in `InterceptMode::AllSyscalls`.
            let _ = seccomp::install_deny_filters(config.network);
        }
    }

    Ok(())
}

fn set_no_new_privs() -> Result<()> {
    // Required for seccomp, and it also stops a sandboxed command from gaining
    // privileges through a setuid binary.
    // SAFETY: `prctl` with `PR_SET_NO_NEW_PRIVS` takes only scalar arguments.
    let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if ret != 0 {
        return Err(SandboxError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Supervisor
// ---------------------------------------------------------------------------

fn run_supervisor(
    config: SupervisorConfig,
    child: libc::pid_t,
    status_pipe: Pipe,
    mode_pipe: Pipe,
) -> Result<ChildStatus> {
    // Wait for the child's initial `SIGSTOP`.
    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: waiting on our own child.
        let waited = unsafe { libc::waitpid(child, &mut status, libc::__WALL) };
        if waited == -1 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SandboxError::Io(err));
        }
        break;
    }

    if !libc::WIFSTOPPED(status) {
        // The child failed before it could stop; its message explains why.
        let message = status_pipe.read_message();
        return Err(SandboxError::Other(match message {
            Some(message) => message,
            None => "the sandboxed process exited before the sandbox was established".to_string(),
        }));
    }

    let common_options = PTRACE_O_TRACESYSGOOD
        | PTRACE_O_TRACEFORK
        | PTRACE_O_TRACEVFORK
        | PTRACE_O_TRACECLONE
        | PTRACE_O_TRACEEXEC
        | PTRACE_O_EXITKILL;

    let mode = match arch::ptrace_set_options(child, common_options | PTRACE_O_TRACESECCOMP) {
        Ok(()) => InterceptMode::SeccompDirected,
        Err(_) => {
            // No `SECCOMP_RET_TRACE` support on this kernel: fall back to
            // stopping on every syscall rather than giving up the boundary.
            arch::ptrace_set_options(child, common_options)?;
            InterceptMode::AllSyscalls
        }
    };

    mode_pipe.write_byte(match mode {
        InterceptMode::SeccompDirected => MODE_SECCOMP,
        InterceptMode::AllSyscalls => MODE_ALL_SYSCALLS,
    })?;
    drop(mode_pipe);

    SANDBOXED_PID.store(child, Ordering::SeqCst);
    install_signal_forwarding();

    let mut supervisor = Supervisor {
        config,
        mode,
        tracees: HashMap::new(),
        denied_syscalls: match mode {
            InterceptMode::SeccompDirected => HashSet::new(),
            InterceptMode::AllSyscalls => supervisor_enforced_denials(),
        },
        reported_denials: 0,
    };
    supervisor.tracees.insert(child, Tracee::new());
    supervisor.resume(child, 0)?;

    let result = supervisor.event_loop(child);

    // Surface a failed exec even though the child technically "ran".
    if let Ok(ChildStatus::Exited(code)) = &result
        && *code == 127
        && let Some(message) = status_pipe.read_message()
    {
        eprintln!("codex-linux-sandbox: {message}");
    }

    result
}

struct Supervisor {
    config: SupervisorConfig,
    mode: InterceptMode,
    tracees: HashMap<libc::pid_t, Tracee>,
    /// Syscalls the supervisor refuses itself, used when seccomp could not be
    /// directed at them.
    denied_syscalls: HashSet<i64>,
    reported_denials: usize,
}

impl Supervisor {
    fn event_loop(&mut self, child: libc::pid_t) -> Result<ChildStatus> {
        loop {
            let mut status: libc::c_int = 0;
            // SAFETY: waiting for any tracee, including cloned threads.
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::__WALL) };
            if pid == -1 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(SandboxError::Io(err));
            }

            if libc::WIFEXITED(status) {
                self.tracees.remove(&pid);
                if pid == child {
                    return Ok(ChildStatus::Exited(libc::WEXITSTATUS(status)));
                }
                continue;
            }
            if libc::WIFSIGNALED(status) {
                self.tracees.remove(&pid);
                if pid == child {
                    return Ok(ChildStatus::Signalled(libc::WTERMSIG(status)));
                }
                continue;
            }
            if !libc::WIFSTOPPED(status) {
                continue;
            }

            self.handle_stop(pid, status)?;
        }
    }

    fn handle_stop(&mut self, pid: libc::pid_t, status: libc::c_int) -> Result<()> {
        let signal = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xff;

        // A tracee created by `fork`/`clone` reports before we have ever seen
        // it. Its first stop is an artefact of attaching, never a real signal.
        if !self.tracees.contains_key(&pid) {
            self.tracees.insert(pid, Tracee::new());
            return self.resume(pid, 0);
        }

        if signal == libc::SIGTRAP && event == PTRACE_EVENT_SECCOMP {
            return self.on_syscall_entry(pid);
        }
        if signal == libc::SIGTRAP && event == PTRACE_EVENT_EXEC {
            // The address space is new, so the cached `/proc/<pid>/mem` handle
            // refers to an image that no longer exists.
            if let Some(tracee) = self.tracees.get_mut(&pid) {
                tracee.memory = None;
                tracee.inside_syscall = false;
                tracee.pending_errno = None;
            }
            return self.resume(pid, 0);
        }
        if signal == libc::SIGTRAP && event != 0 {
            // fork/vfork/clone/vfork-done/exit notifications.
            return self.resume(pid, 0);
        }
        if signal == SYSCALL_TRAP {
            return self.on_syscall_stop(pid);
        }

        // A real signal for the tracee; pass it through.
        self.resume(pid, signal)
    }

    /// A `SIGTRAP | 0x80` stop, which is either a syscall entry or the exit of
    /// a syscall we cancelled.
    fn on_syscall_stop(&mut self, pid: libc::pid_t) -> Result<()> {
        /// What this particular stop turned out to be.
        enum Stop {
            /// The exit of a syscall the policy refused.
            Cancelled(i32),
            /// A syscall entry that still needs a decision.
            Entering,
            /// Nothing to do; let the tracee carry on.
            Passthrough,
        }

        let all_syscalls = self.mode == InterceptMode::AllSyscalls;
        // Classify while only the tracee map is borrowed, so the handling below
        // is free to take `&mut self` again.
        let stop = match self.tracees.get_mut(&pid) {
            None => Stop::Passthrough,
            Some(tracee) => match tracee.pending_errno.take() {
                Some(errno) => {
                    tracee.inside_syscall = false;
                    Stop::Cancelled(errno)
                }
                // With seccomp directing the stops, only cancelled syscalls are
                // followed to their exit, and that case is handled above.
                None if !all_syscalls => Stop::Passthrough,
                // Without it, entry and exit stops are indistinguishable and
                // have to be counted.
                None => {
                    let entering = !tracee.inside_syscall;
                    tracee.inside_syscall = entering;
                    if entering {
                        Stop::Entering
                    } else {
                        Stop::Passthrough
                    }
                }
            },
        };

        match stop {
            Stop::Passthrough => self.resume(pid, 0),
            Stop::Cancelled(errno) => {
                // The kernel skipped the cancelled syscall and left `ENOSYS`
                // behind; replace it with the policy's answer.
                arch::set_syscall_error(pid, errno)?;
                self.resume(pid, 0)
            }
            Stop::Entering => self.on_syscall_entry(pid),
        }
    }

    fn on_syscall_entry(&mut self, pid: libc::pid_t) -> Result<()> {
        let mut regs = Regs::read(pid)?;
        let errno = match self.evaluate(pid, &mut regs) {
            Ok(None) => None,
            Ok(Some(errno)) => Some(errno),
            Err(err) => {
                // The supervisor could not establish what the syscall would
                // touch. Refusing is the only safe answer: allowing would mean
                // running an unchecked operation.
                self.report(&format!(
                    "refusing an unverifiable syscall from pid {pid}: {err}"
                ));
                Some(libc::EACCES)
            }
        };

        match errno {
            None => self.resume(pid, 0),
            Some(errno) => {
                arch::cancel_syscall(pid, &mut regs)?;
                if let Some(tracee) = self.tracees.get_mut(&pid) {
                    tracee.pending_errno = Some(errno);
                }
                self.resume_to_syscall(pid, 0)
            }
        }
    }

    /// Returns `Ok(None)` to allow the syscall, or `Ok(Some(errno))` to refuse
    /// it.
    fn evaluate(&mut self, pid: libc::pid_t, regs: &mut Regs) -> Result<Option<i32>> {
        let nr = regs.syscall_number();

        if self.denied_syscalls.contains(&nr) {
            return Ok(Some(libc::EPERM));
        }
        if self.mode == InterceptMode::AllSyscalls
            && let Some(errno) = self.socket_family_denial(nr, regs)
        {
            return Ok(Some(errno));
        }

        let Some(spec) = syscalls::lookup(nr) else {
            return Ok(None);
        };
        if spec.read_probe_only && !self.config.policy.reads_restricted() {
            return Ok(None);
        }

        let mut rewrites: Vec<(usize, PathBuf)> = Vec::new();
        for path_arg in &spec.paths {
            let Some(target) = self.resolve_target(pid, regs, path_arg)? else {
                // Not a filesystem object (a socket or pipe descriptor), or a
                // descriptor the kernel will reject on its own.
                continue;
            };
            let access = self.needed_access(pid, regs, path_arg)?;
            if let Err(denial) = self.config.policy.check(&target, access) {
                self.report(&format!("{denial} (syscall {})", spec.name));
                return Ok(Some(libc::EACCES));
            }
            if path_arg.rewritable
                && let Some(index) = path_arg.path_arg
            {
                rewrites.push((index, target));
            }
        }

        if !rewrites.is_empty() {
            self.rewrite_paths(pid, regs, &rewrites)?;
        }
        Ok(None)
    }

    /// In full-tracing mode the supervisor also enforces the socket policy that
    /// the seccomp filter would otherwise apply. `AF_UNIX` stays permitted.
    fn socket_family_denial(&self, nr: i64, regs: &Regs) -> Option<i32> {
        if self.config.network != NetworkMode::Denied {
            return None;
        }
        if nr != libc::SYS_socket && nr != libc::SYS_socketpair {
            return None;
        }
        if regs.argument(0) as i64 == i64::from(libc::AF_UNIX) {
            return None;
        }
        Some(libc::EPERM)
    }

    fn needed_access(
        &mut self,
        pid: libc::pid_t,
        regs: &Regs,
        path_arg: &PathArg,
    ) -> Result<Access> {
        Ok(match path_arg.need {
            Need::Read => Access::Read,
            Need::Write => Access::Write,
            Need::WriteName => Access::WriteName,
            Need::OpenFlags(index) => match syscalls::need_from_open_flags(regs.argument(index)) {
                Need::WriteName => Access::WriteName,
                Need::Write => Access::Write,
                _ => Access::Read,
            },
            Need::OpenHow(index) => {
                let flags = self.read_open_how_flags(pid, regs.argument(index))?;
                match syscalls::need_from_open_flags(flags) {
                    Need::WriteName => Access::WriteName,
                    Need::Write => Access::Write,
                    _ => Access::Read,
                }
            }
        })
    }

    /// `struct open_how` starts with a `__u64 flags`.
    fn read_open_how_flags(&mut self, pid: libc::pid_t, addr: u64) -> Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        let memory = self.memory(pid)?;
        Ok(memory.read_u64(addr)?)
    }

    /// Resolves one path argument to the absolute path the kernel would act on.
    ///
    /// `Ok(None)` means there is nothing for the policy to judge: the
    /// descriptor is not a file, or it is invalid and the kernel will fail the
    /// call by itself.
    fn resolve_target(
        &mut self,
        pid: libc::pid_t,
        regs: &Regs,
        path_arg: &PathArg,
    ) -> Result<Option<PathBuf>> {
        let base_fd = match path_arg.base {
            Base::Cwd => libc::AT_FDCWD,
            Base::Fd(index) => regs.argument(index) as i32,
        };

        let raw_path = match path_arg.path_arg {
            None => None,
            Some(index) => {
                let pointer = regs.argument(index);
                if pointer == 0 {
                    // `utimensat(fd, NULL, ...)` and friends act on the
                    // descriptor itself.
                    None
                } else {
                    let memory = self.memory(pid)?;
                    let bytes = memory.read_c_string(pointer)?;
                    Some(PathBuf::from(OsStr::from_bytes(&bytes).to_os_string()))
                }
            }
        };

        // An absolute path makes the directory descriptor irrelevant to the
        // kernel, so it must not be consulted here either: otherwise a bogus
        // descriptor would let `openat(-1, "/etc/passwd", O_RDWR)` skip the
        // check while the kernel happily opened the file.
        let base = if raw_path.as_ref().is_some_and(|path| path.is_absolute()) {
            PathBuf::from("/")
        } else {
            match resolve::descriptor_target(&self.config.proc_root, pid, base_fd) {
                Ok(DescriptorTarget::Path(path)) => path,
                // A socket or pipe descriptor: not something the filesystem
                // policy governs.
                Ok(DescriptorTarget::NotAFile) => return Ok(None),
                // A closed or invalid descriptor: the kernel answers `EBADF`,
                // and letting it do so keeps the tracee's error handling
                // intact.
                Err(_) => return Ok(None),
            }
        };

        let raw_path = raw_path.unwrap_or_default();
        let final_component = match path_arg.follow {
            Follow::Always => FinalComponent::Follow,
            Follow::Never => FinalComponent::Keep,
            Follow::UnlessAtNoFollow(index) => {
                if syscalls::at_flags_nofollow(regs.argument(index)) {
                    FinalComponent::Keep
                } else {
                    FinalComponent::Follow
                }
            }
            Follow::OnlyIfAtFollow(index) => {
                if syscalls::at_flags_follow(regs.argument(index)) {
                    FinalComponent::Follow
                } else {
                    FinalComponent::Keep
                }
            }
            Follow::UnlessOpenNoFollow(index) => {
                if syscalls::open_flags_nofollow(regs.argument(index)) {
                    FinalComponent::Keep
                } else {
                    FinalComponent::Follow
                }
            }
            Follow::UnlessOpenHowNoFollow(index) => {
                let flags = self.read_open_how_flags(pid, regs.argument(index))?;
                if syscalls::open_flags_nofollow(flags) {
                    FinalComponent::Keep
                } else {
                    FinalComponent::Follow
                }
            }
        };

        Ok(Some(resolve::resolve_path(
            &base,
            &raw_path,
            &self.config.proc_root,
            pid,
            final_component,
        )))
    }

    /// Points the syscall at the canonical path that was validated.
    ///
    /// The rewritten strings go below the stopped thread's stack pointer, which
    /// is per-thread scratch space no other thread is using. Since the path is
    /// absolute, the `*at` directory descriptor no longer participates in
    /// resolution, so a descriptor swapped out from under us cannot change the
    /// outcome either.
    ///
    /// Failure is not fatal: the check has already happened, so the worst case
    /// is that the syscall runs against the original argument.
    fn rewrite_paths(
        &mut self,
        pid: libc::pid_t,
        regs: &mut Regs,
        rewrites: &[(usize, PathBuf)],
    ) -> Result<()> {
        const STACK_GAP: u64 = 4096;

        let mut encoded: Vec<(usize, Vec<u8>)> = Vec::with_capacity(rewrites.len());
        for (index, path) in rewrites {
            let mut bytes = path.as_os_str().as_bytes().to_vec();
            if bytes.is_empty() || bytes.len() >= 4096 {
                return Ok(());
            }
            bytes.push(0);
            encoded.push((*index, bytes));
        }

        let total: usize = encoded.iter().map(|(_, bytes)| bytes.len()).sum();
        let sp = regs.stack_pointer();
        let Some(base) = sp
            .checked_sub(STACK_GAP)
            .and_then(|addr| addr.checked_sub(total as u64))
        else {
            return Ok(());
        };
        let base = base & !15;

        let memory = self.memory(pid)?;
        if !memory.is_readable(base, total) {
            return Ok(());
        }

        let mut cursor = base;
        for (index, bytes) in &encoded {
            if memory.write_bytes(cursor, bytes).is_err() {
                return Ok(());
            }
            regs.set_argument(*index, cursor);
            cursor += bytes.len() as u64;
        }
        regs.write(pid)
    }

    fn memory(&mut self, pid: libc::pid_t) -> Result<&TraceeMemory> {
        let tracee = self
            .tracees
            .get_mut(&pid)
            .ok_or_else(|| SandboxError::Other(format!("unknown tracee {pid}")))?;
        if tracee.memory.is_none() {
            tracee.memory = Some(TraceeMemory::open(&self.config.proc_root, pid)?);
        }
        tracee
            .memory
            .as_ref()
            .ok_or_else(|| SandboxError::Other(format!("no memory handle for tracee {pid}")))
    }

    fn resume(&mut self, pid: libc::pid_t, signal: libc::c_int) -> Result<()> {
        match self.mode {
            InterceptMode::SeccompDirected => {
                // A cancelled syscall still has to be followed to its exit
                // stop so the errno can be installed.
                let waiting = self
                    .tracees
                    .get(&pid)
                    .is_some_and(|tracee| tracee.pending_errno.is_some());
                if waiting {
                    self.resume_to_syscall(pid, signal)
                } else {
                    self.cont(pid, signal)
                }
            }
            InterceptMode::AllSyscalls => self.resume_to_syscall(pid, signal),
        }
    }

    fn cont(&self, pid: libc::pid_t, signal: libc::c_int) -> Result<()> {
        ignore_vanished(arch::ptrace_simple(
            "PTRACE_CONT",
            libc::PTRACE_CONT,
            pid,
            signal,
        ))
    }

    fn resume_to_syscall(&self, pid: libc::pid_t, signal: libc::c_int) -> Result<()> {
        ignore_vanished(arch::ptrace_simple(
            "PTRACE_SYSCALL",
            libc::PTRACE_SYSCALL,
            pid,
            signal,
        ))
    }

    fn report(&mut self, message: &str) {
        if self.reported_denials >= MAX_REPORTED_DENIALS {
            return;
        }
        self.reported_denials += 1;
        eprintln!("codex-linux-sandbox: sandbox denied: {message}");
        if self.reported_denials == MAX_REPORTED_DENIALS {
            eprintln!("codex-linux-sandbox: further sandbox denials suppressed");
        }
    }
}

/// A tracee can exit between its stop and our resume; that is not an error.
fn ignore_vanished(result: Result<()>) -> Result<()> {
    match result {
        Err(SandboxError::Ptrace { source, .. })
            if source.raw_os_error() == Some(libc::ESRCH) =>
        {
            Ok(())
        }
        other => other,
    }
}

/// Syscalls the supervisor refuses itself when seccomp could not be directed at
/// them. Mirrors the deny filter in [`super::seccomp`].
fn supervisor_enforced_denials() -> HashSet<i64> {
    let mut denied: HashSet<i64> = HashSet::new();
    denied.extend(seccomp::escape_denied_syscalls());
    denied.extend(seccomp::network_denied_syscalls());
    denied
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

extern "C" fn forward_signal(signal: libc::c_int) {
    let pid = SANDBOXED_PID.load(Ordering::SeqCst);
    if pid > 0 {
        // SAFETY: `kill` is async-signal-safe.
        unsafe {
            libc::kill(pid, signal);
        }
    }
}

/// The supervisor sits between the caller and the sandboxed command, so the
/// signals a caller would have sent straight to the command have to be relayed.
fn install_signal_forwarding() {
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP, libc::SIGQUIT] {
        // SAFETY: installing a handler that only calls `kill`.
        unsafe {
            libc::signal(signal, forward_signal as libc::sighandler_t);
        }
    }
}

// ---------------------------------------------------------------------------
// Pipes
// ---------------------------------------------------------------------------

/// A close-on-exec pipe used for the two handshakes between child and
/// supervisor.
struct Pipe {
    read: libc::c_int,
    write: libc::c_int,
}

impl Pipe {
    fn new() -> Result<Self> {
        let mut fds = [0 as libc::c_int; 2];
        // SAFETY: `fds` is a live two-element array.
        let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
        if ret != 0 {
            return Err(SandboxError::Io(io::Error::last_os_error()));
        }
        Ok(Self {
            read: fds[0],
            write: fds[1],
        })
    }

    fn close_read(&mut self) {
        if self.read >= 0 {
            // SAFETY: the descriptor is owned by this struct and released once.
            unsafe { libc::close(self.read) };
            self.read = -1;
        }
    }

    fn close_write(&mut self) {
        if self.write >= 0 {
            // SAFETY: the descriptor is owned by this struct and released once.
            unsafe { libc::close(self.write) };
            self.write = -1;
        }
    }

    /// Writes a diagnostic for the supervisor to read. Best effort: the
    /// supervisor already knows something went wrong from the exit status.
    fn report(&self, message: &str) {
        let bytes = message.as_bytes();
        // SAFETY: writing a live buffer to an owned descriptor.
        unsafe {
            libc::write(self.write, bytes.as_ptr().cast::<libc::c_void>(), bytes.len());
        }
    }

    fn read_message(&self) -> Option<String> {
        let mut buffer = [0u8; 512];
        // SAFETY: reading into a live buffer from an owned descriptor.
        let read = unsafe {
            libc::read(
                self.read,
                buffer.as_mut_ptr().cast::<libc::c_void>(),
                buffer.len(),
            )
        };
        if read <= 0 {
            return None;
        }
        Some(String::from_utf8_lossy(&buffer[..read as usize]).into_owned())
    }

    fn write_byte(&self, byte: u8) -> Result<()> {
        // SAFETY: writing one byte from a live buffer.
        let written = unsafe { libc::write(self.write, std::ptr::addr_of!(byte).cast(), 1) };
        if written != 1 {
            return Err(SandboxError::Io(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn read_byte(&self) -> Result<u8> {
        let mut byte = 0u8;
        loop {
            // SAFETY: reading one byte into a live buffer.
            let read = unsafe { libc::read(self.read, std::ptr::addr_of_mut!(byte).cast(), 1) };
            if read == 1 {
                return Ok(byte);
            }
            let err = io::Error::last_os_error();
            if read < 0 && err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SandboxError::Other(
                "the sandbox supervisor closed the handshake before sending a mode".to_string(),
            ));
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        // SAFETY: both descriptors are owned by this struct.
        unsafe {
            if self.read >= 0 {
                libc::close(self.read);
            }
            if self.write >= 0 {
                libc::close(self.write);
            }
        }
    }
}

/// Where the supervisor looks up per-process state.
pub(crate) fn default_proc_root() -> &'static Path {
    Path::new("/proc")
}
