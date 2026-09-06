//! Architecture-specific register access for the ptrace supervisor.
//!
//! The supervisor reads syscall arguments out of the stopped tracee's registers
//! and, when a syscall is refused, cancels it by replacing the syscall number
//! with an invalid one. Both operations are architecture specific — most
//! notably on arm64, where writing `x8` does *not* change the syscall being
//! executed; the kernel exposes a dedicated `NT_ARM_SYSTEM_CALL` regset for
//! that, and using it is the only way to cancel a syscall on that architecture.

use std::mem::size_of;

use super::error::Result;
use super::error::SandboxError;
use super::error::ptrace_result;

const NT_PRSTATUS: libc::c_int = 1;
#[cfg(target_arch = "aarch64")]
const NT_ARM_SYSTEM_CALL: libc::c_int = 0x404;

/// Syscall number the kernel treats as "no such syscall", used to cancel a
/// syscall the policy refused.
const CANCELLED_SYSCALL: i64 = -1;

/// True when this build knows how to read the tracee's registers.
pub(crate) const fn supported() -> bool {
    cfg!(any(target_arch = "aarch64", target_arch = "x86_64"))
}

/// A snapshot of a stopped tracee's general purpose registers.
#[derive(Clone, Copy)]
pub(crate) struct Regs {
    raw: libc::user_regs_struct,
}

impl Regs {
    /// Reads the registers of the stopped thread `pid`.
    pub(crate) fn read(pid: libc::pid_t) -> Result<Self> {
        if !supported() {
            return Err(SandboxError::UnsupportedArchitecture);
        }
        // SAFETY: `user_regs_struct` is a plain repr(C) POD; the kernel fills
        // it completely and reports how much it wrote through `iov_len`.
        let mut raw: libc::user_regs_struct = unsafe { std::mem::zeroed() };
        let mut iov = libc::iovec {
            iov_base: std::ptr::addr_of_mut!(raw).cast::<libc::c_void>(),
            iov_len: size_of::<libc::user_regs_struct>(),
        };
        // SAFETY: `pid` is stopped and traced by us, and `iov` points at a
        // live, correctly sized buffer.
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_GETREGSET,
                pid,
                NT_PRSTATUS as usize as *mut libc::c_void,
                std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
            )
        };
        ptrace_result("PTRACE_GETREGSET(NT_PRSTATUS)", ret)?;
        Ok(Self { raw })
    }

    /// Writes the registers back to the stopped thread `pid`.
    pub(crate) fn write(&self, pid: libc::pid_t) -> Result<()> {
        let mut raw = self.raw;
        let mut iov = libc::iovec {
            iov_base: std::ptr::addr_of_mut!(raw).cast::<libc::c_void>(),
            iov_len: size_of::<libc::user_regs_struct>(),
        };
        // SAFETY: as in `read`; the kernel copies out of `iov`.
        let ret = unsafe {
            libc::ptrace(
                libc::PTRACE_SETREGSET,
                pid,
                NT_PRSTATUS as usize as *mut libc::c_void,
                std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
            )
        };
        ptrace_result("PTRACE_SETREGSET(NT_PRSTATUS)", ret)?;
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn syscall_number(&self) -> i64 {
        self.raw.regs[8] as i64
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn argument(&self, index: usize) -> u64 {
        self.raw.regs.get(index).copied().unwrap_or(0)
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn set_argument(&mut self, index: usize, value: u64) {
        if let Some(slot) = self.raw.regs.get_mut(index) {
            *slot = value;
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn stack_pointer(&self) -> u64 {
        self.raw.sp
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn set_return_value(&mut self, value: i64) {
        self.raw.regs[0] = value as u64;
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn syscall_number(&self) -> i64 {
        self.raw.orig_rax as i64
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn argument(&self, index: usize) -> u64 {
        match index {
            0 => self.raw.rdi,
            1 => self.raw.rsi,
            2 => self.raw.rdx,
            3 => self.raw.r10,
            4 => self.raw.r8,
            5 => self.raw.r9,
            _ => 0,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn set_argument(&mut self, index: usize, value: u64) {
        match index {
            0 => self.raw.rdi = value,
            1 => self.raw.rsi = value,
            2 => self.raw.rdx = value,
            3 => self.raw.r10 = value,
            4 => self.raw.r8 = value,
            5 => self.raw.r9 = value,
            _ => {}
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn stack_pointer(&self) -> u64 {
        self.raw.rsp
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn set_return_value(&mut self, value: i64) {
        self.raw.rax = value as u64;
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn syscall_number(&self) -> i64 {
        CANCELLED_SYSCALL
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn argument(&self, _index: usize) -> u64 {
        0
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn set_argument(&mut self, _index: usize, _value: u64) {}

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn stack_pointer(&self) -> u64 {
        0
    }

    #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
    pub(crate) fn set_return_value(&mut self, _value: i64) {}
}

/// Cancels the syscall the stopped thread is about to enter.
///
/// The thread still stops again at syscall exit, where the caller replaces the
/// kernel's `ENOSYS` with the errno the policy decided on.
#[cfg(target_arch = "aarch64")]
pub(crate) fn cancel_syscall(pid: libc::pid_t, _regs: &mut Regs) -> Result<()> {
    let mut number: libc::c_int = CANCELLED_SYSCALL as libc::c_int;
    let mut iov = libc::iovec {
        iov_base: std::ptr::addr_of_mut!(number).cast::<libc::c_void>(),
        iov_len: size_of::<libc::c_int>(),
    };
    // SAFETY: `pid` is stopped in a syscall-entry stop and `iov` points at a
    // live `int`, which is what `NT_ARM_SYSTEM_CALL` expects.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETREGSET,
            pid,
            NT_ARM_SYSTEM_CALL as usize as *mut libc::c_void,
            std::ptr::addr_of_mut!(iov).cast::<libc::c_void>(),
        )
    };
    ptrace_result("PTRACE_SETREGSET(NT_ARM_SYSTEM_CALL)", ret)?;
    Ok(())
}

/// On x86_64 the syscall number lives in `orig_rax`, which the kernel reads
/// after the entry stop, so writing the register cancels the call.
#[cfg(target_arch = "x86_64")]
pub(crate) fn cancel_syscall(pid: libc::pid_t, regs: &mut Regs) -> Result<()> {
    regs.raw.orig_rax = CANCELLED_SYSCALL as u64;
    regs.write(pid)
}

#[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
pub(crate) fn cancel_syscall(_pid: libc::pid_t, _regs: &mut Regs) -> Result<()> {
    Err(SandboxError::UnsupportedArchitecture)
}

/// Sets the value an already-cancelled syscall returns to the tracee.
pub(crate) fn set_syscall_error(pid: libc::pid_t, errno: i32) -> Result<()> {
    let mut regs = Regs::read(pid)?;
    regs.set_return_value(-i64::from(errno));
    regs.write(pid)
}

/// Convenience wrapper used by the supervisor for the plain `ptrace` requests
/// that take no data.
pub(crate) fn ptrace_simple(
    operation: &'static str,
    request: libc::c_int,
    pid: libc::pid_t,
    data: libc::c_int,
) -> Result<()> {
    // SAFETY: every caller passes a request that takes an integer `data`
    // argument and a pid it is the tracer of.
    let ret = unsafe {
        libc::ptrace(
            request,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            data as usize as *mut libc::c_void,
        )
    };
    ptrace_result(operation, ret)?;
    Ok(())
}

/// `PTRACE_SETOPTIONS`, which takes a bit mask rather than a signal number.
pub(crate) fn ptrace_set_options(pid: libc::pid_t, options: libc::c_int) -> Result<()> {
    // SAFETY: `pid` is stopped and traced by us.
    let ret = unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            pid,
            std::ptr::null_mut::<libc::c_void>(),
            options as usize as *mut libc::c_void,
        )
    };
    ptrace_result("PTRACE_SETOPTIONS", ret)?;
    Ok(())
}
