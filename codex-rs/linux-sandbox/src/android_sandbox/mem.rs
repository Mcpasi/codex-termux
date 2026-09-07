//! Reading and writing a stopped tracee's memory through `/proc/<pid>/mem`.
//!
//! Path arguments live in the tracee's address space, so the supervisor has to
//! fetch them before it can decide anything. `/proc/<pid>/mem` is used rather
//! than `PTRACE_PEEKDATA` because it moves whole buffers in one syscall; the
//! kernel applies the same `ptrace` access check to it, so it needs no extra
//! privilege.
//!
//! The handle is tied to the tracee's address space at open time, so it is
//! dropped whenever the tracee execs into a new image.

use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

/// Longest path the kernel accepts; anything longer is refused by the syscall
/// itself, so reading further is pointless.
const PATH_MAX: usize = 4096;

/// A tagged tracee pointer is a virtual address, not a `/proc/<pid>/mem`
/// file offset. Android's arm64 allocator tags heap pointers in the top byte;
/// passing that byte to `pread` produces EINVAL before any path can be checked.
/// Only normalize the offset used by the supervisor, never the tracee's pointer.
fn memory_offset(addr: u64) -> u64 {
    #[cfg(target_arch = "aarch64")]
    {
        addr & 0x00ff_ffff_ffff_ffff
    }
    #[cfg(not(target_arch = "aarch64"))]
    {
        addr
    }
}

pub(crate) struct TraceeMemory {
    file: File,
}

impl TraceeMemory {
    pub(crate) fn open(proc_root: &Path, pid: libc::pid_t) -> io::Result<Self> {
        // Write access is only used for the canonical-path rewrite, which is
        // best effort; read-only would be enough for the policy decision, but
        // reopening later would race with the tracee.
        let path = proc_root.join(pid.to_string()).join("mem");
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(Self { file })
    }

    /// Reads a NUL-terminated string starting at `addr`.
    ///
    /// Reads stop at page boundaries so a string that ends just before an
    /// unmapped page is still returned instead of failing the whole read.
    pub(crate) fn read_c_string(&self, addr: u64) -> io::Result<Vec<u8>> {
        const PAGE: u64 = 4096;
        let mut out: Vec<u8> = Vec::with_capacity(256);
        let mut cursor = memory_offset(addr);

        while out.len() < PATH_MAX {
            let to_page_end = PAGE - (cursor % PAGE);
            let want = to_page_end.min((PATH_MAX - out.len()) as u64) as usize;
            let mut chunk = vec![0u8; want];
            let read = self.file.read_at(&mut chunk, cursor)?;
            if read == 0 {
                break;
            }
            if let Some(end) = chunk[..read].iter().position(|byte| *byte == 0) {
                out.extend_from_slice(&chunk[..end]);
                return Ok(out);
            }
            out.extend_from_slice(&chunk[..read]);
            cursor += read as u64;
        }

        // No terminator within `PATH_MAX`: the kernel would reject this path
        // with `ENAMETOOLONG`, and the caller treats an unterminated read as a
        // path it could not validate.
        Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG))
    }

    /// Reads a little-endian `u64` (used for `struct open_how`).
    pub(crate) fn read_u64(&self, addr: u64) -> io::Result<u64> {
        let mut buffer = [0u8; 8];
        self.file.read_exact_at(&mut buffer, memory_offset(addr))?;
        Ok(u64::from_le_bytes(buffer))
    }

    /// Checks that `len` bytes at `addr` are mapped, so a scratch write cannot
    /// fail halfway through and leave a truncated path behind.
    pub(crate) fn is_readable(&self, addr: u64, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let addr = memory_offset(addr);
        let Some(last) = addr.checked_add(len as u64 - 1) else {
            return false;
        };
        let mut probe = [0u8; 1];
        self.file.read_exact_at(&mut probe, addr).is_ok()
            && self.file.read_exact_at(&mut probe, last).is_ok()
    }

    pub(crate) fn write_bytes(&self, addr: u64, data: &[u8]) -> io::Result<()> {
        self.file.write_all_at(data, memory_offset(addr))
    }
}

#[cfg(test)]
#[path = "mem_tests.rs"]
mod tests;
