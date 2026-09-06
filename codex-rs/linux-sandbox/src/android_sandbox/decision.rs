//! The filesystem policy decision the supervisor makes for each intercepted
//! syscall.
//!
//! This is the piece that replaces Landlock: instead of handing writable roots
//! to an LSM and hoping the kernel has one, the supervisor answers every path
//! question itself from the same [`FileSystemSandboxPolicy`] the rest of Codex
//! uses. That keeps the enforced boundary identical to the configured one — the
//! full policy, including read narrowing and deny-read entries, not just the
//! "writable roots plus full read" subset Landlock could express.

use std::path::Path;
use std::path::PathBuf;

use codex_protocol::permissions::FileSystemSandboxPolicy;

/// What an intercepted path argument needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Access {
    Read,
    /// Modify the object itself.
    Write,
    /// Create or remove a name: the object *and* the directory holding it.
    WriteName,
}

/// Why a syscall was refused, for the diagnostic the tracee's stderr gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Denial {
    pub(crate) path: PathBuf,
    pub(crate) access: Access,
    pub(crate) reason: DenialReason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DenialReason {
    /// The policy does not grant this access to this path.
    PolicyDenied,
    /// The path resolves into the supervisor's own `/proc` directory. Nothing
    /// the sandboxed command legitimately does lands there, and letting it
    /// through would let a tracee reach the supervisor through `/proc/self`.
    SupervisorProcDirectory,
}

/// Evaluates paths against the session's filesystem policy.
pub(crate) struct PolicyEngine {
    policy: FileSystemSandboxPolicy,
    /// The cwd `:workspace`-relative policy entries are resolved against. This
    /// is the *policy* cwd from the helper's arguments, not the tracee's
    /// current directory, which the command is free to change.
    policy_cwd: PathBuf,
    reads_restricted: bool,
    /// `<proc_root>/<supervisor pid>`, precomputed for the escape check above.
    supervisor_proc_dir: PathBuf,
}

impl PolicyEngine {
    pub(crate) fn new(
        policy: FileSystemSandboxPolicy,
        policy_cwd: PathBuf,
        proc_root: &Path,
        supervisor_pid: i32,
    ) -> Self {
        let reads_restricted = !policy.has_full_disk_read_access();
        Self {
            policy,
            policy_cwd,
            reads_restricted,
            supervisor_proc_dir: proc_root.join(supervisor_pid.to_string()),
        }
    }

    /// True when read probes (`stat`, `access`, `readlink`, ...) have to be
    /// intercepted. With full read access their answer is always "allowed", so
    /// leaving them uninstrumented costs nothing and keeps the sandbox fast.
    pub(crate) fn reads_restricted(&self) -> bool {
        self.reads_restricted
    }

    /// Checks one resolved path.
    pub(crate) fn check(&self, path: &Path, access: Access) -> Result<(), Denial> {
        if path.starts_with(&self.supervisor_proc_dir) {
            return Err(Denial {
                path: path.to_path_buf(),
                access,
                reason: DenialReason::SupervisorProcDirectory,
            });
        }

        let granted = match access {
            Access::Read => self.policy.can_read_path_with_cwd(path, &self.policy_cwd),
            Access::Write => self.policy.can_write_path_with_cwd(path, &self.policy_cwd),
            Access::WriteName => {
                self.policy.can_write_path_with_cwd(path, &self.policy_cwd)
                    && match path.parent() {
                        // Adding or removing a name mutates the directory that
                        // holds it, so the directory has to be writable too.
                        // Without this, a policy that grants write to a single
                        // file inside a read-only directory would still allow
                        // that file to be deleted or replaced.
                        Some(parent) => {
                            self.policy.can_write_path_with_cwd(parent, &self.policy_cwd)
                        }
                        // No parent means the filesystem root itself.
                        None => false,
                    }
            }
        };

        if granted {
            Ok(())
        } else {
            Err(Denial {
                path: path.to_path_buf(),
                access,
                reason: DenialReason::PolicyDenied,
            })
        }
    }
}

impl std::fmt::Display for Denial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let access = match self.access {
            Access::Read => "read",
            Access::Write => "write",
            Access::WriteName => "create/remove",
        };
        match self.reason {
            DenialReason::PolicyDenied => write!(
                f,
                "{access} access to {} is not permitted by the sandbox policy",
                self.path.display()
            ),
            DenialReason::SupervisorProcDirectory => write!(
                f,
                "{access} access to {} would reach the sandbox supervisor's own process directory",
                self.path.display()
            ),
        }
    }
}

#[cfg(test)]
#[path = "decision_tests.rs"]
mod tests;
