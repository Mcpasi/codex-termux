//! Optional Landlock hardening.
//!
//! Landlock is applied when the running kernel happens to provide it, purely as
//! an extra layer in front of the supervisor. Nothing depends on it: a kernel
//! built without `CONFIG_SECURITY_LANDLOCK` — which is most Android devices —
//! simply skips this, and the ptrace supervisor remains the enforced boundary.
//!
//! That is the whole reason this is a separate, silent, best-effort step rather
//! than part of the setup sequence that can fail the command.

use codex_utils_absolute_path::AbsolutePathBuf;
use landlock::ABI;
use landlock::Access;
use landlock::AccessFs;
use landlock::CompatLevel;
use landlock::Compatible;
use landlock::Ruleset;
use landlock::RulesetAttr;
use landlock::RulesetCreatedAttr;

/// Restricts writes to `writable_roots` if the kernel supports Landlock.
///
/// Reads stay unrestricted here even when the policy narrows them: the legacy
/// Landlock ruleset shape cannot express read narrowing, and this layer must
/// never be *more* permissive or *less* permissive than the supervisor in a way
/// that changes observed behaviour. Read narrowing is enforced by the
/// supervisor.
pub(crate) fn apply_best_effort(writable_roots: &[AbsolutePathBuf]) {
    if let Err(err) = install(writable_roots) {
        // Not a failure: this layer is optional by design.
        let _ = err;
    }
}

fn install(writable_roots: &[AbsolutePathBuf]) -> Result<(), landlock::RulesetError> {
    let abi = ABI::V5;
    let access_rw = AccessFs::from_all(abi);
    let access_ro = AccessFs::from_read(abi);

    let mut ruleset = Ruleset::default()
        .set_compatibility(CompatLevel::BestEffort)
        .handle_access(access_rw)?
        .create()?
        .add_rules(landlock::path_beneath_rules(&["/"], access_ro))?
        .add_rules(landlock::path_beneath_rules(
            &["/dev/null", "/dev/tty"],
            access_rw,
        ))?
        .set_no_new_privs(true);

    if !writable_roots.is_empty() {
        ruleset = ruleset.add_rules(landlock::path_beneath_rules(writable_roots, access_rw))?;
    }

    // The status is deliberately ignored: `RulesetStatus::NotEnforced` is the
    // expected outcome on kernels without the LSM.
    let _ = ruleset.restrict_self()?;
    Ok(())
}
