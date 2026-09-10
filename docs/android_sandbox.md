# Android sandbox

On Android — Termux as well as builds that embed the Codex app-server inside an
Android application — the sandbox is enforced by the `codex-linux-sandbox`
helper using **seccomp + ptrace**. It does not depend on Landlock.

## Why not Landlock

Landlock is a Linux LSM that has to be compiled into the running kernel
(`CONFIG_SECURITY_LANDLOCK`). Android does not require it, and a large share of
shipped device kernels do not have it. On those devices
`landlock_restrict_self()` succeeds but reports `RulesetStatus::NotEnforced`,
which means the filesystem boundary silently does not exist.

That leaves only three possible behaviours for a Landlock-based backend, and
none of them is acceptable for a product that has to run on arbitrary hardware:

- run the command with no filesystem boundary,
- report the sandbox as active while it is not, or
- refuse to run at all on those devices.

So the Android backend does not use Landlock as its mechanism. Landlock is still
applied when the kernel happens to offer it, purely as an extra layer.

Before the optional Landlock layer is enabled, its complete setup is tested in
a disposable child process. This includes ruleset creation, rule installation
and `restrict_self()`.

This protects the sandbox launcher from Android kernels or inherited seccomp
policies that reject Landlock syscalls with `SIGSYS` instead of returning an
ordinary error. A failed probe disables only the optional Landlock layer. The
seccomp/ptrace supervisor remains the enforced sandbox boundary.

## What is used instead

Two kernel features that **every** Android device is required to have:

| Feature | Guarantee |
| --- | --- |
| `seccomp-bpf` | `CONFIG_SECCOMP_FILTER` is a CTS requirement; the Android application sandbox itself depends on it. |
| `ptrace` of one's own descendants | Used by every in-process crash handler on the platform; permitted within an app's own UID/domain. |

The helper forks the command as a traced child and supervises it:

```
codex-linux-sandbox (supervisor, enforces policy)
└── sandboxed command (traced, seccomp-filtered)
```

1. The child installs three stacked seccomp filters and asks to be traced.
2. Every syscall that names a path stops in the supervisor.
3. The supervisor resolves the path the way the kernel would — applying the
   tracee's working directory, `*at` directory descriptors, `/proc/self`, and
   symlinks — and answers it from the session's `FileSystemSandboxPolicy`.
4. A refused syscall is cancelled before the kernel executes it and returns
   `EACCES`.

Because the policy is evaluated per syscall rather than projected onto a kernel
ruleset, the enforced boundary is the *whole* configured profile, including
read-narrowing and deny-read entries that the old Landlock path could not
express.

### The seccomp layers

| Filter | Action | Contents |
| --- | --- | --- |
| Deny | `EPERM` | The network policy, plus everything that could step around a ptrace supervisor: `io_uring_*` (performs file I/O without further syscalls), `userfaultfd` (widens check-then-use races), `ptrace`/`process_vm_*`, every mount/namespace call, and `open_by_handle_at`. |
| `clone3` | `ENOSYS` | `clone3` passes its flags in a struct that seccomp cannot inspect; reporting `ENOSYS` makes libc fall back to `clone`, whose flags are filterable. |
| Trace | `SECCOMP_RET_TRACE` | The path-carrying syscalls, which stop in the supervisor. |

`seccompiler` emits an architecture check in front of every program that kills
the process on a mismatch, which closes the classic escape of issuing syscalls
through a foreign ABI (a 32-bit ARM binary on an arm64 kernel uses a different
syscall table).

### Performance

When the policy leaves reads unrestricted — the `workspace-write` default — the
trace filter only selects `open` calls that carry write intent, plus the
mutating syscalls. `stat`, `access`, `readlink` and read-only opens are never
stopped, so read-heavy tooling runs at native speed. Read-narrowed policies
intercept the read probes as well.

### Universal fallback

If a kernel does not support `PTRACE_O_TRACESECCOMP`, the supervisor stops on
*every* syscall instead and applies the network and escape deny-lists itself.
This is slower but needs nothing beyond plain `ptrace`.

## Fail-closed behaviour

There is no path that runs the command unsandboxed. If the sandbox cannot be
established, the helper exits with status `9` and the command never runs. The
tracees are attached with `PTRACE_O_EXITKILL`, so losing the supervisor kills
them rather than releasing them.

## Known limitation

A check-then-use race remains for a *multi-threaded* tracee: a sibling thread
could rewrite a path buffer between the supervisor's check and the kernel's own
resolution. The supervisor narrows this as far as a ptrace design allows, by
writing the validated, fully canonical path into per-thread scratch space below
the stopped thread's stack pointer and pointing the syscall at it, so the kernel
resolves the string that was approved rather than the one the tracee supplied.
Since the rewritten path is absolute, swapping the `*at` directory descriptor
cannot change the outcome either, and `userfaultfd` — the reliable way to widen
such a race — is denied outright.

Closing the window completely requires the kernel to perform the path
resolution and the policy check together, which is what an LSM does and what is
not available on these devices.

## Not supported

Managed-network proxy routing needs an isolated network namespace, which Android
cannot create unprivileged. Requests that require it are rejected with
`SandboxTransformError::AndroidSandboxUnsupported` rather than silently
downgraded.
