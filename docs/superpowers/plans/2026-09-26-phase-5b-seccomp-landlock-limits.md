# Phase 5B seccomp, Landlock and Resource Limits Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three defence-in-depth layers to the 5A sandbox: a mandatory seccomp deny-list, a best-effort Landlock filesystem ruleset, and cgroup resource limits, applied by a hidden `runtime sandbox-init` shim that runs inside bwrap.

**Architecture:** `rt_sandbox` gains `seccomp` (hand-assembled classic BPF, no dependency), `landlock` (raw syscalls) and `init` (the shim's logic); the renderer prefixes the program with the shim (binding the runtime executable read-only) and wraps the whole command in `systemd-run --user --scope` when limits apply; `permissions.toml` gains a `[limits]` table.

**Tech Stack:** Rust workspace, `libc` (present), Linux seccomp/Landlock syscalls, bubblewrap 0.11.1, systemd user scopes (verified working on this host: kernel 7.0, Landlock in the LSM list, `systemd-run --user --scope` works).

**Spec:** `docs/superpowers/specs/2026-09-26-seccomp-landlock-limits-design.md`

## Global Constraints

- seccomp is MANDATORY and fail closed: if the filter cannot be built for the architecture or cannot be installed, the shim exits 126 and nothing runs. Landlock is best-effort but its state is always reported. Explicitly configured limits are mandatory (refuse if `systemd-run --user` is unusable); the default `TasksMax` is best-effort with a doctor warning.
- Denied syscalls return `EPERM` (not `SIGSYS`/kill). Filter = arch check first (unknown arch => `EPERM` for everything is NOT acceptable: kill/refuse at build time), then the deny-list, default allow.
- No new crate dependency (no libseccomp, no seccompiler, no landlock crate); unsafe only where a syscall needs it, each block commented with the invariant.
- The shim trusts nothing from the environment; its argument block is built by the renderer and strictly validated (versioned marker, bounded length, absolute paths, no NUL).
- `--new-session` stays (defence in depth). The runtime executable is bound read-only at its own path inside the sandbox; nothing else of the host's home becomes visible.
- Every Phase 2-4 real-Wine suite and the D3D11 fixture must still pass with the filter and Landlock on; a denied syscall Wine needs is fixed by trimming the deny-list with a written reason, never by weakening tests.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green after every task; real-kernel tests skip visibly when seccomp/Landlock/systemd-run are unavailable and are REQUIRED under `RUNTIME_REQUIRE_BWRAP=1`.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## Review Focus

- A denied syscall reached through an ALTERNATE route: `syscall(SYS_x)` numbers on the 32-bit compat ABI (`int 0x80`), x32 ABI (`__X32_SYSCALL_BIT`), `socketcall`/`ipc` multiplexers where relevant, `clone3` (its flags live behind a pointer and cannot be inspected by seccomp: deny `clone3` with `ENOSYS` so libc falls back to `clone`), `ioctl` `TIOCSTI` arg compared as full 32-bit value, `personality` (allow only 0/`PER_LINUX`/0x0008/0xffffffff as flatpak does, or deny wholesale with a reason) (Task 1).
- The filter must not break Wine: `futex`, `mprotect`, `mmap` PROT_EXEC, `clone` for threads (CLONE_THREAD family without NEW* flags), `modify_ldt`/`arch_prctl` (Wine 32-bit), `prctl`, `set_tid_address`, `rt_sigaction`, `memfd_create`, `ptrace`-free operation, `io_uring` unused (decide and document) (Task 3 proves by running).
- Landlock: ABI negotiation on kernels with ABI 1..N; a rule whose path does not exist (skip, not error); `LANDLOCK_ACCESS_FS_REFER`/`TRUNCATE`/`IOCTL_DEV` handling per ABI so the ruleset does not accidentally DENY what bwrap allows (e.g. `/dev/dri` ioctls on ABI 5+) — the classic Landlock breakage (Task 2).
- The shim: `execve` of a path that no longer exists; args with NUL; environment carried through unchanged; exit codes (126 for shim refusal vs the program's own); stdout/stderr untouched; signals (the 5A SIGINT forwarding still ends the program) (Task 3).
- Limits: `systemd-run` missing or user manager down; scope name collisions; the exit status of the scope propagating the program's exit code; Ctrl-C/SIGTERM forwarding still reaching the sandbox through `systemd-run` (it becomes the direct child) (Task 4).

---

### Task 1: `rt_sandbox::seccomp`

**Files:**
- Create: `crates/sandbox/src/seccomp.rs`, `crates/sandbox/src/bpf_interp.rs` (`#[cfg(test)]` only: a minimal classic-BPF interpreter for tests)
- Modify: `crates/sandbox/src/lib.rs`
- Test: same files; a real-kernel test module

**Interfaces:**
- Produces:
  ```rust
  #[repr(C)] #[derive(Clone, Copy, Debug, PartialEq, Eq)] pub struct SockFilter { pub code: u16, pub jt: u8, pub jf: u8, pub k: u32 }
  pub fn build_filter(arch: Arch) -> Result<Vec<SockFilter>, SeccompError>;   // Arch::{X86_64, Aarch64}; others => Err(UnsupportedArch)
  pub fn host_arch() -> Result<Arch, SeccompError>;                           // from cfg!(target_arch)
  pub fn install(filter: &[SockFilter]) -> Result<(), SeccompError>;          // prctl(NO_NEW_PRIVS) + seccomp(SECCOMP_SET_MODE_FILTER, TSYNC not needed)
  pub const DENIED: &[(&str, ...)]                                            // the documented deny-list with a one-line reason each, used by docs and tests
  ```
  Deny-list (each with an `EPERM` return): `ptrace`, `process_vm_readv`, `process_vm_writev`, `kcmp`, `keyctl`, `add_key`, `request_key`, `bpf`, `perf_event_open`, `userfaultfd`, `mount`, `umount2`, `pivot_root`, `chroot`, `unshare`, `setns`, `open_by_handle_at`, `name_to_handle_at`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module`, `syslog`, `acct`, `quotactl`, `swapon`, `swapoff`, `reboot`, `settimeofday`, `clock_settime`, `clock_adjtime`, `adjtimex`, `sethostname`, `setdomainname`, `iopl`, `ioperm`, `lookup_dcookie`, `nfsservctl`, `move_pages`, `mbind`, `set_mempolicy`, `get_mempolicy`, `migrate_pages`, `fanotify_init`, `mount_setattr`, `move_mount`, `open_tree`, `fsopen`, `fsconfig`, `fsmount`, `fspick`, `pidfd_getfd`, `personality` (except 0, 0x0008, 0xffffffff), `clone3` (returns `ENOSYS`), `clone` with any `CLONE_NEW*` flag in arg0 (`EPERM`), `ioctl` with cmd `TIOCSTI` (0x5412) or `TIOCLINUX` (0x541C) (`EPERM`), `socket` with domain `AF_VSOCK` (40), `AF_NETLINK` with protocol `NETLINK_AUDIT`... (keep the socket rules minimal: only `AF_VSOCK`, `AF_KEY`, `AF_ALG`? — decide from what Wine needs; document), and on x86-64 any syscall number with the x32 bit (`0x40000000`) set or the i386 arch value in `seccomp_data.arch` (`EPERM`; Wine's 32-bit programs run as 64-bit processes in WoW64/new-WoW64 mode and do not use `int 0x80` — verify by running the 32-bit fixture `hello32.exe`, and if it breaks, allow the i386 arch and add the same deny-list for it via the i386 syscall numbers; say which you did and why).
  The syscall numbers come from `libc::SYS_*` constants (no hand-typed numbers except the ioctl/clone flag constants, which use `libc::TIOCSTI` etc. where present).

- [ ] **Step 1: Write failing tests** (interpreter-level, no kernel): for each denied name build a `seccomp_data {nr, arch, args}` and assert the program returns `SECCOMP_RET_ERRNO|EPERM` (or ENOSYS for clone3); for a representative allowed set (`read`, `write`, `openat`, `mmap`, `mprotect`, `futex`, `clone` with `CLONE_THREAD|CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID`, `execve`, `prctl`, `arch_prctl`, `modify_ldt`, `memfd_create`, `ioctl` with `FIONREAD`/`TCGETS`, `personality(0)`, `socket(AF_UNIX)`, `socket(AF_INET)`) assert `SECCOMP_RET_ALLOW`; wrong arch => EPERM; x32-bit-set number => EPERM; `clone` with `CLONE_NEWUSER`, `CLONE_NEWNS`, `CLONE_NEWNET`... each => EPERM; `ioctl(TIOCSTI)` compared as 32-bit (upper 32 bits garbage still matches: the arg is `unsigned long`, mask/compare correctly); `personality(0x20000)` => EPERM; program length < 4096 (kernel limit) and every jump target in range (validator test).
- [ ] **Step 2: Run to verify failure, implement** the generator (a small builder with labels so jumps are computed, not hand-counted) and the test-only interpreter (it must implement the BPF ops the generator emits: `LD abs`, `JEQ/JSET/JGT k`, `RET k`, `AND`; panic on anything else so a new op forces an interpreter update).
- [ ] **Step 3: Real-kernel tests** (skip visibly if `prctl(PR_SET_SECCOMP)` is unavailable, required under RUNTIME_REQUIRE_BWRAP): fork a child (`libc::fork`, in the child call `install(build_filter(host_arch())?)` then attempt `ptrace(PTRACE_TRACEME)`, `keyctl`, `unshare(CLONE_NEWUSER)`, `mount`, `ioctl(0, TIOCSTI, ..)`, `clone3` via `syscall`, and an allowed call; `_exit` with a bitmask of results); assert `errno == EPERM` for each denied one (ENOSYS for clone3) and success for the allowed ones; the parent is not affected. Keep everything async-signal-safe in the child (no allocation after fork: build the filter BEFORE fork).
- [ ] **Step 4:** `docs` — the deny-list table (name, reason) generated from `DENIED` into a doc comment; full gate; commit `feat(sandbox): hand-assembled seccomp deny-list filter and installer`.

---

### Task 2: `rt_sandbox::landlock`

**Files:**
- Create: `crates/sandbox/src/landlock.rs`
- Modify: `crates/sandbox/src/lib.rs`
- Test: same file (real-kernel tests in a forked child)

**Interfaces:**
- Produces:
  ```rust
  pub enum Access { ReadExec, ReadWrite }
  pub struct Rule { pub path: PathBuf, pub access: Access }
  pub enum Applied { Enforced { abi: u32 }, Unavailable(String) }   // Unavailable is never an error
  pub fn abi_version() -> Result<u32, LandlockError>;                 // landlock_create_ruleset(NULL,0,VERSION)
  pub fn apply(rules: &[Rule]) -> Result<Applied, LandlockError>;    // Err only for a failure AFTER the ruleset was partially built/enforced (fail closed); Unavailable for ENOSYS/EOPNOTSUPP/EPERM-because-disabled
  ```
  Handled access set per ABI: v1 (read/write file, exec, read dir, remove/make dir/file/sock/fifo/char/block/reg/sym), v2 adds `REFER`, v3 `TRUNCATE`, v4 (net, NOT handled here), v5 `IOCTL_DEV`, v6 scoping (not used). Rule for `ReadExec`: `EXECUTE|READ_FILE|READ_DIR`; for `ReadWrite`: everything the ABI handles for filesystem. CRUCIAL: with `IOCTL_DEV` handled (ABI 5+), device ioctls (DRM, `/dev/dri/*`) are denied unless the rule grants it — give `ReadWrite` rules on `/dev`-tree paths the `IOCTL_DEV` right and put `/dev` (and `/dev/dri`, `/dev/nvidia*`) in the rule set as ReadWrite when the profile has gpu; verify with the D3D11 fixture in Task 3.

- [ ] **Step 1: Failing tests** (real kernel, forked child; skip visibly when `abi_version()` errs with ENOSYS/EOPNOTSUPP): create a temp dir tree `a/ok.txt`, `b/no.txt`; in a child, `apply([ReadWrite a])` then: reading/writing `a/ok.txt` works, reading `b/no.txt` fails `EACCES`, creating `a/new` works, `rename` across `a`→`b` fails; `ReadExec` rule allows reading but not writing; a nonexistent rule path is skipped without error; rules given as a path that is a FILE (ok: file-level rule with file access subset); `apply(&[])` (empty rules) still restricts everything (deny-all) — assert and document; unavailable path simulated by passing an `abi_version` closure returning ENOSYS (the function takes a `Probe` trait/closure in an inner fn for testing) => `Unavailable`; and a test proving `Unavailable` is returned (not an error) when Landlock is disabled (use the injected probe).
- [ ] **Step 2: Implement** with raw `libc::syscall` (numbers 444/445/446 via `libc::SYS_landlock_*` where present, else constants); struct layouts `landlock_ruleset_attr {handled_access_fs, handled_access_net?}` sized by ABI (for ABI < 4 pass the v1 size; the kernel accepts a shorter struct), `landlock_path_beneath_attr {allowed_access u64, parent_fd i32}` packed; open rule paths with `O_PATH|O_CLOEXEC`; `prctl(PR_SET_NO_NEW_PRIVS)` before `restrict_self`; close fds; each unsafe block commented.
- [ ] **Step 3:** full gate; commit `feat(sandbox): Landlock filesystem ruleset with ABI negotiation`.

---

### Task 3: the `sandbox-init` shim, renderer integration, Phase 2-4 suites

**Files:**
- Create: `crates/sandbox/src/init.rs`, `crates/cli/src/sandbox_init.rs`
- Modify: `crates/sandbox/src/render.rs` (+ tests), `crates/cli/src/main.rs` (hidden subcommand, `#[command(hide = true)]`), `crates/cli/src/sandbox.rs` (status lines), `crates/core/src/doctor.rs` + `crates/cli/src/doctor.rs` (seccomp arch supported, Landlock ABI), docs/SECURITY.md, README
- Test: `crates/sandbox/src/init.rs`, `crates/sandbox/src/render/tests.rs`, `crates/cli/tests/e2e_sandbox.rs`, existing e2e suites

**Interfaces:**
- Consumes: `seccomp::{build_filter, host_arch, install}` (Task 1), `landlock::{apply, Rule, Access, Applied}` (Task 2), the 5A renderer.
- Produces:
  ```rust
  // init.rs
  pub struct InitArgs { pub landlock: Vec<landlock::Rule>, pub program: PathBuf, pub argv: Vec<OsString> }
  pub fn encode(&InitArgs) -> Vec<OsString>;            // the shim's argv after "sandbox-init": "--v1", "--rule", "ro:<path>"/"rw:<path>" ..., "--", program, args...
  pub fn parse(args: &[OsString]) -> Result<InitArgs, InitError>;  // strict: exact "--v1" first, each rule prefix ro:/rw:, absolute paths, no NUL, <= 256 rules, program absolute
  pub fn run(args: InitArgs) -> !;                       // rlimit core 0 -> landlock::apply (Unavailable => one stderr line 'runtime: landlock unavailable: <why>' ONLY if RUNTIME_SANDBOX_DEBUG... NO: always silent on stderr; report through `runtime sandbox`/doctor instead) -> seccomp::install (fail => exit 126 + reason) -> execve(program, argv, environ unchanged)
  ```
  Renderer: the program becomes `<runtime exe> sandbox-init --v1 <rules...> -- <orig program> <orig args>`; `<runtime exe>` = `std::env::current_exe()` canonicalised, bound with `--ro-bind` at its own path (fail closed if it cannot be resolved or is under a refused location); the Landlock rule set mirrors the bwrap mounts: ReadExec for `/usr /bin /lib /lib64 /etc /opt(if bound) <ro_binds> <runtime exe> /proc /sys`, ReadWrite for prefix, app home, `/tmp`, the runtime dir tmpfs, `/dev` (+IOCTL_DEV), `/dev/shm`, each rw grant; ReadExec for ro grants; sockets the profile binds (Wayland/pulse/X11 dir) as ReadWrite (connecting to a unix socket needs write access on its path under Landlock ABI < 6? — verify empirically: Landlock `LANDLOCK_ACCESS_FS_WRITE_FILE`/`MAKE_SOCK` semantics for `connect()` on a unix socket file: connect requires write permission on the socket inode; grant the parent dir ReadWrite where needed and record what you found).

- [ ] **Step 1: Failing tests:** `init` encode/parse round trip; every rejection (wrong version marker, relative path, NUL, > 256 rules, missing `--`, empty program); renderer tests: argv contains the shim invocation with the original program after `--`, the runtime exe ro-bound, Landlock rules exactly mirror the binds (frozen expected list for the default profile), gpu off drops the `/dev` IOCTL rule, grants appear as rules with the right access; `current_exe` unresolvable => render error (fail closed); a real-bwrap smoke test running `/bin/sh -c 'echo ok'` through the shim and asserting the process has a seccomp filter (`/proc/self/status` shows `Seccomp: 2`) and `NoNewPrivs: 1`, and (if Landlock available) a read outside the rules fails even though the bwrap mount would have allowed it — punch the hole on purpose with a test-only `extra_binds` in the renderer's test config (`#[cfg(test)]`-only option; never in production API).
- [ ] **Step 2: Implement** `init.rs`, the hidden CLI subcommand (`runtime sandbox-init ...` refuses to run when stdin/argv looks user-driven? — it is hidden, not secret; it must be safe to run by a user: it only restricts itself and execs the given program, which is exactly `runtime`'s existing capability; document that), renderer changes, `runtime sandbox <app>` lines (`seccomp: enforced (x86_64, N rules)`, `landlock: ABI 6 / unavailable: <why>`), doctor lines.
- [ ] **Step 3: Compatibility runs (the point of the task):** with `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1` run `cargo test -p runtime-backend-wine -p runtime-cli -- --ignored --test-threads=1 --skip real_net_ --nocapture`, `cargo test -p runtime-deps --lib -- --ignored e2e_real_wine --test-threads=1 --nocapture`, and the D3D11-under-default-sandbox test (`real_net_wine_d3d11_renders_under_the_default_sandbox`, session DISPLAY/WAYLAND_DISPLAY set, all three devices as in 5A Task 4; DXVK filter via the prefix `HKCU\Environment` as that test already does). Anything broken by seccomp/Landlock: find the syscall/path with `strace -f -e trace=all` (or `SECCOMP_RET_LOG` via a debug env var in a scratch build, not in the product) and fix the FILTER/RULES with a written reason in the report and in the deny-list docs; never weaken a test. Record results.
- [ ] **Step 4:** SECURITY.md (what seccomp/Landlock add and do not: same uid, GPU/display sockets, in-kernel bugs in allowed syscalls, Landlock best-effort), README, full gate; commit `feat(sandbox): sandbox-init shim applies Landlock and seccomp inside bwrap`.

---

### Task 4: resource limits (`[limits]`, `systemd-run --user --scope`)

**Files:**
- Modify: `crates/sandbox/src/permissions.rs` (+ tests), `crates/sandbox/src/render.rs` (+ tests), `crates/cli/src/permissions.rs`, `crates/cli/src/sandbox.rs`, `crates/cli/src/doctor.rs`/core doctor, `crates/cli/src/run.rs` (signal forwarding target if needed), docs/SECURITY.md, README
- Test: sandbox unit tests, `crates/cli/tests/apps.rs`, real-systemd tests in `e2e_sandbox.rs`

**Interfaces:**
- Produces: `Limits { memory_mb: Option<u64>, cpu_percent: Option<u32>, tasks: Option<u32> }` on `Permissions` (`limits` table in TOML; default `tasks = Some(4096)` when the table is absent = "default", distinguish `Default` from an explicitly written value: store `Option` per key and a `limits_explicit: bool` derived from the file, so the renderer knows whether the tasks limit is default (best-effort) or requested (mandatory)); `apply_set` grammar: `memory=<MiB>|off`, `cpu=<percent>|off`, `tasks=<n>|off|default`; bounds in the spec; renderer: when any limit applies, command = `systemd-run --user --scope --collect --quiet -p TasksMax=N [-p MemoryMax=NM -p MemorySwapMax=0] [-p CPUQuota=P%] -- <bwrap ...>`; `find_systemd_run()` + `probe_limits()` (a bounded `systemd-run --user --scope --quiet -p TasksMax=100 true`); explicit limits + probe failure => render error (fail closed); default tasks limit + probe failure => no scope, caveat "resource limits unavailable: <why>".
- [ ] **Step 1: Failing tests:** permissions parse/round-trip of `[limits]`, bounds, `apply_set` forms (incl. `off`, `default`), explicit-vs-default tracking; renderer argv for each combination (exact frozen argv for default = TasksMax only; memory+cpu+tasks), fail-closed vs best-effort, caveat text; signal test: `runtime run` SIGINT/SIGTERM still ends the program when `systemd-run` is the direct child (real-Wine Ctrl-C e2e from 5A must still pass — systemd-run --scope execs the command in the scope, so the forwarded signal target is systemd-run's pid which becomes bwrap? verify: with `--scope` systemd-run `exec`s the command in place, so the pid is unchanged; assert it), exit code propagation; real-systemd tests (skip visibly without a user manager; required under RUNTIME_REQUIRE_BWRAP): a fork bomb helper (a small Rust test binary or `sh -c` loop) in a scope with `tasks=64` gets EAGAIN and the test process is unharmed; a memory hog (allocate + touch 512 MiB) with `memory=128` is OOM-killed while the test survives; both through `runtime run` with a Windows fixture if cheap (`probe.c` gains `forkbomb`/`memhog` modes: CreateProcess loop / VirtualAlloc+touch) — preferred, since it tests the real chain.
- [ ] **Step 2: Implement**, CLI (`permissions --set memory=…`), `runtime sandbox` (limits section + the `systemd-run` argv), doctor (`limits: systemd-run --user available | unavailable: <why>`).
- [ ] **Step 3:** full gate, real-Wine Ctrl-C e2e and the escape suite re-run (paste); SECURITY.md/README; commit `feat(sandbox): per-app resource limits through systemd-run scopes`.

---

### Task 5: escape suite additions and closing the phase

**Files:**
- Modify: `crates/cli/tests/e2e_sandbox.rs`, `tools/fixtures/probe.c`, `crates/cli/compat.toml`, `docs/COMPAT.md`, `docs/SECURITY.md`, `README.md`
- Test: `crates/cli/tests/e2e_sandbox.rs`

- [ ] **Step 1: New probe modes and escape tests** with real Windows programs under the default sandbox (each with the 5A oracle: fails sandboxed, succeeds with `--unsandboxed` where the action is possible unsandboxed; for pure syscall denials use a Linux-side helper inside the sandbox instead where a Windows program cannot issue the syscall — Wine programs cannot call `ptrace` directly, so: (a) `probe.exe` mode `terminal-inject` uses Wine's console APIs only and cannot test TIOCSTI: instead test at the shim level with a real-bwrap Rust test running a Linux helper (`sh` + `python3`? avoid python: use a tiny Rust test binary built by the test crate, or `perl -e`/`dd`? choose a helper that exists on CI: a Rust integration test that re-executes itself (`current_exe`) with an env-selected mode inside the shim, attempting `TIOCSTI` on a pty it created, `ptrace(TRACEME)`, `unshare`, `mount`, `keyctl`, and reporting through exit code bits). Assert each is `EPERM` under the shim and possible/`ENOSYS` differences without it where applicable (for `unshare(CLONE_NEWUSER)` bwrap's own userns may already permit nested… assert the FILTER's effect by running the same helper without the shim (bwrap only) and observing the call succeeded/differs, as the oracle).
- [ ] **Step 2: Fork bomb and memory hog through `runtime run`** (Task 4's fixture modes) as escape tests: the host stays responsive, the app is limited.
- [ ] **Step 3: Re-run everything** (full workspace, all real-Wine suites, D3D11 under the default sandbox per device) with seccomp+Landlock+limits on; add/refresh compat records ("d3d11 clear fixture under the default sandbox (seccomp + Landlock)") ONLY for runs actually done today; regenerate docs/COMPAT.md.
- [ ] **Step 4:** SECURITY.md: replace the "no seccomp/Landlock/cgroups until 5B" statements with what is now true and what still is not (in-kernel bugs in allowed syscalls, same uid, shared X11/GPU/audio, Landlock best-effort, no network filtering); README; full gate; commit `test(cli): seccomp, Landlock and limits escape tests; docs for Phase 5B`.

---

## Self-Review

- Spec criteria: 1 -> Tasks 1, 3, 5; 2 -> Tasks 2, 3; 3 -> Task 4 (+ 5); 4 -> Tasks 1, 5.
- Placeholders: none; the few empirical points (i386 arch handling, Landlock unix-socket connect semantics, `IOCTL_DEV`, `systemd-run --scope` pid behaviour) are explicit investigate-and-record steps with acceptance tests.
- Types: `SockFilter`, `Arch`, `build_filter`, `install`, `Rule`, `Access`, `Applied`, `InitArgs`, `Limits` are named identically across tasks.
