# Phase 5, sub-project B: seccomp, Landlock and resource limits (design)

Status: approved by the controller on the user's standing instruction (2026-09-25: self-approve with recommended
choices). Second of three Phase 5 sub-projects (5A bubblewrap profile is merged; 5C portal "ask" flows is
optional and comes last). Roadmap: "renderer to bubblewrap args + Landlock rules + seccomp deny-list;
`systemd-run --user --scope` (cgroup v2) for memory/CPU limits".

## 1. Purpose and success criteria

5A confines what the program can SEE and REACH (mounts, namespaces). It does not limit what the program can ASK
THE KERNEL to do: the sandbox still shares the host kernel attack surface, keyctl/ptrace/bpf/mount-family
syscalls, `TIOCSTI` terminal injection, nested user namespaces, and a fork bomb or memory hog can take the desktop
down. 5B adds three independent layers, each defence in depth against a flaw in the layer beneath it:

1. **seccomp deny-list** (mandatory, fail closed): dangerous syscalls return `EPERM`; Wine and DXVK still work.
2. **Landlock filesystem ruleset** (best-effort, disclosed): the same paths the bwrap mounts expose, enforced a
   second time by the kernel LSM, so a mount-setup mistake is not a hole.
3. **cgroup limits** via `systemd-run --user --scope`: `TasksMax` by default (fork-bomb guard), optional
   `MemoryMax` and `CPUQuota` per app; explicitly configured limits are mandatory, the default is best-effort.

Success criteria:

1. Inside the sandbox, each denied syscall class fails with `EPERM` (tested with a real program under real
   bwrap): `ptrace`, `keyctl`/`add_key`/`request_key`, `bpf`, `perf_event_open`, `userfaultfd`, `mount`/`umount2`/
   `pivot_root`/`chroot`/`unshare`/`setns`, `clone`/`clone3` with `CLONE_NEW*` flags, `kexec_load`,
   `open_by_handle_at`, `ioctl(TIOCSTI)`/`TIOCLINUX`, `syslog`, `acct`, `quotactl`, `swapon`/`swapoff`,
   `reboot`, `init_module`/`finit_module`/`delete_module`, and 32-bit-ABI (`int 0x80`/x32) entry on x86-64.
   Everything Phase 2-4 exercised still passes with the filter on: the console/GUI/installer fixtures and the
   D3D11 DXVK fixture on RADV, NVIDIA and llvmpipe.
2. With Landlock available, a path the bwrap profile does not expose is ALSO refused by Landlock (proved by a
   test that punches a hole in the mount layer on purpose, e.g. a debug-only extra bind, and sees Landlock still
   deny it); with Landlock unavailable the run proceeds and `runtime sandbox` / `doctor` say so.
3. `runtime permissions <app> --set memory=<MiB>`, `cpu=<percent>`, `tasks=<n>` work; a program that forks past
   `TasksMax` gets `EAGAIN` and does not take the host down; an over-`memory` program is OOM-killed inside the
   scope, not the desktop. `--set memory=off` etc. remove a limit. Missing `systemd-run --user` with an explicit
   limit configured refuses the run (fail closed).
4. `TIOCSTI` is no longer a reason to rely on `--new-session` alone: it stays (defence in depth) but the filter
   makes the terminal-injection class dead on kernels where the sysctl allows it.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Where the filter is applied | A hidden `runtime sandbox-init` shim that runs INSIDE bwrap as the program's launcher: it applies rlimits, Landlock, then `prctl(PR_SET_NO_NEW_PRIVS)` + `seccomp(SET_FILTER)`, then `execve`s the real program | No fd-passing into bwrap, no C library, one place for all in-process hardening; the filter is inherited by every Wine process. bwrap binds the runtime executable read-only at its own path. |
| seccomp implementation | Hand-assembled classic BPF built by a small Rust generator (arch check, syscall-number deny-list, argument checks for `ioctl` and `clone`/`clone3`), no new dependency | The filter is ~60 instructions of pure data; a dependency (`libseccomp`, `seccompiler`) would add C code or a supply-chain surface for something we can test directly by running a program under it. |
| Deny-list vs allow-list | Deny-list (returns `EPERM`, not kill) | Wine's syscall use is broad and version-dependent; an allow-list breaks apps silently. `EPERM` (Flatpak's choice) lets programs degrade instead of dying. |
| Landlock | Best-effort: negotiate the highest ABI the kernel offers, restrict filesystem access to the rule set the bwrap profile mounts; unavailable => proceed and report | Landlock needs kernel 5.13+ and the LSM enabled; a hard requirement would lock out valid hosts, and the real boundary is bwrap. It is defence in depth and says so. |
| Landlock scope | Filesystem rules only in 5B (read/exec on system dirs, read-write on prefix, home, tmp, runtime dir and granted dirs); network rules (ABI 4) not used because `--unshare-net` already covers deny and `allow` means all | Smallest correct change; network rules can follow if a use appears. |
| Limits | New optional `[limits]` keys `memory_mb`, `cpu_percent`, `tasks` in `permissions.toml`; default `tasks = 4096`, no memory/CPU limit | A fork bomb is the cheapest way to hurt the user; memory and CPU limits depend on the workload so they are opt-in. |
| systemd-run | `systemd-run --user --scope --collect -p TasksMax=.. [-p MemoryMax=..M] [-p CPUQuota=..%] --` wrapping bwrap; the scope is the resource boundary for the whole tree | The roadmap's choice; cgroup v2 delegation works for user scopes on modern systemd (verified on this host). |

Non-goals: seccomp allow-lists per app, network Landlock rules, per-app seccomp profiles beyond the one default,
IO/blkio limits, GPU limits, a daemon (Phase 6), portals (5C).

## 3. Components

- `crates/sandbox/src/seccomp.rs`: `build_filter() -> Vec<SockFilter>` (x86-64 and aarch64 syscall tables for the
  denied set; other architectures fail closed with a clear error at sandbox render time), `install(filter)`.
  Unit tests decode the generated program with a tiny BPF interpreter written for the tests, so every rule is
  checked without the kernel, plus real-kernel tests in a forked child.
- `crates/sandbox/src/landlock.rs`: raw syscalls (`landlock_create_ruleset`/`add_rule`/`restrict_self`), ABI
  negotiation, `Ruleset::from_paths`, best-effort apply returning `Applied { abi }` or `Unavailable(reason)`.
- `crates/sandbox/src/init.rs`: the shim entry: parse its argument block (a versioned, strictly validated
  argument list the renderer builds; it trusts nothing from the environment), set `RLIMIT_CORE=0`, apply Landlock,
  apply seccomp, `execve`. Any failure of a MANDATORY step exits 126 with the reason; Landlock failure is logged
  to a line on stderr only when it is `Unavailable`, never fatal.
- `crates/cli`: hidden subcommand `sandbox-init`; `runtime sandbox <app>` shows filter and Landlock status, limits,
  and the systemd-run line; doctor's Sandbox check adds seccomp architecture support, Landlock ABI and
  systemd-run availability.
- `crates/sandbox/src/render.rs`: prefix the program with the shim (binding the runtime executable read-only),
  wrap bwrap in `systemd-run` when limits apply, extend caveats.
- `crates/sandbox/src/permissions.rs`: `[limits]` table, `--set memory=|cpu=|tasks=`, validation (bounds:
  memory 64 MiB..1 TiB, cpu 1..(100 x cores), tasks 16..65536).

## 4. Testing

Interpreter-level BPF tests; a real-kernel test program (the probe fixture cannot issue raw syscalls, so a small
Linux helper compiled by the tests or a Rust test binary re-exec'd inside bwrap) that attempts each denied
syscall and asserts `EPERM`; Landlock hole-punch test; limits tests with real `systemd-run` (fork bomb capped,
memory hog killed in a low `MemoryMax`); every Phase 2-4 real-Wine suite and the D3D11 fixture re-run with the
filter on.

## 5. Risks

- A denied syscall Wine turns out to need (e.g. `ptrace` for some anti-cheat, `personality`/`unshare` for
  helpers): mitigated by `EPERM` semantics and by the compatibility runs; per-app relaxation is a non-goal here
  and would need its own design (documented as "programs that need ptrace do not run in the sandbox").
- Landlock ABI churn: negotiated, never assumed.
- systemd user manager absent (containers, SSH sessions without lingering): explicit limits refuse, default
  `TasksMax` degrades with a doctor warning.
