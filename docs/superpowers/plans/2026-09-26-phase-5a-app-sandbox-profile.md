# Phase 5A Per-App Permissions and Run Sandbox Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `runtime run` starts the program inside a bubblewrap sandbox built from a per-app, validated `permissions.toml` (default: no network, no host dirs, GUI baseline allowed), with `runtime permissions`, `runtime sandbox` and an explicit `--unsandboxed` escape hatch, and an escape-attempt suite.

**Architecture:** New crate `crates/sandbox` (`rt_sandbox`): a strict `Permissions` model and an `AppSandbox` that implements `rt_core::Sandbox` as a pure argv builder over an injected host view; it derives the prefix (and so the app root and its `permissions.toml`) from the wrapped command's `WINEPREFIX`. `rt_core::RunOptions` gains an optional sandbox applied only to the final app spawn. The CLI adds `permissions`, `sandbox` and `run --unsandboxed`; doctor gains a Sandbox check.

**Tech Stack:** Rust workspace, `toml`+`serde` (present), `libc` (present), bubblewrap 0.11.1 (`/usr/bin/bwrap` on this host), real Wine 10.0.

**Spec:** `docs/superpowers/specs/2026-09-26-app-sandbox-profile-design.md`

## Global Constraints

- Fail closed: bwrap missing or unable to create the sandbox => `run` errors with an install hint; never a silent unsandboxed run. `--unsandboxed` is per invocation and prints a stderr line saying so.
- The sandbox never binds the app root (`permissions.toml` must not be reachable, let alone writable); it binds only `prefix` and `<root>/runtime/home` read-write.
- Never bind the real `$HOME`, `/root`, other apps' prefixes or the runtime data root; `--dev-bind` only for the explicit GPU nodes.
- Host directory grants are validated (absolute, canonical-looking, not `/`, not `$HOME` itself, not at/above/below the data root, not on the fixed sensitive list); a stored profile that fails validation at run time is refused, not silently narrowed.
- Untrusted text (paths, error text) is printed through `safe`/`clean`.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` stay green after every task; real-bwrap tests skip visibly when bwrap or user namespaces are unavailable and are REQUIRED when `RUNTIME_REQUIRE_BWRAP=1`.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## Review Focus

- `permissions.toml` hostile input (unknown key, 1 MiB, control characters, `fs` paths with `..`, relative, `/`, `$HOME`, a symlink to home, the data root, another app's prefix, `~/.ssh`): every one refused with a reason, nothing panics (Task 1).
- `--set` while the app runs, with a symlinked `permissions.toml`, with an oversized file: refused, nothing written (Task 1).
- A profile with `network=allow` and no `resolv.conf` reachable: DNS behaviour documented and tested (Task 2).
- A GPU/display/audio grant whose host socket or node does not exist: skipped, not an error, and `runtime sandbox` says which ones were missing (Task 2).
- Ctrl-C in `runtime run` reaches a sandboxed console program and ends it (Task 3).
- The wrapped `wineserver -k` / `wineboot` helpers are NOT sandboxed (Task 3).
- Escape suite: real home secret unreadable, write outside prefix denied, `permissions.toml` unreadable/unwritable, other app prefix invisible, network denied (Task 4).

---

### Task 1: `rt_sandbox::permissions` and `runtime permissions`

**Files:**
- Create: `crates/sandbox/Cargo.toml` (package `runtime-sandbox`, lib `rt_sandbox`, deps `runtime-core`, `serde`, `toml`, `thiserror`, `libc`; dev-deps `tempfile`, `runtime-core` with `testing`), `crates/sandbox/src/lib.rs`, `crates/sandbox/src/permissions.rs`, `crates/cli/src/permissions.rs`
- Modify: `crates/cli/Cargo.toml` (dep), `crates/cli/src/main.rs` (subcommand), README (usage), `docs/THIRD_PARTY.md` only if a new dependency is added (none expected)
- Test: `crates/sandbox/src/permissions.rs` tests; `crates/cli/tests/apps.rs` (rig)

**Interfaces:**
- Produces:
  ```rust
  pub enum Network { Deny, Allow }
  pub enum Access { Ro, Rw }
  pub struct FsGrant { pub path: PathBuf, pub access: Access }
  pub struct Permissions { pub network: Network, pub display: bool, pub audio: bool, pub gpu: bool, pub filesystem: Vec<FsGrant> } // Default = deny net, display/audio/gpu on, no fs
  impl Permissions {
      pub fn parse(text: &str, ctx: &GrantCtx) -> Result<Permissions, PermError>;   // strict: deny_unknown_fields, version = 1, <= 64 KiB, <= 64 grants
      pub fn to_toml(&self) -> String;                                              // canonical, stable
      pub fn apply_set(&mut self, expr: &str, ctx: &GrantCtx) -> Result<(), PermError>; // network=allow|deny, display|audio|gpu=on|off, fs+=<abs>:ro|rw, fs-=<abs>
  }
  pub struct GrantCtx { pub home: PathBuf, pub data_root: PathBuf }
  pub fn validate_grant(path: &Path, ctx: &GrantCtx) -> Result<PathBuf, PermError>;  // see Global Constraints; canonicalises with symlinks resolved and re-checks
  pub fn load(app_root: &Path, ctx: &GrantCtx) -> Result<Permissions, PermError>;   // missing file => Default; O_NOFOLLOW, regular file, size cap
  pub fn store(app_root: &Path, p: &Permissions) -> Result<(), PermError>;          // atomic (tmp + rename) mode 0600, refuses symlinked target
  ```
  CLI: `runtime permissions <app>` prints the profile as the canonical TOML plus a one-line "source: default|permissions.toml"; `--set <expr>` (repeatable) validates all then writes once; `--reset` deletes the file; `--json` prints `{"network","display","audio","gpu","filesystem":[{"path","access"}]}`. Refused while a wineserver runs for the prefix (`rt_deps::wineservers_for`) and takes the app lock exclusively (as `runtime display` does: see crates/cli/src/display.rs for the exact sequence validate -> lock -> re-validate -> write).

- [ ] **Step 1: Write failing tests** for: default; parse/round-trip of a full profile; every rejection in Review Focus with the error variant asserted; `apply_set` for each expression form incl. removal and duplicate add (idempotent), bad syntax (`net=allow`, `fs+=rel:ro`, `fs+=/x:rx`); the sensitive list (`~/.ssh`, `~/.gnupg`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.password-store` under the ctx home, and any path that is an ANCESTOR of one of them, e.g. `$HOME` and `~/.config`? — ancestors of a sensitive dir are refused only if they are `$HOME` itself or `/`; deeper ancestors like `~/.config` ARE refused too, with a message naming the sensitive child); data-root cases (equal, ancestor, descendant); a symlink grant resolving into home is judged by its target; `load` with symlink/FIFO/oversized/hostile bytes; `store` atomicity (file is either old or new; mode 0600); mutation loop over a valid file (no panic).
- [ ] **Step 2: Run to verify failure** (`cargo test -p runtime-sandbox`), implement, run to pass.
- [ ] **Step 3: CLI tests** on the rig (fake Wine as neighbouring tests use): show default; set network=allow then show; set with a bad expression exits 2/1 with usage text and writes nothing; `fs+=` of `~/.ssh` refused; refused while a fake wineserver runs (copy the technique from the `display` test); `--reset`; `--json` parses back; app id validation as in `display`.
- [ ] **Step 4: Implement** the CLI module reusing `lock_or_refuse`, `wineservers_for`, `safe`; README paragraph; full gate.
- [ ] **Step 5: Commit:** `git commit -m "feat(sandbox,cli): per-app permissions.toml and runtime permissions"`

---

### Task 2: bubblewrap profile renderer (`AppSandbox`)

**Files:**
- Create: `crates/sandbox/src/render.rs`, `crates/sandbox/src/host.rs`
- Modify: `crates/sandbox/src/lib.rs` (`find_bwrap`, `probe`, re-exports)
- Test: `crates/sandbox/src/render.rs` tests

**Interfaces:**
- Consumes: `Permissions` (Task 1); `rt_core::Sandbox`; the installer sandbox's `RO_BINDS` set (copy the list into `rt_sandbox` as its own constant with a comment pointing at `rt_installer::sandbox::RO_BINDS`; do NOT make `rt_sandbox` depend on `rt_installer`, and do not refactor the installer sandbox).
- Produces:
  ```rust
  pub trait Host { fn env(&self, name: &str) -> Option<OsString>; fn exists(&self, p: &Path) -> bool; }   // RealHost for production, FakeHost in tests
  pub struct AppSandbox { /* bwrap path, Permissions, ro_binds (backend dll dirs), Arc<dyn Host> */ }
  impl AppSandbox { pub fn new(bwrap: PathBuf, perms: Permissions, ro_binds: Vec<PathBuf>, host: Arc<dyn Host>) -> AppSandbox;
                    pub fn argv_preview(&self, cmd: &Command) -> Vec<OsString>;  // what `runtime sandbox` prints
                    pub fn skipped(&self, cmd: &Command) -> Vec<String>; }       // requested-but-missing host bits (sockets/nodes)
  impl rt_core::Sandbox for AppSandbox { fn wrap(&self, cmd: Command) -> Command }
  ```
  Profile (order matters, mirror the reasoning comments of `rt_installer::sandbox::InstallerSandbox::wrap` about later mounts winning): `--die-with-parent --new-session --unshare-pid --unshare-uts --unshare-ipc` (+ `--unshare-net` unless network allow); `--proc /proc`; `--dev /dev`; `--tmpfs /tmp`; `--ro-bind-try` for `/usr /bin /lib /lib64 /etc/alternatives` and the small `/etc` set Wine/TLS need (`/etc/passwd /etc/group /etc/nsswitch.conf /etc/ld.so.cache /etc/localtime /etc/fonts /etc/ssl /etc/ca-certificates /etc/vulkan /etc/glvnd`, plus `/etc/hosts /etc/resolv.conf /run/systemd/resolve` ONLY with network allow) and the backend dll dirs (`ro_binds`); the prefix (from the command's `WINEPREFIX`) and `<prefix parent>/runtime/home` read-write; HOME env points at the app home (already the backend's choice — keep it), nothing else of the host home; `--tmpfs $XDG_RUNTIME_DIR` (if set and absolute, else `/run/user/<uid>`) then, per grant and only if the host path exists: display => Wayland socket (`$XDG_RUNTIME_DIR/$WAYLAND_DISPLAY`) bound at the same path, `/tmp/.X11-unix` read-only, `XAUTHORITY` file read-only (keep DISPLAY/WAYLAND_DISPLAY/XAUTHORITY env); audio => `$XDG_RUNTIME_DIR/pulse/native` (keep `PULSE_SERVER` if set and it points inside the runtime dir, else set `PULSE_SERVER=unix:<socket>`); gpu => `--dev-bind-try` `/dev/dri`, `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools`, `/dev/nvidia-modeset`, every `/dev/nvidia<N>` that exists, plus `--ro-bind-try /sys/dev/char`, `/sys/devices`, `/sys/class/drm`, `/run/opengl-driver`; `--dev-bind` is never used for anything else; each `filesystem` grant `--ro-bind`/`--bind` (re-validated against the same ctx at render time: a grant that no longer validates is a render error, not skipped); then `--` program args; env: exactly the finalized command's env minus variables for features that are OFF (display off => drop DISPLAY/WAYLAND_DISPLAY/XAUTHORITY; audio off => PULSE_SERVER; network never affects env), cwd copied.
  `find_bwrap`/`probe`: `probe()` runs `bwrap --unshare-all --die-with-parent --ro-bind / / true` once (bounded 5 s, output capped) and returns `Ok`/`Err(reason)` ("user namespaces are disabled: ..." etc.).

- [ ] **Step 1: Failing tests** (Command introspection, FakeHost): default profile argv exact (frozen expected argv Vec) with WINEPREFIX=/data/apps/a/prefix; each switch in isolation (network allow drops `--unshare-net` and adds resolv binds; display off drops sockets+env; audio off; gpu off drops all dev-binds; extra grant ro and rw); missing sockets/nodes skipped and reported by `skipped()`; the app root is never bound (assert no arg equals the app root and no `--bind` targets its parent); another env var (`SSH_AUTH_SOCK`, `LD_PRELOAD`) that somehow is in the finalized command is dropped (allowlist re-applied) — the launcher already filters, this is defence in depth; a `WINEPREFIX`-less command => render error/refusal (no sandbox without an app to bind); a re-validation failure of a stored grant => error; `$XDG_RUNTIME_DIR` unset/relative => audio/display sockets skipped with a note; ordering test: prefix bind after any ancestor tmpfs.
- [ ] **Step 2: Implement** `render.rs` (pure), `host.rs` (`RealHost`), `lib.rs` (`find_bwrap` via PATH like the installer's, `probe`), run tests.
- [ ] **Step 3: One real-bwrap smoke test** (skips visibly without bwrap/userns; required under RUNTIME_REQUIRE_BWRAP): wrap `/bin/sh -c 'echo ok; ls /home'` with a temp prefix and default profile, run it, assert `ok` and that the real `$HOME` listing is empty/absent.
- [ ] **Step 4: Full gate; commit:** `git commit -m "feat(sandbox): render a per-app permission profile to a bubblewrap command"`

---

### Task 3: wire into `runtime run`, `runtime sandbox`, doctor

**Files:**
- Modify: `crates/core/src/run.rs` (`RunOptions.sandbox`), `crates/cli/src/run.rs`, `crates/cli/src/main.rs` (`--unsandboxed`, `sandbox` subcommand, remove/replace `SANDBOX_NOTE`), `crates/cli/src/doctor.rs` and `crates/core/src/doctor.rs` (Sandbox check), `crates/cli/src/sandbox.rs` (new), README, docs/SECURITY.md (Phase 5A section; update the "Phase 2 is NOT a sandbox" statements to say `run` is sandboxed by default, what is still NOT covered: no seccomp/Landlock/cgroups until 5B, same uid, GPU/display sockets are an attack surface, network-allow is the host network)
- Test: `crates/core/src/run.rs` tests, `crates/cli/tests/apps.rs`, `crates/cli/tests/e2e_wine.rs` (real Wine)

**Interfaces:**
- Consumes: `AppSandbox`, `Permissions::load`, `find_bwrap`, `probe` (Tasks 1-2); `CompatBackend::dll_dirs()`; `rt_core::start`.
- Produces: `RunOptions { debug: bool, sandbox: Option<Arc<dyn Sandbox>> }` (drop `Copy`/`Eq` derives as needed; update all constructors — grep) applied ONLY to the app spawn inside `start_in` (the prepare/harden/stop helpers keep using the plain launcher). CLI: `runtime run [--unsandboxed] <app|file> [-- args]`: default builds `AppSandbox` from the app's permissions (for a `Target::File` run the default profile) after finding bwrap and running `probe()`; probe failure or missing bwrap => error "cannot start the sandbox: <reason>. Install bubblewrap (`sudo apt install bubblewrap`) or rerun with --unsandboxed (NOT sandboxed)". `--unsandboxed` prints `warning: running WITHOUT a sandbox (--unsandboxed)`. `runtime sandbox <app>`: prints bwrap availability (`probe`), the profile summary, the skipped host bits, and the full argv preview for the app's executable (quote each arg; paths through `safe`); exit 0; needs no running Wine.

- [ ] **Step 1: Failing tests:** core `start_in` applies the sandbox hook to the app spawn only (fake backend/launcher records which commands were wrapped: prepare/stop helpers NOT wrapped); CLI: run without bwrap on PATH (rig PATH without it) => error text above and exit 1, nothing started; `--unsandboxed` runs and warns; `runtime sandbox <app>` prints argv containing `--unshare-net` for the default profile and `--bind <prefix> <prefix>`, never the app root; doctor Sandbox line for system and app targets (Ok when probe ok; Warn with reason otherwise; the app line summarises the profile); a real-Wine e2e (`e2e_real_wine_run_under_sandbox`, prefix so CI's filter picks it up, requires bwrap): install `hello64.exe` through the existing e2e helper and `runtime run` it under the default sandbox, exit code 7 as the existing MVP e2e expects.
- [ ] **Step 2: Ctrl-C:** investigate for real what happens to SIGINT with `--new-session`: the CLI ignores SIGINT while the child runs (crates/cli/src/run.rs `IgnoreSigint`). Implement forwarding: while a sandboxed child runs, install a handler (or use a signal-waiting thread with `sigwait`) that forwards SIGINT and SIGTERM to the sandbox process GROUP (the bwrap child is spawned in its own session by `--new-session`; use the child's pid as pgid or signal the pid if bwrap is not a group leader — verify empirically which works and that bwrap forwards to its init/child). Test with a console fixture that loops (add `tools/fixtures/spin.c`? if a loop fixture does not exist, use `fs64.exe` with a long sleep argument if it supports one, else add a tiny `spin.c` console fixture built by build-fixtures.sh): send SIGINT to the CLI, assert the app ends within 10 s and the CLI exits 130. If forwarding cannot be made reliable, STOP and report BLOCKED with findings (do not ship a run whose Ctrl-C silently does nothing).
- [ ] **Step 3: Implement** everything; replace `SANDBOX_NOTE` (now false for the sandboxed default): print nothing extra when sandboxed, keep an honest one-line note for `--unsandboxed`. Update every command that prints the old note (`grep -rn SANDBOX_NOTE`).
- [ ] **Step 4: Run** the e2e locally (`cargo test -p runtime-cli --test e2e_wine -- --ignored e2e_real_wine_run_under_sandbox --nocapture`, with `RUNTIME_REQUIRE_BWRAP=1`), full gate; SECURITY.md and README updates.
- [ ] **Step 5: Commit:** `git commit -m "feat(cli): runtime run is sandboxed by default; runtime sandbox and --unsandboxed"`

---

### Task 4: escape-attempt suite and Phase 2-4 apps under the sandbox

**Files:**
- Create: `crates/cli/tests/e2e_sandbox.rs` (real bwrap and real Wine; `#[ignore]` tests named `e2e_real_wine_sandbox_*` so CI's existing `-p runtime-cli -- --ignored` step runs them)
- Modify: `.github/workflows/ci.yml` (only if the new tests need an env var or package the job lacks; keep the existing filters), docs/COMPAT.md source `crates/cli/compat.toml` (new records ONLY for runs actually done), README/SECURITY.md (escape-suite description)
- Test: the file itself

**Interfaces:**
- Consumes: the rig/e2e helpers used by `e2e_wine.rs`/`e2e_installers.rs` (fresh data root, fixtures in `tests/fixtures/build`), `runtime` binary.
- Produces: tests only.

- [ ] **Step 1: Escape tests with a real Windows program.** Extend the fixture `tools/fixtures/fs.c` (or add `tools/fixtures/probe.c`, built by `tools/build-fixtures.sh` for x86_64) into a console program that, given arguments, attempts one action and exits 0 if it SUCCEEDED and 1 if it FAILED: `read <path>` (open+read 1 byte), `write <path>`, `list <path>`, `connect <ip> <port>` (winsock TCP connect, 2 s timeout). Wine exposes host paths through `Z:` ONLY if that drive exists; Phase 2 removed `Z:` and the home links (docs/SECURITY.md) — use the Unix-path escape hatch Wine still has (`\\?\unix\<path>` NT paths, documented in SECURITY.md) AND the inside-the-sandbox truth that the path simply is not mounted: the test's oracle is "the action FAILED under the sandbox and SUCCEEDED with `--unsandboxed`" for the same target, which proves the sandbox (not Wine) made the difference.
- [ ] **Step 2: The suite** (each test creates a temp `HOME` with a canary file `~/.ssh/id_test` = "secret" and points the run at it via the environment the host would have; a temp second app prefix with a canary; a TCP listener on 127.0.0.1:<port> in the test process):
  1. read of the canary in the real `$HOME/.ssh/` FAILS sandboxed, SUCCEEDS with `--unsandboxed` (oracle);
  2. write to `$HOME/escape.txt` FAILS sandboxed (file must not exist afterwards), succeeds unsandboxed;
  3. read of the OTHER app's prefix canary FAILS sandboxed;
  4. read and write of `<own app root>/permissions.toml` FAIL sandboxed; the file is byte-identical afterwards;
  5. TCP connect to the local listener FAILS with the default profile; SUCCEEDS after `runtime permissions <app> --set network=allow`;
  6. a granted directory: `--set fs+=<tempdir>:ro` makes read succeed and write fail; `:rw` write succeeds; the parent directory of the grant stays invisible;
  7. `runtime permissions <app> --set 'fs+=<home>/.ssh:ro'` is refused (CLI level, no run needed);
  8. `--unsandboxed` really is unsandboxed and prints the warning.
- [ ] **Step 3: Exit criteria run:** re-run the existing real-Wine e2e apps with the sandbox ON by default (they go through `runtime run` after this phase): `cargo test -p runtime-backend-wine -p runtime-cli -- --ignored --test-threads=1 --nocapture` with `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1` and `cargo test -p runtime-deps --lib -- --ignored e2e_real_wine --test-threads=1 --nocapture`; fix anything the sandbox broke IN THE SANDBOX PROFILE (Task 2 code) — not by weakening the tests; report every profile change in the fix report. Then run the D3D11 DXVK fixture through `runtime run` under the default sandbox on this host (display session present) and record the result: add a compat record `d3d11 clear fixture under the default sandbox` (per device that was actually run, `manual:<today>`, `works` only if `pixel ok`), regenerate `docs/COMPAT.md`.
- [ ] **Step 4:** SECURITY.md: the escape suite and what it does NOT prove (no seccomp/Landlock yet, GPU/display/audio sockets are reachable when granted, network allow = host network, same uid). Full gate; commit `test(cli): sandbox escape attempts and the Phase 2-4 apps under the default sandbox`.

---

## Self-Review

- Spec criteria: 1 -> Tasks 2-4; 2 -> Tasks 1-2; 3 -> Tasks 1 and 3; 4 -> Task 3; 5 -> Task 4.
- Placeholders: none; investigation steps (SIGINT forwarding, fixture choices) carry explicit acceptance criteria and a STOP rule.
- Types: `Permissions`, `FsGrant`, `Network`, `Access`, `GrantCtx`, `AppSandbox`, `Host`, `RunOptions.sandbox` are named identically across tasks.
