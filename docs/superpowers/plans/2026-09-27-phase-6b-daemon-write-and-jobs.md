# Phase 6B `runtimed` write methods and jobs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clients drive the runtime through `runtimed --write` (run/stop, install, remove, deps install, permissions, display) as jobs that spawn the sibling `runtime` CLI with a validated argv, with long-polled, cleaned output and state, and no new way around consent, the sandboxes, the app lock or the running-app refusals.

**Architecture:** `rt_api::jobs` validates typed params into a `JobSpec` and renders its argv (pure); `runtime deps --install` gains a `--plan-digest` guard; `rt_daemon::jobs` owns the processes (spawn, readers, ring, cancel, shutdown); dispatch gains a context with the job table and a read-only mode; the client gains typed helpers.

**Tech Stack:** Rust workspace; `serde`/`serde_json`, `libc` (getrandom, prctl, waitid, kill), `sha2` (already a workspace dependency, new edge from `runtime-api`); std threads and `Condvar`. No new third-party dependency, no async runtime.

**Spec:** `docs/superpowers/specs/2026-09-27-daemon-write-methods-design.md`

## Global Constraints

- The daemon never reimplements a mutation: every write method starts a job running `<dir of runtimed>/runtime` with `JobSpec::argv()`. No shell, no string concatenation into argv, no client-supplied environment variable, cwd or fd.
- Default is read-only. Every method added in 6B answers `-32000 read_only` without `--write`; unknown names stay `-32601`; notifications are never executed.
- No API parameter maps to `--unsandboxed`, `--debug`, or a blanket consent; `--yes=` only ever carries a package id that matched the recomputed plan.
- Every event text passes `rt_core::clean_text(_, 4096)`; every error message is fixed text or cleaned (6A rule).
- Bounded everything: 4 running jobs, one live job per app, 100 finished jobs / 1 h, 2,000 events and 512 KiB per job, 500 events per poll, `waitMs <= 25000`, 8 waiting polls, SIGKILL 5 s after SIGTERM.
- Tests never touch the real `$XDG_RUNTIME_DIR`, data dir or `runtime` binary except the e2e's explicit real-binary runs in scratch dirs; each process test has a short deadline so a bug cannot hang the suite; Wine-dependent tests are `#[ignore]` like the existing e2e.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` green after every task. `the_documented_methods_are_the_dispatch_table` stays green: a task that adds a method adds its API.md table row.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- Argv injection: a value that starts with `-`, equals `--`, contains a newline or NUL, or an id that `run` would read as a path (`x.exe`), reaching the CLI as anything but the intended value (Tasks 1, 2).
- Consent: any path to `--yes=` that does not go through the digest + exact `{package, version, sha256}` match; the CLI accepting a stale digest (Tasks 1, 2).
- Processes: a signal sent to a pgid after its leader was reaped; a child that survives cancel or daemon shutdown; a job spawned from a thread that exits (PDEATHSIG fires early); a reader that stops draining (child blocks); an env var or fd leaking into the child (Task 3).
- Server: a long-poll that outlives the per-request deadline, delays shutdown past one tick, or lets pollers occupy more than 8 slots; `--write` with a socket a sandbox could see (Task 4).
- Output: an unbounded ring, an event over 4 KiB, a reply over 16 MiB, control or bidi characters surviving (Tasks 3, 4).

---

### Task 1: `rt_api::jobs`: specs, validation, argv, plan digest, consent check

**Files:**
- Create: `crates/api/src/jobs.rs`
- Modify: `crates/api/src/{lib.rs,types.rs,error.rs,runtime.rs}`, `crates/api/Cargo.toml` (`sha2.workspace = true`)
- Test: unit tests in `jobs.rs` and `types.rs`

**Interfaces:**
- Produces:
  ```rust
  pub const API_VERSION: &str = "0.2.0";
  // error.rs: ErrorKind gains ReadOnly, ConsentMismatch, Busy, AppBusy (snake_case on the wire; Unknown fallback kept)
  // types.rs: VersionInfo { api, runtime, protocol, write: bool }   // Runtime::version() sets write: false; the daemon overrides
  //           PlanEntryView gains sha256: Option<String>, consent_text: Option<Vec<String>>  (lines cleaned; Some only for consent == needed)
  //           DepsPlanView gains digest: String
  pub enum JobKind { Run, Install, Remove, DepsInstall, PermissionsSet, PermissionsReset, DisplaySet }   // camelCase on the wire
  pub enum JobSpec {
      Run { app: AppId, args: Vec<String> },
      Install { path: PathBuf, name: Option<String>, exe: Option<String>, silent: bool, network: bool },
      Remove { app: AppId },
      DepsInstall { app: AppId, plan_digest: String, yes: Vec<String> },      // yes = package ids AFTER check_consent
      PermissionsSet { app: AppId, set: Vec<String> },
      PermissionsReset { app: AppId },
      DisplaySet { app: AppId, driver: Driver },                              // Driver { Auto, X11, Wayland }
  }
  impl JobSpec {
      /// Validates by-name params of one write method (not deps.install's consent: see Runtime::deps_install_spec).
      pub fn from_request(method: &str, params: serde_json::Value) -> Result<JobSpec, JobParamsError>;
      // enum JobParamsError { Shape(String /* cleaned */), Api(ApiError) }
      pub fn kind(&self) -> JobKind;
      pub fn app(&self) -> Option<&AppId>;           // None for Install
      pub fn argv(&self) -> Vec<std::ffi::OsString>; // without argv[0]; spec 5.1 table
  }
  pub struct ConsentItem { pub package: String, pub version: String, pub sha256: String }
  pub fn plan_digest(id: &AppId, plan: &rt_deps::AppPlan, manifest: &rt_deps::Manifest) -> String;
  pub fn check_consent(view: &DepsPlanView, digest: &str, consent: &[ConsentItem]) -> Result<Vec<String>, ApiError>;
  impl Runtime { pub fn deps_install_spec(&self, id: &str, digest: &str, consent: &[ConsentItem]) -> Result<JobSpec, ApiError>; }
  // wire types: JobStarted { job_id }, JobInfo, JobEvent { seq, ts, kind: EventKind, text }, JobEvents { events, next_seq, dropped, job },
  // JobState { Queued, Running, Succeeded, Failed, Cancelled }, EventKind { Stdout, Stderr, State, Progress }
  ```
- Consumes: `rt_core::{AppId, classify, TargetKind, clean_text, is_format}`, `rt_deps::{AppPlan, Manifest, consent_text}`.

- [ ] **Step 1: Failing tests:** validator tables for id (`-x`, `--`, `a b`, `a\nb`, `a\0b`, `x.exe`, `X.ZIP`, `a/b`, `..`, 65 bytes: all `invalid_argument`; `notepad` ok), path (relative, `/a/../b`, `/a/./b`, `/a/`, NUL, `\n`, U+202E, 4,097 bytes: refused; `/tmp/My Setup.exe` and `/-x/setup.exe` ok), `name`/`exe`/EXPR bounds and characters, program args (65 args, 4,097-byte arg, NUL refused; `--`, `-x`, `;`, `$(id)` kept verbatim), params of the wrong shape (not an object, an unknown member, a missing or mistyped field) => `JobParamsError::Shape` (the daemon maps it to -32602, as 6A does for shape errors), content errors => `JobParamsError::Api(invalid_argument)` (-32000); `argv()` golden for each spec including `name = "--network"` -> `--name=--network`; `plan_digest` stable across runs and changed by any one field; `check_consent`: right digest + exact items => the package ids; wrong digest, unknown package, version or sha256 differing by one char, duplicate item, item for a `notNeeded` or `alreadyInstalled` entry => `consent_mismatch`; `deps_plan` view has `digest`, `sha256`, and `consentText` only on `needed` entries, cleaned (a consent text with ESC and bidi characters in a test manifest); JSON round trip of every new type; `version().write == false`, `api == "0.2.0"`.
- [ ] **Step 2: Implement.** `from_request` uses `#[serde(deny_unknown_fields)]` param structs per method. `consentText` lines come from `rt_deps::consent_text(pkg)` split on `\n`, each cleaned.
- [ ] **Step 3:** full gate; commit `feat(api): job specs with validated argv, the deps plan digest and the consent check; API 0.2.0`.

---

### Task 2: the CLI side: `--plan-digest` and the argv contract

**Files:**
- Modify: `crates/cli/src/deps.rs` (the flag and its check), `crates/cli/src/main.rs` (help text of `Deps` only if needed)
- Test: `crates/cli/src/deps/tests.rs`, `crates/cli/tests/apps.rs` (new tests at the end), the deps rig tests where plans with packages exist

**Interfaces:**
- Produces: `runtime deps <app> --install --plan-digest HEX` (requires `--install`; refuses non-hex or wrong length at parse time): after computing the plan it is about to install, compare `rt_api::jobs::plan_digest(..)`; on mismatch print `error: the dependency plan changed since it was shown (digest ...); nothing was installed` and exit 1 before `check_yes`, the mark, or any network. Help text: "for clients that showed the plan to the user (runtimed); refuses when the plan differs".
- Consumes: Task 1's `plan_digest`, `JobSpec::argv`.

- [ ] **Step 1: Failing tests:** wrong digest => exit 1, nothing fetched or written (the rig's fetch log and the app tree unchanged); the digest `deps.plan` reports => same behaviour and output as without the flag; `--plan-digest` without `--install` => usage error 2. Parser oracle (a `#[cfg(test)]` module in `main.rs`): for every `JobSpec` variant with hostile values, `Cli::try_parse_from(["runtime"] + spec.argv())` yields exactly the intended `Cmd` (e.g. `Run { target: id, args: ["-x", "--", ";"], unsandboxed: false, debug: false }`; `Install { name: Some("--network"), network: false, .. }`; `Install { exe: Some("--silent"), silent: false, .. }`; `Permissions { set: ["--reset"], reset: false, .. }`; `Display { app, choice: Some("x11") }`; `Remove { app }`). Effect checks through the real binary on the fake-Wine rig for three of them: the install named `--network` exists, `permissions --set=--reset -- <id>` is refused by the expression grammar and changes nothing, `remove -- <id>` removes. `deps --install --plan-digest=<d> -- list` with an app named `list`: record whether clap routes it to the subcommand; if it does, make Task 1's validator refuse `list`/`cache` for `deps.install` and pin that here.
- [ ] **Step 2: Implement** the flag; no other CLI behaviour changes (existing CLI tests pass unchanged).
- [ ] **Step 3:** full gate; commit `feat(cli): deps --install --plan-digest refuses a plan that changed; tests pin the daemon's argv shapes`.

---

### Task 3: `rt_daemon::jobs`: spawn, readers, ring, limits, cancel, shutdown

**Files:**
- Create: `crates/daemon/src/jobs.rs`, `crates/daemon/tests/fixtures/fake-runtime.sh` (or written by the tests into a temp dir; prefer written: no fixture file to keep executable in git)
- Modify: `crates/daemon/src/lib.rs`, `crates/daemon/Cargo.toml` (no new dependency)
- Test: unit tests in `jobs.rs`

**Interfaces:**
- Produces:
  ```rust
  pub struct JobsConfig {
      pub runtime_exe: PathBuf,     // production: current_exe().with_file_name("runtime"); tests: a fake script
      pub cwd: PathBuf,             // $XDG_RUNTIME_DIR/runtime/job-cwd (spec D8)
      pub max_running: usize,       // 4
      pub keep_finished: usize,     // 100
      pub keep_for: Duration,       // 1 h
      pub term_grace: Duration,     // 5 s
      pub now: fn() -> SystemTime,  // injected clock for retention tests
  }
  pub struct Jobs { /* Arc<Mutex<Table>>, per-job Arc<(Mutex<JobData>, Condvar)> */ }
  impl Jobs {
      pub fn new(cfg: JobsConfig) -> Jobs;
      pub fn start(&self, spec: JobSpec) -> Result<JobStarted, ApiError>;          // busy / app_busy / unavailable
      pub fn poll(&self, id: &str, after: u64, wait: Duration, stop: &AtomicBool) -> Result<JobEvents, ApiError>;
      pub fn status(&self, id: &str) -> Result<JobInfo, ApiError>;
      pub fn cancel(&self, id: &str) -> Result<JobInfo, ApiError>;
      pub fn list(&self) -> Vec<JobInfo>;
      pub fn shutdown(&self, within: Duration);                                   // cancel all, wait for reaping
  }
  pub fn child_env(get: &dyn Fn() -> Vec<(OsString, OsString)>) -> Vec<(OsString, OsString)>;  // spec D9 allowlist
  pub fn check_runtime_exe(p: &Path, euid: u32) -> Result<(), ApiError>;         // spec D10 (lstat: regular, owner euid|0, mode & 0o022 == 0)
  pub fn check_job_cwd(p: &Path, euid: u32) -> Result<(), ApiError>;             // dir, not symlink, ours, 0700, empty
  ```
  Rules (spec 5.2-5.6): spawn on the job's supervisor thread (`process_group(0)`, `pre_exec`: `prctl(PR_SET_PDEATHSIG, SIGTERM)` then `getppid()` check -> `_exit(127)`; SAFETY comments, async-signal-safe calls only); a spawn failure is a `failed` job with a `stderr` event naming the cause (cleaned), not a request error, except the pre-spawn checks (`check_runtime_exe`, `check_job_cwd`), which are `unavailable` at `start`; the supervisor waits with `waitid(P_PID, pid, WEXITED | WNOWAIT)`, then locks the job, reaps with `waitpid`, records exit/signal and state, notifies; `cancel` and `shutdown` send `kill(-pgid, ..)` only under that lock while not reaped; readers split on `\n`/`\r`, cut at 4 KiB (` [cut]`), clean, push with `seq` and `ts` (Unix ms), evict at 2,000 events or 512 KiB text, count `dropped`; job ids from `libc::getrandom` (16 bytes, retry on EINTR, fail the start with `internal` otherwise); retention eviction on every `start`/`poll`/`list`; one live job per app.

- [ ] **Step 1: Failing tests** (the fake `runtime`: a `/bin/sh` script written to a temp dir that writes its argv NUL-separated, `env`, `pwd`, `ps -o pgid= $$` to files under `$RUNTIME_DATA_DIR/fake/`, then follows `$RUNTIME_DATA_DIR/fake/mode`: `ok`, `exit N`, `flood` (100,000 short lines), `longline` (1 MiB without newline), `hostile` (ESC `[31m`, U+202E, NUL, CR, invalid UTF-8), `sleep` (`trap '' TERM; sleep 60` for escalation), `child` (spawns a grandchild `sleep 60` in the group and waits)): argv file equals `spec.argv()`; env equals the allowlist (the test sets `SECRET=hunter2` and `LISTEN_FDS` in the injected env source; neither arrives); cwd is the job cwd; stdin is EOF; pgid == child pid != daemon pgid; `ok` => `succeeded (exit 0)` state events in order `queued`, `running`, `succeeded`; `exit 3` => `failed`, `exitCode 3`; `flood` => ring holds 2,000 newest, `dropped` exact, `seq` contiguous, total text <= 512 KiB; `longline` => one event of <= 4 KiB ending ` [cut]`, the child exits normally (never blocked); `hostile` => no control/format char in any event text; 5th start `busy`, 2nd start for one app `app_busy`, start for another app ok; retention: 101 finished => oldest evicted, 1 h + 1 ms with the injected clock => evicted, `status` of an evicted id `not_found`; `cancel` on `sleep` => SIGKILL after `term_grace` (set 300 ms in tests), state `cancelled`, `signal 9`; `cancel` on `child` => the grandchild is gone too (`kill(pid, 0)` ESRCH within 1 s); cancel after the leader exited on its own sends nothing (assert via a recorded "signals sent" counter in the job, test-only accessor); `shutdown(1 s)` with 3 live jobs => all reaped, all `cancelled`; `poll` returns immediately with events after `afterSeq`, waits until a new event or the end, returns after `wait` with no events, and returns within 150 ms when `stop` is set; 1,000 generated ids are unique 32-char lowercase hex; `check_runtime_exe`: symlink, group-writable, directory => refused; `check_job_cwd`: non-empty, 0755, symlink => refused.
- [ ] **Step 2: Implement.** Keep `unsafe` to `prctl`, `getppid`, `_exit`, `waitid`, `waitpid`, `kill`, `getrandom`, each with a SAFETY comment. No panics on any child output.
- [ ] **Step 3:** full gate; commit `feat(daemon): the job table: runtime children in their own process group, bounded cleaned output, cancel and shutdown`.

---

### Task 4: dispatch, `--write`, long-poll admission, shutdown order, unit file

**Files:**
- Modify: `crates/daemon/src/{dispatch.rs,server.rs,main.rs,protocol.rs (only if a constant moves)}`, `contrib/systemd/runtimed.service`, `docs/API.md` (method-table rows only; prose in Task 6)
- Test: `dispatch.rs` and `server.rs` tests (real sockets in temp dirs)

**Interfaces:**
- Produces:
  ```rust
  pub struct Ctx { pub rt: Runtime, pub jobs: Option<Jobs>, pub stop: &'static AtomicBool, pub waiting_polls: AtomicUsize }
  pub const WRITE_METHODS: &[&str] = &["apps.run", "apps.install", "apps.remove", "deps.install", "permissions.set",
      "permissions.reset", "display.set", "jobs.poll", "jobs.status", "jobs.cancel", "jobs.list"];
  pub const MAX_WAITING_POLLS: usize = 8;
  pub fn handle(ctx: &Ctx, req: Request) -> Option<Reply>;       // was (&Runtime, Request)
  pub fn serve(ctx: Arc<Ctx>, cfg: ServerConfig, listener: Option<UnixListener>) -> Result<(), ServeError>;
  // ServerConfig unchanged; stop moves into Ctx
  ```
  `METHODS` = 6A's list + `WRITE_METHODS` (API.md's table test covers both). `jobs: None` => every `WRITE_METHODS` name is `-32000 read_only` (params not even parsed); names in neither list `-32601`. `rpc.version` sets `write = jobs.is_some()`. `jobs.poll`: `waitMs` over 25,000 is `-32602`; admission: `waiting_polls.fetch_add` under the cap, else wait 0; always decrement (a guard). Shutdown order in `serve`: stop flag -> listener closed -> `jobs.shutdown(term_grace + 1 s)` -> existing drain (`GRACE`). `main.rs`: `runtimed [--socket PATH] [--write]`; in write mode: the socket (bound or inherited) must be inside `$XDG_RUNTIME_DIR` (compare canonicalised parent dirs; an inherited socket's path from `getsockname`), create/check `job-cwd` (0700, next to the socket dir as `$XDG_RUNTIME_DIR/runtime/job-cwd`), `check_runtime_exe`, `runtime --version` (5 s bound, stdout compared with `runtime <own version>`), else exit 1 with the reason; the startup log line says `mode: write` or `mode: read-only`. Unit: `ExecStart=%h/.cargo/bin/runtimed --write`, comments: what `--write` allows, that `DISPLAY`/`WAYLAND_DISPLAY` must be in the user manager's environment for `apps.run` to open windows.

- [ ] **Step 1: Failing tests:** over a real socket, read-only server: each `WRITE_METHODS` name => `read_only` (with valid and with garbage params), `apps.install2` => -32601; write server with a fake runtime (Task 3 config): `apps.remove` => `{jobId}`; `jobs.poll` long-poll returns when the fake prints (latency < 300 ms), on end, on `waitMs`, and within one tick of `stop`; `waitMs: 25001` => -32602; a write request without id => not executed (no job in `jobs.list`); 9 simultaneous `waitMs: 5000` polls on 9 connections: 8 wait, the 9th answers within 200 ms, and a 10th connection's `rpc.version` is answered meanwhile; `deps.install` with a wrong digest => `consent_mismatch` and no job; `rpc.version.write` true/false; stop with a running `sleep` job => `serve` returns within term_grace + GRACE bound and the child is gone; `main` helpers: `--write` with `--socket` outside a fake `XDG_RUNTIME_DIR` refused, inside accepted; version mismatch (fake runtime printing another version) refused.
- [ ] **Step 2: Implement**; keep 6A's tests passing (adapt only the `serve`/`handle` call sites).
- [ ] **Step 3:** full gate; commit `feat(daemon): write methods behind --write, long-polled jobs, jobs die with the daemon`.

---

### Task 5: client helpers, `daemon-status` mode, end to end

**Files:**
- Modify: `crates/daemon/src/client.rs`, `crates/cli/src/rpc.rs`
- Test: `client.rs` tests, `crates/daemon/tests/e2e.rs` (new tests), `crates/daemon/tests/e2e_jobs.rs` (new; real binaries)

**Interfaces:**
- Produces: `Client::{run_app(id, args), install(&InstallParams), remove(id), deps_install(id, digest, &[ConsentItem]), permissions_set(id, &[String]), permissions_reset(id), display_set(id, Driver)} -> Result<JobStarted, ClientError>`, `job_poll(id, after, wait_ms) -> JobEvents`, `job_status`, `job_cancel`, `jobs() -> Vec<JobInfo>`. `job_poll` uses a per-call deadline of `wait_ms + 15 s` (never below the default 40 s). `runtime daemon-status` prints `mode: write` / `mode: read-only` (from `rpc.version.write`; an older daemon without the field prints `mode: read-only (API <v>)`).

- [ ] **Step 1: Failing tests:** every helper against the in-process server with a fake runtime; a hostile fake daemon returning job events with ESC/bidi in `text` => `runtime rpc jobs.poll` output escapes them (6A's re-serialisation already does; add the case). e2e A (sibling mechanism, no env override): copy `CARGO_BIN_EXE_runtimed` into a temp dir next to a fake `runtime` script that answers `--version` with the right version; start `runtimed --write --socket $XDG/runtime/runtimed.sock` with a scratch `XDG_RUNTIME_DIR`; `apps.remove` with id `-rf` => `invalid_argument` and no child started, with `notepad` => the fake records exactly `remove -- notepad`; cancel of a `sleep` job; SIGTERM to the daemon with 2 live jobs => both fake children gone (`/proc/<pid>` absent) within 7 s and the daemon exits 0; SIGKILL to the daemon => the fake child gets SIGTERM (PDEATHSIG; its trap writes a marker) within 1 s. e2e B (real `runtimed --write` + real `runtime` from next to it, the CLI rig's fake Wine through `RUNTIME_WINE`/`RUNTIME_WINESERVER` in the daemon's env): `apps.install` of a portable exe => job `succeeded`, `apps.list` shows it; `permissions.set ["network=allow"]` then `permissions.get` shows allow; `permissions.set ["fs+=$HOME:rw"]` => job `failed` with the CLI's refusal in `stderr` events; `display.set x11` succeeded; `deps.plan` then `deps.install` with its digest and no consent => succeeded (empty plan); `apps.run` => job ends `failed` or with the CLI's sandbox error, and no event contains `WITHOUT a sandbox`; `apps.remove` => gone. e2e C `#[ignore]` (real Wine + bwrap, `RUNTIME_REQUIRE_BWRAP` honoured like `e2e_sandbox.rs`): `apps.install` of `hello64.exe`, `apps.run` => `stdout` events carry its output, `succeeded`; `apps.run` of a long-running fixture then `jobs.cancel` => `cancelled` and no wineserver left for the prefix. The D11 test: `rt_sandbox` renders the app and installer sandbox commands for a default and a maximal profile; no bind source is the socket, its directory, or an ancestor below `/` other than via the empty `$XDG_RUNTIME_DIR` tmpfs.
- [ ] **Step 2: Implement.**
- [ ] **Step 3:** full gate (plus `cargo test -p runtime-cli -- --ignored` locally when Wine is present, results noted in the commit body); commit `feat(daemon,cli): job helpers in the client, daemon-status shows the mode; end-to-end job tests`.

---

### Task 6: docs

**Files:**
- Modify: `docs/API.md` (write mode, the jobs model, every new method with params/results/errors/examples via `runtime rpc`, `consent_mismatch` flow, limits table, versioning 0.2.0 and why it is breaking, systemd `--write`), `docs/SECURITY.md` (new section "The `runtimed` daemon: write methods (Phase 6B)"), README (daemon section: `--write`), `docs/superpowers/plans/2026-09-21-runtime-master-roadmap.md` (Phase 6 row: 6B done), this plan's "As built" notes
- Test: the API.md/dispatch-table test; a doc test that every `data.kind` in `ErrorKind` appears in API.md (add if cheap: one `include_str!` scan)

- [ ] **Step 1:** SECURITY.md threat model: a same-uid process could already run `runtime` itself, so the daemon adds no privilege; what must not exist and why it does not: another uid (mode + `SO_PEERCRED`), a browser (no TCP, no HTTP, NDJSON JSON-RPC only), a sandboxed app (D11 and its test), argument injection and path traversal (5.1 and its tests), invented consent (5.3), a hostile program's output (cleaned, bounded), pid-reuse signalling (5.6); known bounds: same-uid DoS within the caps, a CLI started at a terminal is invisible to the job table (the app lock is the guard), version skew checked at startup only (consent re-checked by the CLI), GUI presentation of consent is 6C's.
- [ ] **Step 2:** API.md and README; roadmap row.
- [ ] **Step 3:** full gate; commit `docs: the write methods and jobs in API.md and SECURITY.md; README and roadmap`.

---

## Dependency order

Task 1 -> Task 2 (needs `plan_digest`, `argv`) and Task 3 (needs `JobSpec`); Task 4 needs 1 and 3; Task 5 needs 2 and 4; Task 6 last. Tasks 2 and 3 may run in parallel.

## Self-Review

- Spec criteria: 1 -> Tasks 1, 3; 2 -> Task 4; 3 -> Tasks 1, 2, 4; 4 -> Tasks 3, 4; 5 -> Tasks 1, 2, 5; 6 -> Tasks 3, 5.
- Pre-approved decisions: execution model (Task 3), consent (1, 2, 4), streams and limits (3, 4), authorization (4), progress as lines (3; no CLI output change), client + CLI (5; no `runtime jobs`, spec D15), docs (6), testing (1-5), non-goals respected.
- Placeholders: one open fork, decided by a test: whether clap routes `deps ... -- list` to the subcommand (Task 2 Step 1 fixes the rule either way).
- Types: `JobSpec`, `JobKind`, `JobInfo`, `JobEvent`, `JobEvents`, `JobStarted`, `ConsentItem`, `Jobs`, `JobsConfig`, `Ctx` are named identically across tasks.

## As built (deviations from the text above, and why)

- **Plan digest v2** (review of Tasks 1-2): each entry also binds the sha256 of its consent text (`rt-deps-plan-v2`),
  so consent recorded by the CLI is always for the text the client showed. `deps.plan`'s `digest` defaults to empty
  when read from a 0.1 daemon; the client refuses `deps_install` with it.
- **`JobSpec` is exhaustive** (not `#[non_exhaustive]`), so the CLI's parser-oracle test is one match over every
  variant. `JobKind`/`JobState`/`EventKind` read unknown values as `Unknown`.
- **`list`/`cache` app ids** reach the app after `--` (clap does not route them to the subcommands; pinned by a rig test
  and the oracle), so `deps.install` needs no extra refusal.
- **`JobsConfig`**: `now` and a new `env` are `Arc<dyn Fn>` (tests inject a clock and an environment);
  `JobsConfig::new` holds the production limits. `Ctx.rt` is an `Arc<Runtime>`; `stop` moved into `Ctx`, so
  `serve(ctx, cfg, listener)`.
- **The supervisor polls** `waitid(WNOHANG | WNOWAIT)` every 20 ms (it also escalates the cancel), instead of blocking.
- **The final state event is always the last event**: output a leftover process writes after `runtime` exited (1 s
  drain) is dropped, with a note.
- **Cancel** also SIGKILLs what is left of a cancelled job's group once the leader exited, at the end of the same
  grace (spec 5.6 said "left alone"; the Tasks 3-5 review showed a TERM-ignoring helper would survive; the final
  review asked for the grace). A cancel that finds the leader already exited keeps its result and gives the rest of
  the group SIGTERM, then SIGKILL after the grace. **`cancelled`** only when the cancel
  stopped the job; exit 0 is `succeeded`.
- **Job directory** (spec D8): each daemon takes `job-cwd/d-<32 hex>/`, marked live by an `flock` on
  `d-<32 hex>.lock` for its life, and at startup removes only the `d-*` directories whose lock is free (final review
  I1: a second `runtimed --write` used to remove a live daemon's job directories before the socket lock refused it);
  each job runs in a fresh 0700 subdirectory of it named after the job id, removed after the reap; the shared
  directory must only be ours and 0700 (a stray file there used to block every job).
- **`runtime` binary checks** (spec D10) also cover its directory, and each refusal names the fix (`chmod g-w,o-w
  <path>`): a umask-002 `cargo install` is group-writable and is refused.
- **`--write`** also requires `XDG_RUNTIME_DIR` to be a 0700 directory of the user (not `/`), and reads
  `runtime --version` on a thread against the 5 s deadline (4 KiB, one line).
- **Unit file**: `KillMode=mixed` (the ordered cancel is not bypassed) and `UMask=0022` (jobs create files as from a
  terminal; the daemon's own files have explicit modes).
- **Not done, follow-ups**: a real-Wine e2e that cancels a long-running app (no such fixture); re-checking the
  `runtime` version when the file changes (startup only now); re-digesting the plan under the app lock inside
  `deps --install` (review m3 of Tasks 1-2: not a consent bypass); `progress` events.
