# Phase 6E Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the review-ledger follow-ups that are code work and that this host can verify:
- a per-spawn `runtime` version check in `runtimed --write`;
- a plan re-digest under the app lock in `deps --install --plan-digest`;
- serde fallbacks on every result enum;
- a real-Wine `jobs.cancel` e2e;
- `runtime display` gated by a backend capability;
- an honest `daemon-status`;
- a CI test audit with an unverified hosted-runner workaround.

There are no new features.

**Architecture:** Each item is a small change at the layer that already owns it:
- `rt_daemon::jobs`/`write` for the version check;
- `rt_deps::Orchestrator` (a check closure the CLI supplies, because `rt_deps` cannot depend on `rt_api`) for the
  re-digest;
- `rt_api` types for the fallbacks;
- `rt_core::Capabilities` plus a static lookup in `rt_api::backends` for display;
- `cli/rpc.rs` for status;
- `ci.yml` and test messages for CI.

**Tech Stack:** Rust; existing crates only (`serde`, `libc`, `sha2`, `thiserror`); mingw-w64 for one new C fixture. No new third-party crate.

**Spec:** `docs/superpowers/specs/2026-10-02-phase-6e-hardening-design.md`

## Global Constraints

- **Nothing is pushed:** no `git push` and no PR. Each task is code plus its tests plus the docs it changes. The
  roadmap says so (Task 7).
- **No new third-party crate.** `Cargo.lock` gains no package. If one turns out to be needed, stop and report.
- **Gates after every task:**
  - `cargo fmt --all -- --check`;
  - `cargo clippy --workspace --exclude runtime-gui --all-targets -- -D warnings`;
  - `cargo clippy -p runtime-gui --all-targets -- -D warnings`;
  - `cargo test --workspace --exclude runtime-gui` with `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1`;
  - `cargo build -p runtime-daemon -p runtime-cli && RUNTIME_REQUIRE_DISPLAY=1 xvfb-run -a cargo test -p runtime-gui`;
  - `cargo deny check`.

  `the_documented_methods_are_the_dispatch_table` and every API.md check stay green.
- **Test isolation.** Tests never touch the user's data dir, `$XDG_RUNTIME_DIR` or a running `runtimed`. Real-Wine
  tests are `#[ignore]` and keep the `RUNTIME_REQUIRE_BWRAP` gating. Every process test has a short deadline. Use
  `TMPDIR=$PWD/target/tmp` for real-Wine runs (6D environment note: `/tmp` hits `EDQUOT`).
- **Error text.** Every new error message is fixed text, or cleaned with `rt_core::clean_text` and bounded (6A rule).
  No new message is built from a client-supplied string without cleaning.
- **Commit trailer:** `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- **Version check (Task 2):**
  - a path from `Jobs::start` to `spawn` that skips the probe;
  - a probe run under the table lock;
  - a probe that leaks a thread or a process per call;
  - `runtime_mismatch` given for a probe *failure* (that must be `unavailable`);
  - the probe getting the daemon's full environment instead of `child_env`.
- **Re-digest (Task 3):**
  - the check running before the lock, or on the stale `app.facts`;
  - an install proceeding from `app.facts` after a fresh plan passed;
  - anything fetched, marked consented or written before `plan_check`;
  - `plan_check: None` changing terminal behaviour.
- **Fallbacks (Task 1):**
  - `Unknown` produced by server code;
  - a request enum (`Driver`) made lenient;
  - `compat.toml` accepting an unknown status;
  - the GUI treating `ConsentView::Unknown`/`PlanAction::Unknown` as consentable or installable, or labelling an
    unknown grant as read-only.
- **Display (Task 4):**
  - user.reg read or the lock taken before the capability check;
  - an unknown recorded backend falling back to Wine;
  - the read path now requiring Wine to be installed (it must not);
  - `BACKEND_API_VERSION` not bumped.
- **Status (Task 5):** "start `runtimed`" suggested when a daemon is reachable; busy reported as unreachable.
- **Cancel e2e (Task 6):** a test that passes without the program having run (no `sleeping` event awaited); a cancel
  asserted only by state, not by the app's lock being free afterwards.
- **CI (Task 7):**
  - the workaround presented as verified;
  - a required facility silently skipped (a skip without `SKIPPED` on stderr, or without the `RUNTIME_REQUIRE_*`
    escalation where CI sets it);
  - any push.

---

### Task 1: serde fallbacks on every result enum

**Files:**
- Modify:
  - `crates/api/src/types.rs` (`NetworkView`, `AccessView`, `PermSource`, `PlanAction`, `ConsentView`: new
    `#[serde(other)] Unknown`; `VulkanState::Unknown` gains `#[serde(other)]`; `SubjectView`, `Availability`: a new
    unit `#[serde(other)] Unknown`);
  - `crates/api/src/compat.rs` (`Status::Unknown` with `#[serde(other)]`; `as_str` gets `"unknown"`; record
    validation refuses `Unknown` with the existing unknown-value error);
  - `crates/gui/src/vm/page.rs` (`GrantRow.access` "unknown" for `AccessView::Unknown`);
  - `docs/API.md` ("Versioning and compatibility": every result enum has the fallback; request enums stay strict).
- Test: unit tests beside each enum (in `types.rs`, `compat.rs`, `jobs.rs` and `error.rs` where missing), plus
  `crates/daemon/src/client.rs` tests and `crates/gui/src/vm/tests.rs`.

**Interfaces:**
- Produces: the `Unknown` variants above (all enums are already `#[non_exhaustive]`, except `compat::Status` and
  `Driver`). `Status` stays exhaustive inside `rt_api`; add `#[non_exhaustive]` only if a downstream crate matches
  it, and record which in As built.
- Consumes: nothing new.

- [ ] **Step 1: Audit.**
  - `grep -n "derive(.*Deserialize" crates/api/src` lists every enum.
  - Confirm the list in spec 4.3 is complete. Any enum reachable from a method result that is missing from 4.3 is
    added.
  - Confirm `Driver` (request only) and `DoctorTarget` (not wire) stay strict.
- [ ] **Step 2: Failing tests.**
  - For each enum in 4.3: `serde_json::from_value(json!("fromTheFuture"))` gives `Unknown` (for the tagged ones:
    `json!({"kind": "fromTheFuture", "extra": 1})`, `json!({"state": "fromTheFuture"})`), and every known value
    round-trips through `to_value`/`from_value`.
  - For the four that already have the fallback, add a test only if none exists (grep first).
  - `compat`: a record with `status = "unknown"` and one with `"workz"` are both refused by the TOML parser.
  - Client: an in-process server answers `permissions.get` with `"network": "lan"` and a grant `"access": "append"`,
    and `Client::permissions` returns `Ok` with `NetworkView::Unknown`/`AccessView::Unknown`.
  - GUI vm: that view yields a grant row with access "unknown", and `pending_consent` (or its equivalent) excludes an
    entry with `PlanAction::Unknown` or `ConsentView::Unknown`.
  - `Driver` still refuses `"vnc"` (the existing test stays).
- [ ] **Step 3: Implement.** Doc comment on each new variant: "A value this client does not know (a newer
  daemon's): deserialisation never fails on it. Never produced." (the existing wording).
- [ ] **Step 4:** gates; commit `feat(api): every result enum reads a newer daemon's value as Unknown`.

---

### Task 2: `runtimed --write` checks the `runtime` version before every spawn

**Files:**
- Modify:
  - `crates/daemon/src/write.rs` (`version_of` and the comparison move out and are shared; startup calls the shared
    function);
  - `crates/daemon/src/jobs.rs` (`check_runtime_version`; `JobsConfig::version_timeout` (default 5 s); the call in
    `Jobs::start` after `check_job_cwd`, before the table lock; the reader bounded by the deadline);
  - `crates/api/src/error.rs` (`ErrorKind::RuntimeMismatch`, in `ALL`);
  - `crates/api/src/lib.rs` (`API_VERSION = "0.2.2"`);
  - `crates/daemon/src/jobs/tests.rs`;
  - `crates/daemon/tests/support/mod.rs` (the fake `runtime` reads its version line from a file beside it,
    defaulting to the workspace version);
  - `crates/daemon/tests/e2e_jobs.rs`;
  - `docs/API.md` (the `runtime_mismatch` kind, the 0.2.2 entry);
  - `docs/SECURITY.md` (6B "Known bounds": "checked at startup only" becomes "checked before every job").

**Interfaces:**
- Produces:
  ```rust
  // rt_api::error
  pub enum ErrorKind { /* ... */ RuntimeMismatch /* "runtime_mismatch" */, Unknown }
  // rt_daemon::jobs
  pub struct JobsConfig { /* ... */ pub version_timeout: Duration }
  /// `Ok` when `exe --version`'s first line is `runtime <CARGO_PKG_VERSION>`; `RuntimeMismatch` when it is another
  /// version; `Unavailable` when the probe fails (spawn error, no line within `timeout`, empty output).
  pub fn check_runtime_version(exe: &Path, cwd: &Path, env: &[(OsString, OsString)], timeout: Duration)
      -> Result<(), ApiError>;
  ```
  Startup maps the `ApiError` to its `--write: ...` string (the existing text and tests stay).
- Consumes: Task 1's `ErrorKind::Unknown` (so older clients read the new kind).

- [ ] **Step 1: Failing tests** (spec 6, item 1).
  - Jobs unit tests with the fake script:
    - same version: a job starts;
    - version file rewritten to `runtime 9.9.9`: `start` gives `RuntimeMismatch`, the message names `9.9.9` and
      `restart runtimed`, no job is listed, the argv log is empty;
    - a script that sleeps on `--version` (timeout 300 ms): `Unavailable`;
    - 20 of those probes in a row: the process's thread count (`/proc/self/status` `Threads:`) is back to its
      starting value within 1 s;
    - a script printing nothing: `Unavailable`;
    - a probe that sees `SECRET` in the daemon env does not get it.
  - e2e part A: `runtimed --write` started with the fake sibling; rewrite the version file; `apps.remove` gives
    `ClientError::Rpc` with kind `runtime_mismatch`; restore it and the next job starts.
  - `ErrorKind::ALL` / API.md kind-list test covers the new kind.
- [ ] **Step 2: Implement.**
  - The reader thread reads with `poll(2)` on the pipe fd until the deadline, then returns, so the pipe is dropped
    and no thread outlives the probe. Kill and reap the child at the deadline (unchanged).
  - The mismatch message: `"{path} is now {got:?}; this runtimed is {ours}: restart runtimed (systemctl --user
    restart runtimed)"`, with `path` from `shown`, `got` cleaned to 128.
- [ ] **Step 3:** gates; commit `feat(daemon): check the runtime binary's version before every job; runtime_mismatch (API 0.2.2)`.

---

### Task 3: `deps --install --plan-digest` re-checks the digest under the app lock

**Files:**
- Modify:
  - `crates/deps/src/orchestrate.rs` (`Orchestrator::plan_check`; `install_plan` recomputes and checks under the
    lock when it is set; `DepsError::PlanChanged`);
  - `crates/deps/src/orchestrate/tests.rs`;
  - `crates/deps/src/lib.rs` (the error variant, if errors live there);
  - `crates/cli/src/deps.rs` (passes the check);
  - every other `Orchestrator { .. }` literal (`plan_check: None`; grep `Orchestrator {` across `crates/`);
  - `docs/SECURITY.md` (the 6B consent text: the CLI re-checks under the lock).

**Interfaces:**
- Produces:
  ```rust
  // rt_deps
  pub struct Orchestrator<'a> { /* ... */ pub plan_check: Option<&'a dyn Fn(&AppPlan) -> Result<(), String>> }
  #[error("{0}")] PlanChanged(String),   // DepsError
  ```
  `install_plan`, when `plan_check` is `Some`: `lock_app`, then `check_not_busy`, then read the metadata, then
  `plan_for_app(o.env, &md, o.manifest, o.vulkan)`, then `plan_check(&fresh).map_err(PlanChanged)?`, then the
  existing resolve/decide/execute on `fresh.facts`. When it is `None`: unchanged.
- Consumes: `rt_api::jobs::plan_digest` (CLI side only, through `check_plan_digest`).

- [ ] **Step 1: Failing tests** (spec 6, item 2), all with the existing orchestrator test rig (fake backend, local
  fetcher):
  - a refusing check gives `PlanChanged`, the fetcher was never called, the metadata bytes are unchanged, and no
    consent is recorded;
  - a check that tries `lock_app(env)` itself sees `LockHeld` or `AppRunning`, which proves it runs under the lock;
  - a plan computed, then the metadata changed to record one planned package as installed, then `install_plan` with
    a check that records its argument: the recorded plan no longer has that entry as `Install`;
  - with `plan_check: None`, the existing tests are unchanged;
  - CLI: the existing `--plan-digest` tests (right digest, wrong digest) still pass.
- [ ] **Step 2: Implement.** In `run_app`, build the closure only when `plan_digest` is `Some`. Map `PlanChanged` to
  the same exit 1 and message as the early check.
- [ ] **Step 3:** gates; commit `fix(deps): re-check the plan digest under the app lock before installing`.

---

### Task 4: `runtime display` gated by a backend capability

**Files:**
- Modify:
  - `crates/core/src/backend.rs` (`Capabilities::graphics_driver`; `BACKEND_API_VERSION = 2`; contract docs: the
    field, where it is enforced; drop `runtime display` from "Wine-specific, stays concrete");
  - `crates/core/src/fake.rs` (`true`, builder-configurable);
  - `crates/core/src/backend/conformance.rs` (the `graphics_driver` implies `sandboxable` check);
  - `crates/core/tests/conformance.rs` (null backend `false`; a broken backend for the new check);
  - `crates/backend-wine/src/lib.rs` (`pub const CAPABILITIES`, returned by `capabilities()`);
  - `crates/api/src/backends.rs` (`capabilities(id)`);
  - `crates/cli/src/display.rs` (`require_graphics_driver` first in `run`, both paths);
  - `crates/deps/src/orchestrate/tests.rs` and every other `Capabilities { .. }` literal (grep `sandboxable:`);
  - `crates/cli/src/doctor.rs` tests (interface 2);
  - the CLI rig display tests (`crates/cli/tests/`, wherever `display` is tested now);
  - `docs/SECURITY.md` (6D "Contract gaps" sentence removed; the capability listed with the others).

**Interfaces:**
- Produces:
  ```rust
  // rt_core::backend
  pub const BACKEND_API_VERSION: u32 = 2;
  pub struct Capabilities { /* ... */ pub graphics_driver: bool }  // Wine's graphics-driver registry setting
  // backend_wine
  pub const CAPABILITIES: Capabilities;
  // rt_api::backends
  /// The capabilities of a known backend id, without discovering or starting it; `None` for an unknown id.
  pub fn capabilities(id: &str) -> Option<Capabilities>;
  // cli display.rs
  fn require_graphics_driver(id: &str, caps: Option<Capabilities>) -> Result<(), CmdError>;
  ```
- Consumes: nothing new.

- [ ] **Step 1: Failing tests:**
  - `require_graphics_driver` gives:
    - for `None`: an error containing `unknown compatibility backend` and `(known: wine)`, cleaned;
    - for `graphics_driver: false`: `Unsupported::Feature` text `does not support the graphics driver setting`;
    - for `true`: `Ok`.
  - `backends::capabilities("wine") == Some(backend_wine::CAPABILITIES)`, and `capabilities("null")` is `None`.
  - Conformance: the null backend passes; `GraphicsDriverWithoutSandbox` fails exactly the new check.
  - CLI rig: an installed app whose `metadata.json` is edited to `backend.id = "null"`. Then `runtime display <id>`
    and `runtime display <id> x11` exit 1 with the message, and `user.reg`'s bytes and mtime are unchanged. A
    normal (fake-Wine) app's `display` output is unchanged.
  - `doctor` prints `interface 2`.
- [ ] **Step 2: Implement.** In `display::run`, read the metadata once, then gate, then the existing code. The read
  path still works without Wine installed: the gate uses `backends::capabilities`, not `select`.
- [ ] **Step 3:** gates; commit `feat(core): graphics_driver capability; runtime display refuses a backend without it (backend interface 2)`.

---

### Task 5: `daemon-status` tells busy, not answering and unreachable apart

**Files:**
- Modify:
  - `crates/cli/src/rpc.rs` (`enum Outcome`, `fn outcome`, `status` prints by outcome);
  - `crates/daemon/tests/e2e.rs` (busy and missing-socket cases);
  - `docs/API.md` ("The CLI: `runtime rpc` and `runtime daemon-status`": the four outcomes).

**Interfaces:**
- Produces:
  ```rust
  enum Outcome { Answered { api: String, runtime: String, protocol: String, mode: String },
                 Busy, NotAnswering, Unreachable(String), NotChecked(String) }
  fn outcome(r: Result<(VersionInfo, Option<bool>), ClientError>) -> Outcome;
  ```
  The output lines are:
  - `reachable: yes` and the existing lines (exit 0);
  - `reachable: yes, busy (connection limit reached): try again` (exit 1);
  - `reachable: yes, not answering within 5 s` (exit 1);
  - `reachable: no (<cleaned error>)` plus the existing start hint (exit 1);
  - `reachable: not checked (<cleaned error>)` (exit 1, no hint).
- Consumes: `rt_daemon::protocol::{BUSY, TIMEOUT}`.

- [ ] **Step 1: Spike.** Find what a client read timeout returns today (`ClientError::Io` with `TimedOut` or
  `WouldBlock`, or `Protocol`). The existing e2e "a daemon that never answers is cut at its timeout" shows it. Pin it
  in the `outcome` test.
- [ ] **Step 2: Failing tests:**
  - `outcome` for each `ClientError` variant and for `Rpc` codes -32001, -32002 and -32000;
  - e2e: a real `runtimed` with its connection slots held (there is no `--max-connections` flag: open connections
    until one gets the busy line, as the server tests do). Then `daemon-status` exits 1, prints `busy`, and does not print
    `start`;
  - the existing missing-socket and never-answering e2e cases print `reachable: no` with the hint and `not
    answering` without it.
- [ ] **Step 3: Implement**; commit `fix(cli): daemon-status says busy or not answering instead of unreachable`.

---

### Task 6: a long-running fixture and a real-Wine `jobs.cancel` e2e

**Files:**
- Create: `tools/fixtures/sleep.c`.
- Modify:
  - `tools/build-fixtures.sh` (x86_64 block: `sleep64.exe`);
  - `crates/daemon/tests/e2e_jobs.rs` (part C: `a_real_sandboxed_run_is_cancelled_and_leaves_nothing`, `#[ignore]`;
    the module docs);
  - `.github/workflows/ci.yml` comment only if the wine-e2e job's filter would miss it (it runs `-p runtime-cli`,
    `-p runtime-backend-wine` and `-p runtime-deps`, so the daemon's ignored tests are NOT in CI: record that in the
    test's doc comment, and do not add a CI line, see Decision below).

**Interfaces:**
- Produces: `sleep64.exe`. It prints `sleeping`, calls `fflush(stdout)`, then `for (i = 0; i < 300; i++) Sleep(1000);`
  and returns 0 (spec E10).
- Consumes: the part C rig (`scratch(Ok(&real_runtime()))`, `follow`, `fixture`).

- [ ] **Step 1:** write `sleep.c` and the build line, run `tools/build-fixtures.sh`, and confirm `sleep64.exe` exists
  and `file` says PE32+.
- [ ] **Step 2: The test** (spec E11):
  1. Install `sleep64.exe` through `apps.install`.
  2. `apps.run`, then poll until a `stdout` event contains `sleeping` (deadline 60 s; fail with the events if it
     never arrives).
  3. `jobs.cancel`, then follow the job: the state is `Cancelled` within 15 s of the cancel, and no event contains
     `WITHOUT a sandbox`.
  4. Start `apps.remove` jobs until one succeeds, for up to 10 s. Each failure's events must say the app is running
     or busy (not some other error); fail with the last events otherwise.
- [ ] **Step 3: Run it here.** Use `TMPDIR=$PWD/target/tmp RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-daemon
  --test e2e_jobs -- --ignored a_real_sandboxed_run --test-threads=1 --nocapture`, with both part C tests passing.
  Record the command, the Wine version and the wall time in As built.
- [ ] **Step 4:** gates; commit `test(daemon): real-Wine jobs.cancel of a long-running sandboxed app (sleep64.exe fixture)`.

Decision (recorded here, not in the spec): the daemon's `#[ignore]`d real-Wine tests are not added to the `wine-e2e`
job. That job runs as root in a `--privileged` container, while `runtimed --write` needs a 0700 `XDG_RUNTIME_DIR` of
its uid and a user that owns its binary directory. Making that work in the container is unverified CI work on top of
an unverified CI job. The test is verified locally (Step 3). Adding it to CI is a follow-up for after the first green
hosted run.

---

### Task 7: CI audit, hosted-runner workaround, and the 6E docs

**Files:**
- Modify:
  - `.github/workflows/ci.yml` (`test` and `gui` jobs: the workaround step(s); a comment table of the audited tests);
  - the test files whose failure message the audit finds unactionable (expected candidates: `crates/sandbox/src/lib.rs`
    `probe_limits_on_this_host`, `crates/sandbox/src/landlock/tests.rs`, `crates/sandbox/src/seccomp/tests/kernel.rs`,
    `crates/cli/tests/support/mod.rs` `bwrap_works`, `crates/installer/src/sandbox/tests.rs`,
    `crates/desktop/src/testutil.rs`; confirm, don't assume);
  - `docs/superpowers/plans/2026-09-21-runtime-master-roadmap.md` (Section 0: a `6E Hardening` row; "Known
    follow-ups": the items closed, the CI bullet rewritten per spec 4.6(c));
  - `docs/SECURITY.md` (any remaining 6E wording);
  - this plan's "As built" and the spec's "As built".

**Interfaces:** none (CI and docs). The workaround step, verbatim in shape:
```yaml
      # UNVERIFIED until the first hosted run (Phase 6E). Hypothesis for the 9cf1e27 `test` failure (log unread):
      # Ubuntu 24.04 runners set kernel.apparmor_restrict_unprivileged_userns=1, so an unprivileged bwrap cannot
      # create its user namespace. Alternative: AppArmor's bwrap-userns-restrict profile. The before/after values
      # below are printed so the first hosted log confirms or refutes this.
      - name: Allow unprivileged user namespaces for bwrap (unverified)
        run: |
          sysctl kernel.apparmor_restrict_unprivileged_userns || true
          if sysctl -n kernel.apparmor_restrict_unprivileged_userns >/dev/null 2>&1; then
            sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
          fi
          sysctl kernel.apparmor_restrict_unprivileged_userns || true
          bwrap --unshare-user --ro-bind / / true && echo "bwrap: user namespace OK" || echo "bwrap: STILL FAILS"
```

- [ ] **Step 1: Audit (spec 4.6 a).**
  - Find every test that reaches `bwrap`, `systemd-run`, Landlock (`landlock_create_ruleset`) or Yama
    (`ptrace_scope`):
    `grep -rn "bwrap\|systemd-run\|landlock\|ptrace_scope\|RUNTIME_REQUIRE_" crates --include='*.rs'`, plus the call
    graph from `rt_sandbox` probes into test helpers.
  - Classify each non-`#[ignore]` test:
    - (1) needs the facility and fails loudly with an actionable message under CI's env;
    - (2) needs it, skips loudly (`SKIPPED ...` on stderr) without it, and CI does not require it;
    - (3) needs it and fails with an unactionable message: fix the message;
    - (4) does not need it.
  - Verify locally where possible: run the bwrap-gated set with `PATH` pointing at a directory without `bwrap` and
    `RUNTIME_REQUIRE_BWRAP=1`. Every failure must name bwrap and what to install or set. Where it can be simulated,
    a bwrap that exits 1 with `setting up uid map: Permission denied` (a stub script on `PATH`) must produce a
    message naming `kernel.apparmor_restrict_unprivileged_userns`.
  - Put the table into As built.
- [ ] **Step 2: Messages.** For each class-(3) test, make the failure (or the shared helper's) message name the
  facility and the fix. Example: `bwrap cannot create a user namespace here (on Ubuntu 24.04+:
  kernel.apparmor_restrict_unprivileged_userns=1); see .github/workflows/ci.yml`. No test changes what it asserts.
- [ ] **Step 3: Workaround (spec 4.6 b).** Add the step above to `test` and `gui`, after the apt step and before
  `cargo test`. A user-systemd-session step goes in only if Step 1 found a test of class (1) that needs
  `systemd-run --user`, marked unverified the same way. Otherwise a one-line comment says why none is needed (the
  tests that use it skip loudly, class 2).
- [ ] **Step 4: Docs (spec 4.6 c).**
  - Roadmap Section 0: a row `6E Hardening` (state: implemented on branch `phase-6e-hardening`, pending merge; the
    seven items one line each).
  - "Known follow-ups": the closed items removed from the 6B/6D follow-up lists.
  - The CI bullet rewritten: local pass of `9cf1e27` on 2026-10-02; hypothesis and secondary; at `9cf1e27` the only
    tests of these classes were the installer-sandbox bwrap tests (5A/5B came later); the root cause stays
    unconfirmed until the user reads run 36228837680's log; the workaround is unverified; nothing pushed.
  - `SECURITY.md`: confirm every 6E change is reflected.
  - Fill both As built sections.
- [ ] **Step 5:** `ci.yml` parses as YAML. Run the full gate set once more on the branch tip. Commit `ci: audit of
  host-facility tests, an unverified userns workaround for hosted runners; 6E docs`.

---

## Dependency order

1. Task 1 comes first: Task 2's new error kind relies on the `Unknown` fallback story, and both edit `docs/API.md`
   "Versioning".
2. Task 2 needs 1.
3. Tasks 3, 4 and 5 are independent of each other and of 2; they may run in parallel with it, but serialise commits
   touching `docs/SECURITY.md` and `docs/API.md`.
4. Task 6 is independent: it needs only the existing part C rig, but run it after Task 2, so the per-spawn probe is
   exercised by a real `runtime`.
5. Task 7 comes last: it audits the tests as they are after 1-6 and describes what was built.

## Self-Review

- **Spec criteria:** 1 -> Task 2; 2 -> Task 3; 3 -> Task 1; 4 -> Task 6; 5 -> Task 4; 6 -> Task 5; 7 -> Task 7.
- **Pre-approved scope:** all seven items. The non-goals are untouched: nothing here removes deps, adds 32-bit DXVK,
  portals or signing, or adds a backend. The null backend exists only in tests, as before.
- **Decisions:** E1-E12 are in the spec. The one plan-level decision (the daemon's real-Wine tests stay out of CI)
  is in Task 6.
- **Spikes that can stop a task:** Task 5 Step 1 (what a read timeout surfaces as); Task 7 Step 1 (a test class
  that cannot be made actionable without changing what it asserts: report it, don't change the assertion).
- **Types named identically across tasks:** `ErrorKind::RuntimeMismatch`, `check_runtime_version`,
  `JobsConfig::version_timeout`, `Orchestrator::plan_check`, `DepsError::PlanChanged`,
  `Capabilities::graphics_driver`, `BACKEND_API_VERSION = 2`, `backend_wine::CAPABILITIES`,
  `rt_api::backends::capabilities`, `require_graphics_driver`, `Outcome`, `sleep64.exe`.
- **Placeholders:** none.

## As built

(Filled in by the implementation.)
