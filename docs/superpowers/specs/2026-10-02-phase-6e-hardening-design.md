# Phase 6E: hardening the review-ledger follow-ups (design)

Status: approved by the controller on the user's standing instruction. The user pre-approved the scope (seven
items) and the non-goals on 2026-10-02 and delegated every other choice: those are recorded below as "Decision:" with
the reasoning. Phase 6E comes after 6A-6D are merged on `main` (`f9c8246`). It adds no feature. It closes the
follow-ups from the review ledgers that are code work and that can be verified on this host. Sources: the roadmap's
Section 0 table and "Known follow-ups"; the "As built" sections of the 6A-6D plans; the "Known bounds" sections of
`docs/SECURITY.md`.

Each item was checked against the code at `f9c8246` before it was planned. All seven still exist (section 2).

## 1. Purpose and success criteria

1. **Per-spawn version check.** `runtimed --write` checks the sibling `runtime`'s owner, mode, directory AND version
   before every job spawn, not only at startup. A `runtime` replaced under a running daemon by a different version
   is refused with the new error kind `runtime_mismatch`, and nothing is spawned.
2. **Re-digest under the lock.** `runtime deps --install --plan-digest` recomputes the plan and checks its digest
   again after it has taken the app lock, before any consent, fetch or install. A plan that changed between the
   first check and the lock installs nothing (exit 1, same message as today).
3. **Enum fallbacks.** Every enum that a client deserialises from a daemon reply reads an unknown value as
   `Unknown`. A newer daemon's new variant never makes an older client's typed helper fail. There is one test per
   enum.
4. **Real-Wine cancel e2e.** A real-Wine `jobs.cancel` end-to-end test runs on a long-running mingw fixture
   (`sleep64.exe`, built by `tools/build-fixtures.sh`). It is `#[ignore]` like the other real-Wine tests and was run
   and passed on this host.
5. **Display capability.** `runtime display` (read and set, and therefore `display.set` jobs) is gated by a backend
   capability. A backend without Wine's graphics-driver registry, or an unknown recorded backend, refuses cleanly
   before it touches the prefix.
6. **Honest `daemon-status`.** `runtime daemon-status` says "busy" (connection cap reached), "not answering"
   (connected, no reply in time) and "unreachable" (nothing to connect to) as different things. It suggests
   starting `runtimed` only when the daemon is unreachable.
7. **CI test audit.** Every non-ignored test that needs real bwrap, a user systemd session, Landlock or Yama is
   listed, and each one fails loudly with an actionable message (or skips loudly, when it is not required). The
   `test` and `gui` jobs gain a commented workaround step that is marked "unverified until the first hosted run".
   The roadmap says the root cause of the hosted failure at `9cf1e27` stays unconfirmed until the job log is read.
   Nothing is pushed.

Non-goals (pre-approved): `deps --remove` (needs its own design), 32-bit DXVK, portals (5C), package signing, a
second backend. Also not in scope: `progress` events (6B follow-up, no consumer), the GUI accessibility pass and
display/limits editing (6C follow-ups; they need the manual checklist and a desktop session), the 64 KiB `.wrun`
manifest cap (a format decision, not hardening), and any `git push`.

## 2. The items as they are at `f9c8246`

| # | Where | What the code does now |
|---|---|---|
| 1 | `crates/daemon/src/jobs.rs` `Jobs::start` -> `check_runtime_exe` (owner/mode/dir, every start); `crates/daemon/src/write.rs` `prepare_with` -> `version_of` (startup only) | `docs/SECURITY.md` 6B "Known bounds": "The version is checked at startup only." |
| 2 | `crates/cli/src/deps.rs` `run_app`: `check_plan_digest` runs before `rt_deps::install_plan`, which takes `lock_app` and re-resolves from the facts it was handed (`app.facts`), not from a fresh read of the exe | 6B plan "Not done": "re-digesting the plan under the app lock inside `deps --install` (review m3 of Tasks 1-2: not a consent bypass)". |
| 3 | `crates/api/src/{error.rs,jobs.rs}`: `ErrorKind`, `JobKind`, `JobState`, `EventKind` have `#[serde(other)] Unknown`. `crates/api/src/types.rs`: `NetworkView`, `AccessView`, `PermSource`, `SubjectView`, `VulkanState`, `Availability`, `PlanAction`, `ConsentView` have none; `crates/api/src/compat.rs` `Status` (inside `CompatRecord`) has none | `docs/API.md` "Versioning": "The other enums ... have **no** serde fallback." |
| 4 | `crates/daemon/tests/e2e_jobs.rs`: cancel is tested only against a fake `runtime` (part A); part C runs `hello64.exe`, which exits at once | 6B plan "Not done": "a real-Wine e2e that cancels a long-running app (no such fixture)". |
| 5 | `crates/cli/src/display.rs` `run`: reads and writes `user.reg` for any backend; `Capabilities` (`crates/core/src/backend.rs`) has no such feature | 6D As built, Task 2, M4: deferred; `SECURITY.md` 6D "Contract gaps". |
| 6 | `crates/cli/src/rpc.rs` `status`: any `Err` prints `reachable: no (...)` and the "start `runtimed`" hint, including the `-32001 server busy` line that `rt_daemon::client` returns as `ClientError::Rpc { code: -32001 }` | 6A follow-up. |
| 7 | `.github/workflows/ci.yml` `test` job: `cargo test --workspace --exclude runtime-gui` with `RUNTIME_REQUIRE_BWRAP=1`; no sysctl or user-session step | Roadmap "Open: the hosted `test` job failure at `9cf1e27`". |

## 3. Decisions

| Decision | Choice | Why |
|---|---|---|
| Scope | Items 1-7 above | Pre-approved. |
| Non-goals | `deps --remove`, 32-bit DXVK, portals, signing, a second backend | Pre-approved. |
| CI | A workaround step, marked unverified; no push | Pre-approved: the log is unread, so the cause is a hypothesis. |

### Decisions made while writing this spec (unspecified by the brief; safest simple option)

- **Decision E1: run `runtime --version` before every spawn, with no cache keyed on the file's identity.** The
  check is one short process per user-started job (a few ms; jobs are rare and user-initiated), and there is
  exactly one code path. A cache keyed on `(dev, ino, size, mtime, ctime)` would add state and a second way to be
  wrong (for example, an in-place write within one mtime tick), and it would save nothing a user could notice. The
  version check runs after `check_runtime_exe` and outside the job-table lock, so a slow binary never stalls polls.
- **Decision E2: a "swapped" binary is one whose version differs.** A same-version replacement (a reinstall or a
  rebuild of the same version) is accepted when it passes the owner, mode and directory checks. Those checks are
  the trust guard: only the user or root can write the file or its directory, and they are the people a check would
  protect. The version check protects against protocol skew, for example a `runtime` upgraded under an old daemon,
  whose argv shapes or `--plan-digest` rules may differ.
- **Decision E3: a new `data.kind` `runtime_mismatch`, API 0.2.2 (additive).** `unavailable` already means "the host
  cannot answer", and its remedy is in the message. A version skew has one remedy that a client can act on: restart
  `runtimed`. So it gets its own kind. A probe that fails (no answer within 5 s, a spawn failure, empty output) stays
  `unavailable`. Older clients read the new kind as `ErrorKind::Unknown` (the fallback that exists since 0.2.0) and
  show the message.
- **Decision E4: the probe shares the startup code.** `write.rs`'s `version_of` and the comparison move into one
  function, `check_runtime_version(exe, cwd, env, timeout) -> Result<(), ApiError>`. Startup and `Jobs::start` both
  call it. The probe gets the job environment (`JobsConfig::env` filtered by `child_env`) and the job directory as
  its cwd, as the startup probe does. Its timeout is 5 s, from `JobsConfig`, so tests can shorten it.
- **Decision E5: the re-digest is a check that `rt_deps` calls, not code that `rt_deps` contains.** `rt_api` depends
  on `rt_deps`, so `rt_deps` cannot call `rt_api::jobs::plan_digest`. `Orchestrator` gains
  `plan_check: Option<&dyn Fn(&AppPlan) -> Result<(), String>>`. When it is set, `install_plan` takes the lock,
  re-reads the metadata, recomputes the plan with `plan_for_app` (the exe is read again too), runs the check, and
  installs from that fresh plan. When it is `None` (a terminal run without `--plan-digest`), nothing changes. The
  early check in `run_app` stays: it refuses fast, before the sandbox marker and the backend lookup.
- **Decision E6: the `Unknown` fallbacks are client-side tolerance only.** No server code constructs `Unknown`. It
  serialises as `"unknown"` (as the existing four do). Specifics:
  - `VulkanState::Unknown` already exists with the meaning "not known" and gets the attribute.
  - The internally tagged `SubjectView` (`kind`) and `Availability` (`state`) each gain a unit `Unknown` variant
    with `#[serde(other)]`. Serde supports this for internally tagged enums.
  - `compat::Status` is shared with the strict TOML record parser. It gains `Unknown`, and `Record` validation
    refuses `unknown` explicitly, so a typo in `compat.toml` (`workz`) is still an error. One enum, one extra check.
  - Request-only enums stay strict: `Driver` is a `display.set` parameter that the daemon deserialises, and an
    unknown driver must stay `-32602`. `DoctorTarget` is not a wire type.
  - The GUI already matches with wildcard arms. A grant whose access is `Unknown` is labelled "unknown", not
    "read-only". The permissions editor sends only the change the user made (`PermChange`), so an unknown value is
    never written back.
- **Decision E7: a new capability `graphics_driver`, and `BACKEND_API_VERSION` becomes 2.**
  - The contract says the version is bumped "on any change a backend must react to", and a backend must now
    declare the new field.
  - Wine declares `true`, the fake `true` (configurable), and the null backend `false`.
  - The conformance suite checks that `graphics_driver` implies `sandboxable`, because `reg.exe` runs through
    `helper_launcher`, as for `dependency_packages`.
- **Decision E8: `runtime display` reads capabilities without discovering the backend.**
  - The read path (no driver argument) works today when Wine is missing, and it must keep working.
  - Wine's capabilities become `backend_wine::CAPABILITIES` (a `pub const`, which `capabilities()` returns).
  - `rt_api::backends::capabilities(id) -> Option<Capabilities>` maps an id to its constant without starting
    anything.
  - Both the read and the set path check the recorded `backend.id` first. An unknown id refuses with the registry's
    message. A backend without `graphics_driver` refuses with `Unsupported::Feature { feature: "the graphics driver
    setting" }`. Both exit 1, and `user.reg` is untouched.
- **Decision E9: `daemon-status` has four outcomes and keeps exit 1 for every failure.**
  - Answered (exit 0): unchanged.
  - Busy (`ClientError::Rpc { code: -32001 }`): `reachable: yes, busy (connection limit reached): try again`.
  - Not answering (a timeout, or `-32002`): `reachable: yes, not answering within 5 s`.
  - Unreachable (`NoRuntimeDir`, `Unreachable`): `reachable: no (...)` plus the "start `runtimed`" hint.
  - Refused before sending (`Unsafe`): `reachable: not checked (...)`, with no start hint, because starting a
    daemon would not fix an unsafe socket.
  - Exit codes stay 0 or 1. A script already treats non-zero as "cannot use the daemon now", and a new exit code
    would be a second contract.
- **Decision E10: the fixture is `sleep64.exe`.** It is x86_64 only, like `probe64.exe`. It prints `sleeping`,
  flushes, then sleeps in 1 s steps for at most 300 s and exits 0. The bound means a leaked fixture dies by itself
  and cannot outlive a CI job.
- **Decision E11: the cancel e2e proves a clean end by the app's own lock, not by scanning `/proc`.**
  - After `jobs.cancel` the test asserts these four things:
    - the job ends `cancelled` within 15 s (5 s SIGTERM grace plus margin);
    - its events contain `sleeping` (so the program really ran);
    - they do not contain the unsandboxed warning;
    - an `apps.remove` job then succeeds.
  - `remove` refuses while the app's lock is held or a `wineserver` for the prefix exists, so its success shows that
    nothing of the run is left.
  - The remove is retried for up to 10 s, because a `wineserver` may take a moment to exit after its sandbox's
    leader. This is documented in the test.
- **Decision E12: the CI workaround is an explicit `sysctl`, not a change to bwrap's AppArmor profile.**
  `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` is one line, is reversible, and affects only the
  throwaway runner. The step prints the value before and after, so the first hosted log shows whether the
  hypothesis held. The alternative cause (an AppArmor `bwrap-userns-restrict` profile) is named in the comment. A
  user systemd session is added only if the audit (item 7a) finds a non-ignored test that needs `systemd-run --user`
  and does not skip without it. Otherwise the comment says why no step is needed.

## 4. Behaviour

### 4.1 The per-spawn version check (item 1)

`Jobs::start` runs these steps in order:

1. `check_runtime_exe` (unchanged).
2. `check_job_cwd` (unchanged).
3. **`check_runtime_version(&cfg.runtime_exe, &cfg.cwd, &child_env(&cfg.env), cfg.version_timeout)`**, which
   returns one of:
   - `Ok(())`, when the first line is exactly `runtime <CARGO_PKG_VERSION>`;
   - `runtime_mismatch`, with the message `<path> is now version <got>; this runtimed is <ours>: restart runtimed
     (systemctl --user restart runtimed)`, the path and version cleaned and bounded;
   - `unavailable`, with the probe's failure.
4. The table lock and the caps (unchanged).

This narrows the check-then-exec window to the time between the probe and the spawn, but does not close it. The
existing "Check-then-exec" bound in `SECURITY.md` still applies: only the user or root can swap the file.

The probe must not leak. The child is killed at the deadline, as today. If a process the probe leaves behind keeps
the pipe open, the reader thread is leaked. At startup that was a one-off; per spawn it could repeat. So the reader
gets the same deadline: it reads with `poll(2)` until the deadline and then drops the pipe, so no thread outlives the
probe.

### 4.2 Re-digest under the lock (item 2)

`run_app` (CLI):

1. Compute the plan.
2. Print it.
3. `check_plan_digest` (fast refusal, unchanged).
4. `check_yes`, the backend, the sandbox marker (unchanged).
5. Build the `Orchestrator` with `plan_check: Some(&|p| check_plan_digest(id, p, manifest, Some(want)))` when
   `--plan-digest` was given.

`install_plan` (rt_deps), when `plan_check` is set:

1. `lock_app`.
2. `check_not_busy`.
3. Re-read the metadata.
4. `plan_for_app(env, &md, manifest, vulkan)`.
5. `plan_check(&fresh)?`, which on failure returns `DepsError::PlanChanged(String)` (Display: the check's message).
6. Continue with `fresh.facts` in place of `app.facts`.

The `!has_install` shortcut is unchanged: a plan with nothing to install installs nothing, whatever its digest.

### 4.3 Enum fallbacks (item 3)

| Enum | File | Fallback |
|---|---|---|
| `NetworkView`, `AccessView`, `PermSource`, `PlanAction`, `ConsentView` | `types.rs` | new `#[serde(other)] Unknown` |
| `VulkanState` | `types.rs` | `#[serde(other)]` on the existing `Unknown` |
| `SubjectView` (tag `kind`), `Availability` (tag `state`) | `types.rs` | new unit `#[serde(other)] Unknown` |
| `Status` (in `CompatRecord`) | `compat.rs` | new `#[serde(other)] Unknown`; `Record` validation refuses it |
| `ErrorKind`, `JobKind`, `JobState`, `EventKind` | `error.rs`, `jobs.rs` | already present; a test each if missing |

Every enum gets one test: a value like `"fromTheFuture"` (for tagged enums, `{"kind": "fromTheFuture", "x": 1}`)
deserialises as `Unknown`, and every known value round-trips. The typed client gets a test too: a reply with a new
`network` value parses through `Client::permissions`. `docs/API.md` "Versioning" says every result enum now has the
fallback, and request enums stay strict.

### 4.4 Display gating (item 5)

`display::run` first reads the metadata and calls `require_graphics_driver(&md.backend.id)`. That function is
`rt_api::backends::capabilities(id)`, mapped as follows: `None` refuses with the registry's unknown-id message, and
`Some(c)` with `!c.graphics_driver` refuses with `Unsupported::Feature`. Only then does `display::run` read
`user.reg` or take the lock. The daemon's `display.set` runs the CLI, so it inherits the gate. The 6D wording
"`runtime display` ... is not gated by a capability yet" leaves `rt_core::backend`'s docs and `SECURITY.md`.

### 4.5 `daemon-status` (item 6)

The classification lives in `rpc.rs` as `fn outcome(&Result<(VersionInfo, Option<bool>), ClientError>) -> Outcome`.
It is a pure function with a unit test per arm. `rt_daemon::protocol::{BUSY, TIMEOUT}` are the codes. The task
first confirms what a client-side read timeout surfaces as (`ClientError::Io` with `TimedOut`/`WouldBlock`, or
`Protocol`); the test pins it.

### 4.6 CI audit (item 7)

1. **(a) Audit.** List every non-ignored test (all crates, `gui` included) that needs real bwrap, `systemd-run
   --user`, Landlock or Yama. For each, record what happens without the facility on a hosted runner: it fails
   loudly with a message that names the fix, or it skips loudly. The table goes into the plan's As built and a
   comment in `ci.yml`. A test that fails with a message that does not say what is missing (for example a bare
   `bwrap: setting up uid map: Permission denied` assertion) gets a message that does: the sysctl name, the package,
   or the environment variable. Tests already under `RUNTIME_REQUIRE_BWRAP` are checked for that message, not
   changed.
2. **(b) Workaround.** A step before `cargo test` in the `test` and `gui` jobs:
   - prints `kernel.apparmor_restrict_unprivileged_userns` (tolerating its absence);
   - sets it to 0 with `sudo sysctl -w` when present;
   - prints it again.

   It carries the comment block of Decision E12 and the words "UNVERIFIED until the first hosted run". If the audit
   finds that a user systemd session is needed, a second step does the same for the session, also marked
   unverified: `loginctl enable-linger "$USER"`, export `XDG_RUNTIME_DIR` to `$GITHUB_ENV`, and wait for
   `/run/user/$UID/bus`.
3. **(c) Roadmap.** The "Open: the hosted `test` job failure" bullet records:
   - the local pass of `9cf1e27` (2026-10-02);
   - the hypothesis and the secondary;
   - that at `9cf1e27` the only tests of these classes were the bwrap installer-sandbox tests (5A/5B came later);
   - that the root cause stays unconfirmed until the user reads run 36228837680's log;
   - that the workaround is unverified;
   - that nothing was pushed.

## 5. Components

- `crates/daemon/src/{jobs.rs,write.rs}`, `crates/daemon/src/jobs/tests.rs`: the shared version check, the per-spawn
  call, and `JobsConfig::version_timeout`.
- `crates/api/src/{error.rs,lib.rs}`: `ErrorKind::RuntimeMismatch` (`runtime_mismatch`), `API_VERSION = "0.2.2"`.
- `crates/api/src/{types.rs,compat.rs}`: the fallbacks; `crates/gui/src/vm/page.rs`: the "unknown" labels.
- `crates/deps/src/orchestrate.rs` (+ tests): `Orchestrator::plan_check`, `DepsError::PlanChanged`;
  `crates/cli/src/deps.rs`: passing it.
- `crates/core/src/{backend.rs,fake.rs}`, `crates/core/src/backend/conformance.rs`, `crates/core/tests/conformance.rs`,
  `crates/backend-wine/src/lib.rs`, `crates/api/src/backends.rs`, `crates/cli/src/display.rs`,
  `crates/cli/src/doctor.rs` (prints interface 2): the capability.
- `crates/cli/src/rpc.rs`: the status outcomes.
- `tools/fixtures/sleep.c`, `tools/build-fixtures.sh`, `crates/daemon/tests/e2e_jobs.rs`: the fixture and the e2e.
- `.github/workflows/ci.yml`, test messages found by the audit, `docs/API.md`, `docs/SECURITY.md`, the roadmap.

## 6. Testing

- **Item 1.**
  - `rt_daemon::jobs` unit tests with the fake `runtime`, whose script reads its version from a file the test
    rewrites. Each start case with its expected result:
    - matching version: the job starts;
    - another version: `runtime_mismatch`, no job, no argv recorded;
    - a probe that hangs: `unavailable` within the shortened timeout, with no leaked thread (the thread count is
      unchanged after 20 hanging probes);
    - a probe that prints nothing: `unavailable`;
    - a script swapped to a symlink: `unavailable`, as today.
  - The e2e (part A): the real `runtimed --write` with the fake sibling; the sibling's version file is changed
    after startup, and `apps.remove` answers `runtime_mismatch`.
- **Item 2.**
  - `rt_deps` orchestrator tests:
    - with a `plan_check` that refuses, nothing is fetched or installed and `PlanChanged` comes back;
    - the check runs while the lock is held (the closure's own `lock_app` attempt gets `LockHeld`/`AppRunning`);
    - the check is handed the fresh plan: the metadata is changed between `plan_for_app` and `install_plan` (a
      dependency recorded as installed), and the check sees the changed entries;
    - with `plan_check: None`, behaviour is as today.
  - The CLI deps tests: the right digest behaves as today, and a wrong digest exits 1 (unchanged).
- **Item 3:** one test per enum (4.3); a client test; `compat.toml` with `status = "unknown"` or `"workz"` is
  refused; a GUI vm test (an `Unknown` access shows "unknown").
- **Item 4 (the e2e):** spec E11; run on this host under `RUNTIME_REQUIRE_BWRAP=1`, with `TMPDIR` under `target/`
  (6D environment note); the command and result go into As built.
- **Item 5:**
  - `require_graphics_driver` with `capabilities` returning `None`, `graphics_driver: false` and `true`.
  - CLI rig: an app whose metadata records `backend.id = "null"` makes `runtime display <id>` and `runtime display
    <id> x11` exit 1 with the unknown-backend message, and `user.reg` keeps its bytes.
  - Conformance: a broken backend with `graphics_driver` but not `sandboxable` fails exactly that check.
  - `doctor` prints `interface 2`.
- **Item 6:** `outcome` unit tests per arm; e2e: a daemon whose connection cap is full (hold its slots, as the
  server tests do), where `daemon-status` prints `busy`, does not print `start`, and exits 1; a missing socket still
  prints the hint.
- **Item 7:** the audit table; any message changes are covered by the existing tests that hit them (run locally
  with the facility removed where that is possible, e.g. `PATH` without bwrap); `ci.yml` stays valid YAML (checked
  with `python3 -c 'import yaml,sys; yaml.safe_load(open(sys.argv[1]))'`, if PyYAML is present, else by eye).

## 7. Risks

- **The version probe is a second spawn per job.** That is a few ms, bounded by 5 s, and outside the lock. A
  `runtime` that answers `--version` slowly makes every start slow; that is the user's binary.
- **`runtime_mismatch` after an upgrade.** The user upgrades both binaries while `runtimed` runs, and every write
  job is refused until a restart. This is the intended behaviour: the message says to restart, and read methods keep
  working.
- **The fallback hides a newer value.** A client that shows `unknown` instead of failing could mislead, for example
  a network policy shown as off. The GUI labels it "unknown" where it shows text. The network switch is a boolean
  and shows an unknown value as off. Toggling it sends the value the user picked, which is what the user asked for.
  This is a known bound, written into `SECURITY.md`.
- **The CI workaround may be wrong.** It is labelled unverified, and the roadmap keeps the item open. A wrong guess
  costs one red hosted run, which is no worse than today.

## As built

(Filled in by the implementation.)
