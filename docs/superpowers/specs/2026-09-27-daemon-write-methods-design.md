# Phase 6, sub-project B: `runtimed` write methods and jobs (design)

Status: approved by the controller on the user's standing instruction (self-approve with the recommended choices;
the user pre-approved the ten decisions this spec builds on, 2026-09-27). Second of four Phase 6 sub-projects (6A API
+ read-only daemon, **6B mutating methods + progress/log streams**, 6C GUI client, 6D plugin interfaces + `.wrun`).
Roadmap: "`runtimed` ... JSON-RPC with event streams (install progress, logs). No TCP."

## 1. Purpose and success criteria

A GUI (6C) or a script must be able to DO things through `runtimed`: run and stop an app, install a Windows program
or installer, remove an app, install its dependencies, change its permissions and display driver, and watch the
output while that happens. None of this may open a new way around the runtime's existing safety: the dependency
consent gate, the app sandbox and installer sandbox, the app lock, the permissions grant rules, and the refusals
while an app is running.

Success criteria:

1. The daemon never reimplements a mutating command. Every mutation is a **job** that runs the sibling `runtime`
   binary (the same file `sandbox.info` already names) as a child process with an argv built from validated,
   typed parameters. Every existing guard applies unchanged because the same tested code runs.
2. Write methods exist only when `runtimed --write` was passed. A read-only daemon (the default) answers them with
   `-32000` kind `read_only`; an unknown name stays `-32601`.
3. `deps.install` cannot invent consent: the client must send the digest of the plan it showed the user and the
   exact `{package, version, sha256}` of each consent-gated package the user accepted. The daemon and the CLI each
   recompute the plan and refuse when anything differs (`consent_mismatch`).
4. Output and state reach clients by **long-polling** (`jobs.poll`), ordered and gap-reported, with every line
   cleaned and bounded. No server push.
5. No client-supplied string can become an option, a second argument, a path outside what the CLI itself would
   accept, or a shell word: tested with ids and paths that start with `-`, contain spaces, newlines, NUL, `--`, `..`.
6. Jobs die with the daemon, are bounded in number, output and lifetime, and a cancelled job's process group is
   killed (SIGTERM, then SIGKILL after 5 s) without ever signalling a reused pid.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Execution | Each mutating request starts a job that spawns `<dir of runtimed>/runtime` (argv array, no shell), in its own process group, stdin `/dev/null`, stdout/stderr piped, allowlisted environment, a fixed empty cwd | One code path for every guard; no drift between CLI and daemon. Pre-approved. |
| Seam | `rt_api::jobs::JobSpec` (enum of the mutations) with `JobSpec::from_request(method, params) -> Result<JobSpec, ApiError>` (all validation) and `JobSpec::argv(&self) -> Vec<OsString>` (pure; never fails). The daemon owns processes; `rt_api` owns validation and argv shape; the CLI tests pin that the real parser reads every argv as intended | Validation next to the other API types, testable without processes; the CLI parser is the oracle for the argv. |
| Methods | `apps.run`, `apps.install`, `apps.remove`, `deps.install`, `permissions.set`, `permissions.reset`, `display.set` each return `{jobId}`; `jobs.poll`, `jobs.status`, `jobs.cancel`, `jobs.list` | One start method per mutation keeps params typed per method (no `jobs.start{kind, params}` union to validate). |
| Consent | Plan digest + explicit per-package consent, checked by the daemon (typed error) AND by the CLI under a new `--plan-digest HEX` guard of `runtime deps --install` | See 5.3. The CLI check closes the gap between the daemon's check and the install, and a version skew between `runtimed` and `runtime`. |
| Streams | Long-poll `jobs.poll{jobId, afterSeq, waitMs <= 25000}`; events `{seq, ts, kind, text}` | Pre-approved; fits the existing request/reply server and its deadlines (5.5). |
| Progress | Plain cleaned `stdout`/`stderr` line events plus `state` events. **No new CLI output format**; `progress` is a reserved event kind, not emitted in 6B | The CLI has no machine-readable progress, and nothing in 6C needs a percentage the lines don't give. A flag would be a second output contract to keep stable. |
| Authorization | Same-uid peer is the user (unchanged); write mode is opt-in per daemon (`--write`); the shipped unit passes it | Pre-approved. |
| API version | `0.2.0` | Mutating names change from `-32601` to `read_only` on a read-only daemon, which a 0.1 client may have relied on: breaking by API.md's own policy. Everything else is additive. |

Non-goals: TCP or any remote access; per-client authorization; push subscriptions, WebSocket, HTTP; new sandbox
features; the GUI (6C); `uninstall` (see Decision D6); unsandboxed runs through the API (D5).

### Decisions made while writing this spec (unspecified by the brief; safest simple option)

- **Decision D1: every mutation is a job, even quick ones** (`permissions.set`, `display.set`, `apps.remove`).
  One execution path, one set of tests; a synchronous variant would be a second way to call the CLI.
- **Decision D2: `permissions.set {id, set: [EXPR]}` takes the CLI's own `--set` expressions** (1-32 of them) and
  `permissions.reset {id}` maps to `--reset`, instead of `grant/revoke {dir}` methods. The CLI's grammar and grant
  rules (secret directories, `$HOME`, `/`, the data dir, `$XDG_RUNTIME_DIR` never grantable) are the guard; a
  narrower API would still need them and would lag the CLI. The same user can type any of these at a terminal.
- **Decision D3: `display.set {id, driver}` is included** (driver `auto|x11|wayland`, an enum): trivial argv, the
  CLI's lock and running-app refusal apply, and the GUI needs it.
- **Decision D4: at most one job per app at a time, of any kind** (`app_busy` otherwise), plus the global 4 running.
  No queue: a start over the cap is refused with `busy` and the client retries. The `queued` state exists only
  between accept and spawn (never observable for long). The app lock stays the real guard (a CLI started at a
  terminal is not seen by the daemon's map).
- **Decision D5: `apps.run` never passes `--unsandboxed` or `--debug`.** There is no API parameter for either. The
  program's arguments are allowed (after `--`, capped), because they reach only the program inside its sandbox.
- **Decision D6: `uninstall` is not exposed in 6B.** It runs an installer-recorded command; `apps.remove` covers
  removal. Add it later as its own method if the GUI needs it.
- **Decision D7: `apps.install` returns `app: null` in its job** (the id is derived by the CLI; the client reads it
  from the `Installed: <id>` line or `apps.list`). Install jobs do not take a per-app slot.
- **Decision D8: the child's cwd is a fixed empty directory** `$XDG_RUNTIME_DIR/runtime/job-cwd` (0700, ours,
  checked empty before each spawn; created at startup in write mode). `runtime run <id>` falls back to a FILE of
  that name in the cwd when the id is not installed (`rt_core::find_target`); an empty cwd removes that fallback
  entirely, including in the race where the app is removed between the daemon's check and the child's lookup.
- **Decision D9: the child environment is an allowlist**: `HOME PATH USER LOGNAME LANG LANGUAGE LC_ALL LC_CTYPE
  LC_MESSAGES TZ XDG_RUNTIME_DIR XDG_DATA_HOME XDG_CONFIG_HOME XDG_CACHE_HOME XDG_SESSION_TYPE DISPLAY
  WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS PULSE_SERVER` and every `RUNTIME_*` variable (the runtime's own
  configuration namespace, e.g. `RUNTIME_DATA_DIR`, `RUNTIME_WINE`), taken from the daemon's own environment,
  nothing from the client. The client cannot set any variable. (The sandbox then applies its own, stricter
  allowlist to the program.)
- **Decision D10: the sibling `runtime` is checked before each spawn**: a regular file (not followed if a symlink:
  refused), owned by the daemon's uid or root, not writable by group or others. At startup in write mode `runtimed`
  runs `runtime --version` (5 s bound) and refuses `--write` if its version differs from its own (the CLI's
  `--plan-digest` check still guards consent if the binary is replaced later).
- **Decision D11: `--write` requires the socket inside `$XDG_RUNTIME_DIR`** (the default path, any `--socket` below
  it, or an inherited systemd socket). Every sandbox profile mounts an empty tmpfs over `$XDG_RUNTIME_DIR` and no
  grant may name it, so no sandboxed app can reach a write-capable socket; a `--socket` in an arbitrary directory
  could be inside a granted one. A test renders the app and installer sandbox commands and asserts the socket's
  directory is not visible in either.
- **Decision D12: notifications (requests without `id`) are never executed**, write methods included (unchanged
  rule). A client that cannot learn the job id must not start a job.
- **Decision D13: no per-job wall-clock timeout.** A run lasts as long as the app; install and deps are bounded by
  the CLI's own timeouts. `jobs.cancel` and daemon shutdown are the stop paths.
- **Decision D14: event memory is bounded per job at 2,000 events AND 512 KiB of text** (the brief's 2,000 x 4 KiB
  would allow 8 MiB per job, 832 MiB for 104 jobs). Worst case: (4 running + 100 retained) x 512 KiB = 52 MiB.
- **Decision D15: no `runtime jobs` CLI command.** `runtime rpc jobs.poll '{...}'` works for scripts; the GUI is the
  real consumer. `runtime daemon-status` prints the mode.

## 3. Methods

All new methods are refused with `read_only` on a daemon without `--write`. Params are by-name objects with
`deny_unknown_fields`, like 6A.

| method | params | result |
|---|---|---|
| `apps.run` | `{id, args?: [str]}` | `{jobId}` |
| `apps.install` | `{path, name?, exe?, silent?: bool, network?: bool}` | `{jobId}` |
| `apps.remove` | `{id}` | `{jobId}` |
| `deps.install` | `{id, planDigest, consent: [{package, version, sha256}]}` | `{jobId}` |
| `permissions.set` | `{id, set: [EXPR]}` | `{jobId}` |
| `permissions.reset` | `{id}` | `{jobId}` |
| `display.set` | `{id, driver: "auto"\|"x11"\|"wayland"}` | `{jobId}` |
| `jobs.poll` | `{jobId, afterSeq: u64, waitMs?: u32}` | `JobEvents` |
| `jobs.status` | `{jobId}` | `JobInfo` |
| `jobs.cancel` | `{jobId}` | `JobInfo` |
| `jobs.list` | none | `{jobs: [JobInfo]}` (running first, then finished newest first) |

Changed read methods (additive): `rpc.version` gains `write: bool`; `deps.plan` gains `digest` (64 hex) and each
entry gains `sha256` (nullable, from the bundled manifest) and `consentText` (`null`, or the licence text as an
array of cleaned lines, for entries whose `consent` is `needed`) so a client can show exactly what it asks the user
to accept.

Types:

- `JobInfo {jobId, kind, app, state, exitCode, signal, createdAt, startedAt, endedAt, dropped}`. `kind`:
  `run|install|remove|depsInstall|permissionsSet|permissionsReset|displaySet`. `state`: `queued|running|succeeded|
  failed|cancelled`. `succeeded` = exit 0; `failed` = any other exit or a spawn failure; `cancelled` = ended after
  `jobs.cancel` (whatever the exit). Times are Unix milliseconds; `exitCode`/`signal` are `null` until known.
- `JobEvents {events: [{seq, ts, kind, text}], nextSeq, dropped, job: JobInfo}`. `kind`: `stdout|stderr|state`
  (`progress` reserved). `seq` starts at 1 and increases by 1 per event of the job. `dropped` = how many events
  with `seq > afterSeq` were evicted before this poll. A `state` event's `text` is the new state, with ` (exit N)` or
  ` (signal N)` when it ended.

New `data.kind` values: `read_only`, `consent_mismatch`, `busy` (4 jobs running), `app_busy` (a job for this app
is live). Unknown job id (never existed, evicted, or from a previous daemon) = `not_found`. A missing or unsafe
`runtime` binary or job cwd = `unavailable`. Param content errors = `invalid_argument`.

## 4. Components

- `crates/api/src/jobs.rs` (new): `JobSpec`, `JobKind`, the per-field validators, `argv()`, wire types `JobInfo`,
  `JobEvent`, `JobEvents`, `JobStarted`, `ConsentItem`; `plan_digest(&AppPlan, &Manifest, &AppId) -> String`
  (sha256, `sha2` is already a workspace dependency; no new third-party crate) and `check_consent(plan view,
  digest, consent) -> Result<Vec<String /* package ids for --yes */>, ApiError>`.
- `crates/api/src/types.rs`, `error.rs`, `runtime.rs`: the additive `deps.plan` fields, `VersionInfo::write`, the
  new `ErrorKind` variants, `API_VERSION = "0.2.0"`.
- `crates/cli/src/deps.rs`: `--plan-digest HEX` (requires `--install`): recompute the digest of the plan it is
  about to install and refuse (exit 1, nothing installed) when it differs. The only CLI behaviour change.
- `crates/daemon/src/jobs.rs` (new): `Jobs` (the table, limits, spawn, readers, ring, cancel, shutdown).
- `crates/daemon/src/dispatch.rs`: a `Ctx { rt, jobs: Option<Jobs>, stop }` replaces `&Runtime`; the new methods;
  `read_only` refusals.
- `crates/daemon/src/server.rs` + `main.rs`: `--write`, D8/D10/D11 startup checks, shutdown order, long-poll
  admission.
- `crates/daemon/src/client.rs`: typed helpers; `crates/cli/src/rpc.rs`: `daemon-status` prints the mode.
- `contrib/systemd/runtimed.service`: `ExecStart=... --write`; comments on the new mode and on `DISPLAY` /
  `WAYLAND_DISPLAY` needing to be in the user manager's environment for `apps.run`.
- `docs/API.md`, `docs/SECURITY.md`, README, roadmap row.

## 5. Behaviour

### 5.1 Argv construction (the injection boundary)

Validation in `JobSpec::from_request` (before any job exists; every failure `invalid_argument` with a fixed or
cleaned message):

- **App id:** `AppId::parse` AND `rt_core::classify(id) == TargetKind::Id` (so `x.exe`/`x.zip`, which `run` would
  read as a path, are refused). An `AppId` never starts with `-`, has no `/`, space, control character or NUL.
- **Installer path:** absolute; at most 4,096 bytes; no NUL, control or format character; no `.` or `..` component;
  no trailing `/`. Existence and type are the CLI's to judge (it reads it TOCTOU-safely already).
- **`name` (<= 256 bytes), `exe` (<= 1,024), each `set` EXPR (<= 4,096, 1-32 of them):** non-empty; no NUL, control
  or format character. Always passed in the `--flag=value` form, so a value that starts with `-` or equals `--`
  stays the flag's value.
- **Program args (`apps.run`):** at most 64, each at most 4,096 bytes, 64 KiB in total, no NUL; otherwise verbatim
  (they reach only the program).
- **`driver`:** the enum (an unknown value is a params shape error, -32602). **`planDigest`:** 64 lowercase hex.
  **`consent`:** at most 64 items, each field bounded; matched against the plan (5.3; a duplicate item is
  `consent_mismatch`), so only manifest package ids ever reach `--yes=`.

Argv shapes (after the program path). Every value either is validated to not start with `-` or sits after `--` or
inside `--flag=`:

| spec | argv |
|---|---|
| Run | `run <id> -- <args...>` (the `--` always present) |
| Install | `install [--name=N] [--exe=E] [--silent] [--network] -- <path>` |
| Remove | `remove -- <id>` |
| DepsInstall | `deps --install --plan-digest=<hex> [--yes=<pkg>]... -- <id>` |
| PermissionsSet | `permissions --set=<e1> ... --set=<eN> -- <id>` |
| PermissionsReset | `permissions --reset -- <id>` |
| DisplaySet | `display -- <id> <driver>` |

`runtime deps` has `list` and `cache` subcommands that shadow app ids of those names. If clap still routes `--
list` to the subcommand, `deps.install` refuses the ids `list` and `cache` with `invalid_argument` (the CLI test in
the plan decides which; either way the argv never reaches the wrong code).

### 5.2 Spawning

`Command::new(runtime_exe)` with `env_clear()` + the D9 allowlist, `current_dir(job_cwd)`, `stdin(null)`,
`stdout/stderr(piped)`, `process_group(0)` (the pgid is the child's pid), and a `pre_exec` that sets
`PR_SET_PDEATHSIG = SIGTERM` and `_exit(127)`s if `getppid()` is no longer the daemon (the standard race check).
PDEATHSIG fires when the spawning THREAD exits, so the spawn happens on the job's own supervisor thread, which lives
until the child is reaped. std resets `SIGPIPE` for the child; every daemon fd is `CLOEXEC` (the inherited systemd
listener included, 6A). The job keeps a reference to the `runtime` file it checked (D10) only for the error message;
the spawn itself is by path.

`runtime run` already handles SIGTERM: it forwards it to `bwrap`, whose `--die-with-parent` takes the sandbox down
(`crates/cli/src/run.rs` module docs), and reports 143. `install`/`deps`/`remove`/`permissions`/`display` die on
SIGTERM with the default action; the sandboxes they start die with their parent.

### 5.3 Consent (`deps.install`)

1. `deps.plan` returns `digest = sha256("rt-deps-plan-v2\n" + id + "\n" + for each entry in plan order:
   package "\0" version "\0" sha256 "\0" hex(sha256(consent_text)) "\0" action "\0" consent "\n")`, hex, where
   `consent_text` is `rt_deps::consent_text` of the package (what a prompt shows and a consent record hashes), so the
   digest binds the exact text the client showed. Entries with no manifest record use empty version/sha256/text hash. The function lives in `rt_api` and is the only implementation.
2. `deps.install {id, planDigest, consent}`: the daemon recomputes the plan (same `Runtime::deps_plan`), refuses with
   `consent_mismatch` when the digest differs, or when any `consent` item does not equal `{package, version,
   sha256}` of an entry with `action: install` and `consent: needed`. A needed entry the client did not list is
   simply not consented (the CLI skips it and what needs it, as at a terminal without `--yes`).
3. The argv carries `--plan-digest=<digest>` and one `--yes=<package>` per consented item. The CLI recomputes its
   plan and refuses before installing anything when the digest differs (exit 1, a stderr line; the job fails). Its
   existing `check_yes` still refuses a `--yes` for a package that needs no consent. The CLI prints the licence text
   in full on stdout before it accepts a `--yes`, so the job's events show what was accepted.
4. There is no "yes to all", no consent parameter that is not a concrete `{package, version, sha256}`, and no other
   CLI flag meaning "accept". (`install --network` gives an installer network access; it is a user choice the CLI
   also offers, not a consent, and is off unless the client sets it.)

### 5.4 Output, the ring, and limits

Two reader threads per job read the pipes to EOF, always draining (a child never blocks on a full pipe). A line ends
at `\n` or `\r`; a line longer than 4 KiB is cut at 4 KiB and the rest up to its end is discarded, the event text
ending in ` [cut]`. Text is decoded lossily and cleaned with `rt_core::clean_text(_, 4096)` (control and format
characters removed), so a hostile program cannot drive a terminal or break JSON. Events go into the job's ring
(D14); eviction increments `dropped`. `jobs.poll` returns at most 500 events per reply (<= 2 MiB, under the
client's 16 MiB cap). Limits: 4 running jobs, one live job per app (D4), finished jobs retained 100 and at most 1 h
(evicted oldest first on each start and poll). Job ids are 128 bits from `getrandom(2)`, 32 lowercase hex, held
only in memory: a new daemon knows none of the old ones.

### 5.5 Long-poll and the connection limits

`jobs.poll` waits on the job's condvar in slices of the server's `TICK` (100 ms), checking the stop flag, until an
event with `seq > afterSeq` exists, the job ends, or `waitMs` (default 0, max 25,000) elapses. 25 s is under the
30 s per-request deadline, so a poll never trips `-32002`; the per-line idle deadline starts after the reply, as
for any request, so it is not affected. A waiting poll holds its connection slot (one request in flight per
connection, unchanged): at most **8 polls wait at once** daemon-wide; a poll over that answers immediately as if
`waitMs` were 0, so at least 24 of the 32 slots stay free for other requests. On stop, waiting polls return within
one tick.

### 5.6 Cancel and shutdown

`jobs.cancel` marks the job cancelled-requested and sends SIGTERM to `-pgid`; after 5 s without the leader exiting,
SIGKILL to `-pgid`. **Pid reuse:** the supervisor learns of the leader's exit with `waitid(P_PID, pid, WEXITED |
WNOWAIT)`, which leaves the zombie in place; the pgid cannot be reused while its leader is an unreaped zombie. Group
signals are sent only under the job's lock while the supervisor has not reaped; the supervisor takes the same lock,
reaps, and marks the job ended. So a signal can reach only the job's own group. Group members still alive after the
leader was reaped are left alone (the sandboxes' `--die-with-parent` handle theirs).

Shutdown (SIGTERM/SIGINT): the stop flag is set; the listener closes; waiting polls return; every live job is
cancelled as above, the daemon waiting up to 5 s + 1 s for them to be reaped; then the existing 12 s grace for
in-flight requests. Total bounded well under systemd's 90 s stop timeout, and systemd's default
`KillMode=control-group` kills anything left in the service's cgroup (a sandboxed run's `systemd-run --scope` is
its own cgroup, but its `runtime`/`bwrap` leader was already signalled). If the daemon is SIGKILLed, PDEATHSIG
delivers SIGTERM to every job's `runtime`.

## 6. Testing

- `rt_api::jobs` unit tests: every validator's accept/refuse table (ids and paths starting with `-`, `--`, spaces,
  newlines, NUL, `..`, relative, 4 KiB+1, bidi characters, `x.exe`); `argv()` golden per spec; digest stability and
  sensitivity (changing any field changes it); `check_consent` (digest mismatch, unknown package, version or sha256
  off by one char, duplicate, consent for a not-needed package).
- CLI rig tests (`crates/cli/tests/apps.rs` and the deps tests): the real `runtime` binary parses every `argv()`
  shape as intended, with hostile values (a `name` of `--network`, an EXPR of `--reset`, program args `--`,
  `-x`, `;`); `deps --install --plan-digest` with a wrong digest installs nothing and exits 1; the right digest
  behaves exactly like today; `deps --install -- list` resolves as decided in 5.1.
- `rt_daemon::jobs` unit tests with a fake `runtime` (a shell script in a temp dir injected through the library's
  `JobsConfig`, recording its argv NUL-separated, its env and cwd, and acting on a mode file): env allowlist
  (a `SECRET` in the daemon env never reaches it), cwd empty, stdin EOF, own process group, output cleaning (ESC,
  bidi, NUL, CR, a 1 MiB line without newline, 100,000 lines: ring and `dropped` exact), caps (5th job `busy`,
  second job of an app `app_busy`, retention 100/1 h with an injected clock), cancel escalation (a child that
  ignores SIGTERM is SIGKILLed after 5 s; a grandchild in the group dies too), shutdown kills all jobs, a leader that
  exited before cancel is never signalled (pid reuse guard), job ids unique and 32 hex.
- Daemon socket tests: read-only daemon answers every write method with `read_only` and unknown names with -32601;
  write methods as notifications are not executed; long-poll returns on new output, on job end, on `waitMs`, and on
  stop within a tick; 9 concurrent waiting polls (the 9th answers immediately); a waiting poll does not block other
  connections; `--write` with a socket outside `$XDG_RUNTIME_DIR` refuses to start; `runtime --version` mismatch
  refuses `--write`.
- e2e (`crates/daemon/tests/`): the real `runtimed --write` binary copied next to a fake `runtime` (the production
  sibling mechanism; no environment override exists) for cancel/shutdown/argv at process level; the real `runtimed`
  + real `runtime` with the CLI rig's fake Wine: `apps.install` of a portable exe, `permissions.set` then
  `permissions.get`, `display.set`, `deps.install` of an empty plan, `apps.remove`; `apps.run` of that app fails
  inside the CLI's sandbox path (the fake Wine cannot run sandboxed) and its events never contain the unsandboxed
  warning. A real-Wine sandboxed `apps.run` of `hello64.exe` is `#[ignore]`d like the other Wine e2e tests (CI
  runs them). The sandbox visibility test of D11.

## 7. Risks

- **The daemon is now a same-uid write surface.** It adds no privilege: every job is a `runtime` command the same
  uid could run from a shell, with the same guards. The residual risks are reachability and confusion: other uids
  (refused by mode and `SO_PEERCRED`), browsers (no TCP, no HTTP: a request must be a JSON-RPC line on a Unix
  socket), sandboxed apps (D11), and a GUI that presents consent badly (the API only accepts consent to the exact
  package, version and hash; what the GUI shows is 6C's responsibility).
- **Version skew** between `runtimed` and a replaced `runtime`: checked at startup (D10); the consent path is also
  checked by the CLI itself.
- **Process-group leakage:** a program that leaves the group (`setsid`) survives cancel if it also escaped its
  sandbox's PID namespace, which it cannot; unsandboxed runs are not possible through the API (D5).

## As built

Implemented on branch `phase-6b-daemon-write`. Where the implementation differs from this text (the plan digest v2,
per-job directories, the cancel of a group's leftovers and the meaning of `cancelled`, the binary-directory and
`XDG_RUNTIME_DIR` checks, the unit's `KillMode`/`UMask`), the plan's "As built" section says what and why; docs/API.md
and docs/SECURITY.md describe the result.
