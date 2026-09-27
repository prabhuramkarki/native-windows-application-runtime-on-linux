# The runtime API and `runtimed`

`runtimed` serves the runtime's API (`rt_api`) as JSON-RPC 2.0 over an owner-only Unix socket. A GUI, a tray applet
or a script asks it what the CLI would print, as typed JSON. By default it is **read-only**. Started with `--write`,
it also runs, installs, imports and removes apps, installs dependencies and changes permissions and the display driver: each
such change is a **job** that runs the `runtime` CLI next to `runtimed`, whose output clients follow by long-polling
([Write mode and jobs](#write-mode-and-jobs)). API version **0.2.1**.

The CLI does not need the daemon. Every `runtime` command works on its own, except the two that exist to talk to it:
`runtime rpc` and `runtime daemon-status`.

This file is the wire contract. Where it and the code disagree, it is a bug. The method list below is checked
against the daemon's dispatch table by a test (`the_documented_methods_are_the_dispatch_table` in
`crates/daemon/src/dispatch.rs`).

## Transport

- **A Unix stream socket, and nothing else.** There is no TCP, now or later. The default path is
  `$XDG_RUNTIME_DIR/runtime/runtimed.sock`. `runtimed --socket PATH` and the clients' `--socket PATH` pick another.
  The path must be absolute and shorter than 108 bytes (`sun_path`).
- **Placement** (`runtimed` enforces all of this before it serves):
  - the directory is created 0700, and is refused if it is a symlink, not a directory, not the user's, or open to
    group or others;
  - the socket is 0600;
  - a stale socket of the user's is replaced; anything else at the path (a file, a symlink, another user's socket,
    a live daemon) is refused and left alone;
  - an exclusive `flock` on `<socket stem>.lock` next to the socket keeps a second daemon out.
- **Peer check.** Every connection's `SO_PEERCRED` uid must equal the daemon's uid. Any other is closed without a
  byte.
- **Socket activation.** `LISTEN_PID`/`LISTEN_FDS` (one fd, a listening `AF_UNIX` stream socket) are honoured. See
  [systemd](#running-it-under-systemd).

The security model, and what it does not cover, is in [SECURITY.md](SECURITY.md#the-runtimed-daemon-phase-6a) and,
for write mode, [SECURITY.md](SECURITY.md#the-runtimed-daemon-write-methods-phase-6b).

## Framing and limits

- **NDJSON.** One UTF-8 JSON value per line, `\n`-terminated, in both directions.
  - A last line without `\n` (the client half-closed) is still read as a request.
  - Blank lines are skipped (keep-alives).
- **Request lines are at most 1 MiB** (1,048,576 bytes, not counting the `\n`). A longer line gets one `-32600`
  error and the connection is closed. The daemon never buffers more than the cap plus one read.
- **Deadlines:**
  - Each request line must arrive whole within **30 s** of the previous reply (or of connecting). A silent or
    slow-drip client is closed.
  - Each reply must be written whole within 30 s.
  - Each request has **30 s** to run. After that the client gets `-32002` and the connection is closed. The method
    itself **cannot be cancelled**: it keeps its connection slot until it returns. Every method is bounded by its
    own probe timeouts; the longest is `vulkaninfo`, at 10 s. A `jobs.poll` waits at most 25 s, so it never reaches
    this deadline.
- **Connections:** at most **32** at once. Connection 33 gets one `-32001` line and is closed.
- **Requests:** one in flight per connection. Pipelined requests are answered in order.
- **Replies have no size cap in the daemon.** Clients should cap them. The bundled client accepts 16 MiB, which
  covers `apps.list` at the store's 10,000-entry cap.

## Requests and responses

A request is exactly one JSON object:

```json
{"jsonrpc": "2.0", "method": "apps.get", "params": {"id": "notepad"}, "id": 1}
```

- `jsonrpc` must be `"2.0"`. `method` is a string. No other members are allowed: an unknown member is `-32600`.
- `params` is optional. When present it must be an **object** (by-name). Positional arrays are `-32602`.
- `id` is an integer that fits in i64, or a string of at most 128 bytes without control or format characters, or
  `null`. Any other id (a fraction, a bool, a huge number, a string with an escape character) is `-32600`, answered
  with id `null`. A valid id is echoed exactly.
- **A request without `id` is a notification.** It gets no reply and is **not executed**, write methods included: a
  client that cannot learn a job's id must not start one.
- **Batches (a JSON array) are not supported.** They get one `-32600` with id `null`.

A reply is one of these two shapes:

```json
{"jsonrpc": "2.0", "id": 1, "result": {...}}
{"jsonrpc": "2.0", "id": 1, "error": {"code": -32000, "message": "...", "data": {"kind": "not_found"}}}
```

Member order is not significant; the daemon writes members in alphabetical order.

## Errors

| code | meaning | `data` | connection after it |
|---|---|---|---|
| -32700 | parse error: not UTF-8, not JSON, a NUL | none | kept |
| -32600 | invalid request (see above), a batch, a line over 1 MiB | none | kept (closed after an over-long line) |
| -32601 | method not found (a name in neither list, e.g. `apps.uninstall`) | none | kept |
| -32602 | invalid params: not an object, an unknown member, a missing or mistyped field, an unknown `driver`, `waitMs` over 25000 | none | kept |
| -32603 | internal error (a bug; the text never says more) | none | kept |
| -32000 | domain error from `rt_api` | `{"kind": "..."}` | kept |
| -32001 | server busy (connection cap reached); id is `null` | none | closed |
| -32002 | the request timed out | none | closed |

`data.kind` values for `-32000`:

- `not_found`: a well-formed id names no installed app; a job id the daemon does not know (never existed, expired,
  or from an earlier daemon).
- `invalid_argument`: a value the method refuses: an id that is not a valid app id (or would be read as a file:
  `x.exe`), a path that is not absolute or has `.`/`..`, a value with a control or format character, a value over
  its bound, a `planDigest` that is not 64 lowercase hex.
- `unavailable`: the request is fine but the host cannot answer. Examples: no data directory; corrupt metadata; an
  invalid, oversized or symlinked `permissions.toml`; an app not prepared by this version; a `runtime` binary or job
  directory that is no longer safe to use (the message says what to do, e.g. `run: chmod g-w,o-w <path>`); a daemon
  that is stopping.
- `read_only`: a write method on a daemon started without `--write`. Its params are not even read.
- `consent_mismatch`: `deps.install`'s `planDigest` is not the digest of the plan as it is now, or a `consent` item
  is not exactly `{package, version, sha256}` of a consent-gated package that plan installs (or names one twice).
- `busy`: 4 jobs are already running. Nothing is queued: try again later.
- `app_busy`: a job for this app is still running.
- `internal`: reserved.

**Switch on `code` and `data.kind`, never on `message`.** A `message` is prose for people. It is cleaned (no
control or format characters) and bounded, but it may change between versions.

## Write mode and jobs

Write methods exist only on a daemon started with `runtimed --write` (the shipped systemd unit passes it). A
read-only daemon answers each of them `-32000` kind `read_only`, and `rpc.version` says `"write": false`.

**Every change is a job.** A write method validates its params, starts a job, and returns `{"jobId": "<32 hex>"}` at
once. The job runs the `runtime` binary next to `runtimed` with an argument list built from the validated params,
never a shell. So every guard of the CLI applies unchanged: the dependency consent gate, the app and installer
sandboxes, the app lock, the refusals while an app is running, the grant rules. What each method runs:

- `apps.run`: `runtime run <id> -- <args...>` (always sandboxed: there is no parameter for `--unsandboxed` or
  `--debug`);
- `apps.install`: `runtime install [--name=N] [--exe=E] [--silent] [--network] -- <path>`;
- `apps.import`: `runtime import [--silent] [--network] -- <path>`;
- `apps.remove`: `runtime remove -- <id>`;
- `deps.install`: `runtime deps --install --plan-digest=<hex> [--yes=<pkg>]... -- <id>`;
- `permissions.set`: `runtime permissions --set=<expr>... -- <id>`;
- `permissions.reset`: `runtime permissions --reset -- <id>`;
- `display.set`: `runtime display -- <id> <driver>`.

Every client value is an app id or an absolute path (neither can start with `-`), sits after `--`, or is inside
`--flag=value`, so no value can become an option.

The job's process gets only these variables from the daemon's own environment, never any from a client: `HOME PATH
USER LOGNAME LANG LANGUAGE LC_ALL LC_CTYPE LC_MESSAGES TZ XDG_RUNTIME_DIR XDG_DATA_HOME XDG_CONFIG_HOME
XDG_CACHE_HOME XDG_SESSION_TYPE DISPLAY WAYLAND_DISPLAY XAUTHORITY DBUS_SESSION_BUS_ADDRESS PULSE_SERVER` and every
`RUNTIME_*`. Its working directory is a fresh, empty directory of its own; stdin is `/dev/null`.

**Following a job.** `jobs.poll {"jobId", "afterSeq", "waitMs"}` returns the job's events after `afterSeq`, waiting up
to `waitMs` ms (at most 25,000) for one, or for the job to end. Pass the returned `nextSeq` as the next `afterSeq`.
Stop when `job.state` is `succeeded`, `failed` or `cancelled`: the last event is then that state event.

- An event is `{seq, ts, kind, text}`: `seq` starts at 1 and grows by 1; `ts` is Unix milliseconds; `kind` is
  `stdout` or `stderr` (one line of the job's output) or `state` (`queued`, `running`, then `succeeded (exit 0)`,
  `failed (exit N)`, `failed (signal N)`, `cancelled (signal N)`, ...). `progress` is reserved and never sent in 0.2.
- Output lines end at `\n`, `\r` or `\r\n`. A line over 4,096 bytes is cut, its text ending in ` [cut]`. The daemon
  removes control and format characters from every line. **A client must still clean or escape every string it
  shows** (event texts included): it cannot know that the process at the socket is a well-behaved daemon, and the
  bundled client hands strings back as they came (`runtime rpc` escapes them).
- Memory per job is bounded (2,000 events and 512 KiB of text). The oldest events are dropped first; `dropped` in
  the reply counts those after `afterSeq` that were dropped before this poll, and `job.dropped` all of them.
- If a process the job started still holds its output one second after `runtime` exited, a `stderr` note says later
  output is not shown, and the job ends.

A job's `JobInfo` is `{jobId, kind, app, state, exitCode, signal, createdAt, startedAt, endedAt, dropped}`: `kind` is
`run`, `install`, `import`, `remove`, `depsInstall`, `permissionsSet`, `permissionsReset` or `displaySet`; `app` is
`null` for an install or an import (the CLI derives the id: read it from the `Installed: <id>` line or `apps.list`);
times are Unix ms;
`exitCode` and `signal` are `null` until known.

**States.** `queued` (only between the start and the spawn), `running`, then one of: `succeeded` (exit 0),
`failed` (any other exit, or the job could not start: a `stderr` event says why), `cancelled` (the cancel stopped it:
before it started, or through the SIGTERM it was sent, ending other than with exit 0). A job that exited 0 after a
cancel `succeeded`; one that ended on its own before the cancel reached it keeps its own result.

**Cancel.** `jobs.cancel` sends SIGTERM to the job's process group and SIGKILL 5 s later if `runtime` has not
exited; once it has, whatever is left of the group has the rest of those 5 s to stop, then gets SIGKILL (the job ends
when the group is empty, or after that SIGKILL). A cancel that arrives after `runtime` already exited leaves the job's
result as it is, and gives what is left of the group SIGTERM, then SIGKILL 5 s later. `runtime run` passes SIGTERM on to the sandbox,
which dies with it. A signal is never sent to a process group whose leader was already reaped, so a reused pid is
never signalled.

**Consent (`deps.install`).**

1. Call `deps.plan`. Show the user each entry; for each entry with `consent: "needed"`, show its `consentText` (the
   exact text the CLI prints before it asks), and let the user accept or decline each one.
2. Call `deps.install` with the plan's `digest` and, for each package the user accepted, its exact
   `{package, version, sha256}` from the plan. A needed package you do not list is simply not installed (nor what
   needs it), as at a terminal without `--yes`.
3. The daemon recomputes the plan and refuses with `consent_mismatch` if its digest differs (the app, the manifest,
   an installed package, or a licence text changed since you showed it) or if any item is not exactly a
   consent-gated entry of it. Show the plan again and ask again.
4. The job's `runtime deps --install --plan-digest=<digest>` recomputes the plan once more and refuses (exit 1,
   nothing installed) if it changed in between. It prints the licence text in full before it accepts a package, so
   the job's events show what was accepted.

There is no "yes to all" and no consent that is not a concrete package, version and hash.

**Limits.**

| what | bound | over it |
|---|---|---|
| running jobs | 4 | `busy` |
| live jobs per app | 1 | `app_busy` |
| finished jobs kept | 100, and at most 1 h | the oldest are forgotten (`not_found`) |
| events kept per job | 2,000 and 512 KiB of text | the oldest are dropped (counted in `dropped`) |
| events per poll | 500 | the rest on the next poll |
| event text | 4,096 bytes | cut, ending ` [cut]` |
| a poll's `waitMs` | 25,000 | -32602 |
| polls waiting at once | 8, daemon-wide | a 9th answers at once, as if `waitMs` were 0 |
| program args of `apps.run` | 64, each 4,096 bytes, 64 KiB in all, no NUL | `invalid_argument` |
| expressions of `permissions.set` | 1-32, each 4,096 bytes | `invalid_argument` |
| consent items of `deps.install` | 64 | `invalid_argument` |

Waiting polls take at most 8 of the 32 connection slots. Job ids exist only in the daemon's memory: a restarted
daemon knows none. Jobs die with the daemon: on SIGTERM it cancels every job and waits for them before it removes its
socket; if it is killed outright, each job's `runtime` gets SIGTERM from the kernel (`PR_SET_PDEATHSIG`).

## Methods

| method | params | result |
|---|---|---|
| `rpc.version` | none | `VersionInfo` |
| `apps.list` | none | `AppList` |
| `apps.get` | `{"id"}` | `AppDetail` |
| `permissions.get` | `{"id"}` | `PermissionsView` |
| `compat.list` | none | `CompatView` |
| `doctor.system` | none | `DoctorView` |
| `doctor.app` | `{"id"}` | `DoctorView` |
| `graphics.info` | none | `GraphicsView` |
| `sandbox.info` | `{"id"}` | `SandboxView` |
| `deps.plan` | `{"id"}` | `DepsPlanView` |
| `apps.run` | `{"id", "args"?}` | `JobStarted` (write mode) |
| `apps.install` | `{"path", "name"?, "exe"?, "silent"?, "network"?}` | `JobStarted` (write mode) |
| `apps.import` | `{"path", "silent"?, "network"?}` | `JobStarted` (write mode) |
| `apps.remove` | `{"id"}` | `JobStarted` (write mode) |
| `deps.install` | `{"id", "planDigest", "consent"}` | `JobStarted` (write mode) |
| `permissions.set` | `{"id", "set"}` | `JobStarted` (write mode) |
| `permissions.reset` | `{"id"}` | `JobStarted` (write mode) |
| `display.set` | `{"id", "driver"}` | `JobStarted` (write mode) |
| `jobs.poll` | `{"jobId", "afterSeq", "waitMs"?}` | `JobEvents` (write mode) |
| `jobs.status` | `{"jobId"}` | `JobInfo` (write mode) |
| `jobs.cancel` | `{"jobId"}` | `JobInfo` (write mode) |
| `jobs.list` | none | `JobList` (write mode) |

Conventions:

- "none" means `params` is absent or `{}`. `{"id"}` means `{"id": "<app id>"}` and nothing else.
- Results are the `rt_api` wire types (`crates/api/src/types.rs`), serialised with **camelCase** member names.
- Every free-text string in a result comes from untrusted data (installer metadata, file names, tool output). It is
  cleaned at the API boundary: control and format characters (escape sequences, bidi overrides, zero-width
  characters, newlines) are removed, and the length is bounded. Cleaning is lossy.
- Optional fields are present with value `null`, never absent.

The examples are real output from a scratch store with one app, `notepad` (except `sandbox.info`, see there).
Long arrays and texts are cut (`...`).

### `rpc.version`

The API version (semver), the runtime's crate version, the protocol name, and whether this daemon has the write
methods (`runtimed --write`). A 0.1 daemon has no `write`: treat it as `false`.

```json
{"api": "0.2.1", "protocol": "jsonrpc-2.0-ndjson", "runtime": "0.0.1", "write": false}
```

### `apps.list`

The installed apps, and how many entries of the apps directory were skipped (corrupt metadata, a symlink, a stray
file). `skipped` is a lower bound when the store hits its 10,000-entry cap. The rows are the ones
`runtime list --json` prints.

```json
{
  "apps": [
    {"architecture": "x86_64", "created": 1790451200, "executable": "C:\\app\\a.exe",
     "id": "notepad", "name": "Notepad", "version": "1.0"}
  ],
  "skipped": 0
}
```

### `apps.get`

One app. The fields:

- the summary fields of `apps.list`;
- `backend` `{id, version}`;
- `environment` and `subsystem`;
- `installer`: `null`, or `{family, productName, uninstallCommand}`;
- `dependencies`: `[{id, version, installedAt}]`;
- `prefix`: `{exists, hasDriveC}`, probed without following symlinks;
- `package` (0.2.1): `null`, or, for an app imported from a `.wrun`, `{id, version, digest, requestedDependencies,
  requestedPermissions}`: what the package asked for, recorded and never granted. A 0.2.0 daemon leaves it out;
  clients read a missing `package` as `null`.

```json
{
  "architecture": "x86_64", "backend": {"id": "wine", "version": "10.0"}, "created": 1790451200,
  "dependencies": [], "environment": "default", "executable": "C:\\app\\a.exe", "id": "notepad",
  "installer": null, "name": "Notepad", "package": null, "prefix": {"exists": true, "hasDriveC": true},
  "subsystem": "gui", "version": "1.0"
}
```

Errors: `invalid_argument` for a malformed id; `not_found` for an unknown one; `unavailable` for unreadable
metadata.

### `permissions.get`

The app's sandbox profile. `source` is `default` (no `permissions.toml`) or `file`. The fields:

- `network`: `allow` or `deny`;
- `display`, `audio`, `gpu`: booleans;
- `filesystem`: `[{path, access}]`, where `access` is `ro` or `rw`;
- `limits`: `{memoryMb, cpuPercent, tasks, tasksDefault, explicit}`;
- `requested` (0.2.1): for an app imported from a `.wrun`, the permissions its package requested that this profile
  does not grant, as `runtime permissions --set` expressions (`network=allow`, `gpu=on`, ...). Display only: grant
  one with `permissions.set`. Empty otherwise; a 0.2.0 daemon leaves it out (read as empty).

An invalid file is an `unavailable` error, never a silent default.

```json
{
  "audio": true, "display": true, "filesystem": [], "gpu": true,
  "limits": {"cpuPercent": null, "explicit": false, "memoryMb": null, "tasks": 4096, "tasksDefault": true},
  "network": "deny", "requested": [], "source": "default"
}
```

### `compat.list`

The bundled compatibility matrix (`docs/COMPAT.md`). The `records` are the rows that `runtime compat --json` prints.

```json
{"records": [{"app": "hello64.exe (fixture)", "evidence": "manual:2026-09-26", "gpu": null, "graphics": false,
  "notes": "runtime install + run of a 64-bit console program: ...", "status": "works", "version": null,
  "wine": "10.0 (Ubuntu 10.0~repack-12ubuntu1)"}, ...]}
```

### `doctor.system`

The system health report: the same checks as `runtime doctor`. These fields are **stable**:

- `subject.kind`;
- `verdict`: `good`, `may_fail` or `fail`;
- each check's `area`: `architecture`, `pe`, `imports`, `graphics`, `audio`, `runtime`, `prefix` or `program`;
- each check's `status`: `ok`, `warn` or `fail`.

A check's `text` is prose. `subject`, `verdict` and `checks` equal `runtime doctor --json` for the same host
(tested). Also returned:

- `missingDependencies`: how many packages `runtime deps <app> --install` would install;
- `notes`: installer packages already in the prefix that the runtime did not install.

This method runs host probes: `wine --version`, bwrap's probe, the `systemd-run` scope probe, and `vulkaninfo`,
which is cached for 30 s.

```json
{
  "checks": [
    {"area": "architecture", "status": "ok", "text": "host architecture: x86-64"},
    {"area": "runtime", "status": "ok", "text": "Wine: wine-10.0 (Ubuntu 10.0~repack-12ubuntu1); backend wine, interface 1"},
    {"area": "graphics", "status": "ok", "text": "Vulkan: 3 devices usable"}, ...
  ],
  "missingDependencies": 0, "notes": [], "subject": {"kind": "system"}, "verdict": "may_fail"
}
```

### `doctor.app`

The same report, with the app's own checks added (its program, imports, prefix and sandbox profile).
`subject` is `{"kind": "app", "id", "name", "version"}`. Errors are as for `apps.get`.

```json
{"checks": [...], "missingDependencies": 0, "notes": [],
 "subject": {"id": "notepad", "kind": "app", "name": "Notepad", "version": "1.0"}, "verdict": "fail"}
```

### `graphics.info`

What `runtime graphics info` shows. The fields:

- `devices`: the Vulkan devices, each `{name, deviceType, api, driver}`;
- `verdict`: `usable`, `unusable` or `unknown`;
- `reason`: why, when the verdict is not `usable`;
- `perPackage`: each bundled translation layer's minimum Vulkan version, and whether this host meets it;
- `loader`: whether `libvulkan.so.1` was found;
- `toolFound`: whether `vulkaninfo` was found.

```json
{
  "devices": [{"api": "1.4", "deviceType": "INTEGRATED_GPU", "driver": "radv", "name": "AMD Radeon 660M (RADV REMBRANDT)"}, ...],
  "loader": true, "perPackage": [{"id": "dxvk", "minVulkan": "1.3", "ok": true}, ...],
  "reason": null, "toolFound": true, "verdict": "usable"
}
```

### `sandbox.info`

What `runtime sandbox <app>` shows. The fields:

- `bwrap`, `wine`, `limits`: each `{"state": "available"}` or `{"state": "unavailable", "reason"}`;
- `profile`: as `permissions.get`;
- `seccomp`, `landlock`: text;
- `hardeningComplete`: boolean;
- `cgroupControllers`;
- `refused`: why the sandbox would refuse the command, or `null`;
- `skipped`: what the host lacks for this profile;
- `caveats`: what cannot be enforced;
- `command`: the full argv `runtime run` would start (systemd-run, bwrap, `runtime sandbox-init`).

The `runtime` named as the sandbox's launcher is the binary next to `runtimed`. An app that was not prepared by this
version (no per-app home) is an `unavailable` error. The example is abridged and illustrative: the values depend on
the host.

```json
{"bwrap": {"state": "available"}, "caveats": [], "cgroupControllers": ["cpu", "memory", "pids"],
 "command": ["systemd-run", "--user", "--scope", ...], "hardeningComplete": true, "landlock": "ABI 8 (fs)",
 "limits": {"state": "available"}, "profile": {...}, "refused": null, "seccomp": "enforced (x86_64, 63 rules)",
 "skipped": [], "wine": {"state": "available"}}
```

### `deps.plan`

What `runtime deps <app>` would install. It does not use the network and changes nothing. The fields:

- `entries`: dependencies first, each `{package, version, sha256, action, consent, consentText, blockedReason}`,
  where:
  - `version` and `sha256` are the bundled manifest's (`null` for a package it does not know);
  - `action` is `install`, `alreadyInstalled` or `blocked`;
  - `consent` is `notNeeded`, `needed` or `denied`;
  - `consentText` is, for an entry whose `consent` is `needed`, the exact text a consent prompt shows, one string per
    line (cleaned); otherwise `null`;
- `unsatisfied`: needed capabilities that no bundled package provides;
- `warnings`;
- `digest`: 64 hex digits identifying this plan (the app, and per entry the package, version, sha256, licence text,
  action and consent). `deps.install` needs it back.

```json
{"digest": "5f0c...", "entries": [], "unsatisfied": [],
 "warnings": ["cannot read the app's executable (not a Windows program or a zip archive (unrecognised format)); the plan does not include what it imports"]}
```

### `apps.run`

Params: `{"id": "<app id>", "args": ["...", ...]}` (`args` optional). Runs the app in its sandbox, as `runtime run`
does from a terminal; the job's `stdout`/`stderr` events are the program's output (as the CLI shows it) and its exit
code is the program's (143 after a cancel). `args` reach only the program, verbatim. An id that `runtime run` would
read as a file (`x.exe`, `x.zip`) is `invalid_argument`. The job holds the app's slot while the app runs.

```sh
runtime rpc apps.run '{"id": "notepad", "args": ["C:\\notes.txt"]}'
# {"jobId": "9c4f0d8e5b1a4f7e8d2c3b6a1f0e9d8c"}
```

### `apps.install`

Params: `{"path": "/abs/file", "name"?: str, "exe"?: str, "silent"?: bool, "network"?: bool}`. Installs a portable
`.exe`, a `.zip` or an installer, as `runtime install`. `path` must be absolute, without `.`/`..` components; the
CLI judges the file itself. `name` (at most 256 bytes) and `exe` (1,024) are passed as values, never as options.
`network` gives an installer network access while it runs: a user's choice, off unless set. The job's `app` is
`null`; the new id is in the `Installed: <id>` event.

```sh
runtime rpc apps.install '{"path": "/home/me/Downloads/setup.exe", "silent": true}'
```

### `apps.import`

Params: `{"path": "/abs/file.wrun", "silent"?: bool, "network"?: bool}`. Imports a `.wrun` package as
`runtime import` does: the app gets the id its manifest names (an app with that id already installed fails the job
and is left alone), and what the package requests (dependencies, permissions) is recorded and printed with the
command that would grant it. **Nothing is granted, downloaded or run**: dependencies still need `deps.install` and
their consent, permissions `permissions.set`. `path` is checked as `apps.install`'s; there is no `name` or `exe` (the
manifest has them). `silent` and `network` are the user's choices for an installer package (the job fails, exit 1,
when either is set for a portable one). The job's `app` is `null`; the id is in the `Installed: <id>` event, and the
job's first lines are the package summary (as `runtime inspect`), including that it is unsigned.

```sh
runtime rpc apps.import '{"path": "/home/me/Downloads/example.wrun"}'
```

### `apps.remove`

Params: `{"id"}`. Stops the app's Wine processes and deletes the app, as `runtime remove`. Refused (a `failed` job,
the reason in a `stderr` event) while the app runs.

### `deps.install`

Params: `{"id", "planDigest": "<64 hex>", "consent": [{"package", "version", "sha256"}, ...]}`. Installs the plan
`deps.plan` showed; see [Consent](#write-mode-and-jobs) above. `consent_mismatch` when the plan changed or an item is
not exactly a consent-gated entry of it; no job is started then.

```sh
d=$(runtime rpc deps.plan '{"id": "game"}' | jq -r .digest)
runtime rpc deps.install "{\"id\": \"game\", \"planDigest\": \"$d\", \"consent\": []}"
```

### `permissions.set`

Params: `{"id", "set": ["network=allow", "fs+=/home/me/Games:rw", ...]}` (1-32 of `runtime permissions --set`'s
expressions). All are checked before anything is written; a refused one (a grant of `$HOME`, `/`, a secret
directory, the data directory, `$XDG_RUNTIME_DIR`) fails the job and changes nothing.

### `permissions.reset`

Params: `{"id"}`. Deletes the app's `permissions.toml` (back to the default), as `runtime permissions --reset`.

### `display.set`

Params: `{"id", "driver": "auto" | "x11" | "wayland"}`. Sets the app's Wine graphics driver, as `runtime display`.
Another `driver` is -32602.

### `jobs.poll`

Params: `{"jobId", "afterSeq": u64, "waitMs"?: 0..25000}`. The job's events after `afterSeq` (at most 500), waiting up to
`waitMs` for one or for the job's end. Result `{events, nextSeq, dropped, job}`: pass `nextSeq` as the next
`afterSeq`. The client's call deadline must exceed `waitMs` (the bundled client uses `waitMs` + 15 s).

```sh
runtime rpc jobs.poll '{"jobId": "9c4f0d8e5b1a4f7e8d2c3b6a1f0e9d8c", "afterSeq": 0, "waitMs": 10000}'
# {"dropped": 0, "events": [{"kind": "state", "seq": 1, "text": "queued", "ts": 1790479513925},
#   {"kind": "state", "seq": 2, "text": "running", "ts": 1790479513926}, ...], "job": {...}, "nextSeq": 2}
```

### `jobs.status`

Params: `{"jobId"}`. The job's `JobInfo`.

### `jobs.cancel`

Params: `{"jobId"}`. Stops the job (see Cancel above) and returns its `JobInfo` as it is at that moment; poll to see it
end. A job that already ended is left alone.

### `jobs.list`

Params: none. `{"jobs": [JobInfo, ...]}`: live jobs first (oldest first), then finished ones, newest first.

## Versioning and compatibility

- `API_VERSION` (from `rpc.version`) is semver, currently **0.2.1**. Until 1.0:
  - a **breaking** change bumps the **minor** version: a method removed or renamed, a param changed, a result
    member removed or retyped, an enum value removed;
  - an **additive** change bumps the **patch** version: a new method, a new result member, a new enum value, a new
    `data.kind`.
  1.0 freezes the surface at the end of Phase 6.
- **Clients must ignore unknown members** in results and replies. The bundled client does.
- An **unknown `data.kind`** deserialises as `ErrorKind::Unknown`: `ErrorKind` is `#[non_exhaustive]` with a serde
  fallback.
- The job enums (`JobKind`, `JobState`, `EventKind`) also read an unknown value as `Unknown`. The other enums are
  `#[non_exhaustive]` for Rust callers but have **no** serde fallback. A typed helper of an older client fails with a
  protocol error ("the result does not have the expected shape") when a newer daemon sends a new enum value.
  `Client::call` (raw JSON) always works. A client that must span versions checks `api` first.
- **0.2.0 is breaking** by the rule above: the mutating names that were `-32601` in 0.1 are now known methods, which
  a read-only daemon answers `read_only`. Everything else is additive: the write methods, `rpc.version.write`, and
  `deps.plan`'s `digest`, `sha256` and `consentText`. A 0.2 client reading a 0.1 daemon's `deps.plan` gets an
  empty `digest`, and the bundled client refuses `deps_install` with it before sending.
- **0.2.1 is additive**: the `apps.import` method and its job kind `import`, `apps.get`'s `package` and
  `permissions.get`'s `requested`. A 0.2.0 daemon answers `apps.import` `-32601`; the GUI offers a `.wrun` only to a
  0.2.1 daemon.
- The protocol name `jsonrpc-2.0-ndjson` changes only if the framing does.

## Running it

By hand, in the foreground:

```sh
runtimed                         # read-only, $XDG_RUNTIME_DIR/runtime/runtimed.sock
runtimed --write                 # with the write methods
runtimed --socket /run/user/1000/rt-test.sock
```

It logs one line per event on stderr (including `mode: write` or `mode: read-only` at startup), and never logs a
request's content. SIGTERM or SIGINT stops it (exit 0): it closes the socket to new connections, cancels every job and
waits for them, lets requests in flight finish (up to 12 s), then removes the socket it bound. Exit 1 means it cannot
start (another daemon, an unsafe path, no `XDG_RUNTIME_DIR`, a failed `--write` check); 2 means bad arguments.

**`runtime` must sit next to `runtimed`** (same directory). `sandbox.info` names it as the sandbox's launcher, and
every job runs it. `--write` also requires, before it starts:

- the socket (bound, or inherited from systemd) resolves inside `$XDG_RUNTIME_DIR`, which must be a 0700 directory of
  the user (not `/`). No sandbox profile can see that directory, so no sandboxed app can reach a write-capable socket;
- `$XDG_RUNTIME_DIR/runtime/job-cwd` is (or is created as) a 0700 directory of the user. The daemon takes a
  directory of its own in it (`d-<32 hex>/`, marked live by an `flock` on `d-<32 hex>.lock` held for its life), and
  removes only the directories of daemons that are gone, never another live daemon's;
- `runtime` is a regular file (not a symlink) owned by the user or root and writable only by its owner, in a
  directory with the same property. With a umask of 002 (the Ubuntu default) cargo installs both group-writable:
  `runtimed` then says so and names the fix, `chmod g-w,o-w <path>`. The same check runs before every job;
- `runtime --version` answers within 5 s with this daemon's own version.

### Running it under systemd

The user units are in `contrib/systemd/`. They are not installed by the build.

```sh
cp contrib/systemd/runtimed.socket contrib/systemd/runtimed.service ~/.config/systemd/user/
# edit ExecStart= in runtimed.service to where runtimed is installed (default: %h/.cargo/bin/runtimed)
systemctl --user daemon-reload
systemctl --user enable --now runtimed.socket
runtime daemon-status
```

How it behaves:

- systemd owns the socket: `%t/runtime/runtimed.sock`, with `SocketMode=0600` and `DirectoryMode=0700`.
- The first connection starts `runtimed.service`, which serves the inherited socket and never removes it.
- The service runs `runtimed --write`. Drop `--write` for a read-only daemon. If `runtimed` refuses to start,
  `journalctl --user -u runtimed` has the reason (for a umask-002 install:
  `chmod g-w,o-w ~/.cargo/bin ~/.cargo/bin/runtime`).
- `KillMode=mixed`: `systemctl --user stop` sends SIGTERM to `runtimed` alone, which cancels its jobs in order.
  `UMask=0022`: jobs create files as a terminal with that umask would; the daemon's own socket and directories have
  explicit modes.
- `apps.run` opens windows only if `DISPLAY` / `WAYLAND_DISPLAY` (and `XAUTHORITY`) are in the user manager's
  environment. Most desktop sessions import them; otherwise `systemctl --user import-environment DISPLAY
  WAYLAND_DISPLAY XAUTHORITY`.
- The service has **no sandboxing options**, on purpose. They would change what the daemon's probes see, and
  `NoNewPrivileges=` breaks a setuid bwrap; the unit's comments explain each omission.
- **Environment:** the daemon reads `RUNTIME_DATA_DIR`, `XDG_DATA_HOME` and `HOME` from the **user manager**, not
  from your shell. If your shell profile sets `RUNTIME_DATA_DIR` or `XDG_DATA_HOME`, give the manager the same
  value, or the daemon serves a different store than `runtime` does. Any of these works:
  - `systemctl --user import-environment RUNTIME_DATA_DIR`;
  - a file in `~/.config/environment.d/`;
  - an `Environment=` drop-in.

## Clients

### The CLI: `runtime rpc` and `runtime daemon-status`

```sh
runtime rpc rpc.version
runtime rpc apps.get '{"id": "notepad"}'
runtime rpc doctor.system --socket /run/user/1000/rt-test.sock
runtime daemon-status            # exit 0 when a daemon answers, 1 when none does; says "mode: write" or "read-only"
runtime rpc apps.remove '{"id": "notepad"}'      # write mode: {"jobId": "..."}
```

`runtime daemon-status` prints `mode: write`, `mode: read-only`, or, for a daemon older than 0.2,
`mode: read-only (API <version>)`. There is no `runtime jobs` command: `runtime rpc jobs.*` covers scripts.

`runtime rpc` is a raw tool for debugging and scripts.

- It prints the `result` as pretty JSON on stdout, exit 0.
- On an error it prints `error: <message> (code N, kind K)` on stderr, exit 1.
- `params` must be one JSON object.
- The daemon's answer is displayed, not trusted. The result is re-serialised with every C1, bidi and invisible
  character written as a `\uXXXX` escape, which is lossless for any JSON parser, and error text is escaped. A
  hostile process at the socket path cannot drive your terminal.

The CLI reaches the daemon only through the `runtime-daemon` crate's client (`rt_daemon::client`). That dependency
edge is used by these two commands alone.

### Shell (socat, nc)

```sh
sock=$XDG_RUNTIME_DIR/runtime/runtimed.sock
printf '%s\n' '{"jsonrpc":"2.0","method":"rpc.version","id":1}' | socat - UNIX-CONNECT:$sock
# {"id":1,"jsonrpc":"2.0","result":{"api":"0.2.1","protocol":"jsonrpc-2.0-ndjson","runtime":"0.0.1","write":true}}
printf '%s\n' '{"jsonrpc":"2.0","method":"apps.get","params":{"id":"nope"},"id":"a"}' | nc -U -N $sock
# {"error":{"code":-32000,"data":{"kind":"not_found"},"message":"no app named nope is installed"},"id":"a","jsonrpc":"2.0"}
```

`nc -U -N` is OpenBSD netcat: `-N` half-closes after the input, and the daemon answers before it closes. These tools
do **none** of the client's checks: they do not verify the socket's owner or mode, or the peer's uid. Use them for
debugging only.

### Rust

```rust
use rt_daemon::client::{Client, ClientError, default_socket_path};

let mut c = Client::connect(&default_socket_path()?)?;
println!("API {}", c.version()?.api);
for app in c.apps()?.apps {
    println!("{} {}", app.id, app.name);
}
match c.app("nope") {
    Err(e @ ClientError::Rpc { .. }) => println!("{:?}", e.api_error().map(|a| a.kind)), // Some(NotFound)
    other => println!("{other:?}"),
}
let raw: serde_json::Value = c.call("doctor.system", serde_json::Value::Null)?;
```

Before a connection is used, `Client::connect[_with]` checks the socket as the daemon placed it:

- the directory is not a symlink, is the user's, and has mode `& 0o077 == 0`;
- the socket is a socket, is the user's, and has mode `& 0o077 == 0`;
- after connecting, the peer's `SO_PEERCRED` uid is the user's.

It refuses otherwise (`ClientError::Unsafe`) **before sending a byte**. The connect is non-blocking with a deadline,
so a full backlog cannot hang it.

Each call has a whole-reply deadline: 40 s by default, which is longer than the daemon's 30 s. The reply must be one
line of at most 16 MiB, be JSON-RPC 2.0, carry the call's id (or `null` on an error), and hold exactly one of
`result` and `error`. Anything else is `ClientError::Protocol`, never a panic.

- After a timeout or a protocol error the connection is not used again.
- An error reply leaves it usable.
- Error `message` and `data.kind` are cut to 1,024 characters but not otherwise cleaned. Escape them before showing
  them on a terminal.
- Typed helpers exist for every method: `version`, `apps`, `app`, `permissions`, `compat`, `doctor_system`,
  `doctor_app`, `graphics_info`, `sandbox_info`, `deps_plan`; and for write mode `run_app`, `install`
  (`InstallParams`), `remove`, `deps_install`, `permissions_set`, `permissions_reset`, `display_set`, `job_poll`
  (its deadline is `waitMs` + 15 s, never under 40 s), `job_status`, `job_cancel`, `jobs`.
- Strings in results (event texts included) are returned as the daemon sent them. Clean or escape them before you
  show them.

```rust
let job = c.remove("notepad")?.job_id;
let mut after = 0;
loop {
    let e = c.job_poll(&job, after, 10_000)?;
    for ev in &e.events {
        println!("{:?} {}", ev.kind, rt_core::clean_text(&ev.text, 4096));
    }
    after = e.next_seq;
    if !matches!(e.job.state, JobState::Queued | JobState::Running) { break; }
}
```
