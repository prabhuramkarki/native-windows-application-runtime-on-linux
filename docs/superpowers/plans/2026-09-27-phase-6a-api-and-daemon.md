# Phase 6A API crate and read-only `runtimed` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A typed, sanitised, versioned Rust API (`rt_api`) over everything that only reads state, served by a hardened `runtimed` JSON-RPC daemon on an owner-only Unix socket, with a client and `runtime rpc`.

**Architecture:** `rt_api` owns the wire types, the `Runtime` facade and the host-fact gathering code moved out of the CLI (the CLI delegates to it and keeps its formatting); `rt_daemon` is a thread-per-connection NDJSON JSON-RPC 2.0 server with strict caps; the client is a small synchronous library.

**Tech Stack:** Rust workspace, `serde`/`serde_json` (present), `libc` (SO_PEERCRED, sockets; present), std `UnixListener`/threads — no async runtime, no new dependency.

**Spec:** `docs/superpowers/specs/2026-09-27-api-and-daemon-design.md`

## Global Constraints

- No new third-party dependency in 6A (std + serde + libc only). No TCP, ever; the socket is owner-only (dir 0700, socket 0600) and the peer uid is verified.
- Every free-text field derived from untrusted data (app names, versions, executable paths, doctor check texts, error messages) passes `rt_core::text::clean` (or the existing `clean`/`quote_max` used by doctor) at the API boundary; ids are validated `AppId`s.
- Moved code keeps its tests (git mv, tests move with it) and the CLI's observable behaviour and output do not change (the existing CLI rig tests are the safety net: they must pass unchanged, except for `use` paths).
- The daemon never blocks forever: bounded frame size (1 MiB), per-request deadline, connection cap (default 32), idle timeout; a hostile client can only hurt itself.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` stay green after every task; socket tests run in a temp dir (never the real `$XDG_RUNTIME_DIR`).
- Commit trailer: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## Review Focus

- A method result that leaks an unsanitised installer-supplied string (bidi/control characters in an app name, a `\n` in a path) (Tasks 1, 2).
- Moved gathering code changing behaviour (doctor output byte-for-byte, sandbox status texts, compat table) — the CLI tests are the oracle (Task 2).
- Daemon: frame larger than the cap, a line without newline that never ends, 100 idle connections, a client that connects and stalls mid-request, batch arrays, `id` of every JSON type, `params` of the wrong shape, unknown method, invalid UTF-8, a stale socket file, a symlinked or foreign-owned socket path, a socket dir with the wrong mode (Task 3).
- Socket activation: `LISTEN_PID` not matching, `LISTEN_FDS` > 1, the inherited fd not a listening Unix socket (Task 3).

---

### Task 1: the `runtime-api` crate: types and the simple read-only methods

**Files:**
- Create: `crates/api/Cargo.toml` (package `runtime-api`, lib `rt_api`; deps `runtime-core`, `runtime-deps`, `runtime-sandbox`, `runtime-installer`, `serde`, `serde_json`, `thiserror`; dev-deps `runtime-core` with `testing`, `tempfile`), `crates/api/src/{lib.rs,types.rs,error.rs,runtime.rs}`
- Move: `crates/cli/src/compat.rs` and `crates/cli/compat.toml` -> `crates/api/src/compat.rs` and `crates/api/compat.toml` (git mv; fix the `include_str!` path, the generated-file header text, the docs/COMPAT.md regenerate command, README mentions); the CLI's `compat` subcommand calls `rt_api::compat`
- Modify: `crates/cli/Cargo.toml`, `crates/cli/src/main.rs`, `crates/cli/src/compat.rs` (new thin shim if the clap wiring needs a module; else inline), `docs/COMPAT.md` header, README
- Test: `crates/api/src/*` unit tests, CLI compat tests unchanged

**Interfaces:**
- Produces:
  ```rust
  pub const API_VERSION: &str = "0.1.0";
  pub struct Runtime { /* store: Store, ... */ }
  impl Runtime {
      pub fn open() -> Result<Runtime, ApiError>;                    // rt_core::apps_dir() + Store::new
      pub fn with_store(store: Store) -> Runtime;                    // tests
      pub fn version(&self) -> VersionInfo;                          // { api: String, runtime: String (crate version), protocol: "jsonrpc-2.0-ndjson" }
      pub fn apps(&self) -> Vec<AppSummary>;                         // bad entries skipped and counted in `skipped`
      pub fn app(&self, id: &str) -> Result<AppDetail, ApiError>;    // metadata + dependencies + installer info + prefix state summary
      pub fn permissions(&self, id: &str) -> Result<PermissionsView, ApiError>; // profile + source (default|file) + validation status
      pub fn compat(&self) -> CompatView;                            // records from the moved bundled matrix
  }
  #[derive(Serialize, Deserialize)] pub struct ApiError { pub kind: ErrorKind, pub message: String }   // ErrorKind: snake_case serde: not_found, invalid_argument, unavailable, internal, ...
  ```
  All wire types derive `Serialize, Deserialize, Debug, Clone, PartialEq`, use `#[serde(rename_all = "camelCase")]` consistently with `Metadata`, and hold ONLY sanitised strings (a `Sanitised` newtype is not required: sanitise in the constructor functions and test every one).

- [ ] **Step 1: Failing tests:** `apps()` over a store with 3 valid apps and 1 corrupt entry (returns 3, `skipped == 1`); `app("bad/../id")` => `invalid_argument`; unknown id => `not_found`; a Metadata with control/bidi characters in name/version/executable => every returned string is cleaned (assert no char of `is_control`/`rt_core::is_format` survives); `permissions()` of an app without a file => `source: default`, network deny, display/audio/gpu true, limits default; with a valid file => `file`; with an invalid file => `ApiError` (no silent default); `compat()` equals the moved module's bundled records (count and first record); JSON round trip of every wire type; `version()` values.
- [ ] **Step 2: Implement**; do the `git mv` of compat with its 12 tests; keep `runtime compat` output byte-identical (existing CLI tests + drift test).
- [ ] **Step 3:** full gate; commit `feat(api): the runtime-api crate with typed read-only methods; compat moves into it`.

---

### Task 2: move the host-fact gathering into `rt_api`: doctor, sandbox info, graphics info, dependency plan

**Files:**
- Move (git mv, with tests): the non-formatting parts of `crates/cli/src/graphics.rs` (bounded `vulkaninfo` runner, `host()` cache, verdicts), `crates/cli/src/sandbox.rs` (status/probe gathering: bwrap probe, hardening, limits probe, profile summary; keep `RunSandbox`/`helper_launcher`/marker code in the CLI ONLY IF it is tightly coupled to run/deps wiring — otherwise move too; decide by dependency direction: rt_api may not depend on the CLI), `crates/cli/src/doctor.rs` gathering (`read_pe`, `prefix_state`, `home_state`, `dotnet_state`, `d3d_routes`, DoctorInput construction, `wine_drivers`, session detection) into `crates/api/src/host/{graphics,sandbox,doctor}.rs`
- Create: methods in `crates/api/src/runtime.rs`: `doctor(&self, target: DoctorTarget) -> Result<DoctorView, ApiError>`, `graphics_info(&self) -> GraphicsView`, `sandbox_info(&self, id) -> Result<SandboxView, ApiError>`, `deps_plan(&self, id) -> Result<DepsPlanView, ApiError>`
- Modify: `crates/cli/src/{doctor,graphics,sandbox,deps,main}.rs` (delegate; keep clap wiring, text/JSON rendering, `emit`, `safe`), Cargo.toml files
- Test: moved tests + new API-level tests; CLI rig tests unchanged

**Interfaces:**
- Produces: `DoctorTarget { System, App(String) }` (file targets stay CLI-only: they read arbitrary user paths); `DoctorView { subject, verdict, checks: Vec<CheckView { area, status, text }> }` where `area`/`status`/`verdict` are the same stable strings the CLI's `--json` prints (`graphics`, `ok`/`warn`/`fail`, `good`/`may_fail`/`fail`) and `text` is prose (sanitised); `GraphicsView { devices, verdict, per_package: Vec<{id, minVulkan, ok}>, loader }`; `SandboxView { bwrap: Available|Unavailable{reason}, profile: PermissionsView, seccomp, landlock, limits, caveats: Vec<String> }`; `DepsPlanView { entries: Vec<{package, version, action, consent, blockedReason}>, unsatisfied, warnings }`.
- Boundaries: `rt_api` must NOT depend on the CLI; anything the moved code still needs from the CLI (`safe`, `emit`, `CmdError`) stays behind in the CLI; if a moved function used `crate::` items of the CLI, replace them by parameters or move the small helper along.

- [ ] **Step 1: Baseline:** run the whole CLI test-suite and record counts; capture `runtime doctor`, `doctor <app>`, `sandbox <app>`, `graphics info`, `deps <app>` output for the rig's fixtures as the golden oracle (the existing rig tests already pin much of this; add golden-output tests where they don't so the refactor is provably behaviour-preserving).
- [ ] **Step 2: Move in small commits** (graphics probe, then sandbox status, then doctor gathering, then deps plan), each leaving the workspace green; after each move run the CLI test-suite and `cargo clippy`.
- [ ] **Step 3: API methods + tests** against the fake rig: doctor system/app verdicts and areas equal the CLI `--json` output for the same rig state (assert equality of the (area,status,text) triples through both paths); sanitisation of every string; `sandbox_info` with the fake bwrap probe; `graphics_info` with the injected `RUNTIME_VULKAN_LOADER`-style seam (existing) — no reads of the real host in unit tests except where the CLI tests already did.
- [ ] **Step 4:** `runtime doctor --json` output is byte-identical before and after (diff the goldens); full gate; commit(s) `refactor(cli,api): host-fact gathering moves into rt_api; the CLI delegates` and `feat(api): doctor, graphics, sandbox and dependency-plan methods`.

---

### Task 3: the `runtimed` daemon and protocol

**Files:**
- Create: `crates/daemon/Cargo.toml` (package `runtime-daemon`, lib `rt_daemon`, bin `runtimed`; deps `runtime-api`, `serde`, `serde_json`, `libc`, `thiserror`; dev-deps `tempfile`), `crates/daemon/src/{lib.rs,protocol.rs,server.rs,main.rs}`, `contrib/systemd/runtimed.socket`, `contrib/systemd/runtimed.service`
- Modify: workspace picks the crate up; docs/THIRD_PARTY.md not needed (no new dependency)
- Test: protocol unit tests; real-socket tests in temp dirs

**Interfaces:**
- Produces:
  ```rust
  // protocol.rs
  pub const MAX_FRAME: usize = 1 << 20;
  pub struct Request { pub jsonrpc: String, pub method: String, pub params: Option<serde_json::Value>, pub id: Option<Id> }  // Id = Number(i64)|String(<=128 bytes)|Null
  pub enum Reply { Ok{id, result}, Err{id, code, message, data} }
  pub fn read_frame<R: BufRead>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError>;   // caps at MAX_FRAME, EOF-safe, rejects invalid UTF-8 / NUL
  pub fn dispatch(rt: &Runtime, req: Request) -> Option<Reply>;                       // notifications (no id) => None; methods: rpc.version, apps.list, apps.get, permissions.get, compat.list, doctor.system, doctor.app, graphics.info, sandbox.info, deps.plan
  // server.rs
  pub struct ServerConfig { pub socket: PathBuf, pub max_connections: usize, pub request_timeout: Duration, pub idle_timeout: Duration }
  pub fn serve(rt: Arc<Runtime>, cfg: ServerConfig, listener: Option<UnixListener>, stop: Arc<AtomicBool>) -> Result<(), ServeError>;
  pub fn default_socket_path() -> Result<PathBuf, ServeError>;   // $XDG_RUNTIME_DIR/runtime/runtimed.sock; error if XDG_RUNTIME_DIR unset/relative
  pub fn listener_from_env(get: &dyn Fn(&str)->Option<OsString>) -> Result<Option<UnixListener>, ServeError>; // sd_listen_fds protocol: LISTEN_PID == getpid, LISTEN_FDS == 1, fd 3 is a listening AF_UNIX stream socket
  ```
  Rules: batch arrays (`[...]`) are refused with -32600 (documented: batches unsupported); `jsonrpc` must be `"2.0"`; errors: -32700 parse, -32600 invalid request, -32601 method not found, -32602 invalid params, -32000 domain (`data: {"kind": "..."}`); one thread per connection; connection cap (extra connections get a JSON-RPC error line `-32001 server busy` and are closed); per-connection read timeout = idle timeout; per-request deadline (a dispatch that exceeds it returns -32002 `timeout` — run the dispatch on the connection thread with a watchdog that only stops READING further requests; document that a blocked Wine helper cannot be cancelled in 6A); `SO_PEERCRED` check right after accept (uid mismatch => close immediately, no reply); socket setup: create the dir 0700 (`create_dir` then verify `lstat`: owned by us, mode 0700, not a symlink; refuse otherwise), remove a stale socket only if it is a socket owned by us and nothing accepts on it (connect probe), bind, chmod 0600, verify; on shutdown remove the socket; SIGTERM/SIGINT set `stop` (handler stores an atomic; the accept loop polls with a short timeout via `poll(2)` on the listener and a self-pipe/eventfd); `main.rs`: parse `--socket <path>` (default path), `--max-connections`, log to stderr with `tracing` only if already a dependency of the workspace (it is: the CLI uses it — but keep this crate dependency-free: use `eprintln!` for the few lines).
  Units: `runtimed.socket` (`ListenStream=%t/runtime/runtimed.sock`, `SocketMode=0600`, `DirectoryMode=0700`) and `runtimed.service` (`ExecStart=%h/.cargo/bin/runtimed` placeholder documented as "edit the path"; `NoNewPrivileges=yes`, `PrivateNetwork=yes`? — NO: the daemon runs Wine helpers and `deps` fetches need network only in 6B; for 6A the service is read-only: `PrivateNetwork=yes`, `ProtectSystem=strict` is NOT set because Wine prefixes live under the user's data dir; keep the unit minimal and commented).

- [ ] **Step 1: Failing tests** (real sockets in `tempfile::tempdir()`; each with a short deadline so a bug cannot hang the suite): request/response round trip for every method against a fake-rig Runtime; `id` echo for number/string/null; notification (no id) gets no reply; unknown method -32601; wrong `params` type -32602; batch array refused; oversized frame (> MAX_FRAME) => -32600/closed without buffering more than MAX_FRAME + one read; a frame with invalid UTF-8 and one with a NUL => parse error; a client that sends a partial line then stalls => closed after the idle timeout; 100 connections with cap 8 => exactly 8 served, the rest get -32001 and close, and the server keeps serving afterwards; a client that half-closes after sending a request still gets its reply; socket path safety: parent dir wrong mode / foreign owner (simulate with a dir we chmod 0777 => refused), symlinked socket path => refused, stale socket removed, a live socket => `AlreadyRunning` error; the socket is created 0600; SO_PEERCRED check function unit-tested with an injected uid (the real check needs a second uid: test the comparison logic separately and `getsockopt` success path with our own uid); `listener_from_env`: LISTEN_PID mismatch => None (not an error), LISTEN_FDS=2 => error, fd not a socket => error, valid inherited listener (create a UnixListener, `dup2` to a chosen high fd via `libc`, set env closure) => Some; graceful stop: setting `stop` ends `serve` within 1 s and removes the socket; concurrent clients (16 threads x 50 requests) all correct.
- [ ] **Step 2: Implement**; keep `unsafe` to libc socket options/`poll`/`dup` with SAFETY comments; no panics on any input (fuzz-style mutation loop over a valid frame: flip/truncate/insert bytes, 5,000 iterations through `protocol::parse_request`).
- [ ] **Step 3:** full gate; commit `feat(daemon): runtimed serves the read-only API over an owner-only Unix socket`.

---

### Task 4: client, `runtime rpc`, docs, end to end

**Files:**
- Create: `crates/api/src/client.rs`, `docs/API.md`
- Modify: `crates/cli/src/main.rs` + new `crates/cli/src/rpc.rs` (`runtime rpc <method> [json-params] [--socket PATH] [--local]`, `runtime daemon-status [--socket PATH]`), `docs/SECURITY.md` (daemon section), README (API and daemon section), `docs/superpowers/plans/2026-09-21-runtime-master-roadmap.md` status table (Phase 6 row: 6A done)
- Test: `crates/api/src/client.rs` tests, `crates/cli/tests/e2e_daemon.rs` (spawns the real `runtimed` binary from `CARGO_BIN_EXE_runtimed` — a bin of another crate is NOT available to cli tests via that env var: build the daemon binary path from `target/<profile>/runtimed` after `cargo build -p runtime-daemon` like the deps tests do for `runtime`, failing loudly when absent, OR make the e2e live in `crates/daemon/tests/` where `CARGO_BIN_EXE_runtimed` exists and drive `runtime rpc` via the built `runtime` binary path helper; choose the second)

**Interfaces:**
- Produces: `Client::connect(path) -> Result<Client, ApiError>`, `Client::call<T: DeserializeOwned>(&mut self, method: &str, params: impl Serialize) -> Result<T, ApiError>` (assigns integer ids, validates the reply id and `jsonrpc`, maps JSON-RPC errors to `ApiError` via `data.kind`, caps reply size at 16 MiB, read/write timeouts), typed helpers `apps()`, `app(id)`, `doctor_system()`, ...; `runtime rpc` prints the raw `result` JSON (pretty) or the error (exit 1, kind + message sanitised); `--local` calls `rt_api::Runtime` in process (no daemon) so the CLI and the daemon can be compared in tests.

- [x] **Step 1: Failing tests:** client against the in-process server: every helper; id mismatch / wrong version / oversized reply / connection closed mid-reply => typed errors, no panic, no hang (timeouts); `runtime rpc apps.list` equals `runtime rpc --local apps.list` for the same data root; `runtime daemon-status` on no daemon => exit 1 with a helpful message ("no daemon at <path>: start `runtimed` or use `--local`").
- [x] **Step 2: e2e** (real binaries, temp `XDG_RUNTIME_DIR`, temp data root with the rig's fake-Wine app or a plain metadata-only app): start `runtimed`, wait for the socket (bounded), `runtime rpc rpc.version`, `apps.list`, `doctor.system`, `permissions.get`, `compat.list`; send SIGTERM => the daemon exits 0 and removes the socket; a second `runtimed` on the same socket refuses; garbage on the socket does not crash it (send 1 MiB of junk, then a valid request on a new connection succeeds).
- [x] **Step 3: Docs:** `docs/API.md` (method table with params/results/errors, versioning policy, framing, limits, examples with `runtime rpc`), SECURITY.md daemon section (what it exposes: read-only in 6A; any process of the same user can call it; socket mode/uid checks; no network; mutating methods in 6B come with per-method rules), README, roadmap row.
- [x] **Step 4:** full gate; commit `feat(api,cli): a client, runtime rpc and daemon-status; API and daemon docs`.

**As built (Task 4; deviations from the text above, decided on the controller's Task 4 brief):**
- The client is `rt_daemon::client` (`crates/daemon/src/client.rs`), not `rt_api::client`: it shares the daemon's
  framing (`read_frame_max`), non-blocking connect and `peer_allowed`, and `rt_api` stays free of socket code. The CLI
  depends on `runtime-daemon` for this client only (documented in `crates/cli/Cargo.toml`, README and API.md).
- Errors are `ClientError` (`Rpc { code, message, kind }` keeps the JSON-RPC code and `data.kind`;
  `api_error()` maps -32000 to `ApiError`), not `ApiError`: busy/timeout/protocol failures have no `ApiError` kind.
  `call` is raw (`Value` in, `Value` out); the typed helpers cover every method.
- Before sending, the client checks the socket directory (not a symlink, ours, `& 0o077 == 0`), the socket (a socket,
  ours, `& 0o077 == 0`) and after connecting the peer uid; the connect is non-blocking with a deadline.
- Request lines are capped at the daemon's 1 MiB before sending; replies at 16 MiB (a legitimate `apps.list` can
  exceed 1 MiB). Whole-reply deadline 40 s (`daemon-status`: 5 s).
- No `--local`: the e2e equality oracle is the standalone CLI (`runtime list --json`, `compat --json`,
  `doctor --json`), which is what users compare against.
- The e2e lives in `crates/daemon/tests/e2e.rs` and takes `runtime` from next to `runtimed` (fails loudly when absent).
- `docs/API.md`'s method table and sections are checked against `dispatch::METHODS` by a test.
- Found by the equality test and fixed: `compat.list` cut `notes` at 256 bytes; the matrix allows 300.

---

## Self-Review

- Spec criteria: 1 -> Tasks 1-2; 2 -> Task 3; 3 -> Task 4; 4 -> Tasks 3-4; 5 -> Tasks 1-2.
- Placeholders: none; Task 2's "decide which sandbox code moves" has a rule (no dependency on the CLI) and the CLI test suite as oracle.
- Recorded deviations (Tasks 3-4): busy is -32001 and timeout -32002 (not -32000); `serve` takes `&'static AtomicBool`;
  no `--max-connections`; the unit ships without `PrivateNetwork=` or any hardening option (see its comments); the
  client lives in `rt_daemon` and returns `ClientError`; no `runtime rpc --local`.
- Types: `Runtime`, `ApiError/ErrorKind`, `AppSummary/AppDetail/PermissionsView/CompatView/DoctorView/GraphicsView/SandboxView/DepsPlanView`, `Request/Reply/Id`, `ServerConfig`, `Client` are named identically across tasks.
