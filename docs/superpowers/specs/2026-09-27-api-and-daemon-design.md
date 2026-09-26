# Phase 6, sub-project A: the typed API crate and the `runtimed` daemon (read-only) (design)

Status: approved by the controller on the user's standing instruction (2026-09-25/26: self-approve with recommended
choices; "dont stop in any phases in any task"). First of four Phase 6 sub-projects (6A API + daemon read-only, 6B
mutating methods + event streams, 6C GUI client, 6D plugin interfaces + `.wrun`). Roadmap: "Public Rust API crate
(`Runtime`, `Application`, `Environment`, `Process`, `Dependency`) ... `runtimed` on a Unix domain socket with systemd
user socket activation; JSON-RPC with event streams. No TCP."

## 1. Purpose and success criteria

Everything the CLI does is reachable only by printing text. A GUI, a tray applet or a script needs typed results and
a stable surface that survives backend changes. 6A delivers that surface for everything that only READS state, and
the daemon that serves it; 6B adds the mutating and streaming methods.

Success criteria:

1. A new crate `runtime-api` (`rt_api`) exposes `Runtime` with typed, `Serialize`/`Deserialize` results for: apps
   (list, detail), permissions (get), doctor (system and app), dependency plan, compatibility matrix, graphics
   info, sandbox info, and its own `API_VERSION` (semver). No method prints; no method needs a TTY.
2. `runtimed` serves those methods as JSON-RPC 2.0 over a Unix stream socket (newline-delimited JSON), owner-only,
   with peer-uid verification, size/time limits and systemd socket activation (`LISTEN_FDS`). No TCP, ever.
3. `rt_api::client::Client` speaks the protocol; `runtime rpc <method> [json-params]` is a thin CLI over it
   (raw debugging tool) and works against a running daemon.
4. Hostile clients cannot hurt the daemon: oversized frames, invalid JSON, slow-drip connections, floods of
   connections, unknown methods, and another user's uid are all refused or bounded, tested.
5. Every string derived from untrusted data (app names, versions, paths from installers) is sanitised at the API
   boundary (control and format characters removed), so clients cannot be tricked by terminal or bidi escapes.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| CLI relationship | The host-fact GATHERING code that only the CLI has today (doctor's PE/prefix/Vulkan/drivers facts, sandbox status, graphics probe, compat records, permissions view) moves out of the CLI into `rt_api` (git-moved with its tests), and the CLI calls it; the CLI keeps its text/JSON FORMATTING and stays a standalone binary that needs no daemon. | A doctor report or a sandbox status must be computed the same way for the CLI, the daemon and a GUI; duplicating 1.5k lines of reviewed logic would drift. Moving it is the honest first step of the roadmap's "CLI as a thin client" without rewriting formatting that users see. |
| Wire format | JSON-RPC 2.0, newline-delimited (NDJSON), UTF-8, one request per line, one response per line | Trivial to implement in any language and to fuzz; varlink was the alternative but adds a spec and tooling for nothing here. |
| Transport | `$XDG_RUNTIME_DIR/runtime/runtimed.sock` (dir 0700, socket 0600); refuses to start when `XDG_RUNTIME_DIR` is unset or the path is a symlink/foreign-owned; `LISTEN_FDS` activation supported | Owner-only local IPC; matches systemd user socket activation. |
| Auth | `SO_PEERCRED` uid must equal the daemon's uid; there is no other authentication | The socket is already 0600 in a 0700 directory; the uid check is defence in depth against a mis-set mode. |
| Concurrency | thread per connection, bounded (default 32) with a global request semaphore; each request has a deadline; the `Runtime` value is `Send + Sync` | No async runtime dependency; the workload is small and blocking-friendly (Wine helpers). |
| Errors | JSON-RPC error codes: -32700/-32600/-32601/-32602 standard, `-32000` domain error with `data.kind` (a stable snake_case string) and a sanitised message | Clients switch on `kind`, never on prose. |
| Versioning | `API_VERSION = "0.1.0"`; `rpc.version` method returns it; breaking changes bump the minor until 1.0 | Semver discipline starts now; freeze at 1.0 (Phase 6 exit). |
| Sanitising | `rt_core::text::clean` (existing) at the API boundary for every free-text field | One rule, one place. |

Non-goals in 6A: mutating methods, event streams (6B), authentication beyond uid, remote access, GUI (6C), plugin
interfaces (6D), a permanent CLI migration.

## 3. Components

- `crates/api` (`runtime-api`, lib `rt_api`): `Runtime { store, ... }` (`Runtime::open()`, `Runtime::with_store(..)`
  for tests), `types.rs` (wire types), `methods.rs`, `error.rs` (`ApiError { kind, message }`), `client.rs`
  (`Client::connect(path)`, `call<T>(method, params)`), `API_VERSION`.
- `crates/daemon` (`runtime-daemon`, lib `rt_daemon` + bin `runtimed`): `protocol.rs` (frame reader with caps,
  request/response types, dispatch table mapping method names to `Runtime` calls), `server.rs` (listener setup,
  socket security, activation, accept loop, limits, graceful shutdown on SIGTERM/SIGINT), `main.rs`.
- `crates/cli`: delegates gathering to `rt_api::host`; adds `runtime rpc <method> [json]` and `runtime daemon-status` (connects, prints version and uptime).
- `contrib/systemd/runtimed.socket` and `runtimed.service` (user units; files only, not installed by us).
- `docs/API.md`: the method table, types, error kinds, versioning; `docs/SECURITY.md` daemon section.

## 4. Testing

Unit tests per method against the core `FakeBackend` rig; protocol tests (frame caps, malformed input,
batch requests refused or handled per spec, id echo, notifications ignored); real-socket tests in a temp dir
(concurrency, slow-drip, connection flood, oversized frame, half-closed, socket mode/ownership, stale socket
cleanup, `LISTEN_FDS`); a `cargo run` e2e that starts `runtimed` and drives it through `runtime rpc`.

## 5. Risks

- A daemon widens the attack surface: any process of the same user can call it. Mitigations: read-only in 6A,
  documented in SECURITY.md; mutating methods in 6B get explicit per-method consent rules (no method can bypass
  the deps consent gate or the sandbox).
- `Runtime` shares a store between threads: the store's operations are already lock-file based per app; reads are
  race-tolerant (a listing skips entries that vanish).
