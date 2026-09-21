# Phase 2: Environments + Wine Backend (MVP v0.1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax. **This plan is spec-level**: each task gives interfaces, behaviour, acceptance tests and hostile-input requirements; the implementer writes the code test-first. (Phase 1 showed that plan-supplied code was the weakest part: it was unsafe against hostile input. Here the requirements carry the safety rules instead.)

**Goal:** `runtime install <portable.exe|.zip>`, `run`, `list`, `remove`, `logs`, `doctor` work against an isolated per-app environment, executing Windows code through a swappable `CompatBackend` implemented with system Wine.

**Architecture:** New crate `core` (app ids, data dir, Windows-path handling, metadata, store, install/run services, doctor, the `CompatBackend` trait + `Launcher` seam) and new crate `backend-wine` (system-Wine implementation). `cli` becomes a thin front end. `pe::analyze` (Phase 1) supplies architecture, name, subsystem and imports. All flows are unit-testable with a fake backend; real Wine runs only in `#[ignore]`d end-to-end tests.

**Tech Stack:** Rust 2024 (MSRV 1.88), `serde`/`serde_json`, `thiserror`, `zip` (MIT), `tracing`, dev: `tempfile`. System Wine 10.x (`wine64`).

**Spec:** Master prompt §13-14, §22-23, §25, §36 Stage 2, §48; roadmap Phase 2 (`2026-09-21-runtime-master-roadmap.md`).

## Global Constraints

- Never require root; no global host modification; every app lives under `$RUNTIME_DATA_DIR` or `~/.local/share/runtime/apps/<app-id>/` (§14, §23, §50.5-6).
- Everything derived from a file or a user argument is UNTRUSTED: app ids, zip entries, PE-derived names, metadata.json contents. No shell interpolation anywhere (`Command` with argument vectors only). No path built from untrusted text without validation and a containment check.
- No panics on hostile input; bounded work/memory (zip bombs, huge files, deep trees); failures reported, never swallowed.
- Every string from untrusted sources printed to the terminal goes through the CLI's `safe()` sanitiser (`crates/cli/src/analyze.rs`); move it to a shared place, do not duplicate it.
- The child process gets a cleared environment plus an allowlist (Task 4). Wine's default host exposure is removed from every prefix (Task 5).
- Honest security statement: **Phase 2 is NOT a sandbox.** Wine can still reach the host (`\\?\unix\...` NT paths, `com*` device links Wine recreates on each start). The real boundary is Phase 5. Docs and CLI must say so.
- Phase 1 rules stay: fmt, clippy `-D warnings`, tests green before every commit; tests must fail if the guard they cover is removed (do a mutation check per security guard and paste the failing test name in the report).

## Spike findings (Wine 10.0 on this machine; why the design looks like this)

| Finding | Consequence |
|---|---|
| `wineboot -u` creates a prefix in ~12 s | `install` shows progress; template-prefix reuse is a later optimisation |
| Prefix has `dosdevices/z: -> /` and `com1..com32 -> /dev/ttyS*` | Remove every `dosdevices` entry except `c:` after creation |
| `drive_c/users/<user>/{Desktop,Documents,Downloads,Music,Pictures,Videos}` and `AppData/Roaming/Microsoft/Windows/Templates` are symlinks to the REAL home dirs | Replace each such symlink with an empty real directory |
| Wine recreates `com*` links on every run but not `z:` | Cannot fully prevent; document; Phase 5 sandbox |
| Without `z:` an exe run with cwd outside the prefix prints "could not open working directory" | `run` sets cwd to a directory under `drive_c`; portable exes are COPIED into the prefix |
| `\\?\unix\etc\hostname` still reads host files without `z:` | Removing `z:` is defence in depth, not a boundary |
| 32-bit `hello32.exe` runs in a win64 prefix (WoW64), no `wine32` needed | One backend/prefix type for x86 and x86-64 |
| `wineserver` is not on `PATH` (`/usr/lib/x86_64-linux-gnu/wine/wineserver`); exits ~3 s after the last process | Discover it; `stop` uses `wineserver -k` with `WINEPREFIX` set |
| `WINEDLLOVERRIDES=winemenubuilder.exe=d;mscoree=d;mshtml=d` | No host menu spam, no mono/gecko download dialogs (.NET apps fail until Phase 4; `doctor` says so) |

## File Structure

```text
Cargo.toml                       (add members via crates/*; workspace deps: zip, tempfile)
crates/core/                     package runtime-core, lib name `rt_core` (never name a lib `core`: it shadows std)
  src/lib.rs        re-exports
  src/id.rs         AppId validation + slug
  src/dirs.rs       data dir resolution (RUNTIME_DATA_DIR override)
  src/winpath.rs    Windows path parsing + containment-safe resolution under a root
  src/meta.rs       Metadata (schemaVersion 1) read/write
  src/store.rs      AppEnv, Store: create/list/get/remove (containment-safe)
  src/backend.rs    CompatBackend trait, RunOpts, Launcher, env allowlist builder
  src/install.rs    install service (portable exe, zip)
  src/run.rs        run service, log files
  src/doctor.rs     Report/Check model + checks
  src/fake.rs       FakeBackend (cfg(any(test, feature = "testing")))
crates/backend-wine/             package runtime-backend-wine, lib name `backend_wine`
  src/lib.rs        WineBackend
  src/discover.rs   locate wine, wineserver, dll dirs
  src/harden.rs     prefix hardening (pure fs, unit-testable)
crates/cli/src/{main,analyze,install,run,list,remove,logs,doctor,safe}.rs
docs/SECURITY.md    honest Phase 2 security model
```

---

## Task 1: `core` skeleton, `AppId`, data dir

**Files:** create `crates/core/{Cargo.toml,src/lib.rs,src/id.rs,src/dirs.rs}`; modify root `Cargo.toml` (workspace deps), `docs/THIRD_PARTY.md` (zip, tempfile).

**Interfaces (produces):**
- `AppId` (newtype over `String`): `AppId::parse(&str) -> Result<AppId, IdError>`; rules: 1..=64 chars, regex `^[a-z0-9][a-z0-9._-]*$`, no `..` substring, not ending with `.` or `-`. `AppId::slug(name: &str) -> AppId` (lowercase, non-alnum runs -> `-`, trimmed, truncated to 64, fallback `app`) always valid. `as_str()`, `Display`, serde as string with validation on deserialize.
- `data_root() -> Result<PathBuf, DirsError>`: `$RUNTIME_DATA_DIR` if set and absolute, else `$XDG_DATA_HOME/runtime` (absolute), else `$HOME/.local/share/runtime`; error when none resolvable or relative. `apps_dir() = data_root()/apps`.

**Acceptance tests (write first):** table tests for parse accept/reject (empty, 65 chars, uppercase, `../x`, `a/b`, `a\0b`, `.hidden`, `-x`, `x.`, unicode, whitespace, reserved-looking names like `con` are ALLOWED on Linux but document); `slug` always yields a valid id for arbitrary input incl. empty, emoji, 10 kB strings, `../..`; serde round trip and rejection of invalid ids; `data_root` precedence with env manipulation (serialise env tests with a mutex or run via a helper that takes an env map instead of reading the process env: prefer the pure function `data_root_from(&impl Fn(&str)->Option<String>)`).

- [ ] Steps: failing tests, implement, run, `cargo fmt/clippy/test`, commit `feat(core): app ids and data dir`.

## Task 2: `winpath`: Windows path parsing and containment-safe resolution

**Interfaces:**
- `WinPath::parse(&str) -> Result<WinPath, WinPathError>`: accepts `C:\dir\file.exe` and `C:/dir/file.exe` (forward slashes), drive letters A-Z (case-insensitive), rejects: empty, no drive letter (relative), UNC `\\server\share`, `\\?\` and `\\.\` device paths, NUL and control characters, components `..` (rejected outright, not normalised), components ending with space or `.`, reserved device names (`CON PRN AUX NUL COM1-9 LPT1-9`, with or without extension), components > 255 chars, total > 32_767, more than 128 components. `.` components are dropped. Result exposes `drive: char` (uppercase) and `components: Vec<String>`; `Display` renders canonical `C:\a\b`.
- `resolve_under(root: &Path, p: &WinPath) -> Result<PathBuf, ResolveError>`: maps drive `C` to `root` (the prefix's `drive_c`), resolves each component case-insensitively against the real directory listing (first exact match, else unique case-insensitive match, ambiguity is an error), REFUSES to traverse symlinks (uses `symlink_metadata`), returns the real path, never escapes `root`. Other drive letters -> `ResolveError::UnmappedDrive`. A missing final component returns `NotFound` (callers decide).
- `join_new(root, &WinPath) -> Result<PathBuf>`: for creating destinations: same containment rules, missing components allowed, component text used verbatim (already validated).

**Acceptance tests:** every reject rule above; case-insensitive hit (`c:\program files\App.EXE` finds `Program Files/app.exe`); ambiguity (two entries differing by case) errors; symlink component refused; symlink pointing outside root refused; `..` never accepted; long path caps; fuzz loop (xorshift, 20_000 iterations of random strings from a hostile alphabet incl. `\`, `/`, `:`, `.`, NUL, unicode) asserting no panic and that any `Ok` result canonicalises inside a tempdir root.

## Task 3: `Metadata`, `AppEnv`, `Store`

**Interfaces:**
- `Metadata` (serde, camelCase, `schemaVersion: 1`): `id`, `name`, `version: Option<String>`, `architecture: Arch string ("x86"|"x86_64")`, `executable: String` (canonical WinPath text), `environment: "default"`, `backend: { id, version }`, `subsystem: String`, `created: u64` (unix secs). Reading rejects unknown `schemaVersion`; every string field capped (name 256, others 1024); unknown fields ignored.
- Layout (§23): `<apps>/<id>/{drive_c?,registry,config,cache,logs,runtime,prefix,metadata.json}`. The Wine prefix is `prefix/`, and `AppEnv::drive_c() = prefix/drive_c`. Create the empty dirs `config cache logs runtime` (mode 0700 for the app dir).
- `Store::new(apps_dir)`; `create(&AppId) -> Result<AppEnv>` (fails if exists), `get(&AppId) -> Result<AppEnv>`, `list() -> Vec<Result<Metadata, StoreWarn>>` (corrupt or unreadable entries reported, not fatal, not panicking; entries that are symlinks or not directories are skipped with a warning), `remove(&AppId)`.
- `write_metadata` is atomic (write to temp file in the same dir, `sync_all`, rename).
- `remove` safety: validate the id, `symlink_metadata` the app dir and refuse if it is a symlink or not a directory, verify its parent is exactly `apps_dir`, then `remove_dir_all` (which does not follow symlinks). Never `canonicalize` untrusted input to decide.
- `unique_id(store, base: AppId) -> AppId` (appends `-2`, `-3`, ... up to 999, error afterwards).

**Acceptance tests:** create/get/list/remove happy path in a tempdir; `list` with a corrupt JSON file, a wrong schemaVersion, an oversize name, a symlink entry, a file entry: each a warning, others still listed; `remove` on an id that is a symlink to an outside dir with a canary file: outside dir untouched and error returned; `remove` where the app dir contains a symlink to an outside dir (a leaked profile link): outside content untouched; metadata round trip; atomic write leaves no temp file; `unique_id` collision behaviour.

## Task 4: `CompatBackend`, `Launcher`, env allowlist, `FakeBackend`

**Interfaces:**
```rust
pub trait CompatBackend: Send + Sync {
    fn id(&self) -> &'static str;
    fn version(&self) -> Result<String, BackendError>;
    fn prepare(&self, env: &AppEnv) -> Result<(), BackendError>;          // create + harden prefix
    fn command(&self, env: &AppEnv, exe_unix: &Path, cwd_unix: &Path,
               args: &[OsString], opts: &RunOpts) -> Result<std::process::Command, BackendError>;
    fn stop(&self, env: &AppEnv) -> Result<(), BackendError>;
    fn dll_dirs(&self) -> Vec<PathBuf>;                                    // builtin DLL dirs, for doctor
}
pub struct RunOpts { pub debug: bool }
pub struct Launcher;   // the ONE place a Command is finalised and spawned; identity sandbox hook: fn wrap(&self, Command) -> Command
```
- `allowed_env(host: &impl Fn(&str)->Option<OsString>) -> Vec<(OsString, OsString)>`: allowlist `PATH HOME USER LOGNAME LANG LANGUAGE LC_* TERM DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_RUNTIME_DIR XDG_SESSION_TYPE DBUS_SESSION_BUS_ADDRESS PULSE_SERVER`. Everything else is dropped (API keys, `SSH_AUTH_SOCK`, `LD_PRELOAD`, `WINEPREFIX` from the host...). Values containing NUL are dropped.
- `Launcher::spawn(cmd: Command, env: &AppEnv, log: LogSink) -> io::Result<Child>`: applies `env_clear()` + allowlist + backend vars already on the command, stdout inherited, stderr to the log file (`logs/run-<unix-ts>.log`, created 0600) or, with debug, tee'd (log file AND terminal: spawn a thread copying the pipe to both).
- `FakeBackend` (feature `testing`): records calls (`prepare`, `command` args, `stop`), creates a marker file for `prepare`, builds a `Command` for `/bin/sh -c 'exit N'` style helpers so run/exit-code flows are testable without Wine. NEVER compiled into release binaries (feature-gated; dev-dependency feature).

**Acceptance tests:** allowlist keeps/drops exactly the listed names with an injected host map (incl. `LD_PRELOAD`, `SSH_AUTH_SOCK`, `AWS_SECRET_ACCESS_KEY`, `LC_ALL`, a value with NUL); `Launcher` really strips the environment: spawn `/usr/bin/env` via the fake backend with a poisoned host env (set `SECRET=x` in the test process) and assert `SECRET` absent from the child's output and `PATH` present; stderr goes to the log file with mode 0600; debug tee writes both.

## Task 5: `WineBackend`

**Interfaces:** `WineBackend::discover() -> Result<WineBackend, BackendError>` (no panics; error text tells the user to install Wine, e.g. `apt install wine`).
- Discovery order for the wine binary: `$RUNTIME_WINE` (absolute path), then `wine64`, then `wine` on `PATH`. Wineserver: `$RUNTIME_WINESERVER`, then `wineserver` on `PATH`, then `<libdir>/wine/wineserver` for libdir in {`/usr/lib/x86_64-linux-gnu`, `/usr/lib64`, `/usr/lib`, `/usr/lib/wine`, `/opt/wine-*/lib*` glob-free: a fixed candidate list}. DLL dirs: `<dir of wineserver>/x86_64-windows` and `/i386-windows` if present.
- `version()`: run `wine --version`, parse `wine-X.Y[...]`, cap output length, error on garbage.
- `prepare(env)`: `wineboot -u` (spawn `<wine> wineboot -u`) with `WINEPREFIX=<env.prefix>`, `WINEARCH=win64`, `WINEDEBUG=-all`, `WINEDLLOVERRIDES="winemenubuilder.exe=d;mscoree=d;mshtml=d"`, cleared environment + allowlist, a 120 s timeout (poll `try_wait`, kill on timeout), then `harden_prefix(prefix)`, then `stop(env)`.
- `harden_prefix(prefix: &Path) -> Result<HardenReport>` (pure fs, in `harden.rs`): removes every entry in `dosdevices/` except `c:`; for each symlink under `drive_c/users/*/` (depth <= 3, incl. `AppData/Roaming/Microsoft/Windows/Templates`) whose target is not inside `drive_c`, replaces it with an empty directory; never follows symlinks; returns a report (removed/replaced lists) for logging; idempotent; refuses (error) if `prefix` itself or `drive_c` is a symlink.
- `command(...)`: `<wine> <exe_unix>` with args; vars: `WINEPREFIX`, `WINEARCH=win64`, `WINEDEBUG` (`-all`, or `err+all,fixme-all` when `opts.debug`), `WINEDLLOVERRIDES` as above, `WINESERVER=<path>`; `current_dir(cwd_unix)`; exe/cwd must be under `env.drive_c()` (verify by component prefix on the un-canonicalised paths the caller produced via `winpath::resolve_under`; reject otherwise).
- `stop(env)`: `<wineserver> -k` with `WINEPREFIX` set; success or "no server running" both OK; timeout 20 s.

**Acceptance tests (unit):** `harden_prefix` on a synthetic prefix tree built in a tempdir (dosdevices with `c:`, `z:`, `com1`, `lpt1`; users dir with symlinks to an outside canary dir and an inside one; a nested symlink) asserting exact end state and that the outside canary is untouched; idempotence; refusal when `drive_c` is a symlink; version parser table; `command` builds exact args/env/cwd and rejects an exe outside `drive_c`; discovery with an injected fake filesystem/env (make discovery take a `&impl Fn(&Path) -> bool` + env closure).
**Acceptance tests (e2e, `#[ignore]`, need Wine; CI runs `--ignored`):** create a prefix in a tempdir; assert `dosdevices` == {`c:`}, no symlink under `drive_c` points outside, `system.reg` exists; run `hello64.exe` and `hello32.exe` (copied under `drive_c/Program Files/t/`) and assert stdout `hello from windows` and exit code 7; a second run reuses the prefix (fast, `< 10 s`); running with cwd outside the prefix is impossible through the API.

## Task 6: install service (portable exe and zip)

**Interfaces:** `install(store, backend, path, opts: InstallOpts { name: Option<String>, exe: Option<String> }) -> Result<InstallOutcome>`.
Pipeline: read input with the CLI's size cap (4 GiB; regular files only; reuse the checks) -> `pe::detect`:
- `Pe`: `pe::analyze`; reject (clear message, no env created) when: kernel driver (`Subsystem::Native`), `Kind::Dll`, unsupported arch (host x86-64 accepts `x86`, `x86_64`; reject `arm64/arm64ec/other`), installer family detected (`Installer { kind, .. }` -> message "installer detected (Phase 3)"), `dotnet` (warn only, continue).
- `Msi`: reject "MSI installers arrive in Phase 3". `Zip`: extract (below). `Unknown`: reject.
- Name: `--name`, else version-info `ProductName` (sanitised), else file stem; id = `unique_id(AppId::slug(name))`.
- Create env, `backend.prepare`, copy the exe to `drive_c/Program Files/<dirname>/` (dirname = sanitised name, a validated single component) using `winpath::join_new`, write metadata, atomic. If any step after `create` fails, remove the half-made env (no residue).
- Zip: entry count <= 20_000, total uncompressed <= 4 GiB and each entry's declared size <= 4 GiB, compression ratio guard (reject when uncompressed/compressed > 1000 for entries > 1 MiB), ONLY regular files and directories (symlink entries and unusual modes are skipped and counted in a warning), entry names parsed with `WinPath`-style component rules but as relative paths (reject `..`, absolute, drive letters, NUL, backslash-escapes, reserved names) instead of trusting `enclosed_name` alone; never create a file through a symlink; extraction target is `drive_c/Program Files/<dirname>/`; entry selection: `--exe` (relative path inside the zip), else exactly one top-level or the single `.exe` when the zip contains exactly one; else the largest GUI-subsystem exe that `pe::analyze` accepts, ties -> error asking for `--exe`. Executable path stored in metadata as the canonical WinPath.
- Outcome carries the app id, executable, warnings.

**Acceptance tests (fake backend, tempdirs):** portable exe end to end using the mingw fixture `tests/fixtures/build/hello64.exe` (fixtures exist locally; tests fail with the "run tools/build-fixtures.sh" message if absent, as in `pe` tests): metadata content, files copied, `prepare` called once; rejections leave NO app dir (driver, DLL: use `exports64.dll`, arm64: patched machine field, installer-marker file, MSI magic, unknown); zip: happy path (build zips in-test with the `zip` crate), zip-slip entries (`../evil`, `/abs`, `C:\x`, `a/../../b`, backslash tricks `..\..\x`), symlink entry ignored and counted, zip bomb (a highly compressible 2 GiB entry is NOT actually extracted: use the declared-size/ratio guard with a synthetic zip whose central directory declares huge sizes), entry-count cap, `--exe` selection, ambiguous zip errors, duplicate names, case-colliding names (`A.exe` and `a.exe`) handled without overwrite surprises (fail or last-wins: choose and test), name collisions -> `-2` id; cleanup on failure of `prepare` (fake backend configured to fail).

## Task 7: run service and CLI commands

**Interfaces:** `run(store, backend, target: &str, args, opts: RunOpts) -> Result<ExitStatus>`: `target` is an installed app id, OR a path to a `.exe`/`.zip` (a path that exists on disk and is not a valid installed id is installed first, then run). Resolve `metadata.executable` with `winpath::resolve_under(env.drive_c(), ...)` (missing -> actionable error suggesting `repair`), cwd = its parent dir, `Launcher::spawn`, wait, return status; child stdout inherited; exit code propagated by the CLI (signal -> 128+n).
CLI (`crates/cli`): subcommands `install <file> [--name N] [--exe PATH]`, `run <app|file> [--debug] [-- args...]`, `list [--json]`, `remove <app>`, `logs <app> [--lines N]` (prints the newest log; caps output; sanitised), keep `analyze` unchanged. Every untrusted string printed passes `safe()` (extract `safe` into `crates/cli/src/safe.rs` shared by all commands). Exit codes: 0 ok, 1 error (message on stderr `error: ...`), N from the app for `run`. `--json` for `list` (stable field names). `remove` asks no confirmation but only accepts an id (never a path) and refuses ids that fail `AppId::parse`.

**Acceptance tests:** library-level with the fake backend: run happy path (exit code passthrough 0/7), missing exe -> error, run-by-path installs then runs, args are passed verbatim incl. spaces/quotes/`;`/`$(...)`/newlines (assert argv exactly), no shell involved; `logs` newest file selection + cap; `list` ordering and JSON shape; CLI binary tests (no Wine): `runtime list` on an empty `RUNTIME_DATA_DIR` prints an empty state, `runtime remove ../x` exits 1 without touching anything, `runtime run` unknown id exits 1 with a hint, terminal escapes in a corrupt metadata `name` are sanitised in `list`.

## Task 8: `doctor` (basic)

**Interfaces:** `doctor(store, backend, target: &str) -> Report` where `Report { checks: Vec<Check>, verdict }`, `Check { area, status: Ok|Warn|Fail, text }` (no parsing of texts by consumers; the CLI renders the §32 layout). Checks: host arch (x86-64 required), PE valid + arch/subsystem/kind of the installed executable (or of a file path given), imports vs available DLLs (an imported DLL name, case-insensitive, is "available" when present in the backend `dll_dirs()`, the app's own directory, or is an `api-ms-win-*`/`ext-ms-win-*` name that has a stub in the DLL dirs; missing -> Warn listing at most 20 names + "and N more"; delay-loaded missing -> Warn "optional"), `.NET` -> Warn (needs Mono/.NET, Phase 4), installer family -> Warn, Wine present + version (Fail when missing), Vulkan (`libvulkan.so.1` findable in the standard lib dirs) Warn when absent, Wayland (`WAYLAND_DISPLAY` set and socket exists) else X11 (`DISPLAY`) else Warn, PipeWire (`$XDG_RUNTIME_DIR/pipewire-0` socket) Warn when absent, prefix state (`drive_c` exists, hardened: `dosdevices` == {`c:`}, no outward symlinks) Warn/Fail. Verdict: Fail if any Fail; Warn -> "Application may fail to start."; else "Looks good." `runtime doctor <app|file>` and `runtime doctor` (system checks only).

**Acceptance tests:** each check unit-tested with injected inputs (fake DLL dirs, fake env, fake filesystem paths); an import list with 30 missing DLLs prints 20 + "and 10 more"; hostile PE names sanitised; a hardened vs unhardened synthetic prefix; CLI snapshot of the layout for a fake app.

## Task 9: Wine end-to-end, CI, docs

- `crates/cli/tests/e2e_wine.rs` (`#[ignore]`, needs Wine + fixtures): `RUNTIME_DATA_DIR` = tempdir; `runtime install tests/fixtures/build/hello64.exe` then `runtime list --json` (one app), `runtime run <id>` prints `hello from windows`, exit code 7; `runtime run tests/fixtures/build/hello32.exe`; `runtime doctor <id>` runs; `runtime logs <id>`; `runtime remove <id>` leaves nothing under the data dir and no `wineserver` for that prefix afterwards (poll up to 10 s).
- `.github/workflows/ci.yml`: add `wine64` to the apt install and a step `cargo test --workspace -- --ignored` after the normal tests (the Wine tests); keep everything else.
- `docs/SECURITY.md`: what Phase 2 does and does not do (prefix hardening, env allowlist, zip safety; NOT a sandbox: `\\?\unix\`, `com*` links, network and GPU access, no seccomp; the Phase 5 plan); README: update commands (`install/run/list/remove/logs/doctor`), state Wine is required and Phase 2 is unsandboxed; roadmap Phase 2 amendment note.
- Manual gate (controller runs): install/run/remove real portable apps if the user supplies them.

**Exit criteria (roadmap):** hello64.exe/hello32.exe run with exit code propagation; GUI fixture `gui64.exe` shows a window under Wayland (manual, user); `list/remove` clean; a second app cannot see the first app's files (e2e test: app A writes a file under its `drive_c`; app B `dir`s and does not find it; needs a tiny fixture: extend `tools/fixtures` with `fs.c` that writes/reads `C:\runtime-test.txt`); prefix hardening verified; unit + hostile tests green; final whole-branch review with the Phase 1 standard.

## Self-review against the roadmap

Covered: AppEnv + metadata.json + layout (T3), CompatBackend + Launcher + sandbox seam (T4), WineBackend with `Z:` removal and more (T5), install portable/zip (T6), run/list/remove/logs (T7), basic doctor (T8), `--debug` (T4/T7), Windows path semantics as a pure module (T2), isolation test (T9). Deferred by design: installers/MSI (Phase 3), template prefixes, dependencies/graphics (Phase 4), sandbox (Phase 5), `prefix`/`config`/`shell`/`repair`/`update`/`system-info` commands (later; `repair` is referenced by an error hint only, so print "not implemented yet" there, never a fake fix).
