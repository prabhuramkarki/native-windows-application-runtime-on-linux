# Phase 4A: Dependency Engine and Package Source Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `runtime deps <app>` plans what an app's prefix is missing and, with explicit consent, downloads, verifies and installs it (`archive` and `installer` package kinds) without ever downloading implicitly.

**Architecture:** A new `crates/deps` crate (`rt_deps`) holds a bundled pinned manifest, a pure resolver, the only network code (a streaming, hash-verifying HTTPS fetcher), and two installers that reuse already-hardened code (`rt_core::unzip` for archives, the Phase 3 sandboxed pipeline for vendor installers). Consent and installed packages are recorded in `Metadata` (schema v3). The CLI gains `runtime deps`; other commands only print hints.

**Tech Stack:** Rust 2024 (rust-version 1.88), `ureq` + `rustls` (fetch), `toml` + `serde` (manifest), `sha2` (hashing), existing `rt_core`/`rt_installer`/`rt_pe`, real Wine + `bwrap` + `makensis`/`wixl` for e2e.

**Spec:** `docs/superpowers/specs/2026-09-23-dependency-engine-design.md` (committed on this branch). Read it first; this plan argues from it.

## Global Constraints

- Manifest is bundled and pinned: `crates/deps/packages.toml`, embedded with `include_str!`; no remote manifest, no user manifests.
- Every package `url` is `https://`; every `sha256` is exactly 64 lowercase hex characters; `size` is exact bytes; both checked by a test over the real bundled manifest.
- Fetch: HTTPS only, redirects must stay HTTPS, at most 3 redirects, byte cap = manifest `size` (abort on more OR fewer bytes), connect timeout, total deadline, per-read stall timeout, hash computed while streaming, temp file `0600` + `O_EXCL` inside the app cache, mismatch deletes the file and fails hard, no retry, no HTTP fallback.
- `install`, `run`, `doctor` never download; only `runtime deps <app> --install` may touch the network.
- A bare `--yes` is rejected; consent is per package (`--yes <pkg>`), per version, and records a hash of the licence text shown.
- Packages of kind `installer` run only through the Phase 3 sandbox with `allow_network = false`, staged inside `drive_c`, including the in-sandbox `wineserver` wait; success is confirmed by the package's declared marker, not exit code alone.
- Installed state is what the runtime recorded in `Metadata`; it is never inferred from prefix contents.
- `Metadata` schema goes to 3; v1 and v2 files still read; the migration test uses frozen v1 and v2 byte literals, not bytes regenerated from current code.
- Untrusted text reaching a terminal goes through `crates/cli/src/safe.rs`; no shell interpolation of untrusted data anywhere.
- No new dependency without a `docs/THIRD_PARTY.md` row and a passing `cargo deny check` in the same commit.
- Process standards carried from Phase 3: every new guard is mutation-checked (remove guard, named test fails, restore); CI installs and requires every real tool a job needs from the start; e2e assertions check outcomes not exit codes; never touch the real `~/.local/share` (scratch `XDG_DATA_HOME`/`RUNTIME_DATA_DIR` in every test); commit trailer `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1 cargo test --workspace` green before every commit.

## Review Focus

Each line names an input or condition the spec implies but no obvious task test would exercise; each has a pinning test in the owning task (marked RF-n there).

1. **RF-1 A server that lies about size or stalls.** `Content-Length` larger or smaller than the manifest `size`, a body that drips one byte per second, or a body that never ends must abort with a typed error and leave no file (Task 3).
2. **RF-2 Two apps, one package.** Installing the same package into two apps must not share mutable state; the cache is read-only and shared, prefixes are independent, and removing one app's package leaves the other (Tasks 3, 5).
3. **RF-3 Interrupted install.** Killing the process mid-download or mid-extract must leave no half-written cache entry, no half-extracted files listed as installed, and `state` unchanged (Tasks 3, 5).
4. **RF-4 Manifest edge cases.** A package requiring itself, a diamond dependency, two packages providing the same DLL, an empty manifest, and a manifest with 10,000 packages must each be handled with a clear result and bounded time (Tasks 1, 2).
5. **RF-5 Hostile archive or installer contents.** A package archive with path traversal, absolute paths, symlinks, a zip bomb, or DLL names not in `provides` must install nothing outside its declared destinations (Task 5); an installer that exits 0 without creating its marker must be reported failed, not installed (Task 6).

---

## File Structure

- `crates/deps/Cargo.toml`, `crates/deps/src/lib.rs`: crate root, re-exports.
- `crates/deps/packages.toml`: the bundled manifest (data).
- `crates/deps/src/manifest.rs` (+ `manifest/tests.rs`): types, strict parse, validation.
- `crates/deps/src/capabilities.rs` (+ tests): PE-import to capability table (data + lookup).
- `crates/deps/src/resolve.rs` (+ `resolve/tests.rs`): pure planner.
- `crates/deps/src/fetch.rs` (+ `fetch/tests.rs`, `fetch/testserver.rs`): network edge and hostile test server.
- `crates/deps/src/install_archive.rs`, `crates/deps/src/install_installer.rs` (+ tests): the two installers.
- `crates/deps/src/state.rs` (+ tests): read and write `Metadata.dependencies` helpers.
- `crates/core/src/meta.rs` (modify): schema v3, `dependencies` field.
- `crates/cli/src/deps.rs` (new), `crates/cli/src/main.rs` (modify): `runtime deps` and hints.
- `tools/fixtures/dep-archive/` and `tools/fixtures/dep-installer.nsi` (new), `tools/build-fixtures.sh` (modify): e2e fixtures.
- `crates/cli/tests/e2e_deps.rs` (new, `#[ignore]`d), `docs/SECURITY.md`, `README.md`, `docs/THIRD_PARTY.md`, `.github/workflows/ci.yml` (modify).

---

### Task 0: Crate skeleton and dependency vetting

**Files:**
- Create: `crates/deps/Cargo.toml`, `crates/deps/src/lib.rs`
- Modify: root `Cargo.toml` (workspace deps), `docs/THIRD_PARTY.md`, `deny.toml` if licences require

**Interfaces:**
- Produces: workspace crate `runtime-deps` (lib name `rt_deps`) depending on `runtime-core`, `runtime-pe`, `runtime-installer`, `thiserror`, `serde`, `toml`, `sha2`, `ureq` (dev-deps: `tempfile`, and whatever TLS test-server crates Task 3 needs).

- [ ] **Step 1:** Spike: evaluate `ureq` (rustls backend), `toml`, `sha2`: licence (must pass `cargo deny`), transitive count, and known panic behavior. For `ureq`, defer hostile-response testing to Task 3 but confirm here that it can enforce: HTTPS-only, redirect limit, timeouts, and streaming reads (no full-body buffering).
- [ ] **Step 2:** Add the crate to the workspace using `dep.workspace = true` style (the convention flagged in the Phase 3 reviews); enable only the features needed (no default features you do not use).
- [ ] **Step 3:** Add `docs/THIRD_PARTY.md` rows for each new direct dependency in the house style (what could go wrong, how it is guarded, transitive notes). Run `cargo deny check`; fix `deny.toml` allow-list only for licences you have read.
- [ ] **Step 4:** `cargo build --workspace`, fmt, clippy. Commit `chore(deps): add runtime-deps crate and vetted dependencies`.

**Exit:** workspace builds; `cargo deny check` passes; THIRD_PARTY updated; no behavior yet.

---

### Task 1: Manifest types, strict parsing, bundled manifest loader

**Files:**
- Create: `crates/deps/src/manifest.rs`, `crates/deps/src/manifest/tests.rs`, `crates/deps/packages.toml` (initially a small synthetic-but-valid manifest used by tests; real pins land in Task 8)
- Modify: `crates/deps/src/lib.rs`

**Interfaces:**
- Produces:
```rust
pub enum Kind { Archive, Installer }
pub struct Package {
    pub id: String, pub version: String, pub sha256: String, pub size: u64,
    pub licence: String, pub url: String, pub kind: Kind, pub requires_consent: bool,
    pub requires: Vec<String>, pub provides: Vec<String>, pub install: Install,
}
pub enum Install {
    Archive { format: ArchiveFormat /* Zip | TarGz; no zstd */, extract: Vec<Extract>, dll_overrides: Vec<String> },
    Installer { silent_args: Vec<String>, marker: Marker },
}
pub struct Extract { pub from: String, pub to: String }
pub enum Marker { File(String), RegistryValue { key: String, name: String } }
pub struct Manifest { pub packages: Vec<Package> }
impl Manifest {
    pub fn parse(text: &str) -> Result<Manifest, ManifestError>;
    pub fn bundled() -> &'static Manifest;   // parsed once from include_str!
    pub fn get(&self, id: &str) -> Option<&Package>;
}
pub enum ManifestError { /* typed: Toml, UnknownField, DuplicateId, Cycle, BadUrl, BadHash, UnknownRef, TooLarge, ... */ }
```

- [ ] **Step 1: Write failing tests** covering: valid minimal manifest; unknown field rejected; duplicate id; dependency cycle (A->B->A) and self-requirement (RF-4); `http://` url rejected; sha256 not 64 lowercase hex rejected; `requires` unknown id rejected; `extract.to` absolute or containing `..` rejected; input over 1 MiB rejected; 10,000 synthetic packages parse and validate in bounded time (RF-4); two packages `provides` the same name rejected; and a test that parses the REAL bundled manifest (`Manifest::bundled()`) and re-asserts every url/sha256/size invariant.
- [ ] **Step 2:** Run them; confirm they fail.
- [ ] **Step 3:** Implement with `serde(deny_unknown_fields)`, explicit validation pass (iterative cycle detection, no recursion depth risk), size caps.
- [ ] **Step 4:** Add a hostile-TOML fuzz-style test (10k mutated inputs, `catch_unwind`, never panics). Mutation-check each validation guard.
- [ ] **Step 5:** fmt, clippy, tests; commit `feat(deps): strict manifest parsing and validation`.

**Exit:** manifest parser/validator complete; bundled manifest loads and passes the invariant test.

---

### Task 2: Capability table and resolver

**Files:**
- Create: `crates/deps/src/capabilities.rs`, `crates/deps/src/resolve.rs`, `crates/deps/src/resolve/tests.rs`

**Interfaces:**
- Consumes: `Manifest`, `Package` from Task 1; `rt_pe::PeInfo` imports (`pe::analyze` output: DLL import names); `rt_core::Metadata` (Task 4 adds `dependencies`; until then resolve takes the installed set as a plain argument).
- Produces:
```rust
pub struct Facts { pub imports: Vec<String> /* lowercase dll names */, pub extra_capabilities: Vec<String> }
pub struct InstalledSet(pub Vec<InstalledRef>);           // {id, version, sha256}
pub struct InstalledRef { pub id: String, pub version: String, pub sha256: String }
pub enum ConsentState { NotNeeded, Needed, Denied }
pub enum Action { Install, AlreadyInstalled, Blocked { reason: String } }
pub struct PlanEntry { pub package: String, pub action: Action, pub consent: ConsentState }
pub struct Plan { pub entries: Vec<PlanEntry> }          // dependencies first
pub fn required_capabilities(facts: &Facts) -> Vec<String>;
pub fn resolve(facts: &Facts, installed: &InstalledSet, denied: &[String], manifest: &Manifest) -> Plan;
```

- [ ] **Step 1: Write failing tests:** `d3d11.dll` import yields capability `d3d11` satisfied by the DXVK package; already-installed package (matching id+version+sha256) is `AlreadyInstalled`; installed with a different hash is treated as not installed; dependencies ordered first; diamond dependency appears once (RF-4); a denied package is `Blocked` and so is anything requiring it, while unrelated packages still plan `Install`; unknown capability yields no entry (not a panic); output order deterministic.
- [ ] **Step 2:** Run; confirm failing. **Step 3:** Implement as pure functions (no I/O, no globals). **Step 4:** Mutation-check the installed-hash comparison and the denied-propagation logic. **Step 5:** commit `feat(deps): capability table and pure resolver`.

**Exit:** resolver fully unit-tested; no I/O in the module.

---

### Task 3: Fetch: streaming, hash-verifying HTTPS client, hostile test server

**Files:**
- Create: `crates/deps/src/fetch.rs`, `crates/deps/src/fetch/tests.rs`, `crates/deps/src/fetch/testserver.rs` (test-only in-process TLS server using `rustls` with a test-generated certificate; add any dev-only cert crate with a THIRD_PARTY row)

**Interfaces:**
- Consumes: `Package` (url, sha256, size).
- Produces:
```rust
pub struct FetchOpts { pub connect_timeout: Duration, pub total_deadline: Duration, pub stall_timeout: Duration, pub max_redirects: u8 /* <= 3 */ }
impl Default for FetchOpts { /* connect 10s, total 300s, stall 20s, redirects 3 */ }
pub enum FetchError { NotHttps, TooManyRedirects, RedirectDowngrade, TooLarge, TooShort, HashMismatch, Timeout, Stalled, Tls(String), Http(u16), Io(io::Error) }
pub fn fetch(pkg: &Package, cache_dir: &Path, opts: &FetchOpts) -> Result<PathBuf /* cache/<sha256>, read-only */, FetchError>;
pub fn cached(pkg: &Package, cache_dir: &Path) -> Option<PathBuf>;   // re-verifies hash; never trusts
```
Test seam: `fetch_with(client_config, ...)` or an injectable trust root so tests can point at the local test server; production code path must not allow disabling verification.

- [ ] **Step 1: Write failing tests against the local TLS server:** success path (hash matches, file at `cache/<sha256>`, mode read-only); wrong hash -> `HashMismatch` and temp file deleted; server sends more bytes than `size` -> abort `TooLarge` mid-stream (RF-1); fewer bytes -> `TooShort` (RF-1); lying `Content-Length` both directions (RF-1); one-byte-per-second drip -> `Stalled`/`Timeout` (RF-1); never-ending body -> aborted at the cap (RF-1); redirect loop -> `TooManyRedirects`; HTTPS to HTTP redirect -> `RedirectDowngrade`; plain `http://` package url -> `NotHttps` with no connection attempted; 404/500 -> `Http`; TLS failure (untrusted cert) -> `Tls`; cache hit re-verified, and a corrupted cache entry is discarded and refetched (RF-3: an interrupted fetch leaves no `cache/<sha256>` file, only a deleted temp).
- [ ] **Step 2:** Run; confirm failing. **Step 3:** Implement: stream `Read` in chunks into a `0600`/`O_EXCL` temp file in `cache_dir`, `sha2` update per chunk, count bytes against `size` continuously, rename to `cache/<sha256>` then set read-only only after the hash matches; delete temp on every error path (use a drop guard so a panic or early return cleans up). **Step 4:** Mutation-check: byte cap, hash comparison, HTTPS-only, redirect limit, stall timeout, temp cleanup (each removed guard makes a named test fail). Add a hostile-response fuzz test if `ureq` exposes a way to feed raw bytes; otherwise the server suite above is the fuzz surface and the report says so.
- [ ] **Step 5:** commit `feat(deps): hash-verifying streaming HTTPS fetch with hostile-server tests`.

**Exit:** all hostile-server cases pass; no test uses the real internet; one `#[ignore]`d smoke test fetches a small real file.

---

### Task 4: State and `Metadata` schema v3

**Files:**
- Modify: `crates/core/src/meta.rs`, `crates/core/src/lib.rs` (re-exports)
- Create: `crates/deps/src/state.rs`, `crates/deps/src/state/tests.rs`

**Interfaces:**
- Produces (in `rt_core`):
```rust
pub struct DependencyRecord {
    pub id: String, pub version: String, pub sha256: String, pub installed_at: u64,
    pub consent: Option<ConsentRecord>,
}
pub struct ConsentRecord { pub given_at: u64, pub licence_text_sha256: String }
// Metadata gains: #[serde(default)] pub dependencies: Vec<DependencyRecord>
pub const SCHEMA_VERSION: u32 = 3;
```
and in `rt_deps::state`: `pub fn installed_set(md: &Metadata) -> InstalledSet;`, `pub fn record(md: &mut Metadata, rec: DependencyRecord);`, `pub fn forget(md: &mut Metadata, id: &str);`.

- [ ] **Step 1: Write failing tests:** frozen v1 byte literal and frozen v2 byte literal (copy real files produced by the current code into `const` strings in the test; do NOT generate them from a struct) both read with `dependencies == []`; a v3 round trip; `SCHEMA_VERSION` 3 written by new saves; version 4 rejected; `dependencies` field bounded (cap on count and string lengths using the existing `cap()` pattern); `record` replaces an entry with the same id; `installed_set` maps correctly.
- [ ] **Step 2:** Run; confirm failing. **Step 3:** Implement; keep `MIN_SCHEMA_VERSION = 1`; update the existing exact-version tests to the new range. **Step 4:** Mutation-check the range gate and the caps. **Step 5:** commit `feat(core): metadata schema v3 with recorded dependencies`.

**Exit:** old metadata files still read; new field round-trips; frozen literals guard future migrations.

---

### Task 5: Archive installer

**Files:**
- Create: `crates/deps/src/install_archive.rs`, `crates/deps/src/install_archive/tests.rs`

**Interfaces:**
- Consumes: `Package` with `Install::Archive`, a verified cache file path (Task 3), `AppEnv` (`env.drive_c()`, `env.prefix()`), `rt_core::unzip` (`open`, `extract`, `Limits`) for `format = "zip"`, a NEW small hand-rolled bounded tar reader over the `flate2` gzip decoder for `format = "tar.gz"` (Ruling 5: caps on entry count, name length, per-file and total bytes; refuse symlinks, hardlinks, devices, absolute or `..` names; no zstd), `rt_core::{resolve_under, join_new, WinPath}`.
- Produces:
```rust
pub struct ArchiveInstalled { pub files: Vec<PathBuf> /* drive_c-relative, exactly what was written */, pub overrides: Vec<String> }
pub enum ArchiveError { Zip(ZipError), Destination(String), NotInProvides(String), Io(io::Error), Registry(String) }
pub fn install_archive(pkg: &Package, file: &Path, env: &AppEnv, backend: &dyn CompatBackend) -> Result<ArchiveInstalled, ArchiveError>;
pub fn remove_archive(installed: &ArchiveInstalled, env: &AppEnv) -> Result<(), ArchiveError>;   // deletes exactly those files
```
DLL overrides are written by running the backend's registry helper (or writing `user.reg` through a bounded, tested writer if the backend has none); pick and document one approach in the task.

- [ ] **Step 1: Write failing tests (real zip files built in the test):** happy path extracts only declared `from`->`to` pairs under `drive_c` and records exact paths; path traversal (`../x`), absolute names, backslash tricks, and symlink entries write nothing outside (RF-5); zip bomb over `Limits` rejected before writing (RF-5); an entry not listed in `extract` is ignored; a DLL override for a name not in `provides` is refused (RF-5); failure halfway (second entry corrupt) removes what this package already wrote and records nothing (RF-3); two prefixes, same cache file: independent results, removing from one leaves the other (RF-2); a cache file is never modified.
- [ ] **Step 2:** Run; confirm failing. **Step 3:** Implement on top of `unzip::open`/`extract` (zip) and the bounded tar.gz reader (tests for the tar reader: traversal, absolute names, symlink/hardlink/device entries, oversized headers, truncated archive, gzip bomb, name over cap, all must extract nothing) with an extraction limit set derived from the manifest `size`; resolve every destination with `join_new` under `drive_c`; track every created path for rollback/removal. **Step 4:** Mutation-check containment, provides-filter and rollback. **Step 5:** commit `feat(deps): archive package installer`.

**Exit:** archive installs are contained, reversible and exactly tracked.

---

### Task 6: Installer-kind installer

**Files:**
- Create: `crates/deps/src/install_installer.rs`, `crates/deps/src/install_installer/tests.rs`
- Modify: `crates/installer/src/pipeline.rs` (only to expose the minimum reusable pieces: staging into `drive_c`, running one sandboxed command with `settle`; keep existing behavior and tests unchanged)

**Interfaces:**
- Consumes: `Package` with `Install::Installer { silent_args, marker }`, cache file, `AppEnv`, `&dyn CompatBackend`, `Launcher`, Phase 3 `InstallerSandbox`/`SandboxOpts`, `backend.settle`.
- Produces:
```rust
pub enum InstallerPkgError { Stage(String), Sandbox(String), NonZeroAndNoMarker { code: Option<i32> }, MarkerMissing, BwrapNotFound, Io(io::Error) }
pub struct InstallerPkgInstalled { pub marker_confirmed: bool }
pub fn install_installer_pkg(pkg: &Package, file: &Path, env: &AppEnv, backend: &dyn CompatBackend, launcher: &Launcher) -> Result<InstallerPkgInstalled, InstallerPkgError>;
```
Always `allow_network = false`. Staged installer file is deleted afterward (best effort), as in Phase 3.

- [ ] **Step 1: Write failing tests (FakeBackend for logic, then a real-tool test gated like the Phase 3 bwrap tests):** marker file present after a fake installer run -> success; exit 0 but marker absent -> `MarkerMissing` (RF-5); non-zero exit but marker present -> success with a warning (Phase 3 convention); sandbox is always launched with the network denied (assert the argv contains `--unshare-net`); staged file removed; a missing `bwrap` is a clean typed error.
- [ ] **Step 2:** Run; confirm failing. **Step 3:** Implement by reusing the Phase 3 building blocks; do not fork the sandbox logic. **Step 4:** Mutation-check the marker check and the network-denied setting. **Step 5:** commit `feat(deps): sandboxed installer-kind package installer`.

**Exit:** installer packages install only through the sandbox, offline, with marker confirmation.

---

### Task 7: `runtime deps` CLI, orchestration and hints

**Files:**
- Create: `crates/cli/src/deps.rs`, `crates/deps/src/orchestrate.rs` (+ tests)
- Modify: `crates/cli/src/main.rs`, `crates/cli/src/install.rs`, `crates/cli/src/run.rs`, `crates/cli/src/doctor.rs` (hints only)

**Interfaces:**
- Produces (in `rt_deps`):
```rust
pub struct Orchestrator<'a> { /* manifest, cache dir, AppEnv, backend, launcher, fetch opts, consent provider */ }
pub trait ConsentProvider { fn confirm(&self, pkg: &Package) -> bool; }   // interactive prompt vs `--yes` list
pub struct RunReport { pub completed: Vec<String>, pub failed: Vec<(String, String)>, pub skipped: Vec<String> }
pub fn plan_for_app(env: &AppEnv, md: &Metadata, manifest: &Manifest) -> Plan;
pub fn install_plan(o: &Orchestrator, plan: &Plan) -> RunReport;   // stops at first failure, reports completed/failed/skipped
```
CLI: `runtime deps <app>`, `runtime deps <app> --install [--yes <pkg>]...`, `runtime deps list`, `runtime deps cache [--clear]`. A bare `--yes` is a usage error. Hints in `install`/`run`/`doctor` are one sanitized line, computed without network.

- [ ] **Step 1: Write failing tests:** plan output for a fake app; `--install` without consent for a consent-gated package installs nothing and never fetches (assert the fetcher was not called: inject a counting fetcher); `--yes pkg` for a package not in the plan is an error; bare `--yes` rejected; partial failure reports completed/failed/skipped and leaves `Metadata` recording only completed packages (RF-3); consent record includes the licence text hash; hint lines contain sanitized text only; `run`/`install`/`doctor` code paths make no network call (assert by construction: they do not depend on `fetch`).
- [ ] **Step 2:** Run; confirm failing. **Step 3:** Implement; write `Metadata` atomically via the existing store API after each successful package (so an interrupted run keeps prior successes). **Step 4:** Mutation-check the consent gate and the bare-`--yes` rejection. **Step 5:** commit `feat(cli): runtime deps command and missing-dependency hints`.

**Exit:** end-to-end behavior works against fakes; nothing downloads unless `--install` with consent.

---

### Task 8: Real bundled manifest (verified pins)

**Files:**
- Modify: `crates/deps/packages.toml`, `docs/THIRD_PARTY.md`

**Interfaces:** none new; content only.

- [ ] **Step 1:** With network access, pick the initial package set: DXVK and VKD3D-Proton (`archive`, permissive/LGPL, no consent), a VC++ runtime (`installer`, consent), and `d3dcompiler_47` if a redistributable source can be verified. For each, download the artifact, record exact `sha256` and `size`, record the licence, and record the source URL. Only include packages you actually verified; leave out (and list under "Known gaps" in the report) anything you could not verify. Do NOT invent hashes.
- [ ] **Step 2:** Fill `provides` and `requires`, the marker for the installer package, and the archive `extract` lists from the real archive contents (list them with `unzip -l`/`tar -t`).
- [ ] **Step 3:** The Task 1 invariant test over the bundled manifest must pass; add an `#[ignore]`d test that re-downloads each package and re-checks hash and size (run it once now, report the result).
- [ ] **Step 4:** Add licence notes to `docs/THIRD_PARTY.md` under external components (downloaded with consent). Commit `feat(deps): initial verified package manifest`.

**Exit:** bundled manifest contains only verified, pinned packages; re-verification test exists.

---

### Task 9: Real Wine e2e, CI, docs

**Files:**
- Create: `tools/fixtures/dep-archive/` (a tiny DLL zip built from `tools/fixtures/exports.c`), `tools/fixtures/dep-installer.nsi` (tiny NSIS writing a marker file), `crates/cli/tests/e2e_deps.rs`
- Modify: `tools/build-fixtures.sh`, `.github/workflows/ci.yml`, `docs/SECURITY.md`, `README.md`, plan Execution notes

- [ ] **Step 1:** Build the two fixtures in `tools/build-fixtures.sh` (outputs stay gitignored). Serve them to the e2e via the Task 3 local test server (or a local loopback HTTPS server started by the test); the test manifest is injected, never the bundled one.
- [ ] **Step 2: Write `#[ignore]`d real-Wine e2e tests** using the shared `Rig` (scratch `XDG_DATA_HOME`, no stray `wineserver`): archive package installs into a real prefix (files present, DLL override in the registry, consent record in `metadata.json`); installer package installs through the sandbox (marker present, `metadata.json` records it); a denied package installs nothing and the server saw zero requests for it; a tampered download installs nothing; a package is not installed twice (second run plans `AlreadyInstalled`); removing the app leaves nothing behind; each assertion checks outcomes (files, registry, metadata), not exit codes only (RF-2, RF-3, RF-5).
- [ ] **Step 3:** CI: ensure `wine-e2e` and `test` jobs install every tool used (`nsis`, `msitools`, `wixl`, `bubblewrap`, `desktop-file-utils`, plus whatever TLS test-server support needs) and set the `RUNTIME_REQUIRE_*` variables; new `#[ignore]`d tests are picked up by the existing `--ignored` invocation (verify, do not assume).
- [ ] **Step 4:** Docs: `SECURITY.md` "Dependency downloads" section in the house style (trust model, what is verified, what is not, consent, sandboxed installers, residual risks); README `runtime deps`; append "Execution notes" to this plan LAST, including a verification record with real numbers and a "Ready for the next sub-project" list.
- [ ] **Step 5:** Full gate plus real e2e run for real; commit in sensible pieces.

**Exit criteria (from the spec):** `runtime deps` plans and, with consent, installs an archive and an installer package end to end on real Wine; tampered or mismatched downloads install nothing; denied consent installs nothing and never downloads; `install`/`run`/`doctor` never download; full gate green; final whole-branch review with real experiments before merge.

---

## Self-review against the spec

Covered: manifest (Task 1), capability mapping and resolver (Task 2), fetch and hostile-server suite (Task 3), state and Metadata v3 with frozen-literal migration (Task 4), archive kind (Task 5), installer kind through the Phase 3 sandbox with marker confirmation (Task 6), consent flow, CLI and no-implicit-download guarantee (Task 7), real bundled manifest with verified pins (Task 8), real e2e, CI, docs (Task 9). Non-goals from the spec (graphics selection, audio/Wayland, full `doctor app`, compat matrix, managed Wine, remote/user manifests) have no tasks. Type names used across tasks (`Package`, `Kind`, `Plan`, `PlanEntry`, `Action`, `ConsentState`, `InstalledSet`, `DependencyRecord`, `ConsentRecord`, `ArchiveInstalled`, `InstallerPkgInstalled`, `Orchestrator`, `ConsentProvider`) are defined once in the task that produces them.

---

## Execution notes

Written last, at the end of Task 9 (branch `phase-4-dependencies`, 35+ commits on `main`, not merged or pushed).

### Built versus planned

- **As planned:** the `runtime-deps` crate (`rt_deps`) with the bundled, pinned manifest and strict parser, the
  capability table and pure resolver, the only network code (streaming, hash-verifying HTTPS fetch with a hostile
  in-process TLS test server), `Metadata` schema v3 with frozen v1/v2 literals, the archive and installer package
  installers, the orchestrator, `runtime deps` and the hints in `install`/`doctor`, the verified manifest, real-Wine
  e2e, CI and docs.
- **Beyond the plan:** a hand-rolled bounded `tar.gz` reader (Ruling 5; DXVK ships no zip), an intent journal in
  `<app>/deps-backup` so a killed archive install is exactly undone (`--discard-interrupted`), a per-app `deps.lock`
  plus a `/proc` busy-prefix check, `min_dword` version-aware registry markers, DLL overrides for installer packages,
  a marker pre-check that skips components the app's own installer already put there, and a one-run null-driver
  desktop (`explorer.exe /desktop=...,null`) without which WiX Burn installers cannot run headless.
- **Different from the plan:** the Task 9 e2e lives in `crates/deps/src/orchestrate/tests/e2e.rs`, not
  `crates/cli/tests/e2e_deps.rs`: the CLI cannot take a test manifest (on purpose), and the local HTTPS test server
  and the crash hook are `#[cfg(test)]` items of the library. The fixtures are the existing `exports64.dll` (zipped in
  the test) and `tools/fixtures/dep-installer.nsi`; no `tools/fixtures/dep-archive/` was needed. There is no
  `cargo-fuzz` setup in the repository; fuzzing is in-test (seeded mutations under `catch_unwind`): the manifest
  parser (10k inputs, Task 1) and, added in Task 9, the import-to-capability lookup (20k inputs).
- **Not built:** VKD3D-Proton (`.tar.zst` only), `d3dcompiler_47` (no verifiable redistributable), .NET/Mono/Gecko,
  32-bit DLLs, package upgrades and single-package removal (see "Ready for the next sub-project").

### Rulings (one line each; full text in the SDD ledger)

1. All implementers/reviewers ran on `opus` (Sonnet quota exhausted); final whole-branch review on `fable`.
2. DLL overrides via the prefix's `reg.exe` through the settled backend helper (not a hand-written `user.reg`).
3. Task 6 may only expose Phase 3 pipeline pieces (`installer::run`); Phase 3 behaviour and e2e unchanged (verified).
4. Task 8 downloads real artifacts; anything unverifiable is left out and listed as a gap.
5. Manifest `format = zip | tar.gz`; bounded hand-rolled tar reader over flate2; no zstd.
6. Task 1 fix round covered consent-by-licence, destination uniqueness and the `format` field.
7. `provides` are lowercase DLL base names; PE imports are normalised the same way.
8. Resolver: an exact installed match wins over denial; `Plan.unsatisfied` lists capabilities nobody provides.
9. Task 5 split into 5a (tar reader) and 5b (archive installer) after a lost session.
10. `discard_interrupted` recovery API; `remove_archive` refuses an empty record.
11. Consent hashes the exact `consent_text`; per-app `deps.lock`; refuse a busy prefix; no `--remove`; a marker
    already present is never recorded as installed.
12. Task 7 split into 7a (orchestrator library) and 7b (CLI).
13. Upgrades of recorded packages are refused before any download; recreate the environment.
14. Installer packages may declare `dll_overrides` (set `native,builtin` after the marker is confirmed).
15. An installer whose marker is already in the prefix is skipped before any prompt or download, never recorded.
16. Registry markers may carry `min_dword`: an older build counts as absent (vcrun2022 `Bld >= 35211`).
17. (Final review fix wave) The runtime's own `reg.exe` runs after a vendor installer (set/delete/query of its DLL
    overrides) run in the installer sandbox, offline: the Wine session they start also starts what the installer
    registered (auto-start services, ...). Any later unsandboxed Wine session (`runtime run`) still does.
18. (Final review fix wave, minimal) A marker-present installer package gets no overrides and there is no way to ask
    for them yet: `deps` and `doctor` say so plainly and point at recreating the environment.

### Verification record (numbers from real runs)

- **Workspace gate at the end of Task 9:** `cargo fmt --all -- --check` clean; `cargo clippy --workspace
  --all-targets -- -D warnings` clean; `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1 cargo test
  --workspace`: 1322 passed, 0 failed, 21 ignored (`rt_deps` lib: 350 passed, 10 ignored). `cargo deny check`:
  advisories, bans, licenses, sources ok.
- **Real Wine (Wine 10.0 Ubuntu 10.0~repack-12ubuntu1, bubblewrap 0.11.1):** CI's exact filter
  `cargo test -p runtime-deps --lib -- --ignored e2e_real_wine --test-threads=1` selects 6 tests (archive zip/tar.gz +
  override, NSIS both marker kinds, null-desktop args and marker-only failure, hanging installer deadline, and the two
  new orchestrator tests); run 3 times in a row: 6/6 passed each time (218 s, 152 s, 119 s). The orchestrator run
  (consent-gated archive + sandboxed NSIS installer + denied package) took 3.6 to 4.6 s per run; the second run
  0.005 s with zero requests.
- **CI's other real-Wine step** (`cargo test -p runtime-backend-wine -p runtime-cli -- --ignored --test-threads=1`):
  9 passed (backend 2, CLI Wine 3, Phase 3 installers 4), no wineserver left.
- **Earlier real runs (task reports):** vcrun2022 real download and install through the project path 6/6 (Task 8b,
  and 6/6 again after each fix round, 13.5 to 14.2 s with 16 overrides); bundled DXVK real download, install and
  byte-exact removal (Task 8); both pins re-fetched and matched (`real_net_bundled_packages_refetch_and_match`).
- **Mutation checks (from the reports):** Task 1: 63 of 64 killed; Task 2: all killed (two rounds); Task 3: the
  implementer's set plus 6 reviewer re-runs, all killed, one surviving deadline mutant fixed in round 2; Task 4: 22 of
  22; Task 5a: 65 (63 killed, 2 equivalent); Task 5b: 72 (66 killed, 5 accepted survivors); Task 6: 19 of 19 plus 4 in
  the fix round (2 equivalent); Task 7b: 22 plus 10 in the fix round (1 equivalent: `O_CLOEXEC`); Task 8/8b: 3 + 10
  + 8, all killed. Task 9: 6 of 6 killed (the three lock-classification guards; the Wine version gate; the consent
  gate and the cache rename, each disabled and caught by the real-Wine orchestrator e2e).

- **Final-review fix wave (Rulings 17, 18; I-3, I-4, minors):** workspace gate 1327 passed, 0 failed, 22 ignored
  (`rt_deps` lib 354 + 11 ignored); CI's deps filter now selects 7 real-Wine tests (the new one: an "installer",
  Wine's own `sc.exe`, registers an auto-start service that writes to a host directory through `\\?\unix\`; before the
  fix the runtime's override step wrote the host file, after it the file stays unwritten, and a plain Wine session
  afterwards writes it as the control), run 3 times: 7/7 each (123 s, 124 s, 122 s). The real vcrun2022 download and
  install with the sandboxed overrides passed (61 s including the download). 11 of 11 mutants killed (3 on the
  sandboxed reg calls, 4 on the size-scaled fetch deadline including its wiring into ureq, d3d8 x64-only, the
  marker-present text, 2 on the doctor note). The fetch suite ran 5 times plain and 3 times under 8 CPU hogs, green.

### Deviations and notes

- Commit trailers: several implementer sessions (Tasks 3, 5, 9) used their harness's accurate
  `Co-Authored-By: Claude Opus 5.5 (1M context)` trailer instead of the plan's `Claude Sonnet 5`; to settle at merge.
- The real-Wine tests now check the Wine version first and fail with a clear message on Wine < 10 (they were verified
  on 10.0 only; CI's `ubuntu-latest` may ship 9.x, which is why `wine-e2e` stays `continue-on-error`).
- A real SIGKILL of an in-process install is not practical in a test; the killed-install e2e uses Task 5's
  `#[cfg(test)]` crash hook (a panic at a numbered point, so no rollback runs), on a real prefix, at the two points
  where the prefix is affected (journal created; the DLL written over Wine's placeholder).
- The CI `wine-e2e` job has still never run on a hosted runner and does not gate (`continue-on-error`). It now runs
  in an `ubuntu:26.04` container (distro Wine 10, the packaging verified locally) with `--privileged` for bubblewrap,
  as root. WineHQ's packages were deliberately not used: they install under `/opt/wine-*`, which the installer
  sandbox does not bind, so every sandboxed installer run would fail there (that is itself an open limit, below).
- The fetch deadline is no longer a flat 300 s: 300 s plus one second per 32 KiB of the package, at most one hour.

### Ready for the next sub-project (Phase 4B, graphics selection)

- **Can rely on:** `rt_deps::plan_for_app`/`plan_for_pe` (imports to capabilities to packages, warnings for x86 and
  unsatisfied needs), `install_plan` behind consent with per-app recorded state in `Metadata.dependencies`, DXVK 3.1.1
  as an archive package with `native,builtin` overrides for d3d8/9/10core/11/dxgi, verified downloads in a shared
  cache, and the no-download guarantee of `install`/`run`/`doctor`.
- **Open limits:** x64 DLLs only; no VKD3D-Proton (needs a zstd decision or another source); no `d3dcompiler_47`; no
  .NET/Mono/Gecko (still disabled in every prefix); marker-only success for exe installers (the explorer wrapper hides
  the exit code); `explorer.exe`/`msiexec.exe`/`reg.exe` from the prefix are unpinned; path-based file operations must
  move to `openat`/`renameat`/`unlinkat` before Phase 5 makes the prefix a boundary; the shared run lock is released
  once an app has started.
- **Follow-ups from the final review:** offer DLL overrides for marker-present installer packages (Ruling 18 only
  explains); M-1 (list and sweep stale `.tmp-*` files in the download cache), M-3, M-6 and M-7 as listed by the final
  review; the deferred minors in the SDD ledger (among them: `FetchOpts { total_deadline: Duration::MAX }` overflows
  `Instant`, a torn journal tail cut inside a UTF-8 character blocks the package, `cached()` delete race, restored
  originals come back `0644`, DLL overrides are not journalled, archive packages' `reg.exe` runs unsandboxed like any
  later Wine session); bind a Wine install outside `/usr` (e.g. WineHQ's `/opt/wine-*`) into the installer sandbox.
- **Follow-ups:** package upgrade (undo the old install from the kept journal under the lock, then install) and
  single-package removal (including removing overrides, which today are never removed); a per-DLL override policy
  (which DLLs a graphics selection turns on or off, per app, instead of a fixed `native,builtin` list per package);
  the explorer null-desktop wrapper is a Wine behaviour worth re-checking on each Wine upgrade.
