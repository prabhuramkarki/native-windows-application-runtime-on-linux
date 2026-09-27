# Phase 6D Backend Interface and `.wrun` Packages Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `rt_core::CompatBackend` an audited, capability-declaring, conformance-tested seam selected by id (no plugins), and add the `.wrun` v1 single-file package with `runtime pack|inspect|unpack|import` and `apps.import`, where a package can only request and the user still consents through the existing commands. Close with the 1.0 docs and licence hygiene.

**Architecture:** The trait stays in `runtime-core` and gains `capabilities()`; a conformance suite (behind `testing`) runs over the Wine backend, `FakeBackend` and a test-only `NullBackend`; `rt_api::backends` maps a recorded id to a compiled-in backend. A new pure crate `runtime-package` (`rt_package`) reads `.wrun` through `rt_core::unzip` plus package rules and writes it reproducibly; the CLI's `import` feeds it into the existing `rt_core::install` (new subtree mode with per-file digests and a fixed id) or `rt_installer::install_via_installer`; metadata schema 4 records the requests; `runtimed` exposes `import` as a 6B job; the GUI's install dialog starts it.

**Tech Stack:** Rust; existing crates only (`zip` writer + `flate2` deflate, `toml`, `serde`, `sha2`, `thiserror`). No new third-party crate.

**Spec:** `docs/superpowers/specs/2026-09-27-backend-interface-and-wrun-design.md`

## Global Constraints

- No `dlopen`/`libloading`/`dlsym`/`RTLD_` anywhere in `crates/*/src` (the scan from Task 2 stays green); `deny.toml` bans the plugin crates.
- A `.wrun` is hostile input: every read goes through `rt_core::unzip` limits plus the package rules; nothing is written before the whole container and manifest are validated; every string from a package reaches output only through `clean_text`/`safe()`, bounded.
- Import never writes `permissions.toml`, never installs a dependency, never starts the app, never overwrites or touches an existing app; requests are stored as EXPRs built from enums, never copied from the file.
- Consent, sandbox, lock and grant rules are unchanged code paths (no new bypass flag, no new parameter that reaches them).
- No new third-party crate; if one turns out to be needed, stop and report (THIRD_PARTY.md + `cargo deny` in the same commit).
- Gates after every task: `cargo fmt --all -- --check`, `cargo clippy --workspace --exclude runtime-gui --all-targets -- -D warnings`, `cargo test --workspace --exclude runtime-gui`, `cargo deny check`; Task 6 also the GUI gates (`cargo clippy -p runtime-gui --all-targets -- -D warnings`, `cargo build -p runtime-daemon -p runtime-cli && RUNTIME_REQUIRE_DISPLAY=1 xvfb-run -a cargo test -p runtime-gui`).
- Tests never touch the user's data dir, `$XDG_RUNTIME_DIR` or a running `runtimed`; real-Wine and real-bwrap tests keep their existing gating (`RUNTIME_REQUIRE_BWRAP`).
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- Import granting or skipping anything: a code path from the manifest to `permissions.toml`, to `--yes`, to `--network`, or to running the app (Tasks 4, 5).
- Id collisions: any retry, suffixing, removal or lock of an existing app on `IdTaken`; the `Store::create` race (Tasks 4, 5).
- Container rules: an entry `unzip` would skip being accepted; a manifest path resolving outside `payload/`; integrity checked on declared sizes only, not on streamed bytes; a partial app left after a hash mismatch (Tasks 3, 4).
- Capabilities declared but not enforced; a Wine-specific assumption left in a path the null backend does not exercise (Tasks 1, 2).
- Registry: test code (`NullBackend`, `FakeBackend`) reachable from a release build; an unknown recorded backend id silently falling back to Wine (Task 1).
- API: `apps.import` argv injection (paths starting with `-`, `--`, newlines) and the `read_only` refusal (Task 6).

---

### Task 1: the backend contract, capabilities and the registry

**Files:**
- Modify: `crates/core/src/backend.rs` (contract docs per spec 5.1, `Capabilities`, `Unsupported`, `BACKEND_API_VERSION`, the trait method), `crates/core/src/fake.rs` (capabilities: both arches and subsystems, all features true, configurable through a builder), `crates/core/src/install.rs` (capability check before `Store::create`), `crates/core/src/run.rs` (`dotnet` refusal), `crates/installer/src/pipeline.rs` (`installers`), `crates/deps/src/orchestrate.rs` (`dependency_packages`), `crates/backend-wine/src/lib.rs` (capabilities), `crates/cli/src/main.rs` (`backend()` via the registry), `crates/api/src/host/{doctor,sandbox}.rs` (registry where only `&dyn` is needed; B5 comment where Wine stays concrete), `crates/cli/src/doctor.rs` (print `BACKEND_API_VERSION`)
- Create: `crates/api/src/backends.rs`

**Interfaces:**
- Produces:
  ```rust
  // rt_core::backend
  pub const BACKEND_API_VERSION: u32 = 1;
  #[derive(Debug, Clone, Copy, PartialEq, Eq)]
  pub struct Capabilities { pub arches: &'static [pe::Arch], pub subsystems: &'static [pe::Subsystem],
                            pub dotnet: bool, pub installers: bool, pub dependency_packages: bool }
  impl Capabilities { pub fn check(&self, arch: pe::Arch, subsystem: pe::Subsystem) -> Result<(), Unsupported>; }
  #[derive(Debug, thiserror::Error)] pub enum Unsupported { Arch { backend: &'static str, arch: String },
      Subsystem { backend: &'static str, subsystem: String }, Feature { backend: &'static str, feature: &'static str } }
  pub trait CompatBackend { /* existing */ fn capabilities(&self) -> Capabilities; }
  // rt_api::backends
  pub const KNOWN: &[&str] = &["wine"];
  pub const DEFAULT: &str = "wine";
  pub fn select(id: &str, launcher: &Launcher) -> Result<Box<dyn CompatBackend>, BackendError>;
  ```
  New error variants: `InstallError::Unsupported(Unsupported)`, `InstallerError::Unsupported`, `RunAppError::Unsupported`, `DepsError::Unsupported` (names may follow each enum's style; record in "As built").
- Consumes: nothing new.

- [ ] **Step 1: Audit (report before building on it).** `grep -rn "WineBackend" crates/*/src` and every Wine-layout assumption in core/installer/deps/api reached through `&dyn CompatBackend` (`drive_c`, `system.reg`, `wineserver` in `/proc` checks, `WINEDLLOVERRIDES`); write the list into the `rt_core::backend` module docs as "what the platform assumes of every backend" or "Wine-specific, stays concrete (B5)". Anything that would make the null backend fail silently (not refuse) is a finding to fix in this task.
- [ ] **Step 2: Failing tests:** `Capabilities::check` for each arch/subsystem; `rt_core::install` with a `FakeBackend` whose capabilities exclude `X86` refuses the `hello32.exe` fixture (or the x86 fixture that exists) with `Unsupported` and creates no app directory; `install_via_installer` with `installers: false` refuses before `Store::create`; `rt_deps` install with `dependency_packages: false` refuses before any fetch; a run of an app with Wine Mono recorded on a `dotnet: false` backend refuses; `rt_api::backends::select("wine")` returns id `wine` with a fake Wine on `RUNTIME_WINE` (the CLI rig's script), `select("nope")` and `select("\u{1b}[31m")` return `Unavailable` whose text is cleaned and lists `wine`; the CLI running an app whose metadata says `backend.id = "null"` exits 1 with that message (not a Wine run).
- [ ] **Step 3: Implement.** Wine: `arches: &[X86, X86_64]`, `subsystems: &[Gui, Console]`, all features true.
- [ ] **Step 4:** gates; commit `feat(core): the backend contract, capabilities enforced by install, installer, deps and run; backends selected by id`.

---

### Task 2: the conformance suite, the null backend, the no-plugin guard

**Files:**
- Create: `crates/core/src/backend/conformance.rs` (module under `backend`, `cfg(any(test, feature = "testing"))`; convert `backend.rs` to `backend/mod.rs` only if needed, else `#[path]`), `crates/core/tests/conformance.rs`, `crates/backend-wine/tests/conformance.rs`
- Modify: `crates/backend-wine/tests/e2e_wine.rs` (the live tier), `crates/core/src/lib.rs`, `deny.toml` (`[bans] deny`: `libloading`, `dlopen`, `dlopen2`, `libloading-mini`)

**Interfaces:**
- Produces:
  ```rust
  // rt_core::backend::conformance
  pub struct Scratch { /* data root, store, a prepared-able AppEnv */ }
  pub fn static_checks(b: &dyn CompatBackend, scratch: &Scratch) -> Vec<Failure>;   // no process
  pub fn live_checks(b: &dyn CompatBackend, scratch: &Scratch, launcher: &Launcher) -> Vec<Failure>;
  pub struct Failure { pub check: &'static str, pub detail: String }
  ```
  Returning failures (not panicking) lets each caller assert `is_empty()` and print them all.
- Consumes: Task 1.

- [ ] **Step 1: Failing tests:** in `core/tests/conformance.rs`, `NullBackend` (spec B6) and `FakeBackend` pass `static_checks` and `live_checks`; deliberately broken backends (test-local: one returning a relative program, one accepting `drive_c/../x`, one changing args, one whose `settle` drops args, one with id `Wine!`) each produce exactly the expected `Failure`; the null backend installs `hello64.exe` through `rt_core::install` and runs it through `rt_core::run` with a plain `Launcher` (exit 0, `backend.id == "null"`, a stderr line from its script in the log); `install_via_installer` and the deps install refuse it by capability. The source scan: no `crates/*/src/**/*.rs` contains `dlopen`, `dlsym`, `libloading`, `RTLD_`. In `backend-wine/tests/conformance.rs`: `WineBackend::from_found` with fake `wine`/`wineserver` paths passes `static_checks` (no process started: the fake paths are non-executable files, so an accidental spawn fails loudly). The live tier appended to the real-Wine e2e.
- [ ] **Step 2: Implement** (spec 5.1's observable checks; each check is a named function so a failure names it).
- [ ] **Step 3:** `cargo deny check` with the new bans; gates; commit `test(core): backend conformance suite over Wine, the fake and a null backend; no dynamic loading`.

---

### Task 3: the `runtime-package` crate (format, reader, writer)

**Files:**
- Create: `crates/package/Cargo.toml` (`runtime-package`, lib `rt_package`; deps `runtime-core`, `runtime-pe`, `serde`, `toml`, `sha2`, `zip`, `thiserror` (workspace); dev `tempfile`), `crates/package/src/{lib.rs,manifest.rs,read.rs,write.rs}`, `crates/package/src/tests/{hostile.rs,mutate.rs,roundtrip.rs}`, ~~`crates/package/tests/fixtures/`~~ (none: see As built, Task 3)
- Modify: `Cargo.toml` (`default-members` += `crates/package`), `crates/core/src/unzip.rs` (a public way to read one planned entry by name for the manifest, and `extract_verified`, see Interfaces), `Cargo.lock`

**Interfaces:**
- Produces: spec 3.3 exactly (`FORMAT`, `Manifest`, `Entry`, `Requests::exprs`, `FileRef`, `Package`, `parse_manifest`, `open`, `verify`, `unpack`, `extract_one`, `digests`, `pack`), and
  ```rust
  #[derive(Debug, thiserror::Error)] pub enum PackageError {
      Zip(#[from] rt_core::ZipError), Manifest(String), Layout(String), Integrity { path: String },
      Signed /* wrun.sig present */, Io { what: &'static str, source: io::Error } }
  // rt_core::unzip
  pub fn extract_verified(archive: &mut Archive, plan: &Plan, dest: &Path, limits: &Limits,
      digest: &dyn Fn(&[String]) -> Option<[u8; 32]>) -> Result<u64, ZipError>;   // None = refuse (unlisted)
  // ZipError gains Integrity { name: String } and Unlisted { name: String }
  ```
  `extract` becomes `extract_verified` with no check (one code path).
- Consumes: `rt_core::unzip::{open, Limits, Plan, entry_path, read_entry}`, `rt_core::{AppId, clean_text}`, `pe::Arch`.

- [ ] **Step 1: Spike.** Confirm `zip::ZipWriter` with `CompressionMethod::Deflated` builds under the workspace's `zip` features (`deflate-flate2`) and that `Cargo.lock` gains only `runtime-package`. If the writer needs another zip feature, stop and report.
- [ ] **Step 2: Failing tests** (spec 6 "Package hostile tests", "Mutation harness", "Writer"): one test per rule of spec 3.1 and 3.2, each asserting the `PackageError` variant and, for `unpack`, that `DIR` does not exist afterwards; `parse_manifest` on 2,000 mutants and `open`+`verify`+`unpack` on 2,000 archive mutants (seeded xorshift, the helper copied from `crates/deps/src/manifest/tests.rs`): no panic, `to_string()` at most 4 KiB, the tempdir the only place written; `pack` -> `open` -> `unpack` -> `pack` byte-identical; `pack` refusals (symlink, FIFO, `\` in a name, `[[files]]` present, output exists, over the reader's caps). `Requests::exprs` output is exactly the canonical strings for each enum value and nothing from the file.
- [ ] **Step 3: Implement.** Manifest structs use `#[serde(deny_unknown_fields, rename_all = "camelCase")]` and a separate validated type (serde's raw struct -> `Manifest` through one `validate` function). `open` reads `wrun.toml` via `read_entry` with a 64 KiB budget before parsing.
- [ ] **Step 4:** gates; commit `feat(package): .wrun v1 reader and reproducible writer over the hardened zip planner`.

---

### Task 4: install integration: subtree mode, fixed ids, schema 4, requested roots

**Files:**
- Modify: `crates/core/src/install.rs` (+ `install/tests.rs`), `crates/core/src/meta.rs` (`SCHEMA_VERSION = 4`, `PackageMeta`), `crates/installer/src/pipeline.rs` (+ tests), `crates/deps/src/resolve.rs`, `crates/deps/src/orchestrate.rs` (+ tests), `crates/api/src/types.rs` (`AppDetail.package` optional, additive)

**Interfaces:**
- Produces:
  ```rust
  // rt_core::meta
  pub struct PackageMeta { pub id: String, pub version: String, pub digest: String /* 64 hex */,
                           pub requested_dependencies: Vec<String>, pub requested_permissions: Vec<String> }
  // Metadata gains `#[serde(default)] pub package: Option<PackageMeta>`; validation bounds every field (ids by
  // the deps id grammar, at most 16; EXPRs from the fixed set only).
  // rt_core::install::InstallOpts gains
  pub id: Option<AppId>,                          // fixed: AlreadyExists => InstallError::IdTaken, no retry
  pub subtree: Option<String>,                    // archive only: install just this top-level dir, prefix stripped
  pub digests: Option<BTreeMap<String, [u8; 32]>>,// with subtree: every file must be listed and match
  pub package: Option<PackageMeta>,
  pub expect_arch: Option<pe::Arch>,              // InstallError::Mismatch when the program differs
  // rt_installer::InstallerOpts gains `id: Option<AppId>` and `package: Option<PackageMeta>` (same semantics)
  // rt_deps::resolve::Facts gains `requested: Vec<String>`; PlanEntry reason "requested by the package"
  ```
  `InstallOpts` loses `Default`-derive only if the new fields force it; keep it `Clone + Default`.
- Consumes: Task 3's `extract_verified`; Task 1's capabilities.

- [ ] **Step 1: Failing tests:** subtree install of an archive with `payload/App/app.exe` + a data file places them at `drive_c/Program Files/<id>/App/...` and nothing from outside the subtree; an unlisted file or a flipped byte => `Integrity`/`Unlisted`, and the app directory is gone; `expect_arch` mismatch refused before `Store::create`; fixed id taken => `IdTaken`, the existing directory's tree hash unchanged, no second id tried; the same for `InstallerOpts.id`; metadata v4 round trip, v3 files still read (`package: None`), a v4 file with an EXPR outside the fixed set or 17 dependencies refused; `plan_for_pe` with `requested: ["vcrun2022"]` and no imports needing it yields an install entry with the requested reason, `consent: needed`, and the 6B digest changes with the request; a requested id missing from the manifest is a warning; `runtime install` of a `.wrun` (a zip whose first entry is `wrun.toml`) is refused with the W11 message (test in `crates/cli/tests`).
- [ ] **Step 2: Implement.**
- [ ] **Step 3:** gates; commit `feat(core): package-aware install: verified subtree, fixed ids, schema 4 with requests; deps plan requested roots`.

---

### Task 5: CLI `pack`, `inspect`, `unpack`, `import`; permissions show requests

**Files:**
- Create: `crates/cli/src/package.rs`, ~~`crates/cli/tests/package.rs`~~ `crates/cli/tests/apps/package.rs` (see As built, Task 5)
- Modify: `crates/cli/src/main.rs` (four subcommands), `crates/cli/src/install.rs` (W11 check), `crates/cli/src/permissions.rs` (requested lines, `--json` `requested`), `crates/cli/Cargo.toml` (`runtime-package`), `crates/api/src/runtime.rs` + `types.rs` (`PermissionsView.requested`, additive)

**Interfaces:**
- Produces: `runtime pack <DIR> -o <FILE>`, `runtime inspect <FILE> [--json]` (`{id, name, version, arch, kind, entry, files, bytes, digest, signed: false, installed: bool, requests: {dependencies: [{id, consent: "needed"|"none"}], permissions: [EXPR]}}`), `runtime unpack <FILE> -o <DIR>`, `runtime import <FILE> [--silent] [--network]` (spec 5.3, 5.4). Staging per W13 in `package.rs` (`<data root>/staging`, 0700; file `create_new` 0600; removed on every path including errors).
- Consumes: Tasks 3, 4; `rt_deps::Manifest::bundled()` (or its existing loader) for dependency id checks and consent flags.

- [ ] **Step 1: Failing tests** (fake-Wine rig from `crates/cli/tests/support`): spec 6 "Integration" list. Plus: `inspect` and `unpack` never create an app or touch the store (store dir listing unchanged); `inspect` output contains "unsigned" and each grant command, with a package whose `name` holds ESC/U+202E printed escaped; `import --network` of a portable package exits 2/1 with the installer-only message; an import that fails after `Store::create` leaves no app and no staging file; the imported app's `runtime sandbox <id>` command equals a locally installed one's with ids normalised; `runtime permissions <id>` after `--set=network=allow` no longer lists the network request.
- [ ] **Step 2: Implement.** All output through `safe()`; exit codes as `install` (0 ok, 1 refused/failed, 2 usage).
- [ ] **Step 3:** gates (plus the bwrap-gated installer-kind test under `RUNTIME_REQUIRE_BWRAP=1` on this host); commit `feat(cli): runtime pack, inspect, unpack and import; permissions show what a package requested`.

---

### Task 6: `apps.import` in the API, the daemon and the GUI

**Files:**
- Modify: `crates/api/src/jobs.rs` (`JobSpec::Import`, `JobKind::Import`, validation, argv), `crates/api/src/lib.rs` (`API_VERSION = "0.2.1"`), `crates/daemon/src/{dispatch.rs,client.rs}`, `crates/daemon/tests/e2e_jobs.rs`, `crates/cli/tests` (the argv oracle test of 6B gains `import`), `crates/gui/src/vm/mod.rs`, `crates/gui/src/ui/{install.rs,app.rs}`, `crates/gui/tests/{widgets.rs,e2e.rs}`, `docs/API.md`

**Interfaces:**
- Produces: method `apps.import {path, silent?, network?}` -> `{jobId}`; argv `import [--silent] [--network] -- <path>`; `rt_daemon::client::{ImportParams, Client::import}`; `vm::Cmd::Import(ImportParams)`; GUI install dialog filter `*.wrun` (plus the existing ones), a chosen `.wrun` hides name/exe; app page line `widget_name = "perm-requested"` "Requested by the package (not granted): ..." from `PermissionsView.requested`, cleaned, `use_markup(false)`.
- Consumes: Task 5.

- [ ] **Step 1: Failing tests:** `JobSpec::from_request("apps.import", ...)` with the 6B hostile path set (`-x`, `--`, relative, `a/../b`, NUL, newline, U+202E, 4,097 bytes) => `invalid_argument`; argv exact; the CLI parser reads the argv as `import` with the path verbatim; read-only daemon => `read_only`; write daemon + real `runtime` + fake Wine: an import job of a portable test package succeeds, `apps.list` shows the id, `permissions.get` has `requested`; GUI vm: an `InstallForm` with a `.wrun` path yields one `Cmd::Import` (name/exe dropped), read-only => refused with the read-only reason; widget: the requested line shows `<b>x</b>`-style text literally (canned model).
- [ ] **Step 2: Implement;** `docs/API.md`: the method, the kind, `requested`, `package` on `AppDetail`, the 0.2.1 entry.
- [ ] **Step 3:** both gate sets; commit `feat(api): apps.import as a job; the GUI imports .wrun packages and shows requested permissions`.

---

### Task 7: docs, licences and the 1.0 hygiene

**Files:**
- Create: `LICENSE-MIT`, `LICENSE-APACHE`, `docs/ARCHITECTURE.md`, `docs/README.md`, `docs/WRUN.md`
- Modify: `Cargo.toml` (`[workspace.package] license = "MIT OR Apache-2.0"`), every `crates/*/Cargo.toml` (`license.workspace = true`), `README.md`, `docs/SECURITY.md`, `docs/THIRD_PARTY.md` (the project's own licence line), `docs/superpowers/plans/2026-09-21-runtime-master-roadmap.md` (Phase 6 rows 6D and "6C-6D", B2 note on the other backend traits, Open Decision on licence/name marked settled for the licence), this plan's "As built"

- [ ] **Step 1: Licences.** `LICENSE-MIT`: the standard MIT text, `Copyright (c) 2026 Prabhuram Karki` (from `git config user.name`). `LICENSE-APACHE`: the verbatim Apache License 2.0 text, copied from a crate in `~/.cargo/registry/src` and checked identical (sha256) against a second crate's copy, no appendix edits. `cargo deny check` still passes (the workspace crates are `publish = false`; confirm deny does not now flag them, else configure `[licenses.private] ignore = true`).
- [ ] **Step 2: `docs/ARCHITECTURE.md`:** one paragraph per crate (what it owns, what it must not do, who depends on it), the crate dependency graph as a text diagram generated from `cargo tree --workspace --depth 1 -e normal` and checked by hand, the three flows (install, run, daemon job/GUI) as short step lists, the trust boundaries (hostile inputs: PE, zip, MSI, `.lnk`, `.reg`, deps archives, `.wrun`; the sandbox; the socket), and the backend seam with a link to the contract docs.
- [ ] **Step 3: `docs/README.md`:** an index of every doc under `docs/` (and the specs/plans directories) with one line each. `docs/WRUN.md`: the format for package authors (spec 3 as a reference, a worked `pack` example, what a package cannot do).
- [ ] **Step 4: `README.md`:** a top "Status" section: Phases 0-6 done, what works, what is not claimed; the v1.0 exit criteria still open (the roadmap's >= 25 matrix apps, the GUI checklist on GNOME and KDE, the gui CI job's hosted run), stated plainly, not "1.0"; the new commands in the table; a Licence section ("MIT OR Apache-2.0, at your option"). `SECURITY.md`: section "Backends and `.wrun` packages (Phase 6D)": no plugins and why (spec 5.2), the capability refusals, the package threat model (unsigned, request-only, id collisions refused, integrity, the reserved signature), known bounds (spec 7).
- [ ] **Step 5:** gates; commit `docs: licences, architecture overview, docs index, .wrun format, 6D security notes, README status`.

---

## Dependency order

Task 1 first. Task 2 needs 1. Task 3 is independent of 1-2 (may run in parallel with them). Task 4 needs 1 and 3. Task 5 needs 4. Task 6 needs 5. Task 7 last (it describes what was built).

## Self-Review

- Spec criteria: 1 -> Tasks 1, 2; 2 -> Task 1 (refusals), 2 (null backend proves them); 3 -> Tasks 1 (registry), 2 (scan, bans); 4 -> Task 3; 5 -> Tasks 4, 5; 6 -> Task 6; 7 -> Task 7.
- Pre-approved decisions: scope A (1, 2), scope B (3-6), non-goals (nothing here signs, fetches, loads or updates; signing slot reserved in 3), security (3 hostile + mutation, 4 collisions and integrity, 5 sandbox equivalence), hygiene (7).
- Placeholders: none. Two spikes can stop the plan: Task 1 Step 1 (an audit finding that the null backend exposes) and Task 3 Step 1 (the zip writer under the current features).
- Types named identically across tasks: `Capabilities`, `Unsupported`, `BACKEND_API_VERSION`, `backends::select`, `PackageMeta`, `InstallOpts.{id, subtree, digests, package, expect_arch}`, `extract_verified`, `PackageError`, `ImportParams`, `Cmd::Import`, `PermissionsView.requested`.

## As built

Branch `phase-6d-backend-and-package`, commits `decfaec` onward. Reviews:
`.superpowers/sdd/2026-09-27-phase-6d/` (Tasks 1-3: approve with fixes, 1 Important; Task 4: approve; Tasks 5-6:
approve with 1 Important). Both Important findings were fixed. No new third-party crate: `Cargo.lock` gained only
`runtime-package` and dependency edges between existing crates (`sha2` for `runtime-core`; `runtime-core` with
`testing` and `runtime-installer` as dev-dependencies of `runtime-core`).

**Task 1 (the contract, capabilities, registry).**
- `Capabilities::check(&self, backend: &'static str, arch, subsystem)`: it takes the backend id, because
  `Unsupported` names the backend. `Capabilities::check_arch` was added for the installer pipeline and `run`.
- Error variants: `InstallError::Unsupported`, `InstallerError::Unsupported`, `DepsError::Unsupported` and
  `RunAppError::Unsupported { id, source }`.
- `rt_core` re-exports `pe`, so `backend-wine` needs no new dependency.
- The audit is written into the `rt_core::backend` module docs:
  - "what the platform assumes of every backend": the `drive_c` layout, and `WINEPREFIX` for sandboxing;
  - "Wine-specific, stays concrete (B5)": doctor's Wine checks, the Wine-shaped `sandbox` fallback,
    `harden_cause`, `runtime display`, and the `wineserver` busy checks.
- The CLI selects backends through the registry, and `backend_of` uses the recorded `backend.id` for run, deps,
  display, remove and uninstall. `doctor` prints `backend wine, interface 1`.

**Task 2 (conformance).**
- `live_checks(b, scratch, launcher, program: &[u8], expect_exit)`: the live check needs a program with a known exit
  code, and for Wine that is a real PE.
- Wine's containment check moved to core as `rt_core::backend::inside_drive_c`, shared by Wine and `FakeBackend`.
- Review fix I1: every symlink on the way (in `drive_c`, an intermediate directory, the final component, or the cwd)
  is now `OutsideDriveC`; Wine returned `Failed` for these before. The checks `outside-dotdot`, `outside-absolute` and
  `outside-symlink` cover every case the spec lists and require exactly `OutsideDriveC`.
- Broken backends: 13, each failing exactly one named check. They include `FollowsFinalSymlink`,
  `SandboxableWithoutPrefix` and `InstallersWithoutSandbox`.
- Review fix M2: a new capability, **`sandboxable`**, not in the spec.
  - Meaning: the command carries `WINEPREFIX = env.prefix()`.
  - A conformance check, `command-sandboxable`, tests it.
  - `installers || dependency_packages` imply it.
  - `rt_core::run` refuses a sandboxed run without it (only `--unsandboxed` runs such a backend).
  - Wine and the fake declare it; the null backend does not.
- Review fix M1: `rt_deps::check_backend` runs in the CLI before `rt_sandbox::mark`, so a refused `deps --install`
  leaves no sandbox marker.
- Review fix M3: the installer pipeline checks the installed program's architecture, and `run` checks the recorded
  architecture. The recorded subsystem is informational and not checked at run.
- The deps refusal is proven with `FakeBackend` (`dependency_packages: false`), not with the null backend.
- M4, gating `runtime display` by a capability, is deferred to the arrival of a second backend.
- The live tier passed on real Wine.

**Task 3 (`runtime-package`).**
- `unzip::extract_verified` takes a borrowing digest closure (`&DigestOf`), and `copy_verified` serves
  `verify`/`extract_one`. `ZipError` gained `Integrity` and `Unlisted`.
- The manifest is written by a hand-written canonical emitter: the `toml` `display` feature would pull in a new
  crate.
- `pack` stores (does not deflate) a file whose deflate ratio would trip the reader's 1000:1 bomb guard; otherwise
  the writer would produce packages its own reader refuses.
- `pack` refuses anything in DIR other than `wrun.toml` and `payload/`, rather than silently leaving it out.
- Dependency ids are checked for grammar only in `rt_package`; the CLI checks that they exist in the bundled
  manifest.
- `digests()` keys are full `payload/...` paths.
- No checked-in fixtures: the tests build archives in memory.
- W9 as built: the `icon` is checked only for being listed, a `.png` name and at most 1 MiB. Its content is not
  validated as PNG, and `PackageMeta` does not record it. It is otherwise unused.
- Review fix M5: three name-encoding tests (not UTF-8, UTF-8 bytes without the flag, the Info-ZIP 0x7075 field).
- Known v1 limit (controller ruling): the 64 KiB manifest cap holds about 450 payload files. A test pins it (400
  pack, 600 fail), and larger apps ship as installer-kind packages.

**Task 4 (install integration).**
- New `InstallError` variants: `IdTaken`, `Mismatch { expected, found }`, `Package(&'static str)` and
  `WrunPackage`. New `InstallerError::IdTaken` and `MetaError::BadPackage`.
- W11 is enforced in `rt_core::install` itself, not the CLI, so `run <file>` and the API are covered too.
- `rt_deps`: a requested root is shown through `AppPlan::is_requested` and `REQUESTED_REASON`; `PlanEntry` has no
  new field. An unknown requested id is a warning and is not planned.
- `SCHEMA_VERSION = 4` applies to every app written by this version, including plain installs and `deps` state
  writes, not only imports (the existing schema policy).
- `AppDetail.package` is additive.
- Review minors left as they are:
  - the installer pipeline validates `opts.package` only after the installer ran (the CLI always builds a valid
    record);
  - `plan_digest` does not bind "requested", and the reason is kept out of the consent prompt;
  - `package.digest` is recorded, never re-verified (documented in SECURITY.md).

**Task 5 (CLI).**
- `rt_api::requests_not_granted` and the additive `PermissionsView.requested`. `deps` plan lines for requested
  roots end with "(requested by the package)", display only.
- The tests are in `crates/cli/tests/apps/package.rs`, included from `apps.rs` to reuse the fake-Wine rig.
- **Exit code:** `--silent`/`--network` on a portable package exits 1, not 2.
- W13 staging layout: `<data>/staging/import-<pid>-<nanos>/<installer file name>`. The installer's name is kept,
  because the pipeline derives its extension and provisional name from it.
- Files are opened with `O_NONBLOCK` and must fstat as regular, so a FIFO cannot block.
- Import checks the manifest arch against the default backend early. The subsystem is checked by core and the
  installer pipeline. For installer-kind packages the manifest `arch` is not compared with the installed PE; the
  metadata records the real one. Review M1: the early check is defence in depth under Wine.
- Installer-kind packages ignore the manifest `name`; the installer's own name wins, as with `install`.
- The bwrap-gated real-Wine test `e2e_import_of_an_installer_package` passes.

**Task 6 (API, daemon, GUI).**
- `apps.import` is a write method, API `0.2.1`.
- `api_at_least` compares `[major, minor, patch]`, and the GUI refuses to send a `.wrun` to an older daemon
  (`NO_IMPORT`, with the reason).
- The install dialog adds a `.wrun` filter and hides the name entry. The Silent and Network switches stay visible
  for a portable package, whose job then fails with the CLI's message. Hiding them would need a package preview
  method, a follow-up.
- The requested-permissions line is one cleaned, bounded, plain label (`perm-requested`). Review M2: the per-item
  clean was dropped as redundant.
- Review fix I1: a signal skipped the staging cleanup. `Staged::new` now sweeps every `import-<pid>-<digits>`
  directory whose `/proc/<pid>` is gone. A test covers a dead pid (removed), a live pid (kept) and a non-pid name
  (kept). Spec W13 carries the same as-built note.
- A killed import can leave a half-built app. A test pins that re-import is refused with "`runtime remove`" in the
  message, and that remove then re-import works. `runtime import --help` and `docs/API.md` say so.
- Not fixed, pre-existing, shared with `install`: a closed stdout or stderr panics with exit 101, leaving a
  consistent state.

**Task 7 (licences and docs).**
- `LICENSE-APACHE` is the apache.org text (sha256 `cfc7749b...`), identical to the copies in the `encoding_rs` and
  `env_home` crates; `LICENSE-MIT` names "Prabhuram Karki", 2026.
- `license = "MIT OR Apache-2.0"` in `[workspace.package]` and `license.workspace = true` in all 12 crates.
  `cargo deny` needed no change, because `[licenses.private] ignore = true` was already set.
- New: `docs/ARCHITECTURE.md`, `docs/README.md` and `docs/WRUN.md`. `docs/WRUN.md`'s example is a real session.
- Updated: README (a Status section that states the open v1.0 criteria, the new commands, a Licence section),
  `docs/SECURITY.md` (the 6D section), `docs/THIRD_PARTY.md` and the roadmap (the 6B/6C rows, a 6D row, the Phase 6
  exit criteria, the B2 note, and the licence decision settled).

**Commit trailers.** The session's attribution rule and this plan both name `Co-Authored-By: Claude Opus 5.5`. Most
commits carry it; `decfaec`, `cdc184f`, `60851a9`, `b5cea6c` and `244eef1` carry `Claude Sonnet 5`.

**Environment note.** This host's `/tmp` tmpfs hits `EDQUOT` during long real-Wine runs. Point `TMPDIR` at
`target/` for those runs.
