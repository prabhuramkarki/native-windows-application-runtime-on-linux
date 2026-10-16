# Phase 6F `deps --remove` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `runtime deps <app> --remove <pkg>` for archive packages (dxvk, vkd3d-proton):
- **The record.** Every archive install records exactly what it wrote: files with their sha256, created
  directories, and overrides with their previous values. This is metadata schema 5.
- **Verified removal.** Removal checks the record against the prefix:
  - unchanged files are deleted, or restored from backup when the install replaced a file;
  - unchanged overrides get their previous value back;
  - anything changed since the install is left in place and reported.
- **Refusals.** These are refused, changing nothing:
  - installer packages;
  - packages installed before schema 5;
  - a package another recorded package still needs.
- **Same guards as install.** The app lock, the busy-prefix check and the sandbox rules are the ones install uses.
- **Daemon.** `deps.remove` is a daemon write job (API 0.2.3).

**Architecture:**
- The persisted type is `rt_core::ArchiveRecord`, an optional field of `DependencyRecord`. The meta crate checks its
  shape; `rt_deps` re-validates its meaning before acting on it.
- `rt_deps::install_archive` gains three functions:
  - `record_of`, which hashes from disk after the install, under the lock;
  - a verifying `remove_archive` that takes the record;
  - `undo_install`, which is the old unverified body, renamed and used only to roll back the current run.
- `rt_deps::orchestrate::remove_packages` owns the lock, the guards, the pre-checks and the order. The CLI flag and
  the daemon job are thin layers over it.

**Tech Stack:** Rust; existing crates only (`serde`, `sha2`, `libc`, `thiserror`, `clap`). No new third-party crate.

**Spec:** `docs/superpowers/specs/2026-10-02-deps-remove-design.md` (Decisions R1-R13).

## Global Constraints

- **Branch `phase-6f-deps-remove`, nothing pushed.** There is no `git push` and no PR.
- **No new third-party crate.** `Cargo.lock` gains no package. If one turns out to be needed, stop and report.
- **Gates after every task:**
  - `cargo fmt --all -- --check`;
  - `cargo clippy --workspace --exclude runtime-gui --all-targets -- -D warnings`;
  - `cargo clippy -p runtime-gui --all-targets -- -D warnings`;
  - `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1 cargo test --workspace --exclude runtime-gui`;
  - `cargo build -p runtime-daemon -p runtime-cli && RUNTIME_REQUIRE_DISPLAY=1 xvfb-run -a cargo test -p runtime-gui`;
  - `cargo deny check`.

  `the_documented_methods_are_the_dispatch_table` and every API.md check stay green.
- **Test isolation.** Tests never touch the user's data dir, `~/.wine`, `$XDG_RUNTIME_DIR` or a running
  `runtimed`. Real-Wine tests are `#[ignore]`, with names starting `e2e_real_wine` (CI's `wine-e2e` filter), and keep
  the `RUNTIME_REQUIRE_BWRAP` gating. Use the default `TMPDIR` (6E As built: a `TMPDIR` under the repo makes socket
  paths too long).
- **Never delete what is not in the record.** Every delete or restore goes through `Ledger::resolve` (no symlink in
  any component, inside `drive_c`). No code path globs, lists or walks the prefix.
- **Error text.** Every new message is fixed text, or built from manifest ids and paths that were validated and
  then `clip`ped. Registry values read from `user.reg` are never quoted.
- **Commit trailer:** `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- **Schema (Task 1):**
  - a schema 1-4 file that no longer reads;
  - `archive` that is not `#[serde(default)]`;
  - validation that quotes content;
  - `deny_unknown_fields` missing on the new structs;
  - `SCHEMA_VERSION` bumped without the frozen-v4 test.
- **Install (Task 2):**
  - the previous value read after the fetch, or outside the lock;
  - an unrestorable value quoted, or treated as absent (that would delete it on removal);
  - hashes taken anywhere other than from the file on disk under the lock;
  - a record failure that leaves files or overrides behind;
  - `undo_install` reachable from anything except `install_one`'s failure path.
- **Remover (Task 3):**
  - a delete or restore before the hash check;
  - a hash read through a symlink (the `O_NOFOLLOW` open and the `fstat` regular-file check);
  - an override restored when its current value is not `native,builtin`;
  - `reg` argv built as one string;
  - the journal deleted after a hard failure;
  - `remaining` that is not exactly the failed entries;
  - a changed replaced file's backup deleted.
- **Command (Task 4):**
  - any change (file, registry, metadata) before every pre-check passed;
  - the lock taken after the metadata read;
  - dependents ordered wrong (dxvk before vkd3d-proton);
  - an unknown recorded package that does not refuse;
  - `helper_launcher` bypassed (a marked app's `reg.exe` run unsandboxed);
  - exit 0 with anything left.
- **Daemon (Task 5):**
  - an argv element that could read as a flag;
  - a missing `WRITE_METHODS` entry (a read-only daemon must refuse);
  - `JobKind` without the `Unknown` fallback test;
  - API.md out of sync.
- **Docs (Task 6):**
  - "removable" claimed for installer packages or old records;
  - the GUI button presented as done;
  - the e2e result recorded without the command and the Wine version.

## Dependency order

Task 1, then Task 2, then Task 3, then Task 4, then Task 5, then Task 6.
- Task 3 needs only Task 1. It may run in parallel with Task 2, but both edit `install_archive.rs`, so serial is
  simpler.
- Task 5 needs Task 4's CLI flag, because its argv must parse.
- Task 6 needs everything.

---

### Task 1: metadata schema 5 with the archive record

**Files:**
- Modify:
  - `crates/core/src/meta.rs`: `SCHEMA_VERSION = 5`; `MAX_RECORDED`; `ArchiveRecord`, `RecordedFile`,
    `RecordedOverride`; `DependencyRecord::archive`; `MetaError::BadArchiveRecord`; the `validate` shape checks;
    the `MIN_SCHEMA_VERSION` doc comment gets the v5 sentence;
  - `crates/core/src/lib.rs` (re-exports);
  - every `DependencyRecord { .. }` literal (`archive: None`). Grep `DependencyRecord {` across `crates/`:
    `orchestrate.rs`, `state/tests.rs`, `cli/tests/apps.rs`, and others.
- Test: `crates/core/src/meta.rs` tests.

**Interfaces:**
- Produces (spec 4.1):
  ```rust
  pub const SCHEMA_VERSION: u32 = 5;
  pub const MAX_RECORDED: usize = 64;
  pub struct DependencyRecord { /* ... */ #[serde(default)] pub archive: Option<ArchiveRecord> }
  pub struct ArchiveRecord { pub files: Vec<RecordedFile>, pub created_dirs: Vec<String>, pub overrides: Vec<RecordedOverride> }
  pub struct RecordedFile { pub path: String, pub sha256: String, pub replaced: bool }
  pub struct RecordedOverride { pub name: String, pub previous: Option<String> }
  #[error("dependency record `archive`: {0}")] BadArchiveRecord(&'static str),   // MetaError
  ```
- Consumes: nothing new.

- [ ] **Step 1: Failing tests.**
  - The existing `schema_version_accepts_1_to_4...` test is renamed `..._1_to_5...` and accepts 5, refuses 6.
  - A frozen v4 file with two dependency records parses with `archive: None` on both. `write_atomic` of it keeps
    `schemaVersion` 4: only `state::record` bumps it.
  - A v5 dxvk record (5 files, 5 overrides, one `previous: Some("builtin")`) round-trips through
    `write_atomic` and `read`.
  - `validate` refuses each of these, with `BadArchiveRecord` and without quoting:
    - 65 files;
    - 65 overrides;
    - a sha256 `"ABC"`;
    - two files with the same path;
    - two overrides with the same name;
    - an override named `D3D11` or `a;b`;
    - a `previous` of 33 bytes;
    - a path over `MAX_FIELD_LEN`.
  - Parsing refuses `{"archive": {"files": [], "createdDirs": [], "overrides": [], "x": 1}}` (deny_unknown_fields).
- [ ] **Step 2: Implement.** Shape checks only (spec 4.1). Semantic path checks stay in `rt_deps` (Task 3).
- [ ] **Step 3:** gates; commit `feat(core): metadata schema 5 records what an archive dependency wrote`.

---

### Task 2: archive installs record their files, hashes and previous overrides

**Files:**
- Modify:
  - `crates/deps/src/wine_config.rs`: `read_dll_overrides`;
  - `crates/deps/src/install_archive.rs`:
    - `INSTALLED_OVERRIDE`;
    - `record_of`;
    - `undo_install`, which is the current `remove_archive` body renamed and made `pub(crate)`. The old
      `remove_archive` is deleted here; Task 3 adds the new one;
    - `set_override` uses `INSTALLED_OVERRIDE`;
  - `crates/deps/src/orchestrate.rs` `install_one` and `record`: previous values before the fetch, the record after
    the install, and the undo on failure;
  - `crates/deps/src/install_archive/tests.rs`: the `remove(..)` helper calls `undo_install` for now.
- Test:
  - `crates/deps/src/wine_config.rs` tests (or its existing test module);
  - `crates/deps/src/install_archive/tests.rs`;
  - `crates/deps/src/orchestrate/tests.rs`.

**Interfaces:**
- Produces:
  ```rust
  // rt_deps::wine_config
  /// For each of `names`, the current value under HKCU\Software\Wine\DllOverrides in the prefix's user.reg
  /// (case-insensitive name match, last spelling wins), `None` when absent. Err (fixed text, never the value): an
  /// unreadable/oversized/symlinked hive, or a value that is not a string matching [a-z, ]{0,32}.
  pub fn read_dll_overrides(env: &AppEnv, names: &[String]) -> Result<Vec<(String, Option<String>)>, String>;
  // rt_deps::install_archive
  pub const INSTALLED_OVERRIDE: &str = "native,builtin";
  /// The persisted record of `done`: each file hashed from disk (no-follow resolution, regular file only), each
  /// override paired with its previous value from `previous`. Err: a file unreadable, over MAX_RECORDED entries,
  /// an override without a previous entry.
  pub fn record_of(done: &ArchiveInstalled, previous: &[(String, Option<String>)], env: &AppEnv)
      -> Result<rt_core::ArchiveRecord, ArchiveError>;
  pub(crate) fn undo_install(done: &ArchiveInstalled, pkg_id: &str, env: &AppEnv, backend: &dyn CompatBackend,
      launcher: &Launcher) -> Result<(), ArchiveError>;
  ```
- Consumes: Task 1's types.

- [ ] **Step 1: Failing tests.**
  - `read_dll_overrides` cases (parsed from bytes through a small `overrides_in(&WineReg, names)` that it wraps,
    as `driver_in` is):
    - absent key gives `None`;
    - `"d3d11"="builtin"` gives `Some("builtin")`;
    - `"D3D11"="n,b"` matches `d3d11`;
    - `""` gives `Some("")`;
    - a dword is `Err`;
    - `"a;b"` is `Err`;
    - 33 bytes is `Err`;
    - the error text contains the name but not the value.
  - `record_of` in the fake-backend rig:
    - after `install_archive` of a two-file zip whose second destination pre-exists (a placeholder), the record
      has two files whose sha256 equals `sha256(bytes)`, `replaced` false/true, `created_dirs` as written, and
      overrides paired with `previous`;
    - a recorded file swapped for a symlink before `record_of` gives `Err`.
  - Orchestrator (fake fetcher):
    - an archive install writes `archive: Some(..)` matching the files;
    - `user.reg` with `"<dll>"=dword:1` refuses the package and the fetcher's call log is empty;
    - a metadata write forced to fail (make `metadata.json` a directory after the plan; or a test hook) gives
      `failed` with "removed again", and no package file and no override `reg add` remains unreverted (the fake
      `reg` log shows the delete);
    - an installer package's record still has `archive: None`.
- [ ] **Step 2: Implement.** `install_one` order (spec 4.2):
  1. `not_busy_now`;
  2. `read_dll_overrides` (archive packages only);
  3. fetch;
  4. `not_busy_now`;
  5. `install_archive`;
  6. `record_of`;
  7. `record` (with the archive record).

  If step 6 or step 7 fails: `undo_install`, and the reason as in spec 4.2.
- [ ] **Step 3:** gates; commit `feat(deps): archive installs record their files, hashes and previous overrides; an unrecordable install is undone`.

---

### Task 3: the verifying `remove_archive`

**Files:**
- Modify:
  - `crates/deps/src/install_archive.rs`:
    - `RemoveOutcome` and the new `remove_archive`;
    - a record-to-`Ledger` adapter that runs the `win_path` and `check_overrides` checks, plus the R5 charset on
      `previous`;
    - the module docs: the "Recording" paragraph and the journal sentences about `remove_archive`;
  - `crates/deps/src/lib.rs` (re-exports).
- Test: `crates/deps/src/install_archive/tests.rs`. Port the existing `remove_archive` tests to records. Tests of
  the rollback semantics stay on `undo_install`.

**Interfaces:**
- Produces (spec 4.3):
  ```rust
  pub struct RemoveOutcome { pub done: Vec<String>, pub left: Vec<(String, String)>,
                             pub failed: Vec<(String, String)>, pub remaining: rt_core::ArchiveRecord }
  pub fn remove_archive(rec: &rt_core::ArchiveRecord, pkg_id: &str, env: &AppEnv, backend: &dyn CompatBackend,
                        launcher: &Launcher) -> Result<RemoveOutcome, ArchiveError>;
  ```
  `Err` only for an invalid id or record: nothing has been touched then.
- Consumes: Task 1 types; Task 2's `read_dll_overrides`, `INSTALLED_OVERRIDE`, `record_of` (tests build records
  with it).

- [ ] **Step 1: Failing tests** (spec 6, "Remover"). Each test installs with `install_archive` and builds the record
  with `record_of`. It then mutates the prefix as the case needs, runs `remove_archive`, and asserts the following:
  - the file system: the bytes of every path, the backups present or absent;
  - the fake `reg` argv log: exactly `add ... /v <n> /d <prev> /f` or `delete ... /v <n> /f`, one argv element
    each;
  - the journal: present or absent;
  - `done`, `left`, `failed` and `remaining`.

  The cases:
  - clean;
  - a tampered new file;
  - a tampered replaced file (its backup is kept, and the message names `deps-backup/<id>/c/...`);
  - an override changed to `disabled` (no `reg` call for it);
  - an override already deleted;
  - a symlink in place of a file (the link and its target are untouched);
  - a symlinked parent directory;
  - a new file already gone;
  - a replaced file already gone (its original is restored);
  - a `reg` failure (a fake launcher that fails `add` for one name): `remaining` is exactly that override, and the
    journal is kept. Then `remove_archive(&remaining)` finishes the job and deletes the journal;
  - records with `../x`, `/etc/x`, `windows/con`, an override `A`, and `previous` `"a;b"`: each is `Err`, and the
    prefix and `user.reg` bytes are unchanged.
- [ ] **Step 2: Implement** (spec 4.3 order: validate, overrides newest first, files in reverse, directories
  children first, then the journal). Hashing: `open_nofollow` on the `resolve`d path, then `fstat` that it is a
  regular file, then stream it through `Sha256` with `io::copy`. `rt_deps::fetch::hex` formats the digest.
- [ ] **Step 3:** gates; commit `feat(deps): remove_archive verifies each file's hash and each override before restoring`.

---

### Task 4: `remove_packages` and `runtime deps --remove`

**Files:**
- Modify:
  - `crates/deps/src/orchestrate.rs`: `RemoveReport`, `remove_packages`, `DepsError::CannotRemove`; the module
    docs gain a "Removal" list;
  - `crates/deps/src/manifest.rs`: `valid_id` becomes `pub`;
  - `crates/deps/src/lib.rs`;
  - `crates/cli/src/deps.rs`:
    - `--remove` (`Vec<String>`, `value_name = "PKG"`, `conflicts_with_all = ["install", "discard_interrupted"]`);
    - duplicates are a usage error;
    - `run_app` gets the remove branch (spec 4.4);
    - `format_remove_report`;
    - the module doc line;
  - `crates/cli/src/deps/tests.rs`;
  - `crates/cli/tests/apps.rs`;
  - `crates/deps/src/orchestrate/tests.rs`;
  - `crates/deps/src/orchestrate/tests/e2e.rs`.

**Interfaces:**
- Produces (spec 4.4):
  ```rust
  pub struct RemoveReport { pub removed: Vec<String>, pub left: Vec<(String, String)>,
                            pub failed: Vec<(String, String)>, pub skipped: Vec<(String, String)> }
  pub fn remove_packages(store: &Store, env: &AppEnv, backend: &dyn CompatBackend, launcher: &Launcher,
                         manifest: &Manifest, ids: &[String]) -> Result<RemoveReport, DepsError>;
  #[error("{0}")] CannotRemove(String),   // DepsError
  ```
  `left` entries are `(pkg, "<item>: <why>")`.
- Consumes: Task 3's `remove_archive`; `lock_app`, `check_not_busy`, `not_busy_now` (shared with install),
  `state::forget`.

- [ ] **Step 1: Failing tests.**
  - Orchestrator, with the fake backend and a manifest with `a` and `b` requiring `a`:
    - each R3, R4 and R8 refusal returns `CannotRemove` with the spec's text, and the metadata bytes and prefix
      files are unchanged;
    - `[a, b]` and `[b, a]` both remove `b` first (recorded by the fake `reg` log order);
    - `AppRunning` (a shared lock held), `LockHeld` (exclusive), and `PrefixBusy` (the fake wineserver helper of
      the install tests);
    - a `reg` failure in `b` gives `failed b`, `skipped a`, `b`'s record shrunk to `remaining`, and `a`'s record
      unchanged;
    - a clean run calls `forget` for both, keeps schema 5, and other records stay untouched.
  - CLI unit: `--remove` with `--install`, and `--remove x --remove x`, are exit 2; the formatter output for each
    report part.
  - CLI rig:
    - Plant an app (`install_d3d11`).
    - Write a dxvk record with `archive: Some` and its five DLL files in `drive_c`.
    - Install the fake `reg.exe` hook (the `display_app` style, extended to log only).
    - Then check:
      - `deps <id> --remove dxvk` is exit 0, with `removed dxvk`;
      - the files are gone;
      - the reg log has five `delete`s;
      - the record is gone;
      - **`doctor <id>`'s route line is the `[warn]` built-in one** (`route_lines` as in
        `doctor_predicts_the_built_in_route_when_dxvk_is_not_installed`).
    - Variants:
      - one DLL tampered: exit 1, and `left dxvk: windows/system32/d3d11.dll: changed since it was installed`;
      - a marked app under `no_bwrap`: refused with "must run sandboxed too", with an empty reg log;
      - a vcrun2022 record: exit 1 with the installer text;
      - a dxvk record without `archive`: exit 1 with the "recreate the environment" text.
  - Real Wine: `e2e_real_wine_remove_restores_overrides_and_leaves_a_tampered_file` (spec 6), using `WineRig`.
    Run it here:

    `RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-deps --lib -- --ignored e2e_real_wine_remove --test-threads=1 --nocapture`

    Record the command, the Wine version and the result in As built. If `reg add /d ""` does not restore an empty
    value on Wine 10.0, stop and report: the R5 charset then needs `""` dropped (a spec amendment), not a
    workaround.
- [ ] **Step 2: Implement.**
  1. `check_backend`.
  2. `lock_app`.
  3. `check_not_busy`.
  4. Read the metadata.
  5. The pre-checks (R3, R4, R8).
  6. The order: dependents first, as a reverse topological order over the manifest's `requires` within the set.
  7. For each package: `not_busy_now`, then `remove_archive`, then the metadata is updated (`forget` when
     `remaining` is empty, else the record is replaced by the shrunk one). The run stops at the first `failed`.
- [ ] **Step 3:** gates; commit `feat(deps,cli): runtime deps --remove for recorded archive packages`.

---

### Task 5: `deps.remove` daemon job (API 0.2.3)

**Files:**
- Modify:
  - `crates/api/src/jobs.rs`: `DepsRemoveParams`, `JobSpec::DepsRemove`, `from_request`, `argv`, `kind`,
    `JobKind::DepsRemove`;
  - `crates/api/src/lib.rs`: `API_VERSION = "0.2.3"`;
  - `crates/daemon/src/dispatch.rs`: `WRITE_METHODS`, `METHODS`, the doc table;
  - `crates/daemon/src/client.rs`: `deps_remove`;
  - `crates/cli/src/main.rs`: the JobSpec mapping test gets a `DepsRemove` arm and samples, and the variant
    count becomes 9;
  - `crates/gui/src/ui/jobs.rs`: the kind label `"dependency removal"`. The GUI's match has a wildcard; add the
    label only if the match is exhaustive over known kinds;
  - `crates/daemon/tests/e2e_jobs.rs`;
  - `docs/API.md`.

**Interfaces:**
- Produces:
  ```rust
  JobSpec::DepsRemove { app: AppId, packages: Vec<String> }   // argv: deps --remove=<p>... -- <id>
  JobKind::DepsRemove                                          // "depsRemove"
  pub fn deps_remove(&mut self, id: &str, packages: &[String]) -> Result<JobStarted, ClientError>;  // Client
  ```
- Consumes: Task 4's CLI flag; `rt_deps::manifest::valid_id`.

- [ ] **Step 1: Failing tests.**
  - `from_request("deps.remove", ..)` refusals:
    - `{}`, `{"id":"a"}` and `{"id":"a","packages":[],"x":1}` are `Shape`;
    - `packages: []`, 17 ids, a duplicate, `"-x"`, `"A"` and `"a b"` are `invalid_argument`;
    - a bad app id from `BAD_IDS` is `invalid_argument`.
  - `argv` is exactly `["deps","--remove=a","--remove=b","--","game"]`, and the `main.rs` mapping test parses it
    back to `Cmd::Deps` with `remove == ["a","b"]`, `install == false`, `app == "game"`.
  - `JobKind` round-trips `"depsRemove"`.
  - Dispatch:
    - read-only `deps.remove` is `read_only`, without reading the params;
    - `METHODS` equals the API.md table (the existing test).
  - e2e part A (the fake sibling `runtime`): `deps_remove("a", ["dxvk"])` starts a job, and the fake's argv log
    shows the argv above.
  - Client: an in-process server test for `deps_remove`.
- [ ] **Step 2: Implement.** Constant cap `MAX_REMOVE = 16`. Messages are fixed text.
- [ ] **Step 3:** gates; commit `feat(api,daemon): deps.remove write job (API 0.2.3)`.

---

### Task 6: docs, roadmap and As built

**Files:**
- Modify:
  - `docs/SECURITY.md`, "Dependency downloads (Phase 4A)": a "Removal (Phase 6F)" subsection that covers:
    - the record and what it trusts: re-validated, and hashes from disk under the lock;
    - left-and-reported;
    - never deleting outside the record;
    - the refusals;
    - the new install refusal (R5);
    - the noisy-retry bound;
    - the check-then-act bound (the same as 4A).
  - `README.md`: the `deps` command row and an example line; the "no removal of a single package" sentence
    becomes "archive packages only".
  - `docs/superpowers/specs/2026-09-25-graphics-backends-design.md`: the "Opt-out is deferred" cell gets "(done in
    6F: `deps --remove`)".
  - The roadmap:
    - a 6F row;
    - the `deps --remove` follow-up is closed;
    - new follow-ups: a GUI Remove button (R10), removing installer packages (R3), repairing pre-schema-5 records
      (R4);
    - the API version becomes 0.2.3 in the Phase 6 criteria text.
  - This plan's As built: commits, gates, the Task 4 real-Wine run, deviations.
- [ ] **Step 1:** write the docs.
- [ ] **Step 2:** check every claim against the code: `rg` for each named function and constant.
- [ ] **Step 3:** gates; commit `docs: 6F deps --remove (SECURITY, README, roadmap, As built)`.

---

## Self-review

- Spec coverage:
  - criterion 1: Tasks 1-2;
  - criterion 2: Task 3, plus Task 4 for the command;
  - criterion 3: Task 4's pre-checks;
  - criterion 4: Task 4 (`lock_app`, the busy check, `helper_launcher`);
  - criterion 5: Task 5;
  - criterion 6: Task 4's CLI rig doctor assertion;
  - criterion 7: Tasks 1-5 unit tests, Task 4 rig and real-Wine e2e.
- Decisions:
  - R1 is Task 1;
  - R2 and R5 are Task 2;
  - R6, R7 and R11 are Task 3;
  - R3, R4, R8, R9 and R12 are Tasks 2 and 4;
  - R13 is Task 5;
  - R10 is Task 6 (roadmap).
- No placeholders. Every type named in a later task is produced by an earlier one.

## As built

Branch `phase-6f-deps-remove`, nothing pushed. Gates passed after every commit, with the default `TMPDIR`:
- fmt and both clippy runs;
- the workspace tests with `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1`;
- `cargo deny`;
- the GUI tests under `xvfb-run` at least once per task. The last run was on `3b8a093`.

| Task | Commit(s) |
|---|---|
| 1 Schema 5 | `655a996` |
| 2 Install record | `78b6063`, ruling fix `75d57d7` (R14) |
| 3 Verifying remover | `4e9fb70`, ruling fix `75d57d7` (R15) |
| 4 `remove_packages`, `deps --remove` | `f90933b`, review fixes `caab4b7` (R16-R19) |
| 5 `deps.remove` job (API 0.2.3) | `3b8a093` |
| 6 Docs | this commit |

**Task 1.** As planned. Deviation: `archive` is `skip_serializing_if = "Option::is_none"`, so rewriting a schema 4
file keeps it byte for byte (`FROZEN_V4`, produced by running the code at `088595a`).

**Task 2.** Deviations:
- Hashing reads in a loop. The plan said `io::copy` into `Sha256`, but the workspace builds `sha2` without `std`.
- A missing `user.reg` reads as "no previous values", as the graphics-driver read does.
- Controller ruling R14: `undo_install` puts each previous override value back, and deletes only the overrides that
  had none.
- Review M5 (R19): `install_archive_with_previous` makes `install_archive`'s own rollback restore previous values
  too.

**Task 3.** Deviations:
- The old empty-record journal guard stays on `undo_install` only. On `remove_archive` it would block a legitimate
  retry of a record that holds only overrides; a recorded package is never installed again, so its journal is that
  install's own.
- Controller ruling R15: a replaced file that is gone together with its backup is left, not failed.
- Review fixes:
  - I1 (R16): an unchanged replaced file whose backup is missing is left as installed and dropped from the record;
  - M2 (R19): a file over `MAX_EXPANDED` is "changed" and not read;
  - M4: the "kept at deps-backup/..." text appears only while the backup exists.

**Task 4.** As planned. Deviations and decisions:
- `--remove` also conflicts with `--yes` and `--plan-digest`. clap let `--remove x --yes y` through, because `--yes`
  is declared `requires = "install"`, which did not reject it here.
- A duplicate `--remove` is printed as an `error:` line with exit 2 after parsing (clap cannot see across values).
- Ruling 3 and review M3 (R18): any `failed` entry fails the package. If only the journal deletion failed, the whole
  record is kept (fail closed).
- Review I2 (R17): `check_archive_record` runs for every package in `removal_order`.
- Review M1: the per-package busy re-check now has a test, which kills the reviewer's mutation.
- **Real Wine.** `RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-deps --lib -- --ignored e2e_real_wine_remove
  --test-threads=1 --nocapture` passed on `wine-10.0 (Ubuntu 10.0~repack-12ubuntu1)` in 13.3 s.
  - The install recorded previous values `Some("builtin")`, `None` and `Some("")`.
  - After the removal, `user.reg` showed `"rta"="builtin"` and `"rtc"=""` again and no `rtb`. So
    `reg add /d ""` restores an empty value on Wine 10.0, and the R5 charset keeps `""`.
  - The tampered `rtb.dll` stayed and was reported `left`; the record and `deps-backup` were gone.
  - All 10 `e2e_real_wine` tests of runtime-deps pass with the extended `WineRig` (about 155 s).

**Task 5.** As planned. `MAX_REMOVE = 16`. A `deps.remove` package that is not in the manifest id grammar, a
duplicate, and 0 or 17 packages are `invalid_argument`. The GUI's job-kind match has a wildcard, so no label was
added (a `depsRemove` job shows as "job").

**Task 6.** The docs updated:
- `docs/SECURITY.md`: a "Removal (Phase 6F)" subsection, the helper table row, and the override sentence;
- `README.md`: the `deps --remove` row and example, and the known-gaps sentence;
- `docs/API.md`: done in Task 5;
- the 4B spec's opt-out cell;
- the roadmap: a 6F row, 6E marked merged, the follow-up closed with its three new follow-ups, and API 0.2.3.


### GUI follow-up — 2026-10-16 (working tree)

R10's deferred GUI action is now implemented. The app page lists installed packages from `apps.get` separately
from its install plan, confirms the app/package pair, and sends `deps.remove` through the existing client.
API < 0.2.3, read-only/disconnected daemons and busy apps cannot send removal. A stale confirmation cannot target
another app. The existing job follower displays output and refreshes the page; the old install plan is discarded.
The job-kind label now says "dependency removal". Backend removal rules and the wire format are unchanged.

The GUI removes one package per action. A dependent-package refusal remains visible in the job log, including
the CLI command for removing a required group together. Installer packages and pre-schema-5 records remain
unsupported. Validation is recorded in `docs/VALIDATION.md`; manual GNOME/KDE verification remains open.
