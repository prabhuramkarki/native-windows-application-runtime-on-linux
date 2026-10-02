# Phase 6F: `runtime deps <app> --remove <package>` (design)

Status: approved by the controller on the user's standing instruction. The user pre-approved the direction on
2026-10-02 (seven points: an exact install record, refusing installer packages unless that is safe, dependents,
the run guards, a daemon job, the doctor route, tests). Every other choice was delegated to this spec and is
recorded below as "Decision:" with its reasoning. Phase 6F comes after 6A-6E are merged on `main` (`dd7c8f5`).

Removal has been deferred since 4B. The 4B plan says: "`remove_archive` exists but the CLI never calls it and the
`ArchiveInstalled` record is not persisted in `Metadata` (only `DependencyRecord` is), so removal needs a schema
change and its own design". The roadmap repeats it under "Known follow-ups". Until now, a user who wants wined3d
back has to delete and recreate the environment.

## 1. Purpose and success criteria

1. **Exact record at install time.** When an archive package is installed, the app's metadata records exactly what
   the install wrote:
   - each file, as a path relative to `drive_c`, with the sha256 of its bytes and whether it replaced a file;
   - each directory the install created;
   - each DLL override it set, with the value that override had before.

   This is `metadata.json` schema 5. A schema 1-4 file still reads: its records simply have no install record.
2. **`runtime deps <app> --remove <pkg> [--remove <pkg>]...`** removes recorded archive packages:
   - A file whose current sha256 equals the recorded one is deleted (if the install created it) or replaced by its
     backup (if the install replaced a file).
   - A file that changed since the install is left in place and reported.
   - An override still set to the value the install wrote gets its previous value back, or is deleted when it had
     none. It is set through the same `reg.exe` path the install used.
   - An override that was changed since the install is left and reported.
   - Then the package's record is deleted.
   - Nothing that is not in the record is ever deleted or changed. Every recorded path is validated to stay inside
     `drive_c`, and a path that goes through a symlink is never followed and never deleted.
3. **Never guesses.** The command refuses, changing nothing, in these cases:
   - a package recorded without an install record (an app whose package was installed before this phase);
   - an installer package (`vcrun2022`, `wine-mono`);
   - a package that is not recorded at all;
   - a package that another recorded package needs, unless that one is removed in the same command.
4. **Same guards as install.** These are the same as for `deps --install`:
   - the exclusive app lock (`AppRunning`, `LockHeld`);
   - the busy-prefix check (`PrefixBusy`);
   - the backend's `dependency_packages` capability;
   - the helper launcher. A marked (sandboxed) app runs `reg.exe` in the app sandbox, and the command refuses
     without a working bwrap.
5. **Daemon.** `deps.remove` is a 6B-style write job. Its argv is validated, a read-only daemon refuses it, and
   it is API 0.2.3 (additive).
6. **Doctor follows.** After DXVK is removed, `doctor` predicts the built-in (wined3d) route for Direct3D 11
   again. It reads the records and nothing else, so this needs no doctor change, only a test.
7. **Tests.** Unit tests, the CLI rig with a fake Wine, and one `#[ignore]` real-Wine e2e. The e2e installs a
   fixture archive, removes it, checks that the overrides are restored and the files are gone, and checks that a
   tampered file is left in place and reported.

Non-goals:
- removing installer packages (Decision R3);
- a GUI Remove button (Decision R10: a follow-up);
- upgrades or a reinstall over an existing record;
- repairing records written before this phase;
- 32-bit DXVK.

Nothing is pushed.

## 2. The code as it is at `dd7c8f5`

| Where | What it does now |
|---|---|
| `crates/deps/src/install_archive.rs` `install_archive` | Returns `ArchiveInstalled { files, replaced, created_dirs, overrides }`, which has no hashes and no previous override values. Sets each override to `native,builtin` with `reg add ... /f`, so a previous value is overwritten and lost. Keeps a journal (`deps-backup/<id>/journal`, `F`/`D`/`R` lines) and the backups of replaced files (`deps-backup/<id>/c/...`) after a successful install. |
| `install_archive.rs` `remove_archive` | Deletes the overrides, deletes the recorded new files, restores the replaced ones from backup, removes empty created directories, and deletes the journal. It checks nothing about file contents, deletes an override even when it had a value before the install, and is called only by tests. |
| `crates/deps/src/orchestrate.rs` `install_one` | `install_archive(..).map(\|_\| Vec::new())`: the `ArchiveInstalled` is thrown away. `record` writes a `DependencyRecord { id, version, sha256, installed_at, consent }`. When that write fails, the report says "installed but not recorded" and the files stay. |
| `crates/core/src/meta.rs` | `SCHEMA_VERSION = 4`, `MIN_SCHEMA_VERSION = 1`. Each version only added a `#[serde(default)]` field, so there is no migration code. `MAX_FILE_BYTES` is 64 KiB. |
| `crates/deps/src/state.rs` | `record`, which bumps `schema_version`, and `forget`, which no caller uses yet. |
| `crates/cli/src/deps.rs` `run_app` | For `--install`: the backend is selected, then `check_backend`, then the sandbox mark (only when an installer package may run), then `sandbox::helper_launcher`, and then `install_plan`. `install_plan` takes `lock_app` and checks that the prefix is not busy. |
| `crates/api/src/jobs.rs`, `crates/daemon/src/dispatch.rs` | `deps.install` is a `JobSpec::DepsInstall`. Its argv is `deps --install --plan-digest=<hex> [--yes=<pkg>]... -- <id>`, and it is in `WRITE_METHODS`. API `0.2.2`. |
| `crates/api/src/host/doctor.rs` `d3d_routes` | Predicts DXVK or vkd3d-proton from the recorded packages and the plan, never from the files in the prefix. |
| `crates/gui/src/ui/app.rs` | The Dependencies group lists *plan* entries. There is no list of installed packages to hang a button on. |

## 3. Decisions

| Decision | Choice | Why |
|---|---|---|
| Record | An exact per-file, per-override record, persisted at install time in schema 5 | Pre-approved. |
| Old records | `--remove` refuses | Pre-approved: never guess. |
| Dependents | Refused unless removed in the same command, which orders them | Pre-approved. |
| Guards | The same lock, busy check and sandbox rules as install | Pre-approved. |
| Daemon | `deps.remove` write job, API 0.2.3 | Pre-approved. |

### Decisions made while writing this spec (unspecified by the brief; safest simple option)

- **Decision R1: the record lives in `rt_core`, as an optional field of `DependencyRecord`.**
  - `DependencyRecord` gains `#[serde(default)] archive: Option<ArchiveRecord>`. `None` means one of two things:
    an installer package, or an archive package installed before schema 5.
  - `rt_deps` depends on `rt_core`, not the other way round, so the persisted type is defined in `meta.rs`.
    `ArchiveInstalled` stays `install_archive`'s in-memory result and is not persisted. The two have different
    jobs: one is what one call did (with journal adoption), the other is what is on disk and verifiable.
  - The "migration" is the existing pattern: a schema 1-4 file reads `archive: None`, which IS its correct v5
    reading. A frozen v4 test guards it. `state::record` writes 5, so an older runtime refuses the file from then
    on (schema policy).
  - Paths are stored as `/`-separated strings relative to `drive_c`, which is the spelling `ArchiveInstalled`
    already uses.
- **Decision R2: hash from disk right after the install, not while writing.**
  - The orchestrator calls `install_archive::record_of(&done, &previous, env)`. It opens each recorded file through
    the same no-follow resolution, and hashes it.
  - This runs under the exclusive app lock with no `wineserver` for the prefix, so nothing else can have written
    the files since the install.
  - It also covers files adopted from a killed earlier attempt, which this call did not write.
  - It changes nothing in the `Ledger`, the journal or the extraction code, which are 4A's most reviewed paths.
- **Decision R3: installer packages are refused in v1.** The message is fixed text: "`<pkg>` is an installer
  package: the runtime cannot remove it (that would run the vendor's uninstaller); recreate the environment to drop
  it". Exit 1. Why no uninstall:
  - The existing uninstall machinery (`runtime uninstall`) runs an app's own recorded uninstall command. It does
    not apply to a dependency. Using it here would trust a vendor uninstaller (MSI `msiexec /x`, the Burn bundle's
    `/uninstall`), which is new trust: new vendor code would run with a read-write prefix.
  - Wine Mono's removal would also have to re-disable `mscoree`.
  - What a vendor uninstaller leaves behind cannot be verified against a record, because the runtime never
    recorded what the installer wrote.
  - This is a separate design.
- **Decision R4: an old record is refused, and the message suggests recreating the environment, not
  reinstalling.** The brief suggested "reinstall the package first". That is not safe here:
  - Upgrades and reinstalls of a recorded package are refused (Ruling 13).
  - Even with that lifted, an install over the old one would treat the DXVK DLLs already in `system32` as
    originals. It would back them up, so a later `--remove` would put DXVK back.
  - The old install's journal lists `F`/`R` entries, but it has no hashes and no previous override values. Using
    it would be a guess.

  So the message is: "`<pkg>` was installed by an older runtime that did not record what it wrote, so it cannot be
  removed safely; recreate the environment (`runtime remove <app>`, then install the app again) to drop it". The
  roadmap keeps "repair old records" as an open follow-up.
- **Decision R5: previous override values are read from `user.reg` before the download, and an unrestorable one
  refuses the install.**
  - `wine_config::read_dll_overrides(env, names)` uses the bounded, no-follow hive reader (`read_hive`) and
    `WineReg::parse`. It matches value names case-insensitively, as `driver_in` does, and the last spelling wins.
  - It runs in `install_one` after the busy check and before the fetch. The exclusive lock and the absence of a
    `wineserver` mean that `user.reg` on disk is current and cannot change until the install has set the
    overrides.
  - A previous value is restorable when it is a string matching `[a-z, ]{0,32}`. That covers `native,builtin`,
    `n,b`, `builtin`, and `""` (disabled).
  - Anything else (a dword, other characters, an unreadable hive) refuses the package before it is downloaded, with
    "the existing DLL override `<name>` has a value the runtime cannot restore; reset it (winecfg, Libraries) and
    install again". The value itself is never quoted.
  - This is a new refusal on install. It is the only way to keep criterion 2 ("restore the previous value")
    without guessing, and in a real prefix it needs a hand-edited registry.
- **Decision R6: anything left behind is still reported, and the record is then deleted.**
  - A file whose hash differs, a path that is gone through a symlink or is not a regular file, and an override
    whose current value is not `native,builtin` are all left in place.
  - The report lists each one as `left: <path or override>: <why>`.
  - The backup of a replaced file that was left stays where it is, and the report names it. A later install of the
    package reuses it as the original (4A's "a backup that already exists is kept"), which it is.
  - Such items are no longer the runtime's: they leave the record. Keeping them would make every later `--remove`
    refuse forever, for something only the user can decide.
  - The run exits 1 when anything was left, so a script or a daemon job sees that the removal was not clean.
  - A recorded file that is already gone counts as removed. For a replaced file that is gone, the original is
    restored.
- **Decision R7: hard failures shrink the record instead of deleting it.**
  - A hard failure is an I/O error, or `reg.exe` failing or timing out.
  - `remove_archive` returns `RemoveOutcome { done, left, failed, remaining }`, where `remaining` holds the entries
    whose step failed.
  - When `remaining` is empty, the orchestrator deletes the record. Otherwise it writes the record shrunk to
    `remaining` (one metadata write per package), reports the package as failed, and stops the run.
  - A retry then works only on what failed.
  - The journal is deleted only when the package's removal had no hard failure.
- **Decision R8: dependents are checked against the bundled manifest's `requires`.**
  - The command refuses, changing nothing, when a recorded package outside the removal set requires one inside
    it: "`<a>` needs `<b>`; remove both: `runtime deps <app> --remove <a> --remove <b>`".
  - A recorded package that the bundled manifest does not know, and that is outside the removal set, also
    refuses, because its needs are unknown: "cannot tell whether `<x>` needs `<b>`".
  - Inside the set, dependents go first, in the reverse of the manifest's dependency order (vkd3d-proton before
    dxvk).
  - Duplicates in `--remove` are refused by the CLI, which is clap-level data validation (exit 2).
- **Decision R9: every refusal is decided before anything changes, under the lock.**
  - Order: `check_backend`, then `lock_app`, then `check_not_busy`, then the metadata is read, then every
    pre-check (recorded, kind, `archive: Some`, record valid, dependents), then the removal in order.
  - Before each package, the busy check runs again (as `not_busy_now` does for install).
  - No plan digest: a removal names its packages exactly and asks no consent, so there is no plan shown to the
    user that could go stale.
- **Decision R10: no GUI button in 6F.**
  - The app page lists plan entries, not installed packages. A Remove button would need its own list of installed
    rows with a removable flag, a confirm dialog, a `Msg`/`Cmd`, vm tests and an xvfb UI test. That is a task of
    its own, not "cheap".
  - 6F ships the typed client method (`Client::deps_remove`), so the follow-up is UI-only. It is recorded in the
    roadmap.
- **Decision R11: one remover for persisted records.** `remove_archive` is rewritten to take the persisted
  `ArchiveRecord` and to verify before acting. There is no second, unverified remover of records. Its existing
  tests are ported.

  Undoing what the *current* call just wrote is a different job: the same locked run, with no gap in which anyone
  else could write. Today's `remove_archive` body (the `Ledger` undo without verification, the same undo that
  `install_archive` runs on its own errors) is kept for that one case under the name `undo_install`. Only
  `install_one` calls it, and only before the lock is released.
- **Decision R12: if an install cannot be recorded, it is undone.** `record_of` or the metadata write can fail:
  for example `MetaError::TooLarge`, more than `MAX_RECORDED` (64) files, or a hash read error. Before 6F the files
  stayed unrecorded. Now `install_one` calls `undo_install(&done, &previous, ..)` (R11, R14) and then reports the failure. An
  archive package therefore never stays in a prefix without a record. The bundled packages record 2 to 5 files,
  about 1 KiB each.
- **Decision R13: `deps.remove` params are `{"id": str, "packages": [str]}`.**
  - `packages` has 1 to 16 unique ids in the manifest id grammar, checked with `rt_deps::manifest::valid_id`
    (made `pub`). A bad value is `invalid_argument`, and a bad shape is -32602.
  - argv: `deps --remove=<pkg>... -- <id>`.
  - `JobKind::DepsRemove` (`"depsRemove"`). An older client reads it as `Unknown` (the fallback exists since
    0.2.0).
  - The daemon does not pre-check that the packages are recorded. The CLI decides that under the lock, and the
    job's events carry the refusal.

- **Decision R14 (controller ruling during Task 2-3 review): `undo_install` restores previous override values.**
  - R12's undo deleted every override the failed install set, so a pre-existing value (say `"d3d11"="builtin"`)
    was lost when the record could not be written.
  - `undo_install(&done, &previous, ..)` now takes the values read before the download (R5). An override that had
    a value gets it back with `reg add ... /d <previous> /f`; only one that had none is deleted.
  - `install_archive`'s own rollback on its errors is unchanged (it deletes, as since 4A): it runs inside the call
    and has no previous values. Only the record-failure path of R12 restores.
- **Decision R15 (controller ruling): a replaced file that is gone together with its backup is left, not failed.**
  - R6 restores the original of a replaced file that is gone. When the backup is gone too, there is nothing to
    restore: it is reported `left: <path>: missing, nothing to restore` (so the run exits 1 once) and is not in
    `remaining`, so the record can be deleted and a retry never loops on it. Empty backup directories are pruned.

## 4. Behaviour

### 4.1 Schema 5 (`rt_core::meta`)

```rust
pub const SCHEMA_VERSION: u32 = 5;
/// Most files, created directories or overrides one archive record may hold.
pub const MAX_RECORDED: usize = 64;

pub struct DependencyRecord { /* id, version, sha256, installed_at, consent */
    /// What the install wrote (schema 5; archive packages only). `None`: an installer package, or an archive package
    /// installed before schema 5 (not removable).
    #[serde(default)]
    pub archive: Option<ArchiveRecord>,
}
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ArchiveRecord { pub files: Vec<RecordedFile>, pub created_dirs: Vec<String>, pub overrides: Vec<RecordedOverride> }
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedFile { pub path: String, pub sha256: String, pub replaced: bool }
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecordedOverride { pub name: String, pub previous: Option<String> }
```

`validate` checks the shape only:
- each list has at most `MAX_RECORDED` entries;
- every string is at most `MAX_FIELD_LEN`;
- `sha256` is hex (the existing `sha256_hex`);
- paths are unique within the record;
- override names are unique and match `[a-z0-9_]{1,32}`;
- `previous` is at most 32 bytes.

A failure is the new `MetaError::BadArchiveRecord(&'static str)`, which never quotes content. `rt_deps`
re-validates the meaning before it acts: paths through `win_path` (the Windows name rules, inside `drive_c`), names
through `check_overrides`, and `previous` against the charset of R5.

### 4.2 Install (`rt_deps`)

`install_one` for an archive package. Steps 1, 2 and 5 are unchanged:
1. Defence-in-depth checks, then `not_busy_now`.
2. **New:** `previous = read_dll_overrides(env, overrides)`. An unrestorable value is an error, which is the report
   reason, and nothing is downloaded.
3. Fetch, then `not_busy_now`, then `install_archive` (unchanged).
4. **New:** `rec = record_of(&done, &previous, env)`, then the record is written with `archive: Some(rec)`. If
   either fails, `undo_install(&done, &previous, ..)` takes the install away again (R12), putting previous override
   values back (R14). The reason says "not installed: it
   could not be recorded (<e>); what it wrote was removed again", or the undo's own failure is appended, as
   `rollback_error` does.
5. Report.

### 4.3 Removal of one package (`install_archive::remove_archive`)

```rust
pub const INSTALLED_OVERRIDE: &str = "native,builtin";
pub struct RemoveOutcome {
    pub done: Vec<String>,                     // "removed <path>", "restored <path>", "override <name> restored"/"deleted"
    pub left: Vec<(String, String)>,           // (item, why), R6
    pub failed: Vec<(String, String)>,         // (item, error), R7
    pub remaining: rt_core::ArchiveRecord,     // the entries of `failed`
}
pub fn remove_archive(rec: &ArchiveRecord, pkg_id: &str, env: &AppEnv, backend: &dyn CompatBackend,
                      launcher: &Launcher) -> Result<RemoveOutcome, ArchiveError>;
```

1. Validate `pkg_id` and the whole record (R1's semantic checks). `Err` means nothing is touched.
2. **Overrides**, newest first:
   - read `user.reg` once with `read_dll_overrides`;
   - current value is `native,builtin` (exact, after the parser): restore. `previous: Some(v)` runs
     `reg add OVERRIDES_KEY /v <name> /d <v> /f`, and `None` runs the existing `delete_override`. Both are one
     argv element each, through the given launcher (`helper_launcher`'s);
   - otherwise (another value, or absent): `left`, "changed since it was installed" or "already removed".
3. **Files**, in reverse order:
   - `resolve` (no symlink in any component). A symlink or a non-regular file goes to `left`.
   - Absent and not replaced: done. Absent and replaced: restore the backup, or, when the backup is gone too,
     `left` "missing, nothing to restore" (R15).
   - Present: open it `O_NOFOLLOW`, `fstat` that it is a regular file, and hash it.
     - The hash is equal and the file is not replaced: `remove_file`.
     - The hash is equal and the file is replaced: `restore`, the existing temp-and-rename from
       `deps-backup/<id>/c/<path>`, which then prunes the backup.
     - The hash differs: `left`, "changed since it was installed". A replaced file's backup is kept, and the
       message names the backup.
4. **Directories**: `remove_dir` on each recorded created directory, children first. The existing call removes it
   only if it is empty.
5. If nothing failed, delete the journal (`drop_journal`).

### 4.4 The command (`rt_deps::remove_packages`, `runtime deps --remove`)

```rust
pub struct RemoveReport { pub removed: Vec<String>, pub left: Vec<(String, String)>,
                          pub failed: Vec<(String, String)>, pub skipped: Vec<(String, String)> }
pub fn remove_packages(store: &Store, env: &AppEnv, backend: &dyn CompatBackend, launcher: &Launcher,
                       manifest: &Manifest, ids: &[String]) -> Result<RemoveReport, DepsError>;
// DepsError::CannotRemove(String): every pre-check refusal of R3, R4, R8 and "not installed"
```

CLI: `--remove <PKG>` (repeatable, `conflicts_with_all = ["install", "discard_interrupted"]`, duplicates are a
usage error). `run_app` then does the following:
1. `app_env`, then `read_metadata`.
2. `backends::select`, then `check_backend`.
3. `crate::sandbox::print_hardening_caveat`.
4. `crate::sandbox::helper_launcher`. A marked app with no bwrap refuses here, exactly as install does.
5. `remove_packages`.
6. Print the report through `safe`: `removed <pkg>`, `left <pkg>: <item>: <why>`, `failed <pkg>: <why>`,
   `skipped <pkg>: not attempted: an earlier package failed`.

It prints no plan. Exit 0 only when every package was removed with nothing left. Any refusal, failure or
left item is exit 1. Usage errors are clap's 2.

### 4.5 Daemon (`deps.remove`)

- `rt_api::jobs`: `JobSpec::DepsRemove { app: AppId, packages: Vec<String> }`; `from_request("deps.remove", ..)`
  with `DepsRemoveParams` (`deny_unknown_fields`); `argv()`; `JobKind::DepsRemove`; `API_VERSION = "0.2.3"`.
- `rt_daemon::dispatch`: the name joins `WRITE_METHODS` and `METHODS`, and the doc table gets a row. A read-only
  daemon answers `read_only` before it reads the params.
- `rt_daemon::client`: `deps_remove(id, packages) -> Result<JobStarted, ClientError>`.
- `docs/API.md`: the method, its params, its argv, its caps (1 to 16 packages), and the 0.2.3 entry.

## 5. Components

- `crates/core/src/meta.rs` (+ its tests), `crates/core/src/lib.rs` re-exports: schema 5 and the record types.
- `crates/deps/src/wine_config.rs`: `read_dll_overrides`.
- `crates/deps/src/install_archive.rs` (+ tests): `record_of`, `remove_archive` rewritten, `RemoveOutcome`,
  `INSTALLED_OVERRIDE`, `undo_install` (the old `remove_archive` body, renamed).
- `crates/deps/src/orchestrate.rs` (+ tests, + `tests/e2e.rs`): `install_one` records and undoes;
  `remove_packages`, `RemoveReport`, `DepsError::CannotRemove`.
- `crates/deps/src/manifest.rs`: `valid_id` made `pub`. `crates/deps/src/state.rs`: `record` keeps its signature.
- `crates/cli/src/deps.rs` (+ tests), `crates/cli/src/main.rs` (the JobSpec-to-argv mapping test),
  `crates/cli/tests/apps.rs`: `--remove`.
- `crates/api/src/{jobs.rs,lib.rs}`, `crates/daemon/src/{dispatch.rs,client.rs}`, `crates/daemon/tests/e2e_jobs.rs`.
- Docs: `docs/API.md`, `docs/SECURITY.md` (the Dependency downloads section), `README.md` (the `deps` row and the
  "no removal" sentence), the roadmap (a 6F row; the follow-up closed; new follow-ups: GUI button, installer
  packages, old-record repair), and the 4B spec's "Opt-out is deferred" line (amended to point here).

## 6. Testing

- **Schema (Task 1):**
  - a frozen v4 file with dependencies reads with `archive: None`, and writing it back gives schema 4 unchanged;
  - `state::record` writes 5;
  - schema 6 is refused;
  - `validate` refuses each of these: 65 files, a bad sha256, a duplicate path, a duplicate override, a bad override
    name, a `previous` over 32 bytes, an unknown field in the record;
  - a realistic dxvk record round-trips.
- **Install (Task 2):** in the fake-backend rig of the orchestrator tests:
  - an archive install records every file with the sha256 of its bytes, `replaced` set for a Wine placeholder
    that existed, and created directories;
  - a pre-existing `"d3d11"="builtin"` in `user.reg` is recorded as `previous: Some("builtin")`, and an absent one
    as `None`;
  - a dword or `"x;y"` value refuses before the fetch (the fetcher is never called);
  - a metadata write forced to fail (a read-only metadata file, or an over-cap record) leaves no file of the package
    and no override, and the report says it was removed again.
- **Remover (Task 3):** unit tests with `FakeBackend` and a recording launcher:
  - every entry unchanged: the files are gone, replaced files have their originals' bytes back, the backups are
    pruned, the journal is deleted, and the argv is `reg add /d builtin` for a previous value and `reg delete` for
    none;
  - a tampered file: left, the others removed, its backup kept and named;
  - an override changed to `disabled`: left, with no `reg` call for it;
  - a symlinked file, and a symlinked parent directory: left, the link and its target untouched;
  - a recorded path with `..`, an absolute path, or a reserved name: `Err` before anything is touched;
  - a `reg` failure: `failed` and `remaining` hold exactly that override, and the journal is kept;
  - a retry with `remaining` finishes it;
  - a file already gone: done;
  - a replaced file already gone: original restored.
- **Command (Task 4):**
  - Orchestrator tests:
    - refuses each of: not installed, installer package, `archive: None`, dxvk while vkd3d-proton is recorded,
      an unknown recorded package;
    - the refusal changes nothing: the files and the metadata bytes are unchanged;
    - `--remove vkd3d-proton --remove dxvk` in either order removes vkd3d-proton first;
    - `AppRunning` while a shared lock is held, `PrefixBusy` with a fake wineserver (the existing helpers);
    - a failure in the first package skips the second and keeps its record.
  - CLI rig (fake Wine and fake `reg.exe`, as the `display` tests have):
    - an app with a dxvk record planted in the metadata and files in `drive_c` is removed with exit 0;
    - `reg-argv.txt` shows the deletes;
    - the record is gone;
    - **`doctor` then prints the built-in route** for Direct3D 11 (the existing route assertion);
    - a tampered DLL is exit 1 with `left`;
    - a marked app without bwrap is refused before any `reg` call;
    - `--remove` together with `--install` is exit 2.
  - Real Wine (`#[ignore]`, in `orchestrate/tests/e2e.rs`, so CI's `wine-e2e` filter `e2e_real_wine` picks it
    up), `e2e_real_wine_remove_restores_overrides_and_leaves_a_tampered_file`:
    1. Create a prefix and set `"dllpkg"="builtin"` with `reg add`.
    2. Install a two-DLL zip (`exports64.dll` twice) through `install_plan` and the local HTTPS server.
    3. Check the record.
    4. Overwrite one DLL.
    5. Run `remove_packages`.
    6. Check the results:
       - the untouched DLL is gone;
       - the tampered DLL is still there with its tampered bytes and is reported `left`;
       - `user.reg` shows `"dllpkg"="builtin"` again and the second override is absent;
       - the record is gone;
       - no `wineserver` is left.

    The test also restores a previous value of `""` (disabled), which checks that `reg add /d ""` works on Wine
    10.0. The test is run on this host, and the command and result go into As built.
- **Daemon (Task 5):**
  - `from_request` refuses each of: no packages, 17 packages, a duplicate, `-x`, `A`, an unknown member;
  - the argv is exactly `deps --remove=a --remove=b -- <id>`, and the CLI parses it back (the mapping test in
    `main.rs`);
  - read-only `deps.remove` gives `read_only`;
  - e2e part A, with the fake `runtime`: the argv log shows the call;
  - the API.md dispatch-table test covers the new row.

## 7. Risks

- **A new install refusal (R5).** A prefix with a hand-written, non-string override for one of the package's DLLs
  can no longer install the package until the user resets it. The message says how. It is rare, and the safe
  direction.
- **A noisy retry after a metadata write failure.** Files are removed, then the shrunk record cannot be written, so
  the old record stays. On the retry, the restored originals hash differently and are reported `left`, and the
  restored overrides are `left` too. Nothing wrong is deleted, and the run converges. This is documented in
  `SECURITY.md`.
- **Check-then-act inside `drive_c`.** The window between the hash and the delete is the same as for every 4A
  write. It is closed by the app lock, the busy check and the sandbox, not by the remover.
- **Doctor and the plan ask for the package again** after removal, because the app still imports `d3d11`. That is
  the intended effect of removal. The hint is not new.
