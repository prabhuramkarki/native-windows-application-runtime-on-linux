# Phase 6, sub-project D: the backend interface and the `.wrun` package format (design)

Status: approved by the controller on the user's standing instruction (self-approve with the recommended choices;
the user pre-approved the four decisions this spec builds on, 2026-09-27). Fourth and last of the Phase 6
sub-projects (6A API + read-only daemon, 6B mutating methods + jobs, 6C GUI client, **6D backend interface +
`.wrun`**). Roadmap Phase 6: "Backend plugin interface frozen & versioned ... Register by capability" and "`.wrun`
package (§43): manifest + reproducible env recipe; `.exe`/`.msi` remain first-class". This spec narrows the first to
one audited, compiled-in seam (no plugins) and defines `.wrun` v1.

## 1. Purpose and success criteria

Two things must be true before 1.0. First, the line between the runtime (store, install, sandbox, deps, API, GUI) and
the thing that executes Windows code (Wine today) is a written, tested contract, so that Phases 7-9 can add a backend
without touching the platform, and so that nobody mistakes "backend" for "plugin". Second, an app can be handed to
the runtime as one file that says what it is and what it asks for, and importing that file can never do more than
the user could do with `runtime install` and their own consent.

Success criteria:

1. `rt_core::CompatBackend` is the only execution seam. Its contract (every method: inputs, outputs, what it may and
   must not do) is written in its module docs and checked by a **conformance suite** that the Wine backend, the
   test `FakeBackend` and an in-tree **null backend** (test-only, no Wine knowledge) all pass. The null backend
   installs and runs an app through the unmodified `rt_core::install` and `rt_core::run`: the proof that the seam is
   backend-neutral.
2. A backend declares **capabilities** (guest architectures, subsystems, features). The platform refuses what the
   backend's capabilities exclude (an install of an unsupported architecture, the installer pipeline or dependency
   packages on a backend that cannot take them) before creating anything.
3. Backends are compiled in and **selected by id** (`rt_api::backends::select`) from the app's recorded
   `backend.id`. No `dlopen`, no `libloading`, no third-party code loaded into a runtime process: enforced by a
   source scan and a `cargo deny` ban.
4. `.wrun` v1 is a single zip file: a strict TOML manifest, a `payload/` tree, a sha256 per file. It is read only
   through the existing hardened zip planner (`rt_core::unzip`) plus package-level rules, and every rule has a
   hostile test; a mutation harness shows no input panics or writes outside its destination.
5. `runtime pack`, `inspect`, `unpack` and `import` exist. `inspect` and `unpack` run nothing. `import` creates the
   app through the existing install flows with a fixed id (collision = refusal, the existing app untouched), records
   what the package **requested** (dependencies, permissions) and grants nothing: dependencies still go through
   `runtime deps --install` and its per-package consent, permissions still through `runtime permissions --set`. The
   resulting app's sandbox and consent behaviour equals a locally installed app's, byte for byte in its
   `permissions.toml` (absent) and in its dependency plan (plus the requested roots).
6. `apps.import` is a 6B job method behind `--write`; the GUI's install dialog accepts a `.wrun` and starts it.
7. The 1.0 hygiene exists: `LICENSE-MIT`, `LICENSE-APACHE`, `license = "MIT OR Apache-2.0"` on every crate, a
   README status section, `docs/ARCHITECTURE.md`, `docs/README.md` (an index).

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Scope | (A) the backend seam made real and stable, with capabilities, a conformance suite and a null backend in tests; (B) `.wrun` v1 with `pack`/`inspect`/`unpack`/`import` and `apps.import` | Pre-approved. |
| Non-goals | Package signing and trust chains (fields reserved, threat documented), a registry or any network fetch of packages, dynamic plugins, a real non-Wine backend (Phases 7-9, post-1.0), auto-update | Pre-approved. |
| Plugins | None. Backends are Rust types in the workspace, chosen by id | Pre-approved; section 5.2 says why (the security model). |
| Package trust | A `.wrun` is hostile input; it can only REQUEST; the user consents through the existing commands; import never pre-grants, never skips consent, adds no hooks | Pre-approved. |
| Hygiene | LICENSE files, README status, `docs/ARCHITECTURE.md`, docs index, as the last task | Pre-approved. |

### Decisions made while writing this spec (unspecified by the brief; safest simple option)

- **Decision B1: the trait stays in `runtime-core` (`rt_core::backend`); no `runtime-backend-api` crate.** Core
  already has no Wine dependency (the dependency runs the other way: `runtime-backend-wine` depends on core), the
  trait's argument types (`AppEnv`, `RunOpts`, `Launcher`, `BackendError`) are core types, and a new crate would be a
  re-export shim that moves every import for no gain. "Stable" is: the documented contract, the conformance suite,
  and `pub const BACKEND_API_VERSION: u32 = 1` in `rt_core::backend`, bumped on any change a backend must react to
  (printed by `runtime doctor` next to the backend id and version).
- **Decision B2: only `CompatBackend` is frozen.** The roadmap's `GraphicsBackend`, `WindowBackend`, `AudioBackend`,
  `CpuBackend` are not defined in 6D: none has a second implementation or a consumer (graphics is already manifest
  data in `rt_deps`, audio/display are Wine configuration, `CpuBackend` is Phase 9). A trait with one
  implementation and no caller is a guess that Phase 7-9 would have to break. The roadmap row says so.
- **Decision B3: capabilities are plain data on the trait**, `fn capabilities(&self) -> Capabilities` (required, no
  default, so a backend must state them):
  ```rust
  pub struct Capabilities {
      pub arches: &'static [pe::Arch],            // guest architectures it runs (Wine: X86, X86_64)
      pub subsystems: &'static [pe::Subsystem],   // Wine: Gui, Console
      pub dotnet: bool,                           // honours RunOpts::dotnet
      pub installers: bool,                       // its prefix is what rt_installer reads (drive_c, system.reg/user.reg, .lnk)
      pub dependency_packages: bool,              // rt_deps may install packages into its prefix (DLL overrides, Wine config)
  }
  ```
  `Capabilities::check(arch, subsystem) -> Result<(), Unsupported>`. Enforced in `rt_core::install` (before
  `Store::create`), `rt_installer::install_via_installer` (`installers`), `rt_deps` install (`dependency_packages`),
  `rt_core::run` (`dotnet` false + the app has Wine Mono recorded = refusal, not a silent run without it). The
  prefix layout the other crates rely on (`AppEnv::drive_c()` is the guest's `C:`) is part of the trait contract,
  not a capability: every backend must present one.
- **Decision B4: the registry is `rt_api::backends`**: `KNOWN: &[&str] = &["wine"]`, `DEFAULT: &str = "wine"`,
  `select(id, &Launcher) -> Result<Box<dyn CompatBackend>, BackendError>` (an unknown id is `Unavailable` naming
  the id, cleaned, and the known ones). It lives in `rt_api` because that crate already depends on
  `runtime-backend-wine` and the CLI already depends on it; core cannot name Wine. The CLI's `backend()` and the
  API's host probes use it wherever they only need `&dyn CompatBackend`; new installs use `DEFAULT`; an existing app
  uses its recorded `backend.id` (the existing `RunAppError` backend-mismatch check stays as the second guard).
  There is **no user-facing backend choice** in 6D (one real backend; no flag, no variable). The null backend is
  never in the registry: tests pass it as `&dyn CompatBackend` directly, so no test code reaches a release build.
- **Decision B5: Wine-specific diagnostics stay Wine-specific.** `doctor`'s Wine checks, `sandbox.info`'s Wine
  paths and `backend_wine::harden_cause` keep the concrete `WineBackend`; they are listed in the contract docs as
  "a second backend brings its own doctor section". The audit (Task 1) lists every concrete `WineBackend` use in
  production code and either moves it behind the registry or records why it stays.
- **Decision B6: the null backend.** `NullBackend` in `crates/core/tests/conformance.rs` (test-only; not the
  `FakeBackend`, which records calls and runs scripts): `id "null"`, `prepare` creates `drive_c/` only, `command`
  returns `/bin/sh -c 'exit 0' <exe>` (or a script fixed per test), `stop` succeeds, `dll_dirs` empty, capabilities
  `X86_64` + both subsystems, all features false. With it: `rt_core::install` of the `hello64.exe` fixture and
  `rt_core::run` of the result with a plain `Launcher` succeed and record `backend.id = "null"`; the installer
  pipeline and `rt_deps` install refuse it by capability.
- **Decision B7: no-plugin enforcement.** `deny.toml` `[bans] deny` gains `libloading`, `dlopen`, `dlopen2`,
  `libloading-mini`; a workspace source scan test (in `crates/core/tests/conformance.rs`) fails on `dlopen`,
  `dlsym`, `libloading`, `RTLD_` in any `crates/*/src` file. (The sandbox's seccomp and bwrap code do not use
  them today; a legitimate future use is a deliberate edit of the scan with a SECURITY.md entry.)
- **Decision W1: the container is zip**, not tar.zst: the hardened planner (`rt_core::unzip`) is in core, plans the
  whole archive from the central directory before writing a byte, refuses case collisions, duplicates, type
  conflicts, links and bombs, and is what `install` already trusts with hostile zips. Random access lets `inspect`
  read the manifest without extracting. The `zip` crate's writer (`ZipWriter`, always compiled; deflate through the
  already-enabled `deflate-flate2`) serves `pack`: no new third-party crate.
- **Decision W2: package-level rules on top of `unzip`'s** (section 3.1): the first central-directory entry is
  `wrun.toml`; every other entry is below `payload/`; `wrun.sig` is reserved and refused in v1; entries `unzip`
  would skip (symlink, device, FIFO, socket) are refused, not skipped; names use `/` only.
- **Decision W3: the manifest is TOML** (`toml` is already a workspace dependency; `permissions.toml` and the deps
  manifest are TOML), parsed with `deny_unknown_fields` at every level, `format = 1` required.
- **Decision W4: a package can request only typed permissions**: `network = allow|deny`, `display|audio|gpu =
  on|off`. No filesystem grants (a host path in a portable file is meaningless and a lure), no resource-limit
  relaxation. Requests are recorded as canonical EXPR strings built from those enums only, never copied from the
  file.
- **Decision W5: import never grants; it records and tells.** Import writes no `permissions.toml` (the app gets the
  default profile, exactly as `install`), installs no dependency, and prints each request as the exact command that
  would grant it (`runtime permissions <id> --set=network=allow`, `runtime deps <id> --install`). The requests are
  stored in the app's metadata (`package` field, schema 4) so that `runtime permissions <id>` and the GUI show
  "requested by the package, not granted", and `rt_deps` plans requested dependencies as roots, each still behind
  the unchanged per-package consent.
- **Decision W6: ids.** The manifest `id` must parse as an `AppId`; it becomes the app id unchanged (no
  `unique_id` suffixing, unlike `install`). An existing app with that id => refusal before anything is created,
  and `Store::create`'s atomic `mkdir` refuses the race; nothing of the existing app is read, locked or changed.
  There is no upgrade, overwrite or `--force` in v1 (`runtime remove` first).
- **Decision W7: two payload kinds.** `portable`: the payload tree is copied to `drive_c/Program Files/<id>/`
  through the existing archive install (a new subtree mode of `rt_core::install`, section 5.4), the entry program is
  a listed file. `installer`: the payload is exactly one file, an `.msi`/`.exe` installer, run through the unchanged
  `rt_installer::install_via_installer` (its sandbox, no network unless the USER passes `--network`, `--silent` a
  user flag too); the manifest may name the installed program (`installedExe`, the `--exe` of `install`).
  Installer-kind import runs the package's installer exactly as `runtime install setup.exe` would; that is the
  install flow the user asked for. The format has no scripts, hooks or "run after import"; import never starts the
  app.
- **Decision W8: integrity.** Each payload file's sha256 and size are in the manifest; they are checked against the
  central directory before anything is written and against the bytes while streaming (a mismatch aborts; the
  install cleanup removes the half-built app). The **package digest** is the sha256 of the raw `wrun.toml` bytes:
  it covers every file hash, `inspect` prints it, the app's metadata records it, and it is what a future signature
  (`wrun.sig`) will sign. v1 packages are unsigned and every command says so ("unsigned: its origin is not
  verified").
- **Decision W9: `icon`** is optional, must be a listed `.png` file of at most 1 MiB, and is validated and recorded
  only; desktop integration keeps using the program's own icon. Using the package icon is a follow-up.
- **Decision W10: `pack` is reproducible**: files sorted by path bytes, fixed timestamp (1980-01-01, the zip
  minimum), mode 0644 for files, no directory entries, deflate at the default level, the manifest re-serialised
  canonically with the generated `[[files]]` table. `pack` opens its own output with the reader before reporting
  success (the writer never produces what the reader refuses). Symlinks, special files, names the reader would
  refuse and inputs over the reader's caps are errors.
- **Decision W11: `runtime install` refuses a `.wrun`** (a zip whose first entry is `wrun.toml`) with "this is a
  `.wrun` package: use `runtime import`", so a package's requests are never silently dropped by the zip path.
- **Decision W12: GUI Import is in 6D** (cheap: the install dialog adds a `*.wrun` filter; a chosen `.wrun` hides
  name/exe and starts `apps.import`). The GUI shows the metadata's requested permissions as a read-only line on the
  app page. A package preview before import (a read method) is a follow-up: the import job's log prints the same
  summary as `inspect`.
- **Decision W13: staging for installer-kind.** The installer file is extracted (verified) to
  `<data root>/staging/import-<pid>-<nanos>` (directory 0700 created on demand, file `create_new` 0600), passed to
  `install_via_installer`, and removed afterwards on every path. No `tempfile` in production code. (As built: a
  signal skips that removal, so each import first removes the `import-<pid>-*` directories of dead processes.)

## 3. The `.wrun` v1 format

### 3.1 Container

A zip archive read by `rt_core::unzip::open` with the production `Limits` of `install` (entry count, per-entry and
total sizes, ratio, depth: unchanged), then:

- the first central-directory entry is a file named exactly `wrun.toml`, declared size at most 64 KiB;
- every other entry name starts with `payload/`; `wrun.sig` is refused ("signed packages need a newer runtime");
  any other name is refused;
- names are UTF-8 and contain no `\`; every other name rule is `unzip`'s (`..`, absolute, drive, `:`, control and
  format characters, reserved device names, trailing dot or space, depth, case collisions, duplicates, file/dir
  conflicts: all refused);
- entries whose mode is a symlink, device, FIFO or socket are refused (`unzip` would skip them);
- encrypted entries and methods other than stored/deflate are refused (`unzip`).

### 3.2 Manifest (`wrun.toml`)

```toml
format = 1
id = "example-app"                # AppId grammar (lowercase, digits, '-', at most 64 bytes)
name = "Example App"              # 1-256 bytes, no control or format characters (refused, not stripped)
version = "1.2.0"                 # 1-64 bytes of [0-9A-Za-z.+~-]
arch = "x86_64"                   # "x86" | "x86_64"; must equal the program's PE architecture
dependencies = ["vcrun2022"]      # optional, at most 16, unique, each a package id of the bundled deps manifest
icon = "payload/app.png"          # optional, W9

[entry]
kind = "portable"                 # "portable" | "installer"
exe = "payload/App/app.exe"       # portable: the program, a listed file
# installer = "payload/setup.exe" # installer: the installer, the only payload file
# installedExe = "Program Files/App/app.exe"   # installer: optional, as `install --exe`

[permissions]                     # optional; requests only (W4, W5)
network = "allow"
gpu = "on"

[[files]]                         # written by `pack`; one per payload file, archive order irrelevant
path = "payload/App/app.exe"
size = 123456
sha256 = "<64 lowercase hex>"
```

Rules: `deny_unknown_fields` everywhere (a `[signature]` table, a `filesystem` permission, `scripts`, anything
else is an error naming the key, cleaned); the whole file is UTF-8 and at most 64 KiB; `files` has at most
`Limits::max_entries` items with unique paths, and equals exactly the set of file entries below `payload/` (a
missing or an unlisted file is an error), each `size` equal to the entry's declared size; `exe`, `installer` and
`icon` are listed file paths (exact match; a directory, an unlisted path or anything outside `payload/` is an error);
`installedExe` passes `WinPath` rules as `install --exe` does; for `installer` kind `files` has exactly one item.
Every error message quotes file content only through `clean_text`, bounded.

### 3.3 Reader and writer API (`crates/package`, `runtime-package`, lib `rt_package`)

```rust
pub const FORMAT: u32 = 1;
pub struct Manifest { pub id: AppId, pub name: String, pub version: String, pub arch: pe::Arch,
                      pub dependencies: Vec<String>, pub icon: Option<String>, pub entry: Entry,
                      pub permissions: Requests, pub files: Vec<FileRef> }
pub enum Entry { Portable { exe: String }, Installer { installer: String, installed_exe: Option<String> } }
pub struct Requests { pub network: Option<bool>, pub display: Option<bool>, pub audio: Option<bool>, pub gpu: Option<bool> }
impl Requests { pub fn exprs(&self) -> Vec<String> }            // canonical "network=allow", ...
pub struct FileRef { pub path: String, pub size: u64, pub sha256: [u8; 32] }
pub struct Package { pub manifest: Manifest, pub digest: [u8; 32], /* archive + plan */ }
pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest, PackageError>;
pub fn open(file: File) -> Result<Package, PackageError>;       // container + manifest + cross-checks; reads no payload
impl Package {
    pub fn verify(&mut self) -> Result<(), PackageError>;       // streams every payload file through sha256
    pub fn unpack(&mut self, dest: &Path) -> Result<(), PackageError>;   // dest must not exist
    pub fn extract_one(&mut self, path: &str, dest: &Path) -> Result<(), PackageError>;  // create_new 0600, verified
    pub fn digests(&self) -> BTreeMap<String, [u8; 32]>;        // for rt_core::install's subtree mode
}
pub fn pack(dir: &Path, out: &Path) -> Result<[u8; 32], PackageError>;   // returns the package digest
```

## 4. Components

- `crates/core/src/backend.rs`: the contract docs, `Capabilities`, `Unsupported`, `BACKEND_API_VERSION`;
  `crates/core/src/backend/conformance.rs` (`cfg(any(test, feature = "testing"))`): the suite.
- `crates/core/tests/conformance.rs`: `NullBackend`, the suite over `NullBackend` and `FakeBackend`, the
  install-and-run proof, the no-plugin source scan.
- `crates/backend-wine`: `capabilities()`; `tests/conformance.rs` (static tier over `WineBackend::from_found` with
  fake paths); the live tier added to `tests/e2e_wine.rs` (real Wine, existing gating).
- `crates/api/src/backends.rs`: the registry; `crates/api/src/host/*`, `crates/cli/src/main.rs`: use it.
- `crates/core/src/install.rs`, `unzip.rs`: the subtree mode with per-file digests and a fixed id;
  `crates/core/src/meta.rs`: schema 4, `PackageMeta`; `crates/installer/src/pipeline.rs`: fixed id and package
  metadata; `crates/deps`: requested roots, the capability check.
- `crates/package` (new): format, reader, writer, hostile tests and the mutation harness.
- `crates/cli/src/package.rs` (new): `pack`, `inspect`, `unpack`, `import`; `install.rs`: W11; `permissions.rs`:
  requested lines.
- `crates/api/src/jobs.rs`, `types.rs`, `lib.rs`: `apps.import`, `PermissionsView.requested`, `API_VERSION`
  `0.2.1`; `crates/daemon`: dispatch and client helper; `crates/gui`: the install dialog and the requested line.
- `deny.toml` (bans), `docs/API.md`, `docs/SECURITY.md`, `docs/WRUN.md` (the format for package authors), README,
  `docs/ARCHITECTURE.md`, `docs/README.md`, `LICENSE-MIT`, `LICENSE-APACHE`, `Cargo.toml` licence fields, roadmap.

## 5. Behaviour

### 5.1 The backend contract (written into `rt_core::backend`'s docs)

For each method: `id` is a constant lowercase ASCII word (`[a-z0-9-]{1,32}`), recorded in metadata; `version`
never spawns outside `Launcher::run_helper`; `capabilities` is constant; `prepare` creates the prefix so that
`env.drive_c()` exists and is the guest's `C:`, is idempotent, and runs helpers only through the backend's
`Launcher`; `command` describes and never spawns, never calls `env_clear`, refuses an exe or cwd outside
`env.drive_c()` with `OutsideDriveC`, passes `args` verbatim, and sets only its own variables; `stop` with nothing
running succeeds; `dll_dirs` are absolute; `settle` keeps the program and arguments of the command it wraps. Plus
the prohibitions: a backend never reads the app's `permissions.toml`, never decides sandboxing (the `Launcher` and
`rt_sandbox` do), never downloads, never writes outside `env.root()`.

The conformance suite checks what is observable: id grammar and stability; capabilities non-empty and stable;
`command` has no side effect (a tree snapshot of the scratch data dir is unchanged; spawning itself is not
observable reliably and is left to review) and its program is an absolute path; `OutsideDriveC` for `../` escapes, absolute paths outside and a symlinked `drive_c` entry;
args byte-identical (NUL-free non-UTF-8, leading `-`, spaces, newlines); `current_dir` equals `cwd_unix`; no
`LD_PRELOAD`/`LD_LIBRARY_PATH` set by the backend; `settle` keeps program and args; live tier: `prepare` twice
succeeds, `stop` on an idle prepared env succeeds, a command launched through `Launcher::spawn` reports the exit
code the script sets.

### 5.2 Why no plugins (the security model)

Every runtime process (the CLI, `runtimed`, the GUI) runs as the user with the user's full access; the sandbox is
built by the runtime for the Windows program, not around the runtime itself. A dynamically loaded backend would run
in-process, unsandboxed, with access to every app's prefix, the daemon's write socket and the consent flow it could
answer itself. A plugin API also freezes an ABI (Rust has none) and invites "install this backend" instructions from
strangers. Compiled-in backends are reviewed, built from the lock file and checked by `cargo deny`. A future
out-of-tree backend is a fork or a pull request. (An out-of-process backend protocol could be reconsidered after
1.0; it would need its own threat model.)

### 5.3 `inspect`, `unpack`, `pack`

- `runtime inspect FILE [--json]`: `open` + `verify`; prints id, name, version, arch, kind, entry, file count and
  total size, the package digest, "unsigned: its origin is not verified", and "It would request:" each dependency
  ("needs your consent when you run `runtime deps <id> --install`" for consent-gated ones, looked up in the bundled
  deps manifest; unknown ids are an error here too) and each permission ("not granted; you can grant it with
  `runtime permissions <id> --set=...`"). Whether the id is already installed is shown. Every string through
  `safe()`. Writes nothing. Exit 1 on any error.
- `runtime unpack FILE -o DIR`: `DIR` must not exist; created 0755; `wrun.toml` and the payload tree written with
  `create_new`, verified while streaming; on any error `DIR` is removed (it was created by this call).
- `runtime pack DIR -o FILE`: W10; `FILE` must not exist (`create_new`), removed on error; prints the package
  digest.

### 5.4 `import`

`runtime import FILE [--silent] [--network]`:

1. `open` (container, manifest, cross-checks; nothing read from the payload yet). Refuse an id that exists (W6),
   unknown dependency ids, an arch or subsystem the default backend's capabilities exclude, and `--silent` or
   `--network` with a portable package (installer-only flags, as `install`).
2. Print the `inspect` summary (so the job log shows the requests).
3. **portable:** `rt_core::install` in subtree mode: `InstallOpts { id: Some(fixed), subtree: Some("payload"), exe:
   Some(entry without "payload/"), digests: Some(package.digests()), package: Some(PackageMeta), name: Some(name) }`.
   The zip plan is filtered to the subtree with the prefix stripped; `unzip::extract` gets a per-file digest check
   (sha256 while streaming; a mismatch is `ZipError::Integrity`, the file is left partial and the install cleanup
   removes the environment). The program's PE arch must equal the manifest's (`InstallError::Mismatch`). The fixed
   id's `AlreadyExists` is `InstallError::IdTaken` with no retry and nothing removed.
4. **installer:** W13 staging, then `install_via_installer(store, backend, launcher, staged, InstallerOpts { silent,
   allow_network, exe_override: installed_exe, id: Some(fixed), package: Some(PackageMeta) })`; `NeedsChoice`
   behaves as in `install` (nothing installed, candidates printed); the staged file is removed on every path.
5. Metadata (schema 4) is written last, as today, and carries
   `package: {id, version, digest, requestedDependencies, requestedPermissions}`.
6. Print `Installed: <id>`, then each permission request as its grant command and, when dependencies were
   requested, `runtime deps <id> --install`. Exit 0. Nothing is run, granted or downloaded.

### 5.5 Requested dependencies and permissions afterwards

- `rt_deps::plan_for_pe` adds `md.package.requested_dependencies` as roots (`Facts::requested`), with the reason
  "requested by the package"; an id no longer in the manifest becomes a plan warning. Consent, digest (6B), `--yes`
  rules: unchanged; a requested consent-gated package still asks.
- `runtime permissions <id>` prints `requested by the package (not granted): network=allow` for each request that
  the current profile does not satisfy, with the grant command; `--json` adds `"requested": [...]`. `permissions.get`
  gains `requested` (additive). The sandbox never reads `package`.

### 5.6 `apps.import`

`{path, silent?: bool, network?: bool}` -> `{jobId}`, `JobKind::Import` (`kind: "import"`, `app: null` like
install, no per-app slot), path validated exactly like `apps.install`'s, argv `import [--silent] [--network] --
<path>`. `API_VERSION` `0.2.1` (additive). Client helper `Client::import(ImportParams)`. GUI: W12.

## 6. Testing

- **Conformance** (unit + integration): the suite over `NullBackend` and `FakeBackend` (all checks), `WineBackend`
  static tier with `from_found` fake paths (no process), live tier in the real-Wine e2e. The null backend install
  and run of `hello64.exe`; capability refusals (installer pipeline, deps install, an x86 program on an
  `X86_64`-only backend) create nothing. Registry: `select("wine")` ok with a fake Wine on `RUNTIME_WINE`,
  `select("null")` and `select("\u{1b}x")` are `Unavailable` with a cleaned message. The no-plugin scan.
- **Package hostile tests** (`crates/package`, each asserting the error kind and that the destination holds
  nothing): traversal (`payload/../x`, `/abs`, `C:x`, `payload\x`), symlink/device entries, case collision,
  duplicate, file/dir conflict, zip bomb (ratio and declared size), manifest missing / not first / over 64 KiB /
  not UTF-8 / `format = 2` / unknown key at each level (`[signature]`, `permissions.filesystem`, `scripts`),
  `wrun.sig` present, another top-level entry, ESC/U+202E/NUL in `name`, overlong fields, bad hex, a listed file
  missing, an unlisted file, a size mismatch, a sha mismatch discovered while streaming (unpack leaves no `DIR`),
  `exe` naming a directory, an unlisted path, a path outside `payload/`, installer kind with two files.
- **Mutation harness** (xorshift byte flips, inserts, truncations; the style of `deps/src/manifest/tests.rs` and
  `pe/tests/robust.rs`): 2,000 mutants each of a valid `.wrun` (through `open` + `verify` + `unpack` into a tempdir)
  and of a valid `wrun.toml` (through `parse_manifest`): no panic, error text at most 4 KiB, nothing written
  outside the tempdir.
- **Writer**: pack -> open -> unpack -> pack is byte-identical; pack refuses a symlink, a FIFO, a `\` name, an
  existing `[[files]]`, an existing output.
- **Integration** (CLI e2e with the fake-Wine rig): import portable `hello64.exe` package => app with id, metadata
  `package`, no `permissions.toml`, `runtime permissions` shows the request, `runtime deps` plan contains a requested
  package with its consent gate and nothing installed; import with a taken id => exit 1 and the existing app's files
  byte-identical (tree hash before/after); a tampered payload => no app directory; `install` of a `.wrun` refused;
  installer kind with a fixture installer under real bwrap (gated by `RUNTIME_REQUIRE_BWRAP`). Sandbox equivalence:
  the rendered `runtime sandbox <id>` command of an imported app equals that of the same exe installed with
  `install --name` (ids normalised).
- **API/daemon/GUI**: `JobSpec` validation and argv for `apps.import` (hostile paths as 6B); daemon e2e: an import
  job on a write daemon, `read_only` on a read-only one; GUI view-model: a `.wrun` path sends `Cmd::Import`, name/exe
  ignored; widget test: the requested-permissions line is literal text.

## 7. Risks

- **Unsigned packages.** A `.wrun` from a stranger is as trustworthy as a `setup.exe` from a stranger: import
  cannot tell who made it. Mitigations: it cannot grant anything, runs only the flows `install` already runs, and
  says "unsigned" everywhere. The digest is the hook for signing later; a signature scheme (key distribution,
  revocation) is a separate design.
- **Social engineering through requests**: a package asks for `network=allow` and its README tells the user to
  grant it. The grant is still the user's explicit command; the request text is fixed wording built from enums, so
  a package cannot put its own words in it (its `name` is cleaned and shown as data).
- **Capability drift**: a capability flag that the platform forgets to check. The conformance tests assert each
  refusal; new capabilities need a refusal test in the same change.
- **Schema 4**: an older runtime refuses an app imported by a newer one (existing schema policy). Documented.
- **Backend contract gaps**: parts of the contract (never spawning in `command`, never reading `permissions.toml`)
  are only partly observable; they are reviewed, not proven. Stated in the docs.
