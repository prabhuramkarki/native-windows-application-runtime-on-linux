# Architecture

This page is the map: what each crate owns, how they depend on each other, the three main flows, where hostile
input enters, and the seam a second compatibility backend would plug into. The details live in each crate's
module docs, in [SECURITY.md](SECURITY.md) and in the phase specs under `docs/superpowers/specs/`.

## Crates

**`runtime-pe` (`pe`).** It parses untrusted PE files: headers, sections, imports, exports, the version resource,
icons, installer markers, .NET. It reports what a file is (`detect`, `analyze`) and trusts no extension. It must
never execute or load anything, and it never writes: the input is bytes, the output is typed facts. Almost every
other crate depends on it: `runtime-core`, `-installer`, `-desktop`, `-deps`, `-package`, `-api` and `-cli`.

**`runtime-core` (`rt_core`).** It owns app ids (`AppId`), the data directory, Windows path handling (`WinPath`,
`resolve_under`), `metadata.json` (schema 4, validated on every read and write) and the `Store`. It also holds the
portable-exe and zip install service (`install`, including the `.wrun` subtree mode), the run service (`run`) and
the hardened zip planner (`unzip`). The `Launcher` is the one place a Windows program, a backend command or a Wine helper is started: it
clears the environment, applies an allowlist and attaches the sandbox hook. (Other processes are started elsewhere:
`runtimed`'s job runner starts `runtime`, the host probes start `vulkaninfo` and the like, and `runtime-desktop` runs
`desktop-file-validate`.) The `CompatBackend` trait and its contract live
here too (`backend`, with the conformance suite behind the `testing` feature). Core must not name Wine or depend
on any other workspace crate except `runtime-pe`, and it never downloads. Every workspace crate except `runtime-pe`
depends on it.

**`runtime-backend-wine` (`backend_wine`).** The system-Wine `CompatBackend`. It finds `wine`/`wineserver`, creates
and hardens prefixes (no `Z:` drive, the program's `HOME` is the app's own directory) and describes the command
that runs a program. It must never spawn outside the backend's `Launcher`, never decide sandboxing, never read
`permissions.toml` and never download. `runtime-api` (the backend registry, Wine diagnostics) and `runtime-cli`
use it.

**`runtime-sandbox` (`rt_sandbox`).** It owns the per-app permission profile (`permissions.toml`, parsed as untrusted
input) and renders it into a bubblewrap command, a `systemd-run --user` scope for resource limits, and the
`sandbox-init` shim that applies the seccomp deny-list and the Landlock ruleset before it `execve`s the program. It
must not weaken a profile to make a program start: a missing `bwrap` or a failing mandatory layer is a refusal.
`runtime-installer`, `runtime-api` and `runtime-cli` use it.

**`runtime-desktop` (`rt_desktop`).** It extracts a program's icon, writes and removes
`~/.local/share/applications/runtime-<id>.desktop` and its icons, and registers the MIME handler. It is wired only
into the installer pipeline: portable installs (and portable `.wrun` imports) get no menu entry. `runtime-installer` and
`runtime-cli` use it.

**`runtime-installer` (`rt_installer`).** It detects the installer family (MSI, Inno Setup, NSIS, InstallShield,
WiX Burn) and picks its silent flags. `install_via_installer` runs the installer in the installer sandbox, then
finds the installed program from a snapshot diff of the prefix, the Start Menu `.lnk` files and the registry
(`system.reg`/`user.reg`); all of these were written by the installer, so they are hostile input. It also runs recorded uninstallers. It never grants
network unless the user passed `--network`, and it refuses a backend without the `installers` capability.
`runtime-deps` and `runtime-cli` use it.

**`runtime-deps` (`rt_deps`).** The dependency engine. It holds the bundled, pinned package manifest (DXVK,
VKD3D-Proton, the VC++ runtime, Wine Mono), plans an app's needs from its PE imports plus what an imported
package requested, and handles per-package consent for proprietary items. Its verified HTTPS fetcher is the only
network code in the project. It installs archive packages and installer packages into a prefix. It never
downloads without an explicit `deps --install`, and it never installs a consent-gated package without consent to
that exact package, version and sha256. It refuses a backend without `dependency_packages`. `runtime-api` and
`runtime-cli` use it.

**`runtime-package` (`rt_package`).** The `.wrun` v1 format. It reads a package through `rt_core::unzip` plus the
package rules, verifies every file's sha256 while streaming, and writes packages reproducibly (`pack`). It is
pure: it never installs, runs, grants or looks anything up in the store. It checks dependency ids for their grammar
only; the CLI checks that they exist in the bundled manifest. Only `runtime-cli` depends on it.

**`runtime-api` (`rt_api`).** The typed, sanitised API that front ends use: apps, permissions (including what a
package requested), doctor, the dependency plan, sandbox and graphics info, and the compatibility matrix. It also
holds the host-fact gathering the CLI shares (`host`), the backend registry (`backends`: `KNOWN = ["wine"]`,
`select` by recorded id) and `jobs`, the write methods' validated job specs and `runtime` argv plus the dependency
plan digest. No API method changes anything on disk; a change is a `JobSpec` that the daemon runs through the CLI.
Every free-text field is cleaned at this boundary. `runtime-daemon`, `runtime-gui` and `runtime-cli` use it.

**`runtime-daemon` (`rt_daemon`, binary `runtimed`).** JSON-RPC 2.0 (NDJSON) over an owner-only Unix socket, with a
peer-uid check, caps and deadlines. By default it is read-only. With `--write` it keeps a job table whose every
mutation is the sibling `runtime` binary, run with a validated argv in its own process group. It also owns the
client (`rt_daemon::client`) that `runtime rpc` and the GUI use. It must never perform a mutation in-process and
never open a network socket. `runtime-gui` and `runtime-cli` depend on it; `runtime-cli` uses only the client.

**`runtime-gui` (`rt_gui`, binary `runtime-gui`).** A GTK 4 + libadwaita client of `runtimed`, outside
`default-members`. It has a toolkit-free view model (`vm`), a backend with one request thread and at most 4 job
followers, and the widgets (`ui`). It must never start a process, use the in-process API, or parse daemon text as
markup; a source scan test enforces the first two. Nothing depends on it.

**`runtime-cli` (binary `runtime`).** The command-line front end over all of the above. It is also the program that
`runtimed --write` runs for every job and that bubblewrap starts as `runtime sandbox-init`. Every string from a file
reaches the terminal through `safe()`. Nothing depends on it as a crate.

## Dependency graph

This is the workspace-internal part of `cargo tree --workspace --depth 1 -e normal` (normal dependencies only;
third-party crates are in [THIRD_PARTY.md](THIRD_PARTY.md)). Each line is a crate and the workspace crates it depends
on directly.

```text
runtime-pe
runtime-core          -> pe
runtime-backend-wine  -> core
runtime-sandbox       -> core
runtime-desktop       -> core, pe
runtime-package       -> core, pe
runtime-installer     -> core, pe, sandbox, desktop
runtime-deps          -> core, pe, installer
runtime-api           -> core, pe, backend-wine, sandbox, deps
runtime-daemon        -> core, api
runtime-gui           -> core, api, daemon
runtime-cli           -> core, pe, backend-wine, sandbox, desktop, installer, deps, package, api, daemon
```

`runtime-daemon` has no crate dependency on `runtime-cli`: it runs the `runtime` binary as a separate process.
Only `runtime-api` and `runtime-cli` name the Wine backend.

## Flows

### Install (`runtime install FILE`, `runtime import FILE.wrun`)

1. The CLI classifies the file by content (`pe::detect`), never by extension.
2. A portable `.exe` or a `.zip` goes to `rt_core::install`. It reads the input (at most 4 GiB) and plans a zip
   through `unzip`. It refuses a driver, a DLL, an installer, or an architecture or subsystem the backend's
   capabilities exclude. It builds and validates the metadata. Only then does it call `Store::create`, then
   `backend.prepare` (Wine: create and harden the prefix), then copy the program below
   `drive_c/Program Files/<id>/`, and finally write `metadata.json`. A failure after `create` removes the app.
   A zip whose first entry is `wrun.toml` is refused with "use `runtime import`".
3. A `.msi` or recognised installer `.exe` goes to `rt_installer::install_via_installer`. The installer runs in the
   installer sandbox (bwrap, seccomp, Landlock; no network unless `--network`). The pipeline then finds the
   program (or uses `--exe`), writes the metadata and creates the `.desktop` entry.
4. `runtime import` first opens and cross-checks the `.wrun` (`rt_package::open`). It refuses unknown dependency ids,
   installer-only flags on a portable package, and an id that is already installed, all before anything is
   written. A portable package then goes to `rt_core::install` in subtree mode with the fixed id, the per-file
   digests and `expect_arch`. An installer package's single file is extracted and verified into
   `<data>/staging/import-<pid>-<nanos>/` and passed to `install_via_installer` with the fixed id. Either way the
   metadata records `package` (id, version, digest, the requests), and nothing is granted, downloaded or run.

### Run (`runtime run APP`)

1. The CLI selects the backend by the app's recorded `backend.id` (`rt_api::backends::select`); an unknown id is
   refused, never run with Wine. `rt_core::run` checks the id again (a mismatch is refused) and checks the
   recorded architecture, `dotnet` and, for a sandboxed run, `sandboxable` against the backend's capabilities.
2. The program path is a canonical `WinPath` mapped with `resolve_under` into `drive_c` and must be a regular file.
3. `backend.command` describes the process (Wine: `WINEPREFIX`, `HOME`, the program, the arguments verbatim).
   `settle` wraps it so that `wineserver` flushes inside the sandbox.
4. The CLI builds the app's sandbox from its `permissions.toml` (`rt_sandbox`) and attaches it to that one spawn.
   The `Launcher` clears the environment, applies the allowlist, and lets the sandbox wrap the command: `systemd-run --user --scope` (limits), then
   `bwrap`, then `runtime sandbox-init` (seccomp, Landlock), then the program. Missing `bwrap` is a refusal unless
   the user passed `--unsandboxed`.
5. The program's stderr goes to the app's log. The exit code is the program's.

### Daemon job and GUI (`runtimed --write`, `runtime-gui`)

1. The GUI's view model turns a user action into a typed `Cmd`. The backend thread sends it through
   `rt_daemon::client`, which checks the socket's owner and mode before it sends anything.
2. `runtimed` checks the peer uid and the request size and deadline, then dispatches. A write method on a
   read-only daemon is `read_only` before its parameters are read.
3. `JobSpec::from_request` validates the parameters (absolute plain paths, typed values, bounded) and builds the
   `runtime` argv, with every path after `--`.
4. The job table runs the sibling `runtime` binary with that argv. The child gets stdin `/dev/null`, its own
   process group and `PR_SET_PDEATHSIG`. Its output becomes cleaned, bounded events.
5. Clients follow a job with `jobs.poll` (long poll) and can `jobs.cancel` it (SIGTERM to the group). The CLI
   itself re-checks everything: consent, locks and the sandbox are the CLI's own code paths, whether a job or a
   user started it.

## Trust boundaries

- **Hostile files.** These are always parsed as untrusted input and bounded before use:
  - PE files: `runtime-pe`.
  - Zip archives: `rt_core::unzip`. It plans the whole central directory before writing a byte and refuses
    traversal, links, case collisions, duplicates and bombs.
  - MSI databases, `.lnk` shortcuts and `.reg` hives written by an installer: `runtime-installer`.
  - Dependency archives (`.zip`, `.tar.gz`, `.tar.zst`): `runtime-deps`, after the pinned sha256 and size match.
  - `.wrun` packages: `runtime-package`, on top of `unzip`.
  - `metadata.json` and `permissions.toml` inside the app directory: validated on every read.
  - Program output: cleaned before it reaches a terminal or a client.
- **The sandbox.** It is the boundary between a Windows program (and Wine) and the host. Wine itself is not a
  boundary. What crosses the sandbox and what does not is in [SECURITY.md](SECURITY.md).
- **The socket.** `runtimed` serves only the same uid over an owner-only socket in `$XDG_RUNTIME_DIR`. Mutations
  need `--write`, and they happen only through the CLI with a validated argv. The GUI is one more same-uid client
  and adds no privilege.
- **The runtime's own processes are not sandboxed.** The CLI, `runtimed` and the GUI run with the user's full
  access. This is why backends are compiled in and never loaded as plugins (below).

## The backend seam

`rt_core::CompatBackend` is the only execution seam. Its contract is in the module docs of
[`crates/core/src/backend.rs`](../crates/core/src/backend.rs), version `BACKEND_API_VERSION = 1`, which `runtime
doctor` prints. The contract covers:

- the id grammar, and when `prepare`, `command`, `stop`, `settle` and `dll_dirs` may do what;
- `command` never spawns and keeps the program inside `drive_c`: symlinks, `..` and absolute paths outside are
  `OutsideDriveC`, through the shared `inside_drive_c`;
- a backend never reads `permissions.toml`, never decides sandboxing, never downloads.

A backend declares **capabilities**: guest architectures, subsystems, `dotnet`, `installers`,
`dependency_packages` and `sandboxable`. The platform refuses what they exclude before it creates or starts anything,
in `rt_core::install`, `install_via_installer`, `rt_deps` and `rt_core::run`.

The **conformance suite** (`rt_core::backend::conformance`: `static_checks`, `live_checks`) runs the same named
checks over the Wine backend (the static tier with fake paths, the live tier in the real-Wine e2e), `FakeBackend`
and a test-only `NullBackend`. The null backend installs and runs `hello64.exe` through the unmodified install and
run services. That proves the seam is backend-neutral where the platform does not need Wine's layout. Parts of the
contract (never spawning in `command`, never reading `permissions.toml`) are reviewed, not proven.

The **registry** (`rt_api::backends`) maps a recorded id to a compiled-in backend. There is no user-facing backend
choice while it lists one entry, and test doubles are never in it.

What still assumes Wine (`doctor`'s Wine checks, `runtime display`, the `wineserver` busy checks) is listed in the
contract docs as "Wine-specific, stays concrete". A second backend brings its own. `runtime display` is not yet
gated by a capability; that is to do when a second backend arrives. Only `CompatBackend` is defined: the roadmap's
graphics, window, audio and CPU backend traits have no second implementation and no caller yet, so they are not
guessed at (spec Decision B2).
