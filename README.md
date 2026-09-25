# Native Windows application runtime on Linux

A Linux command-line runtime that runs Windows applications through Wine, one isolated Wine prefix per app.

**Status: Phase 4A (dependency engine), an early MVP, and app runs are NOT sandboxed.** Windows programs run as your Linux user, with
your network, GPU, audio and files; Wine can still reach the whole host (see
[docs/SECURITY.md](docs/SECURITY.md) for what is and is not protected). Only run software you would run
directly on your account. `.msi`/`.exe` installers now install through a `bwrap` sandbox (Phase 3) — narrower
than a plain app run, but not a full boundary either, see SECURITY.md's "Installer sandbox" section — and
`.NET` programs still fail (no .NET package yet); the sandbox for ordinary app runs is Phase 5. `runtime deps` is the
only command that downloads anything, and only when asked (see below).

## Commands

The binary is `runtime` (`cargo run -p runtime-cli -- <command>`).

| Command | What it does |
|---|---|
| `install <file.exe\|file.zip> [--name N] [--exe PATH]` | Creates an app with its own hardened Wine prefix and copies the program in. For a zip, `--exe` names the program inside it. |
| `install <file.msi\|installer.exe> [--silent] [--network] [--exe PATH]` | Installs a `.msi` or a recognised `.exe` installer (Inno Setup, NSIS, InstallShield, WiX Burn) through a `bwrap` sandbox with no display, network or host filesystem access by default. `--silent` runs it non-interactively with its family's standard silent flags; `--network` allows it network access while it runs; display, audio and D-Bus environment variables are never passed into the sandbox either way (with `--network`, an installer that guesses the host's X display can still reach it where the X server grants same-user access without a cookie; see `docs/SECURITY.md`). `--exe` names the installed program directly (a path inside the installed prefix, e.g. `Program Files\App\app.exe`), skipping automatic discovery. |
| `run <app\|file> [--debug] [-- args...]` | Runs an installed app; a `.exe`/`.zip` path is installed first (a new app on every call). The exit code is the program's, `& 0xff` (128+N when it was killed by signal N). |
| `list [--json]` | Lists installed apps. |
| `remove <app>` | Stops the app's Wine processes and deletes the app, its prefix and its desktop menu entry/icon (if any). Takes an id, never a path. |
| `uninstall <app>` | Runs the app's recorded installer uninstall command (if any), sandboxed, then removes the environment and its desktop menu entry/icon regardless of what that did. An app with no recorded uninstaller (a portable-exe install) behaves like `remove`. Takes an id, never a path. |
| `logs <app> [--lines N]` | Shows the end of the newest log (the app's stderr from its last run). |
| `doctor [app\|file]` | Read-only checks: Wine, architecture, DLL imports, prefix hardening, display, Vulkan, audio. Exit 1 when a check fails. |
| `analyze [--json] <file>` | Reports what a PE file or installer is and needs (header-based, extension ignored). |
| `deps <app> [--install] [--yes PKG]... [--discard-interrupted PKG]` | Plans (no network, no changes) and with `--install` downloads, verifies and installs the packages an app needs, see below. |
| `deps list` / `deps cache [--clear]` | Shows the bundled package manifest / the download cache (`--clear` deletes completed downloads). |

```sh
runtime install ~/Downloads/tool.exe --name tool
runtime install ~/Downloads/setup.msi --silent
runtime run tool -- --some-arg
runtime list
runtime uninstall tool
runtime remove tool
```

`--json` output is the stable interface for `list`, `doctor` and `analyze`; free-form text fields (warnings,
check texts) may change, do not parse them. Strings from files are escaped in human output; in JSON,
sanitise before displaying.

## Dependencies (`runtime deps`)

```sh
runtime deps game                      # the plan: what the app's imports need, what is installed, warnings
runtime deps game --install            # download, verify and install it; consent-gated packages ask first
runtime deps game --install --yes vcrun2022   # no terminal: consent to that one package (its text is printed)
runtime deps game --discard-interrupted dxvk  # undo what a killed install left, then install again
runtime deps list                      # the bundled manifest
runtime deps cache --clear             # delete cached downloads
```

The plan comes from the app's PE imports (e.g. `d3d11.dll` needs DXVK, `msvcp140.dll` the VC++ runtime).
`install`, `run` and `doctor` never download; `install` and `doctor` print a one-line hint when something is missing.
Every download is pinned (https, exact size and sha256 from the manifest compiled into the binary) and cached in
`<data>/deps-cache`. Packages with a proprietary licence need consent per package and version: the prompt shows the
package, version, licence label, url, size and sha256, and for a vendor installer says that running it silently
accepts the vendor's EULA, which is not shown. A bare `--yes` is refused. Exit code 1 when anything failed or was
skipped. How downloads are verified and what is not: `docs/SECURITY.md`, "Dependency downloads".

Bundled packages (pins in [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md)):
- **DXVK 3.1.1** (Zlib, no consent): d3d8, d3d9, d3d10core, d3d11 and dxgi, x64 DLLs with `native,builtin` overrides.
- **VKD3D-Proton 3.0.1** (LGPL-2.1-or-later, no consent, needs DXVK): d3d12 and d3d12core, x64 DLLs with
  `native,builtin` overrides, read from upstream's `.tar.zst` by the bounded zstd reader. Installing works on any host;
  actually rendering Direct3D 12 needs a GPU and driver with Vulkan 1.3, which CI does not have, so rendering is not
  verified in CI (only the download, install and overrides are, on real Wine). `runtime graphics info` shows what
  the host offers (Vulkan loader, devices and API versions, from a bounded `vulkaninfo` run), and `deps` marks
  `dxvk` and `vkd3d-proton` as blocked, with the reason, when Vulkan is unusable.
- **VC++ 2015-2022 redistributable x64 14.44.35211** (Microsoft, consent): Microsoft's installer, run offline in the
  installer sandbox on a one-run null-driver desktop; success is its registry marker; 16 DLL overrides set after.

Known gaps: `d3dcompiler_47` (no verifiable redistributable
source), .NET, Mono and Gecko (no packages; they stay disabled), 32-bit apps (x64 DLLs only; the plan warns), no
package upgrades (a newer pinned version is refused: recreate the app) and no removal of a single package (removing
the app removes everything). A component the app's own installer already put in the prefix (e.g. the VC++ runtime) is
left alone: the runtime neither installs it nor sets its DLL overrides (`deps` and `doctor` say so).

## Requirements

- Linux on x86-64 with **Wine 10** (`wine64` or `wine`, and `wineserver`; on Debian/Ubuntu `apt install wine`).
  Wine 10.0 is what was tested. 32-bit programs run through Wine 10's WoW64, no 32-bit Wine is needed; Wine 9
  (Ubuntu 24.04) may lack that and is untested. `wine`/`wine64` is looked up on `PATH`; `wineserver` on `PATH`
  and then in a fixed list of directories (it is not on `PATH` on some distributions, e.g. Ubuntu 26.04;
  Ubuntu 24.04's Wine 9 is reported to use `/usr/lib/wine/wineserver64`, which is searched too but was not
  verified here). Override both with `RUNTIME_WINE=/abs/path/to/wine` and
  `RUNTIME_WINESERVER=/abs/path/to/wineserver` (a wrong value is an error, not a fallback).
  `RUNTIME_VULKAN_LOADER=present|absent` overrides the Vulkan loader lookup (used by the tests; any other
  value, or unset, means the real lookup).
- Stable Rust 1.88 or newer to build (`cargo build`).
- mingw-w64 (`apt install mingw-w64`) only to build the test fixtures, never to use the program.

## Where things live

`RUNTIME_DATA_DIR` (absolute path) holds the data; without it `$XDG_DATA_HOME/runtime` or
`~/.local/share/runtime`. Each app is `<data>/apps/<id>/` with `prefix/` (the Wine prefix, `prefix/drive_c` is
the app's `C:`), `runtime/home/` (the program's `HOME`, so Wine does not hand it yours; see `docs/SECURITY.md` for what still shows through), `logs/` (20 kept) and
`metadata.json`. `RUNTIME_LOG=debug` turns on the runtime's own logging.

## Tests

```sh
tools/build-fixtures.sh                 # test .exe/.dll files into tests/fixtures/build (mingw-w64)
cargo test --workspace                  # unit, hostile-input and hermetic CLI tests; no Wine needed
cargo test -p runtime-backend-wine -p runtime-cli -- --ignored --test-threads=1
                                        # real-Wine end-to-end tests (minutes; needs Wine 10 and the fixtures)
RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-deps --lib -- --ignored e2e_real_wine --test-threads=1
                                        # dependency engine on real Wine + bwrap (local HTTPS server, no internet)
cargo test -p runtime-deps --lib -- --ignored real_net --nocapture
                                        # re-downloads the bundled pins (internet; weekly in CI, verify-pins.yml)
RUNTIME_SAMPLES=dir1:dir2 cargo test -p runtime-pe -- --ignored --nocapture
                                        # PE oracle: compares every PE under those dirs with file(1)
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
```

The Wine tests use temporary data directories, stop and kill their `wineserver` on exit, and never run
`gui64.exe` (a modal message box; run it by hand to look at a window). Run them with `--test-threads=1`.
On Wine older than 10 their 32-bit steps are skipped with a `SKIPPED 32-bit` message. Each test removes its apps with a
persistent `wineserver` running and requires that `runtime remove` ends it.
Fixtures: `hello{32,64}.exe` (print `hello from windows`, exit 7), `fs{32,64}.exe` (file, environment and
directory probe for the isolation tests), `gui{32,64}.exe`, `exports{32,64}.dll`, `hello.msi` (built with
`wixl`) and `hello-nsis.exe` (built with `makensis`) for the installer-pipeline tests
(`crates/cli/tests/e2e_installers.rs`), both wrapping the same `hello64.exe` payload.

## Layout

- `crates/pe`: hardened parser for untrusted PE files (Phase 1).
- `crates/core`: app ids, data dir, Windows path handling, metadata and store, install/run services,
  `doctor`, the `CompatBackend` trait and the `Launcher` (the one place child processes are started).
- `crates/backend-wine`: the system-Wine backend: discovery, prefix creation and hardening.
- `crates/installer`, `crates/desktop`: installer pipeline and sandbox (Phase 3), desktop entries.
- `crates/deps`: the dependency engine: bundled manifest, resolver, verified HTTPS fetch, archive and installer
  package installers (Phase 4A).
- `crates/cli`: the `runtime` binary, a thin front end over the above.
- `tools/`: fixture build script and fixture sources. `docs/`: security model, third-party inventory, plans.

The roadmap and the phase plans, with notes on where the code departs from them, are in
`docs/superpowers/plans/`. Third-party components and licences: [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md).
