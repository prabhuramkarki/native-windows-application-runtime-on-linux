# Native Windows application runtime on Linux

A Linux command-line runtime that runs Windows applications through Wine, one isolated Wine prefix per app.

**Status: Phase 2, an early MVP, and it is NOT sandboxed.** Windows programs run as your Linux user, with your
network, GPU, audio and files; Wine can still reach the whole host (see [docs/SECURITY.md](docs/SECURITY.md)
for what is and is not protected). Only run software you would run directly on your account. Installers and MSI
packages are refused (Phase 3), .NET programs fail until Phase 4, and the sandbox is Phase 5.

## Commands

The binary is `runtime` (`cargo run -p runtime-cli -- <command>`).

| Command | What it does |
|---|---|
| `install <file.exe\|file.zip> [--name N] [--exe PATH]` | Creates an app with its own hardened Wine prefix and copies the program in. For a zip, `--exe` names the program inside it. |
| `run <app\|file> [--debug] [-- args...]` | Runs an installed app; a `.exe`/`.zip` path is installed first (a new app on every call). The exit code is the program's, `& 0xff` (128+N when it was killed by signal N). |
| `list [--json]` | Lists installed apps. |
| `remove <app>` | Stops the app's Wine processes and deletes the app and its prefix. Takes an id, never a path. |
| `logs <app> [--lines N]` | Shows the end of the newest log (the app's stderr from its last run). |
| `doctor [app\|file]` | Read-only checks: Wine, architecture, DLL imports, prefix hardening, display, Vulkan, audio. Exit 1 when a check fails. |
| `analyze [--json] <file>` | Reports what a PE file or installer is and needs (header-based, extension ignored). |

```sh
runtime install ~/Downloads/tool.exe --name tool
runtime run tool -- --some-arg
runtime list
runtime remove tool
```

`--json` output is the stable interface for `list`, `doctor` and `analyze`; free-form text fields (warnings,
check texts) may change, do not parse them. Strings from files are escaped in human output; in JSON,
sanitise before displaying.

## Requirements

- Linux on x86-64 with **Wine 10** (`wine64` or `wine`, and `wineserver`; on Debian/Ubuntu `apt install wine`).
  Wine 10.0 is what was tested. 32-bit programs run through Wine 10's WoW64, no 32-bit Wine is needed; Wine 9
  (Ubuntu 24.04) may lack that and is untested. `wine`/`wine64` is looked up on `PATH`; `wineserver` on `PATH`
  and then in a fixed list of directories (it is not on `PATH` on some distributions, e.g. Ubuntu 26.04;
  Ubuntu 24.04's Wine 9 is reported to use `/usr/lib/wine/wineserver64`, which is searched too but was not
  verified here). Override both with `RUNTIME_WINE=/abs/path/to/wine` and
  `RUNTIME_WINESERVER=/abs/path/to/wineserver` (a wrong value is an error, not a fallback).
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
RUNTIME_SAMPLES=dir1:dir2 cargo test -p runtime-pe -- --ignored --nocapture
                                        # PE oracle: compares every PE under those dirs with file(1)
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
```

The Wine tests use temporary data directories, stop and kill their `wineserver` on exit, and never run
`gui64.exe` (a modal message box; run it by hand to look at a window). Run them with `--test-threads=1`.
On Wine older than 10 their 32-bit steps are skipped with a `SKIPPED 32-bit` message. Each test removes its apps with a
persistent `wineserver` running and requires that `runtime remove` ends it.
Fixtures: `hello{32,64}.exe` (print `hello from windows`, exit 7), `fs{32,64}.exe` (file, environment and
directory probe for the isolation tests), `gui{32,64}.exe`, `exports{32,64}.dll`.

## Layout

- `crates/pe`: hardened parser for untrusted PE files (Phase 1).
- `crates/core`: app ids, data dir, Windows path handling, metadata and store, install/run services,
  `doctor`, the `CompatBackend` trait and the `Launcher` (the one place child processes are started).
- `crates/backend-wine`: the system-Wine backend: discovery, prefix creation and hardening.
- `crates/cli`: the `runtime` binary, a thin front end over the above.
- `tools/`: fixture build script and fixture sources. `docs/`: security model, third-party inventory, plans.

The roadmap and the phase plans, with notes on where the code departs from them, are in
`docs/superpowers/plans/`. Third-party components and licences: [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md).
