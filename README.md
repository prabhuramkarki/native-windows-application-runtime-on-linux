# Native Windows application runtime on Linux

A Linux command-line runtime that runs Windows applications through Wine, one isolated Wine prefix per app.

**Status: Phase 5B (bubblewrap sandbox plus seccomp, Landlock and resource limits), an early MVP.** `runtime run` starts every
program in a bubblewrap sandbox built from the app's permissions (default: no network, no host files, only its own
prefix writable; display, audio and GPU on), and refuses to run without a working `bwrap` (`sudo apt install
bubblewrap`) unless you pass `--unsandboxed`. Inside it, a small launcher (`runtime sandbox-init`, hidden) applies a
seccomp deny-list (mandatory) and a Landlock filesystem ruleset (when the kernel has Landlock) before the program
starts, and the run gets a task limit (a fork-bomb guard) and optional memory/CPU limits through a systemd user
scope. It is not a VM: same Linux user, and the display, audio and GPU it is given are shared
with the host (an X11 display lets a program read and inject input to other windows). See [docs/SECURITY.md](docs/SECURITY.md) for exactly what is and is not
protected. `.msi`/`.exe` installers, uninstallers and `runtime deps` installer packages run in their own `bwrap`
sandbox (Phase 3) behind the same `sandbox-init` launcher (seccomp and Landlock since Phase 5B Task 6; no resource
limits, only the dependency engine's deadline). A C# console program (including threads and garbage collection) was
verified running through Wine Mono under the `runtime run` sandbox on the development host (see .NET below); other
frameworks and GUI programs are not claimed. `runtime deps` is the only command that downloads anything, and only
when asked (see below).

## Commands

The binary is `runtime` (`cargo run -p runtime-cli -- <command>`).

| Command | What it does |
|---|---|
| `install <file.exe\|file.zip> [--name N] [--exe PATH]` | Creates an app with its own hardened Wine prefix and copies the program in. For a zip, `--exe` names the program inside it. |
| `install <file.msi\|installer.exe> [--silent] [--network] [--exe PATH]` | Installs a `.msi` or a recognised `.exe` installer (Inno Setup, NSIS, InstallShield, WiX Burn) through a `bwrap` sandbox with no display, network or host filesystem access by default. `--silent` runs it non-interactively with its family's standard silent flags; `--network` allows it network access while it runs; display, audio and D-Bus environment variables are never passed into the sandbox either way (with `--network`, an installer that guesses the host's X display can still reach it where the X server grants same-user access without a cookie; see `docs/SECURITY.md`). `--exe` names the installed program directly (a path inside the installed prefix, e.g. `Program Files\App\app.exe`), skipping automatic discovery. |
| `run <app\|file> [--debug] [--unsandboxed] [-- args...]` | Runs an installed app in its sandbox (see `permissions` and `sandbox`); a `.exe`/`.zip` path is installed first (a new app on every call, default profile). Refuses to start when bubblewrap is missing or cannot create a sandbox. `--unsandboxed` runs this once WITHOUT the sandbox and says so. Ctrl-C (or SIGTERM to `runtime`) ends the sandboxed program. The exit code is the program's, `& 0xff` (128+N when it was killed by signal N). |
| `sandbox <app>` | Shows the app's sandbox without running anything: whether bubblewrap works, the seccomp filter and the host's Landlock ABI (or why Landlock is unavailable), the `sandbox-init` launcher, the profile, its resource limits and whether systemd user scopes work, the requested pieces the host lacks, what the profile cannot enforce, and the full command line (`systemd-run` scope, `bwrap`, the launcher's Landlock rules). |
| `list [--json]` | Lists installed apps. |
| `remove <app>` | Stops the app's Wine processes and deletes the app, its prefix and its desktop menu entry/icon (if any); refuses, changing nothing, while the app still runs (a sandboxed app must be quit first). Takes an id, never a path. |
| `uninstall <app>` | Runs the app's recorded installer uninstall command (if any), sandboxed, then removes the environment and its desktop menu entry/icon regardless of what that did; like `remove`, refused while the app still runs. An app with no recorded uninstaller (a portable-exe install) behaves like `remove`. Takes an id, never a path. |
| `logs <app> [--lines N]` | Shows the end of the newest log (the app's stderr from its last run). |
| `doctor [app\|file]` | Read-only checks: Wine, the sandbox (and an app's profile), its seccomp filter and Landlock, its resource limits (`systemd-run --user` scopes), architecture, DLL imports, prefix hardening, display, the app's graphics driver setting, Vulkan, audio (the PulseAudio-compatible socket Wine uses; `pipewire-pulse` provides it). Exit 1 when a check fails. |
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

## Graphics driver (`runtime display`)

```
runtime display game            # the app's Wine graphics driver, this session, and whether Wine has winewayland
runtime display game wayland    # auto | x11 | wayland (the app must be stopped)
```

`auto` removes the setting, so Wine picks its own driver (X11/XWayland). Wayland is experimental in Wine 10.0 and
opt-in per app: `wayland` is refused without a Wayland session or without `winewayland` in the Wine build.

## Permissions (`runtime permissions`)

```
runtime permissions game                                  # the app's profile (permissions.toml) and its source
runtime permissions game --set network=allow --set gpu=off
runtime permissions game --set fs+=/home/me/saves:rw      # grant a host directory (ro | rw); fs-=<dir> removes it
runtime permissions game --set memory=2048 --set cpu=150  # MiB (no swap); percent of one CPU; `off` removes
runtime permissions game --set tasks=256                  # processes+threads; `unlimited`, or `default` (4096)
runtime permissions game --reset                          # back to the default; --json for scripts
```

Limits run the app's sandbox in a `systemd-run --user --scope` (cgroup v2). The default task limit (4096) is
applied when a user manager is available and skipped with a note otherwise; a limit you set is mandatory: without a
working `systemd-run --user` the app does not start (`runtime doctor` and `runtime sandbox <app>` say why). Bounds:
memory 64..1048576 MiB, cpu 1..100 x the CPUs you have (a stored profile loads anywhere up to 409600), tasks
16..65536. Resource limits need systemd 254 or newer (older: the default is skipped with a note, set limits refuse).

The default is no network, no host directories, and display, audio and gpu on. The profile is stored in the app's
own directory, checked strictly, and changed only while the app is stopped. A grant must be an existing absolute
directory (never a socket or file); symlinks are resolved and the target is judged. `$HOME`, `/`, the runtime's data directory, `~/.ssh`,
`~/.gnupg`, `~/.aws`, `~/.config/gcloud`, `~/.kube`, `~/.docker`, `~/.password-store` (and anything containing or
inside them, for `$HOME` and the account's real home), `/proc`, `/sys`, `/dev`, `/run`, `/var/run`, `/tmp`
and everything below it, and `$XDG_RUNTIME_DIR` are always refused, and `rw` is refused on `/etc`, `/usr`, `/var`, `/opt` and
the other system trees (`ro` is allowed). (`/tmp` is refused whole: other programs'
sockets live there under arbitrary names.) `runtime run` enforces the profile; `runtime sandbox <app>` shows the resulting `bwrap` command.

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
  actually rendering Direct3D 12 needs a GPU and driver with Vulkan 1.3 and is not verified anywhere. CI verifies
  the `.tar.zst` install path and the manifest entry's paths and overrides on real Wine with a fixture archive;
  the pin's download is re-verified weekly by `verify-pins`; installing the real downloaded package on Wine is a
  manual `--ignored real_net_*` run. `runtime graphics info` shows what
  the host offers (Vulkan loader, devices and API versions, from a bounded `vulkaninfo` run), and `deps` marks
  `dxvk` and `vkd3d-proton` as blocked, with the reason, when Vulkan is unusable (and `deps --install` skips them).
- **VC++ 2015-2022 redistributable x64 14.44.35211** (Microsoft, consent): Microsoft's installer, run offline in the
  installer sandbox on a one-run null-driver desktop; success is its registry marker; 16 DLL overrides set after.

.NET: the bundled `wine-mono` package is Wine Mono 9.4.0 (the version that matches Wine 10.0; an 85 MB pinned
download, about 231 MiB in each app that installs it). A managed program imports `mscoree`, so `runtime deps <app>`
plans it, and once it is recorded for the app `runtime run` enables `mscoree` for that app's program only (a native
app, and every installer or helper, keep it disabled). Verified on 2026-09-26 (Wine 10.0, kernel 7.0, Landlock ABI 8;
`crates/cli/tests/e2e_dotnet.rs`): a C# console program (`tools/fixtures/hello-managed.cs`, built with Wine Mono's
own compiler by `tools/build-managed-fixture.sh`) installed, got Wine Mono through `runtime deps <app> --install`, and
ran through `runtime run` under the default sandbox (bwrap, seccomp, Landlock, task limit): arguments, exit code,
four JIT-compiled threads under a lock and 64 MiB of allocation with a forced GC; no seccomp or Landlock change was
needed. Not claimed: GUI programs (WinForms/WPF), a real .NET Framework 4.8 application, or other frameworks (.NET
Core / .NET 5+ are not Mono). `runtime doctor <app>` says whether Wine Mono is recorded.

Known gaps: `d3dcompiler_47` (no verifiable redistributable
source), Gecko (no package; `mshtml` stays disabled), 32-bit apps (x64 DLLs only; the plan warns), no
package upgrades (a newer pinned version is refused: recreate the app) and no removal of a single package (removing
the app removes everything). A component the app's own installer already put in the prefix (e.g. the VC++ runtime) is
left alone: the runtime neither installs it nor sets its DLL overrides (`deps` and `doctor` say so).

**Rendering check (manual only).** `real_net_wine_d3d11_renders_via_dxvk` downloads and installs the bundled DXVK
into a fresh prefix and runs `tools/fixtures/d3d11.c` (`d3d11_64.exe`): an offscreen D3D11 device (no window, no
swapchain) clears a 64x64 target and reads one pixel back. It passes only when the pixel is right, the program exits
0, system32's `d3d11.dll` is byte-identical to DXVK's and DXVK's own log shows it created its Vulkan device on the
adapter the program reports. `DXVK_FILTER_DEVICE_NAME=<name>` picks the Vulkan device. It proves that DXVK 3.1.1
renders on that Wine, driver and GPU; it does not prove any real app or game works, and its `frame ms` (CPU time to
submit 100 clears) is printed, never asserted. No CI runner has a GPU, so it runs by hand only and its results go
into the matrix below as `manual:` records. It needs a display session: headless, Wine 10.0's winevulkan cannot
create a Vulkan instance. x86_64 only, like the bundled DXVK (32-bit Direct3D stays on Wine's wined3d).

## Compatibility (`runtime compat`)

`runtime compat [--json]` prints the compatibility matrix: only what was really run (a CI job or a dated manual
check), on which Wine, with what result; it needs no Wine, store or network. The same table is
[docs/COMPAT.md](docs/COMPAT.md), generated from `crates/api/compat.toml` (a test fails when they differ;
regenerate with `cargo run -q -p runtime-cli -- compat > docs/COMPAT.md`).

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
RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-backend-wine -p runtime-cli -- --ignored --skip real_net_ --test-threads=1
                                        # real-Wine end-to-end tests and the sandbox escape suite (minutes; Wine 10, bwrap, fixtures)
DXVK_FILTER_DEVICE_NAME=<device> cargo test -p runtime-cli --test e2e_sandbox -- --ignored real_net_wine_d3d11 --nocapture
                                        # the D3D11 fixture through DXVK under the default sandbox (internet, Vulkan, display)
RUNTIME_REQUIRE_BWRAP=1 cargo test -p runtime-deps --lib -- --ignored e2e_real_wine --test-threads=1
                                        # dependency engine on real Wine + bwrap (local HTTPS server, no internet)
cargo test -p runtime-deps --lib -- --ignored real_net --nocapture
                                        # re-downloads the bundled pins (internet; weekly in CI, verify-pins.yml)
cargo test -p runtime-deps --lib -- --ignored real_net_wine_d3d11 --test-threads=1 --nocapture
                                        # D3D11 render through DXVK on real Wine (internet, Vulkan device, display)
RUNTIME_SAMPLES=dir1:dir2 cargo test -p runtime-pe -- --ignored --nocapture
                                        # PE oracle: compares every PE under those dirs with file(1)
cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings
```

The Wine tests use temporary data directories, stop and kill their `wineserver` on exit, and never run
`gui64.exe` (a modal message box; run it by hand to look at a window). Run them with `--test-threads=1`.
On Wine older than 10 their 32-bit steps are skipped with a `SKIPPED 32-bit` message. Each test removes its apps with a
persistent `wineserver` running and requires that `runtime remove` ends it.
The escape suite (`crates/cli/tests/e2e_sandbox.rs`) runs a real Windows probe (`probe64.exe`) inside the sandbox
and tries to read a fake home's `.ssh` secret, write to that home, read another app's prefix, read or rewrite its
own `permissions.toml`, connect to a local TCP listener, and step outside a granted directory. Each action must fail
sandboxed AND succeed with `--unsandboxed` on the same target, so the sandbox is shown to be what stops it; what the
suite does not prove is in `docs/SECURITY.md` ("The escape suite"). Since Phase 5B it also checks that the program
runs under the seccomp filter and that cross-process memory and thread contexts (wineserver's `ptrace` use) still work,
that a fork bomb and a memory hog stop at the app's limits, and (the `syscall_escape_*` tests, no Wine needed) that a
Linux helper run through the real `sandbox-init` launcher is refused 36 denied system calls covering every class the
spec names (`ptrace`, `unshare`/`clone` into a new user namespace, the mount family, `keyctl`, `bpf`, module and kexec
loading, `reboot`, `TIOCSTI`, `AF_VSOCK`, `int 0x80`, ...), with EPERM except `clone3` (ENOSYS), while the same command
with bubblewrap alone answers differently wherever the kernel's own answer is not EPERM too (28 of the 36 on the
development host), that the installer sandbox refuses the same calls through the same launcher, and that `ptrace`
reaches only the app's own Landlock domain. With `RUNTIME_REQUIRE_BWRAP=1` these
tests also require seccomp, Landlock and IA32 emulation instead of skipping.
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
- `crates/api`: `rt_api`, the typed, sanitised, read-only API (`Runtime`: apps, permissions, doctor, dependency
  plan, sandbox and graphics info, compatibility matrix) and the host-fact gathering the CLI shares (`rt_api::host`).
- `crates/cli`: the `runtime` binary, a thin front end over the above.
- `tools/`: fixture build script and fixture sources. `docs/`: security model, third-party inventory, plans.

The roadmap and the phase plans, with notes on where the code departs from them, are in
`docs/superpowers/plans/`. Third-party components and licences: [docs/THIRD_PARTY.md](docs/THIRD_PARTY.md).
