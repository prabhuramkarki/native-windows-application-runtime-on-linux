# Security model (Phase 2)

**Phase 2 is NOT a sandbox.** A Windows program started by `runtime run` runs as your Linux user, with your
network, GPU, audio and display, and can read and write everything that user can. The measures below make
accidents less likely and remove Wine's most obvious host exposure. They do not stop a program that wants out.
The real boundary is planned for Phase 5. Every command that runs Windows code prints a note saying so.

## Threat model

Assume the installer or application is **malicious**. It will run Windows code inside Wine as your uid. What this
project tries to protect is the *runtime's own* handling of untrusted input (archives, PE files, `metadata.json`,
file names, program output) so that merely installing, listing, inspecting or removing something cannot hurt you.
It does not protect anything a running program can reach on its own. Do not run software you would not run
directly on your account. Treat the separation between apps (separate prefixes) as accident prevention, not a
guarantee: a hostile program can go around it (below).

## What Phase 2 does

Covered by unit or hostile-input tests; items marked (e2e) are also checked against real Wine by the
`#[ignore]`d tests (`crates/cli/tests/e2e_wine.rs`, `crates/backend-wine/tests/e2e_wine.rs`).

- **One Wine prefix per app**, under `$RUNTIME_DATA_DIR/apps/<id>/prefix` (default `~/.local/share/runtime`).
  A second app does not see the first app's `C:` files (e2e).
- **Prefix hardening** after creation (`crates/backend-wine/src/harden.rs`): `dosdevices` is reduced to `c:`, so
  there is no `Z:` drive (e2e: `Z:\etc\hostname` is not found from inside the app); every symlink under `drive_c`
  that resolves outside it (Wine's links to the real Desktop, Documents, ...) is replaced by an empty real
  directory or removed (e2e). It decides by `lstat`, resolves one link at a time (`canonicalize`/`metadata`) only
  to learn where it points, and never descends into a link; it refuses a symlinked prefix or `drive_c`. The
  whole tree is examined before anything is changed. `runtime doctor <app>` audits the same state read-only.
- **The app's own `HOME`**: Wine derives the program's home (`WINEHOMEDIR`), shell folders and caches from
  `HOME`, so passing the host `HOME` handed the real home to every app. The backend sets `HOME` to
  `<app>/runtime/home` (0700, checked to be a real directory) for `wineboot`, the program and `wineserver -k`
  alike (e2e: `WINEHOMEDIR` is that directory). With it Wine creates no home links at all (checked on Wine 10.0
  by listing a fresh prefix); hardening still runs. This is hygiene: see "What the program can still learn".
- **Environment allowlist**: the program starts with `env_clear()` plus `PATH HOME USER LOGNAME LANG LANGUAGE
  LC_* TERM DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_RUNTIME_DIR XDG_SESSION_TYPE DBUS_SESSION_BUS_ADDRESS
  PULSE_SERVER` (`HOME` is then replaced as above). API keys, `SSH_AUTH_SOCK`, `LD_PRELOAD` and any host `WINE*`
  variable are dropped, and so is any value containing NUL (e2e: a host variable is not visible inside the app).
- **Zip extraction defences** (`crates/core/src/unzip.rs`): the end record and central directory are validated
  strictly *before* the zip library sees the file (one valid end record at the exact end of the file, consistent
  counts, at most 20 000 entries and, separately, at most 20 000 directories (`max_dirs`), directory at most
  64 MiB, zip64 checked); at most 4 GiB in total and per entry;
  a compression-ratio limit; only regular files and directories are extracted, symlink and special entries are
  skipped; names follow Windows path rules (no `..`, absolute or drive paths, reserved device names, backslash
  tricks) and are never trusted as given; files are created with `create_new` (no overwrite, never through a
  link) and archive permission bits are ignored.
- **`AppId` and Windows path containment**: app ids match `^[a-z0-9][a-z0-9._-]*$`, at most 64 characters, no
  `..`, and may not end in `.` or `-`; `remove` and `logs` accept ids only, never paths. Windows paths from
  metadata or archives are parsed (`winpath.rs`) and resolved case-insensitively under `drive_c` without
  traversing symlinks.
- **Atomic, bounded metadata**: `metadata.json` is written to a temporary file, synced and renamed; reads are
  size-capped and non-blocking, the schema version is checked, string fields are capped.
- **Read-only `doctor`**: it installs and changes nothing, and reports what it could not check.
- **No shell anywhere**: every child process is started from an argument vector; arguments reach the program
  verbatim (tested with quotes, `;`, `$(...)` and newlines).
- **Terminal-escape sanitising** of what the runtime itself prints from untrusted text (names, PE strings,
  `logs`, `doctor`, `list`, error messages): control and bidi characters are escaped. `list --json` and
  `doctor --json` also escape C1 and bidi characters. **`analyze --json` does not** (JSON only escapes controls
  below U+0020): sanitise its strings before displaying them. Text the *program* prints is not the runtime's
  text (below).
- **Cleanup**: `remove` stops the app's `wineserver` first; the e2e tests start a persistent `wineserver` for an
  app and require that `runtime remove` alone ends it.

## What Phase 2 does NOT do

- **No sandbox boundary.** No seccomp, namespaces, Landlock or bubblewrap. The program shares the host's
  network (it can connect anywhere), GPU, audio and display sockets.
- **Wine's `\\?\unix\` escape.** Wine maps the host filesystem into the NT namespace regardless of drive letters.
  From a Windows program, `\\?\unix\etc\hostname` (in a C string `"\\\\?\\unix\\etc\\hostname"`) names the
  host's `/etc/hostname`; `\\?\unix\etc\passwd` and `\\?\unix\home` are found the same way, with the `Z:` drive
  gone. Verified by hand on Wine 10.0 with the `fs64.exe` fixture (`stat` prints `EXISTS`). Removing `Z:`, the
  home links and the host `HOME` is defence in depth against casual access, nothing more, and there is
  deliberately no test that claims isolation from `\\?\unix\`. It also means one app can read another app's
  prefix.
- **`com*` links come back.** Wine recreates `dosdevices/com1..` (links to `/dev/ttyS*`) whenever a prefix
  starts. Only `c:` is left after `prepare`; the e2e tests allow `com*` after a run. Not preventable without a
  sandbox.
- **Terminal and stdin.** The program's stdout and stdin are the CLI's own (needed for console programs): it can
  write terminal escape sequences to your terminal on every run, not only with `--debug`, and read what you type.
  `--debug` additionally copies its stderr to the terminal as it is; the log keeps the same bytes and `logs`
  sanitises them.
- **What the program can still learn** (observed inside an app on Wine 10.0): the host user name (`USERNAME`,
  `WINEUSERNAME`, `USER`, `LOGNAME`, `C:\users\<name>`), the host name (`COMPUTERNAME`), the host path of the
  app's home (`WINEHOMEDIR`, `\??\unix<data dir>/apps/<id>/runtime/home`, which contains your real home path
  with the default data directory) and of its prefix (`WINEPREFIX`), `XDG_RUNTIME_DIR` (so your uid),
  `DISPLAY`, `WAYLAND_DISPLAY`. The Windows environment shows `HOME` as unset. The variables that are passed are
  visible to Wine and its host-side processes.
- **What redirecting `HOME` costs.** Everything a program would look up under your home is gone, on purpose:
  user fonts (`~/.fonts`, `~/.local/share/fonts`, `~/.config/fontconfig`; the per-app fontconfig cache is rebuilt
  on the first run), `~/.drirc` and `~/.config/drirc.d` and other user GPU settings, `~/.asoundrc` and
  `~/.config/pulse/client.conf` (audio), cursor and icon themes, and the default-handler configuration used by
  `xdg-open`/`winebrowser`. Shader and GPU caches live in `runtime/home/.cache`: they are per app, start cold and
  grow with use. X11 authentication is handled: when `DISPLAY` is set, `XAUTHORITY` is unset or empty and
  `$HOME/.Xauthority` (the host's `HOME`) is a regular file (not a symlink or a directory), the runtime passes
  that path as `XAUTHORITY` (the path only, never the contents; a host `XAUTHORITY` is left as it is). Checked by
  unit tests, not against a real X server. Two things matter for Phase 4: Vulkan ICD and implicit-layer discovery
  under `$HOME/.local/share/vulkan` and `~/.config/vulkan` (`XDG_DATA_HOME` is not allowlisted) no longer sees
  user-installed drivers or layers (system files under `/usr/share/vulkan` still work), and the Wine Mono/Gecko
  download cache in `~/.cache/wine` is not visible, so a dependency mechanism must use an explicit cache path.
- **Session D-Bus.** `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` are allowlisted, so a program that speaks
  D-Bus can reach the session bus (keyring/secret service, portals). Not tested.
- **Races (TOCTOU).** Checks such as "not a symlink" are followed by uses without `openat2`/`O_PATH`
  confinement, and a same-uid process (the app itself) that keeps swapping directories for links can win a race
  against `run`, `logs`, `doctor` or `remove`. Some cases are narrowed (`O_NOFOLLOW`, `O_NONBLOCK`, lstat before
  use, `remove_dir_all` does not follow links), none are closed. `wineboot` runs before hardening, so on an
  already existing prefix it could follow links planted by an earlier run.
- **Hardening and `doctor` limits.** Both refuse a prefix with more than 12 directory levels or 200 000 entries
  below `drive_c` (an error, not a partial job). `doctor` merges the 32-bit and 64-bit DLL directories, so a DLL
  present only for the other bitness can be reported as available.
- **Zip rules stricter than the format.** These valid archives are refused on purpose: self-extracting archives
  (data before the first entry), archives with signature records, an archive that contains a stored
  (uncompressed) zip in its last 64 KiB, and archives with more than 20 000 entries or a directory over 64 MiB.
- **Memory.** `analyze`, `install` and `doctor` read a whole file into memory, up to 4 GiB.
- **Logs.** One log per run under `logs/`, 20 kept per app, no size limit on a single log (a program can fill the
  disk). `logs` prints only the end of the newest one.
- **No locking.** `remove` can race `run` (or a second `run`); the last writer wins and a run can lose its
  prefix. `remove` deletes the app and its prefix even when stopping its `wineserver` failed (it warns), so a
  Wine process may keep running on a deleted prefix. Do not run several commands on one app at once.
- **Interrupted installs.** Ctrl-C or a kill during `install`, and especially during `run <file>` (which installs
  first), can leave a partial app that `remove` cleans up.
- **Run-by-path installs every time.** `runtime run some.exe` creates a *new* app on each invocation
  (`some-2`, `some-3`, ...) with its own prefix. Use `install` once and `run <id>` afterwards.
- **.NET, Mono and Gecko are disabled** by `WINEDLLOVERRIDES=winemenubuilder.exe=d;mscoree=d;mshtml=d`, so .NET
  and HTML-embedding programs fail until Phase 4 provides a dependency mechanism. `doctor` warns about .NET.
- **Installers and MSI are refused** (Phase 3); only portable `.exe` files and `.zip` archives are handled.

## Installer sandbox (Phase 3 Task 5)

`rt_installer::InstallerSandbox` is a `bwrap` profile for the installer helper processes Task 6 will run
through it (unpacking an installer payload, running a silent `.exe`/`.msi`). **It is scoped to those helpers,
not to Wine app runs in general**: a plain `runtime run` still has none of this (the "What Phase 2 does NOT do"
list above is still the truth for it) until a later phase attaches a sandbox to every app's `Launcher`, not
just the installer's. It is wired through the same `Launcher::wrap` seam named in the roadmap below (now a
`Sandbox` trait a `Launcher` can optionally carry, rather than a hard-coded identity function), so a sandboxed
run still goes through `Launcher::spawn`/`run_helper`, never a second `Command::spawn` path.

**The profile**, verified against a real `bwrap` (bubblewrap 0.11.1) in `crates/installer/src/sandbox/tests.rs`:
- The app's own `prefix` (which contains `drive_c`) is bound read-write, at the same path. Nothing else on the
  real filesystem is bound: no `Downloads`, no other app's data, no arbitrary host path.
- `/usr`, `/bin`, `/lib`, `/lib64`, `/etc/alternatives` are bound read-only (a fixed, documented set a system
  Wine package needs to run at all — not a walk of its actual shared-library dependency closure, and not
  everything under `/`; a distro without one of these directories just does not get it, `--ro-bind-try`; `/bin`
  was added by Task 8, see below — plain Wine binaries alone were not the whole story), plus any extra
  read-only paths the caller passes (`SandboxOpts::extra_ro_binds`, also `--ro-bind-try`) — for a Wine install
  outside the fixed set, e.g. a WineHQ package under `/opt/wine-stable`. Nothing walks the fixed set today, so a
  Wine there needs Task 6 to add its install root explicitly.
- `$HOME` is never the real one: an empty `tmpfs` stands in for whatever the finalized command's own `HOME` is
  (real bwrap test: the directory exists and is empty, a canary file placed at the real `$HOME` cannot be read).
  The prefix bind and this `$HOME` tmpfs are ordered relative to each other at runtime, never a fixed argv
  order: a later bwrap mount wins over an earlier one at the same or a nested path, so if `$HOME` were ever the
  prefix itself or a directory above it, mounting it in a fixed order could silently swallow the whole prefix
  (reproduced against real bwrap, then fixed and regression-tested: `when_home_is_an_ancestor_of_the_prefix_*`,
  `real_sandbox_prefix_is_not_shadowed_when_home_is_an_ancestor_of_it`).
- A private, empty `/tmp` (`tmpfs`), a fresh `/proc` and a fresh `/dev` (never `--dev-bind`, which would hand
  over the host's real device nodes).
- A fresh PID, UTS and IPC namespace, and a new session (`--new-session`), which detaches the sandboxed process
  from the real controlling terminal so it cannot use `TIOCSTI`-style terminal escapes to inject input back into
  the host's tty (most current kernels already disable legacy `TIOCSTI` injection by default, so this is
  defence in depth, not the only thing standing between a hostile installer and your terminal).
- The network namespace is unshared (`--unshare-net`) unless the caller sets `allow_network` — Phase 3's own
  target is offline-only installers; an installer that needs to fetch a redistributable is Phase 4's problem.
  Real bwrap test: a loopback TCP connect to a listener on the host succeeds only when `allow_network` is set (a
  DNS-based probe was deliberately not used — this sandbox does not bind `/etc/resolv.conf` or
  `/etc/nsswitch.conf` either, so name resolution would fail for a reason unrelated to the network namespace).
- `--die-with-parent`: a sandboxed helper cannot outlive the runtime process that started it.
- **No display, audio or D-Bus, regardless of `--network`.** `InstallerSandbox::wrap` never replays
  `SANDBOX_ENV_DENYLIST` (`DISPLAY`, `WAYLAND_DISPLAY`, `XAUTHORITY`, `XDG_RUNTIME_DIR`, `XDG_SESSION_TYPE`,
  `DBUS_SESSION_BUS_ADDRESS`, `PULSE_SERVER`) into the sandbox, even though the ordinary launcher allowlist
  passes them to unsandboxed runs. This matters with `--network`: the host network namespace is then shared, so
  the host's abstract X11 socket is reachable (verified in the Phase 3 final review), and before this fix
  `DISPLAY`/`XAUTHORITY` were passed straight through — only X auth-cookie binding stood between a `--network`
  installer and the host session. No socket is bound either (`/tmp` is a fresh tmpfs, `$XDG_RUNTIME_DIR` is not
  bound), so a program that guesses `DISPLAY=:0` on its own can still try the abstract socket under
  `--network`; it would need the (unbound) X authority cookie to get in — but only where the X server has no
  `SI:localuser` grant (`xhost +si:localuser:$USER`, which some desktop sessions set by default and which
  admits any process of the same user with no cookie at all). Where that grant exists, a `--network` installer
  can reach the host display.
- **Wine's registry flush happens inside the sandbox.** `--unshare-pid` makes `bwrap` tear down the PID namespace
  the instant its direct child exits, killing `wineserver` before it writes `system.reg`/`user.reg`. Every
  installer/uninstaller command is therefore wrapped by `CompatBackend::settle` (Wine:
  `/bin/sh -c '<fixed script>' sh <wineserver> <program> <args...>`, which runs the program, then
  `wineserver -w`, then exits with the program's own status). The script text is a constant; every path and
  argument arrives as argv, never interpolated. Residual risk: if `wineserver -w` never returns (a Wine process
  left holding the prefix), the install waits with no internal timeout, the same as the installer run itself.

**What this narrows.** An installer running under it cannot read or write anything on the host outside its own
app directory and the fixed read-only system paths listed above (needed to run Wine itself; verified: a write
attempt outside the prefix fails and leaves nothing on the real filesystem), cannot see the real user's home,
other apps' data or any other host path, and (by default) has no network at all, not even loopback to the host.

**What this does NOT stop** — read this before trusting it as "the app is contained":
- **Same uid, no user namespace remapping.** The sandboxed process runs as the same Linux user as everything
  else; anything that same uid can reach OUTSIDE the mount namespace bwrap builds (signals to other processes of
  that uid, `/proc/<pid>` of a process outside the fresh PID namespace it cannot even see, System V IPC objects
  outside the fresh IPC namespace, and — only with `--network` — the host's abstract-namespace sockets) is still
  reachable exactly as any other process of that user would reach it. The display/audio/D-Bus variables that
  would point at those sockets are stripped (see above), which is not the same as the sockets being unreachable.
- **No seccomp filter, no Landlock, no capability drop, no resource limits (cgroups, rlimits).** A sandboxed
  process still has every syscall a normal process has inside its namespaces; a kernel exploit or a namespace
  escape is not this profile's problem to solve. `bwrap` itself is trusted, unaudited code running with
  whatever privilege unprivileged user namespaces (or its setuid bit) give it on this machine.
- **What is bound read-only is still a real, current copy of `/usr` et al.** and could itself contain something
  exploitable already on the host; this profile does not vet, pin or checksum it.
- **The app's own prefix is fully read-write**, on purpose (installers write there) — a malicious installer can
  still plant anything it wants inside its own prefix, corrupt its own registry hives, or write a `.lnk`/`.exe`
  that a LATER, unsandboxed `runtime run` of that same app would execute. The sandbox boundary is the real
  filesystem outside the app, not "this installer cannot do anything bad to this app".
- **No output/resource caps of its own.** `run_helper`'s own timeout and capped-output rules still apply (they
  are `Launcher`'s, not the sandbox's), but the sandbox adds no additional CPU, memory or disk-space limit; a
  hostile installer can still fill disk inside its own prefix or spin the CPU until the helper's timeout fires.
- **TOCTOU on the bound paths.** Same caveat as the rest of this document: nothing here uses `openat2` path
  confinement: what is real at the moment `bwrap` sets up its mounts is what gets bound.
- **Wired into `runtime install` since Task 6** (this bullet was true only through Task 5; corrected by
  Task 8, which is what actually ran a real installer through it end to end for the first time — see
  below). `installer::pipeline::install_via_installer` runs every `.msi`/`.exe` installer through this
  sandbox unconditionally (no bwrap on `$PATH` is `InstallerError::BwrapNotFound`, never a silent
  fallback to running it unsandboxed); `runtime uninstall`'s recorded uninstall command runs through it
  too (`crate::uninstall`).

### Task 8: what real end-to-end testing found

Task 8 ran real `hello.msi`/`hello-nsis.exe` installs through this exact sandbox on a stock Ubuntu Wine
setup (Wine 10.0~repack, the `wine`/`wine64` apt packages) for the first time — Tasks 5-7 verified the
sandbox itself (a plain `/usr/bin/sh` payload) and the pipeline's logic, but never a real installer
through both together. Three things surfaced that were not previously visible:

- **The fixed read-only bind set was missing `/bin`, and every real installer run silently failed
  because of it.** Ubuntu's/Debian's `wine`/`wine64` commands are `update-alternatives` symlinks to
  small `#!/bin/sh -e` wrapper scripts (`/usr/bin/wine{,64}-stable`), not plain ELF binaries. Without
  `/bin` in [`RO_BINDS`](../crates/installer/src/sandbox.rs), the sandbox's mount namespace has no
  `/bin` at all (only `/usr`, `/lib`, `/lib64`, `/etc/alternatives` existed), so the kernel's own
  shebang resolution for `/bin/sh` failed with ENOENT before Wine ever started — `bwrap` reported this
  as `execvp /usr/bin/wine: No such file or directory`, which reads exactly like "Wine is missing" and
  is not: the wrapper script itself was reachable, its interpreter was not. The practical effect: EVERY
  installer run through this sandbox failed (silently, as an empty-candidate "nothing installed"), on a
  completely stock Ubuntu install, regardless of `--silent`. Fixed by adding `/bin` to `RO_BINDS`
  (`crates/installer/src/sandbox.rs`); real installs now succeed (verified: `hello.msi --silent` and
  `hello-nsis.exe --silent` both install, run and uninstall cleanly end to end). The exact set of real
  host paths reachable read-only inside the sandbox is now `/usr`, `/bin`, `/lib`, `/lib64`,
  `/etc/alternatives` (plus `SandboxOpts::extra_ro_binds`, the backend's own `dll_dirs()`) — everything
  else on the real filesystem is still invisible, and the app's own `prefix` (`drive_c` included) is
  still the only path bound read-write, exactly as designed.
- **The no-display-socket gap is real, but which outcome it produces depends on the installer — checked
  for real, not assumed (task Ruling 4).** Two non-`--silent` installs were run against the FIXED
  sandbox above (so Wine genuinely starts this time, unlike the `/bin` bug's silent no-op):
  - `hello.msi` (`msiexec /i ...` with no silent flags): **installs successfully anyway**, in about the
    same ~15 seconds as a silent install. `hello.wxs` (the MSI fixture) defines no `<UI>` table at all
    (no `WixUI` extension), so `msiexec` has no dialog sequence to show in the first place; with nothing
    to render, the missing display socket never matters, and the install completes as if headless. This
    is not the CLI "silently forcing `--silent`" (`family::plan` genuinely adds zero `msiexec` flags for
    `silent=false`, unit-tested): it is a property of THIS installer package, and a real MSI shipping
    Microsoft's standard UI dialogs could behave differently.
  - `hello-nsis.exe` (no `/S`, so NSIS tries to show its real wizard UI): **fails fast**, in about 10-15
    seconds, reporting no new files ("nothing installed") rather than hanging — because there is no
    display for it to attach to (no `/tmp/.X11-unix` socket bound, no `$XDG_RUNTIME_DIR`, `--unshare-ipc`
    breaks X11 shared memory even if a socket were reachable). Never a fake success, never a silent
    fallback to `--silent` behaviour.

  Neither case hangs, but there is currently no *internal* bounded timeout on this step
  (`pipeline::run_installer_process` calls `Running::wait()` directly, not `Launcher::run_helper`'s
  deadline form) — today it is the installer's own fast failure (or, for a dialog-less MSI, its own fast
  success) that keeps this from hanging, not a guarantee this sandbox or pipeline provides.
  `crates/cli/tests/e2e_installers.rs`'s `e2e_install_without_silent_never_silently_forces_silent_mode`
  (using the NSIS fixture, the one that actually needs a display) bounds this from the OUTSIDE (a test
  timeout that kills the process) so the test suite itself can never hang on this, but a real user
  running `runtime install` without `--silent` on an installer that manages to render (e.g. if a display
  socket were ever added to this sandbox in a later phase, or one with a dialog sequence that blocks
  differently than NSIS's) has no such external bound today.
- **(Fixed in Task 9 and the final review.) `.lnk`-based executable discovery did not fire for a real
  Wine-created Start Menu shortcut**, because such a shortcut carries its target only in
  `LinkTargetIDList`, which `rt_installer::lnk` did not parse then; Task 9 added that fallback. Auto-discovery
  for `hello-nsis.exe` wrongly picked its `uninstall.exe`. Task 8 blamed tier (2) (the `Uninstall` registry
  entry), but the final review found the registry diff was always empty (the `wineserver` teardown bug above),
  so the wrong pick really came from tier (3), the GUI-subsystem heuristic. Once that teardown bug was fixed
  and registry writes survived, tier (2) itself became a hazard: it matched candidates against
  `UninstallString`, which for NSIS/Inno names the uninstaller, so with no matching `.lnk` the uninstaller
  would have won tier (2) outright. Now: tier (2) matches only `DisplayIcon`, and every path is matched
  structurally, never by substring: each `DisplayIcon`/`UninstallString` is reduced to the one `C:` executable
  path it names (quoted or not, spaces, trailing arguments, a `,index` suffix; `%VAR%` paths match nothing) and
  compared component-wise, case-insensitively, with the candidate's drive_c-relative path. A candidate is
  dropped from the pool before any tier is scored when (a) its basename looks like an uninstaller
  (`uninstall*`, `uninst*`, `unins<digits>`, `remove*`, case-insensitive) — always, whatever names it, so a
  file named `uninstall.exe`/`unins000.exe` never wins — or (b) an `UninstallString` names it and there is no
  positive evidence it is the app: no normal Start Menu `.lnk` targets it, and no `DisplayIcon` names it
  other than in an entry whose `UninstallString` names it too. A `.lnk` is not normal when a word of its own name
  (split on non-alphanumeric characters) is the whole word `remove` or starts with `uninst`, `deinstall`,
  `entfern`, `désinstall` or `desinstal` ("Uninstall My App", "Remove My App"; not "Watermark Remover" or
  "MyAppUninstall"); such shortcuts count for nothing (not tier (1), not evidence). So an app whose `UninstallString` is its own main
  exe (`app.exe /uninstall`) is still auto-picked when a normal shortcut names it. An exclusion is
  *doubtful* when the exe was dropped by (b) alone, or by (a) despite positive evidence (a real app named
  `Remove Background.exe`); then, if the surviving winner has no tier (1)/(2) signal of its own, discovery
  asks for a manual choice listing the survivor(s) and the doubtful exes, instead of letting a bundled
  `helper.exe`/`vcredist.exe` win by elimination. A file named like an uninstaller with no evidence
  (`uninstall.exe`, `unins000.exe`) is a confident exclusion and never forces a choice. If the exclusion
  leaves no candidate, discovery asks too. Unit-tested in `rt_installer::discover`. For real:
  `hello-nsis.exe --silent` records `hello64.exe` via tier (1) (its Start Menu shortcut), and
  `hello-nsis-noshortcut.exe --silent` (no shortcut) records `hello64.exe` with `uninstall.exe` excluded;
  both run without `--exe` in `crates/cli/tests/e2e_installers.rs`. Which `Uninstall` entry's
  `DisplayName`/`UninstallString` gets recorded is decided the same structural way: the only entry, else the
  one whose `DisplayIcon` names the winner, else the one whose `UninstallString` program is in the winner's
  directory; with several entries and no tie, nothing is recorded from the registry and the install warns
  (so with several entries a bundled redistributable's name and `MsiExec` command are never picked; but a
  single entry is recorded unconditionally, so if the redistributable's is the ONLY `Uninstall` entry, its
  name and command are what get recorded). Manual-choice lists are sorted by path. Known limits (mostly a
  manual choice, a wrong recorded name, or `--exe`, but the first one can silently pick the wrong exe): the
  filename rule has false positives (an app really named `Remove*.exe`/`Uninst*.exe` is excluded; with
  evidence that becomes a manual choice, but if its only shortcut is itself named `Remove …` there is no
  evidence and another exe can win silently); Squirrel installers, MSI cached icons and the recorded-entry
  directory match have further gaps (listed in the Phase 3 plan's open items); and the path parser
  does not normalise doubled separators (`C:\App\\app.exe`) or 8.3 short names (`C:\PROGRA~1\...`), so such
  registry values match nothing.

## Dependency downloads (Phase 4A)

`runtime deps <app> --install` is the runtime's first network access and the only command that downloads anything
(`crates/deps`, `rt_deps`). `install`, `run` and `doctor` never download; at most they print a one-line hint, and they
do not even link against the fetch code path (`missing_hint` takes no fetcher).

**Trust model.** The network, the downloaded file and the vendor installer inside it are untrusted. The only trusted
input is the manifest `crates/deps/packages.toml`, compiled into the binary with `include_str!`: there is no remote
manifest, no user manifest, and no flag or environment variable that points the runtime at another one (tests inject
theirs through the library, never through the CLI). Updating a pin is a release task. Parsing is strict (unknown
fields, duplicate ids, cycles, non-`https` urls, malformed sha256, unknown references, overlapping destinations and a
url whose path names a sha256 other than the package's are errors), and the same checks run as a test over the real
bundled manifest, which also refuses placeholder-looking pins.

**What is verified.**
- **The file itself: sha256 and exact size from the manifest.** The hash is computed while streaming; a mismatch
  deletes the temp file and fails hard. There is no retry and no fallback. Only then is the file renamed to
  `<data>/deps-cache/<sha256>` and made read-only (`0400`).
- **HTTPS only**, checked before any connection; every redirect must stay HTTPS; at most 3 redirects.
- **Byte cap = the manifest size.** The connection is aborted as soon as more bytes arrive, and a short body fails
  too. `Content-Length` is never trusted on its own; an unsolicited `Content-Encoding` is hashed as served (and fails).
- **Deadlines.** Connect timeout 10 s, a per-read stall timeout of 20 s, and an absolute total deadline of 300 s that
  every redirect hop, TLS handshake, header and body read shares (a peer dribbling the handshake a byte at a time is
  cut off too). Proxies from the environment are ignored.
- **Cache hits are re-verified** (size and sha256) before use, never trusted; a corrupt entry is deleted. The cache
  directory must be a real directory owned by the user and not group- or world-writable; temp files are `0600`,
  `O_EXCL`, and removed on every error path.
- **Hostile archives.** Zip goes through the Phase 2 hardened `rt_core::unzip`; `tar.gz` through a small bounded tar
  reader (caps on entries, names and sizes; no symlinks, hardlinks or devices; no absolute or `..` names). Only the
  manifest's `extract` pairs are written, each resolved under `drive_c` without following symlinks, and DLL overrides
  are written only for names the package `provides`. Every file written, replaced (backed up in `<app>/deps-backup`)
  or created is journalled before it is touched, so a killed install can be discarded exactly
  (`runtime deps <app> --discard-interrupted <pkg>`).
- **Installer packages run only in the installer sandbox, offline** (`allow_network = false`, always; see "Installer
  sandbox" above), from a copy staged in `drive_c` and re-hashed there, with a 20-minute deadline, on a one-run
  null-driver desktop (`explorer.exe /desktop=...,null`). The staged copy is removed afterwards by re-resolving its
  path, so a symlink the installer planted is never followed.
- Real-Wine end-to-end tests (`e2e_real_wine_*` in `crates/deps`, run by CI's `wine-e2e` job) check these outcomes
  against the local HTTPS test server: a tampered download installs nothing and leaves no cache file, a denied package
  is never requested, a second run downloads nothing, and removing the app leaves nothing of it.

**Consent.** Packages whose licence is not permissive (`proprietary-redistributable`) need consent, per package and per
version. The prompt shows the package id, version, licence LABEL, url, size and sha256; the consent record in
`metadata.json` stores a hash of exactly that text, so a different version, url or hash means earlier consent does not
count. A bare `--yes` is rejected; `--yes <pkg>` must name a consent-gated package of the plan, and its text is still
printed. With no terminal and no `--yes`, the answer is no. A denied package, and everything that needs it, is skipped
and never downloaded. Permissive packages (DXVK) need no consent but still need an explicit `--install`.

**What is NOT verified, or not prevented** (read this before trusting a package install):
- **The vendor installer's behaviour.** The sha256 pin proves which file was staged, nothing about what it does. The
  sandbox bounds what it can touch (its own prefix, read-write); inside the prefix it can do anything. Success is judged
  by the package's marker (a file or registry value), which is the installer's own claim: a hostile installer can
  write it and exit. The exit status of an exe installer is not even visible (the desktop wrapper exits 0), so marker
  presence is the ONLY success signal. `explorer.exe`, `msiexec.exe` and `reg.exe` are whatever the prefix holds, not
  pinned: a program that earlier planted a native copy there could fake a marker or an override.
- **EULA acceptance on the user's behalf.** A vendor's silent installer accepts the vendor's own licence terms. The
  prompt says so, but the terms themselves are not shown (the manifest carries only a licence label); the user reads
  them at the vendor.
- **Path-based operations (TOCTOU).** Extraction, backups, removal and staging check and use paths, not held
  directory descriptors; `O_NOFOLLOW` covers only the last component. A process running inside `drive_c` at the same
  time could race a check and redirect a write or delete. Today apps are not sandboxed anyway (they can reach the host
  directly), and Wine's `Z:` drive maps the host `/` for the same user, so `deps-backup` is reachable from inside the
  prefix too. Before Phase 5 makes the prefix a boundary, these must move to `openat`/`renameat`/`unlinkat` against
  held parent descriptors.
- **Busy-prefix and lock limits.** An install refuses while any `wineserver` serves the prefix (checked before the
  download and again before installing) and holds `<app>/deps.lock` exclusively. `run` holds the lock shared only
  while it starts the app and releases it once the app has started; after that the running-`wineserver` check is what
  refuses an install. Detection is a `/proc` scan by `WINEPREFIX` and Wine's server directory: a program started
  another way can be missed. If `deps.lock` cannot be locked by anyone (a symlink or directory in its place, or a file
  system without `flock`: `ENOLCK`, `EOPNOTSUPP`, `ENOSYS`), `run`, `remove` and `uninstall` warn and continue, and
  dependency installs refuse.
- **Wine builtin versus native DLLs.** A DLL in `system32` is not necessarily loaded: Wine prefers its own builtins for
  many names. Each package declares its `dll_overrides`, set to `native,builtin` in `HKCU\Software\Wine\DllOverrides`
  through the prefix's `reg.exe` (run unsandboxed through the backend, like any Wine helper). There is no per-DLL
  policy beyond that list, and overrides are never removed (there is no dependency removal).
- **Dependencies of a denied package still install** (spec rule: only the denied package and what needs it are
  skipped).
- **Upgrades are not supported.** A package recorded at another version or sha256 is refused before any download;
  the user recreates the environment to get the new version.
- **Recorded state is the runtime's own record**, never inferred from the prefix. An installer package whose marker is
  already present (usually from the app's own installer) is skipped and not recorded.
- **x64 only.** Archives install their 64-bit DLLs; a 32-bit app keeps Wine's builtins (the plan warns).

**Residual risks.** A compromised upstream serving the pinned bytes cannot happen without breaking SHA-256; a
compromised upstream serving other bytes fails the pin (safe, but the package cannot be installed until a release
refreshes it; the weekly `verify-pins` workflow notices). TLS uses rustls with the bundled Mozilla roots: frozen at
build time, no revocation checks, system and enterprise CAs ignored (a TLS-intercepting proxy fails closed); TLS is
defence in depth behind the pin. The trust placed in a pinned vendor installer is trust in the vendor. The download
cache is shared by all apps of the user and trusted only after re-verification.

## Roadmap

Phase 5 adds the actual boundary for ordinary app runs, not just installer helpers: run Wine itself inside
bubblewrap (mount and PID namespaces, a private filesystem view without the host), Landlock rules as a second
layer where bubblewrap is unavailable, and a seccomp filter, with the network and device access decided per
app. The `Launcher::wrap` hook in `rt_core` — now a `Sandbox` trait a `Launcher` can carry, per the installer
sandbox above — is the seam prepared for it. Until then, this document is the truth and the README says the
same.

## Reporting

Please report a hole in any of the measures above as an issue or privately to the maintainer. Bypasses of the
"does NOT do" list are known and are not vulnerabilities in Phase 2.
