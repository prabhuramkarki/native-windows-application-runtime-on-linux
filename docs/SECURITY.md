# Security model

**Since Phase 5A, `runtime run` starts the program in a bubblewrap sandbox by default** (see "App sandbox (Phase
5A)" below): a private filesystem view with only the app's own prefix and home writable, no network unless the
app's `permissions.toml` allows it, and the display, audio and GPU it is given. Without a working `bwrap` it
refuses to run. Since Phase 5B the program also runs under a seccomp deny-list, a Landlock filesystem ruleset where
the kernel has Landlock, and a task limit (with optional memory and CPU limits) in a systemd user scope where one
can be created (see "seccomp and Landlock (Phase 5B)", "Resource limits (Phase 5B)" and "What the hardening layers
add and do not"). `runtime run --unsandboxed` is the per-run escape hatch, and it says so on stderr: such a run (and
every run before Phase 5A) is what the Phase 2 sections below describe, the program with your full access; Phase 2's
measures make accidents less likely and remove Wine's most obvious host exposure, and do not stop a program that
wants out.

## Threat model

Assume the installer or application is **malicious**. It runs Windows code inside Wine as your uid. **Wine is not a
security boundary**: a Windows program can reach every host file Wine's process can (`\\?\unix\` paths), and native
code in it can make any Linux system call Wine's process could. For a sandboxed run the boundary is the kernel's:
**bubblewrap** (a mount, PID, IPC, UTS and, unless network is allowed, network namespace), **seccomp** (a deny-list of
dangerous system calls), **Landlock** (the file layout enforced a second time, where the kernel has it) and **cgroup
limits** (a task limit against fork bombs, memory and CPU on request). What still reaches the host from inside is
listed in "What the hardening layers add and do not"; the biggest items are the X11 server (shared input), the GPU
driver and every allowed system call's kernel code. Installers, uninstallers and `runtime deps` installer packages
run in the installer sandbox: bubblewrap, seccomp and Landlock, but no cgroup limits ("Installer sandbox" below).
Outside both sandboxes (`--unsandboxed` and the unsandboxed Wine helpers) the older statement holds: the runtime protects its *own* handling of untrusted input (archives, PE files, `metadata.json`, file names,
program output), so that merely installing, listing, inspecting or removing something cannot hurt you, and nothing
a running program can reach on its own. Treat the separation between apps (separate prefixes) outside the sandbox as
accident prevention, not a guarantee (below). Do not run software you would not trust with your X11 session.

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

## What is still NOT covered without the app sandbox

This list describes a program that runs WITHOUT the app sandbox: a `runtime run --unsandboxed` run (and every run
before Phase 5A). The app sandbox removes the first two items for a sandboxed run (its host view has no host files
to reach through `\\?\unix\`, and its devices and sockets are only those the profile grants); the rest still
apply. What the app sandbox itself does not protect is listed in "App sandbox (Phase 5A)" and "What the hardening
layers add and do not".

- **No sandbox boundary** in such a run: no bubblewrap namespaces, no seccomp filter, no Landlock, no resource
  limits. The program shares the host's network (it can connect anywhere), GPU, audio and display sockets.
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
- **Session D-Bus** (`--unsandboxed` runs; a sandboxed run drops `DBUS_SESSION_BUS_ADDRESS` and never binds the bus
  socket, so only an ABSTRACT bus address stays reachable, and only with `network = "allow"`).
  `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` are allowlisted, so a program that speaks D-Bus can reach the
  session bus (keyring/secret service, portals). Not tested.
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
- **Locking.** Every `runtime run` holds the app's `deps.lock` SHARED from before the start until the program has
  ended (a file target's from right after its install); `remove`, `uninstall`, `deps --install`, and `display`/
  `permissions` changes take it EXCLUSIVELY and refuse while any run of the app lives ("the app is running (started
  by `runtime run`); quit it first"), whatever the program does. Two runs of one app can still run at once (both
  shared). A program started another way (plain `wine` with the app's `WINEPREFIX`) holds no lock: the `/proc`
  `wineserver` scan below is the second, weaker check for it, and `remove`/`uninstall` refuse while it sees one.
- **Interrupted installs.** Ctrl-C or a kill during `install`, and especially during `run <file>` (which installs
  first), can leave a partial app that `remove` cleans up.
- **Run-by-path installs every time.** `runtime run some.exe` creates a *new* app on each invocation
  (`some-2`, `some-3`, ...) with its own prefix. Use `install` once and `run <id>` afterwards.
- **Gecko is disabled, and Mono is off until an app has it.** Every Wine process gets
  `WINEDLLOVERRIDES=winemenubuilder.exe=d;mscoree=d;mshtml=d`, except the program of an app whose metadata records
  the `wine-mono` package: it gets `winemenubuilder.exe=d;mshtml=d`. Only the recorded state decides (never files in
  the prefix), and only `command()` in the Wine backend can pick the second string; native apps, installers and every
  helper keep `mscoree=d`. HTML-embedding programs still fail. `doctor` says whether a managed program has Wine Mono.
  Mono adds a JIT to the sandboxed process set (writable and executable memory inside the Wine process, like
  Wine's own code): seccomp and Landlock are applied to it exactly as to any program, with no rule added for it.
  Verified on 2026-09-26 (`crates/cli/tests/e2e_dotnet.rs`, Wine 10.0, Landlock ABI 8): the MSI installed in the
  installer sandbox with its shim, and a managed console program ran under the default sandbox, including four
  JIT-compiled threads and a 64 MiB allocation with a forced GC, with the deny-list and the Landlock rule set
  unchanged. The package is a pinned upstream MSI
  (Wine Mono 9.4.0, SHA-256 checked) installed through the sandboxed installer pipeline, with the installer's own
  `mscoree=d`, like any other package.
- **Installers and MSI are refused** (Phase 3); only portable `.exe` files and `.zip` archives are handled.

## Installer sandbox (Phase 3 Task 5; seccomp and Landlock since Phase 5B Task 6)

`rt_installer::InstallerSandbox` is a `bwrap` profile for the installer helper processes: `runtime install`'s
`.exe`/`.msi` installers (msiexec for MSI), `runtime uninstall`'s recorded uninstaller, and `runtime deps --install`'s
installer packages with the `reg.exe` steps that follow them. **It is scoped to those helpers,
not to Wine app runs in general**: app runs have their own, per-app profile since Phase 5A ("App sandbox
(Phase 5A)" below). It is wired through the same `Launcher::wrap` seam named in the roadmap below (now a
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
- **The `sandbox-init` shim (Phase 5B Task 6).** bubblewrap does not start the installer itself: it starts
  `runtime sandbox-init --v1 <rules> -- <program> <args>`, the same launcher and code as the app sandbox ("seccomp
  and Landlock (Phase 5B)" below): `RLIMIT_CORE = 0`, the Landlock ruleset (best effort: a kernel without Landlock
  runs without it, as for apps), the same seccomp deny-list (mandatory; `ptrace` for Wine's requests only inside an
  enforced Landlock domain), then `execve` of the unchanged program. The runtime executable is an explicit input of
  `InstallerSandbox::new(bwrap, runtime_exe)`, the only constructor (the CLI passes its own `current_exe()`), and is
  bound read-only at its resolved path after the system binds and before the prefix. One that is relative, ends in
  ` (deleted)` (replaced since it started), does not resolve to a file or lies inside the data directory is refused
  before anything runs: every caller runs the sandbox's pre-flight check first (`InstallerSandbox::check`), so
  `runtime install` and `runtime deps --install` fail with `the installer sandbox refused to start: <why> (nothing
  was run; nothing was installed)`, a `reg.exe` step fails with that text, and `runtime uninstall` warns with it and
  removes the environment as it does for any uninstaller failure. `wrap` itself still fails closed (a refusal command:
  exit 126, the reason on stderr) should it ever be reached with such an executable. There is no switch, variable or
  feature that runs an installer without the shim. The Landlock rules mirror the
  mounts, each for its path inside the sandbox: read-write for `/proc`, bwrap's `/dev/null`, `/dev/zero`,
  `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty` and its `/dev/pts` and `/dev/shm` directories (`/dev/ptmx`
  is a link to `pts/ptmx`, covered by the `pts` rule), `/tmp`, the prefix and the empty `$HOME`; read-execute for
  `/usr`, `/bin`, `/lib`, `/lib64`, `/etc/alternatives`, the backend's dll directories and the runtime executable.
  A dll directory that is a host symlink under an already-bound tree (e.g. a `*-windows` link inside `/usr`) stays a
  symlink inside, where bwrap cannot mount over it and a Landlock rule on it fails (ELOOP), so both sandboxes bind
  and rule its resolved directory instead (`rt_sandbox::render::ro_bind_target`); the link inside resolves into it.
  No display, audio, GPU or `/sys` rule, as there is no such mount. Tests: the frozen argv and rules
  (`the_exact_argv_for_a_typical_command`), the refusals, `Seccomp: 2`/`NoNewPrivs: 1` inside, a nested user
  namespace refused (`unshare -U`: EPERM through the shim, success with bwrap alone on this host), a test-only bind
  without a rule unreadable through Landlock, and `syscall_escape_4` (below).
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
- **No resource limits.** Unlike app runs, installers get no systemd scope: no task, memory or CPU limit, so a fork
  bomb or a memory hog in an installer reaches the desktop. What bounds them is time only: the dependency engine's
  20-minute installer deadline and the `reg.exe` timeout (killing bwrap ends the whole tree: the PID namespace and
  `--die-with-parent`), `--die-with-parent` and Ctrl-C of the `runtime` command. `runtime install` and
  `runtime uninstall` have no deadline (an installer GUI may take as long as the user needs).
- **The seccomp and Landlock layers carry the app sandbox's own limits** ("What the hardening layers add and do
  not" below): the kernel code behind every allowed call, Landlock only where the kernel has it (without it, the
  mounts are the only file boundary and `ptrace` is denied outright), and bubblewrap's own unfiltered pid 1. Nested
  user namespaces, `bpf`, `userfaultfd`, `keyctl`, `io_uring`, `TIOCSTI` and the rest of the deny-list are refused
  (before Phase 5B Task 6 they were not: `unshare -U` inside the installer sandbox succeeded). A kernel exploit
  through an allowed call is not this profile's problem to solve. `bwrap` itself is trusted, unaudited code running with
  whatever privilege unprivileged user namespaces (or its setuid bit) give it on this machine.
- **What is bound read-only is still a real, current copy of `/usr` et al.** and could itself contain something
  exploitable already on the host; this profile does not vet, pin or checksum it.
- **The app's own prefix is fully read-write**, on purpose (installers write there) — a malicious installer can
  still plant anything it wants inside its own prefix, corrupt its own registry hives, or write a `.lnk`/`.exe`
  that a later Wine session of that app outside a sandbox would execute (`runtime run --unsandboxed`, or a
  helper session of an app that never ran sandboxed: see "Wine helpers in a prefix the app has written"). The sandbox boundary is the real
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
(`crates/deps`, `rt_deps`). `install`, `run` and `doctor` never download; at most they print a one-line hint. They
never call the fetch code (`missing_hint` takes no fetcher), although it is linked into the same binary.

**Where the guarantees live.** The library pieces `fetch::fetch`, `install_archive::install_archive` and
`install_installer::install_installer_pkg` are building blocks: they verify what they are given but ask for no
consent and take no lock. The consent guarantee, the lock, the busy-prefix check and the recording are
`orchestrate::install_plan`'s and the CLI's (`runtime deps`); any other caller of the building blocks must provide
them itself.

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
- **Deadlines.** Connect timeout 10 s, a per-read stall timeout of 20 s, and an absolute total deadline that every
  redirect hop, TLS handshake, header and body read shares (a peer dribbling the handshake a byte at a time is cut off
  too): 300 s plus one second per 32 KiB of the package, at most one hour (1082 s for the 25 MB VC++ redistributable,
  so a slow but steady link of about 24 KB/s still finishes; a dead one is cut off by the stall timeout). Proxies
  from the environment are ignored.
- **Cache hits are re-verified** (size and sha256) before use, never trusted; a corrupt entry is deleted. The cache
  directory must be a real directory owned by the user and not group- or world-writable; temp files are `0600`,
  `O_EXCL`, and removed on every error path.
- **Hostile archives.** Zip goes through the Phase 2 hardened `rt_core::unzip`; `tar.gz` through a small bounded tar
  reader (caps on entries, names and sizes; no symlinks, hardlinks or devices; no absolute or `..` names). Only the
  manifest's `extract` pairs are written, each resolved under `drive_c` without following symlinks, and DLL overrides
  are written only for names the package `provides`. Every file written, replaced (backed up in `<app>/deps-backup`)
  or created is journalled before it is touched, so what a killed install did to files and directories can be
  undone (`runtime deps <app> --discard-interrupted <pkg>`). Not exactly everything: DLL overrides are not journalled
  (an override a killed run already set stays), and a restored original comes back with mode `0644`, not the mode it
  had (Wine creates its placeholders `0664`); its bytes are restored exactly.
- **Installer packages run only in the installer sandbox, offline** (`allow_network = false`, always; see "Installer
  sandbox" above), from a copy staged in `drive_c` and re-hashed there, with a 20-minute deadline, on a one-run
  null-driver desktop (`explorer.exe /desktop=...,null`). The staged copy is removed afterwards by re-resolving its
  path, so a symlink the installer planted is never followed. The runtime's own steps right after the installer (its
  `reg.exe` runs that set, and on failure delete, the package's DLL overrides) run in the same sandbox, offline too
  (Ruling 17): the Wine session they start also starts whatever the installer registered (auto-start services and
  the like). Real-Wine test: an "installer" that registers an auto-start service writing to a host directory; the
  override step leaves the host file unwritten, and a plain Wine session afterwards writes it (the control).
- Real-Wine end-to-end tests (`e2e_real_wine_*` in `crates/deps`) check these outcomes against the local HTTPS test
  server: a tampered download installs nothing and leaves no cache file, a denied package is never requested, a
  second run downloads nothing, and removing the app leaves nothing of it. They have been run locally only (Wine
  10.0 on Ubuntu 26.04). CI's `wine-e2e` job is written to run them but has NEVER run on a hosted runner and does not
  gate anything (`continue-on-error`).

**Consent.** Packages whose licence is not permissive (`proprietary-redistributable`) need consent, per package and per
version. The prompt shows the package id, version, licence LABEL, url, size and sha256; the consent record in
`metadata.json` stores a hash of exactly that text, so a different version, url or hash means earlier consent does not
count. A bare `--yes` is rejected; `--yes <pkg>` must name a consent-gated package of the plan, and its text is still
printed. With no terminal and no `--yes`, the answer is no. A denied package, and everything that needs it, is skipped
and never downloaded. Open-licence packages (DXVK, VKD3D-Proton) need no consent but still need an explicit `--install`.

**What is NOT verified, or not prevented** (read this before trusting a package install):
- **The vendor installer's behaviour.** The sha256 pin proves which file was staged, nothing about what it does. The
  sandbox bounds what it can touch (its own prefix, read-write); inside the prefix it can do anything, including
  registering programs that Wine starts on its own later (services, `RunOnce` entries, ...). **Only the runtime's own
  steps are sandboxed.** Any later Wine session in the prefix outside a sandbox (`runtime run --unsandboxed`; and, for
  an app that has never run sandboxed, the `reg.exe` runs that set an ARCHIVE package's overrides and `runtime display
  <app> <choice>`: see "Wine helpers in a prefix the app has written" below) starts whatever a vendor installer
  registered, unsandboxed, with the user's network and files. Success is judged
  by the package's marker (a file or registry value), which is the installer's own claim: a hostile installer can
  write it and exit. The exit status of an exe installer is not even visible (the desktop wrapper exits 0), so marker
  presence is the ONLY success signal. `explorer.exe`, `msiexec.exe` and `reg.exe` are whatever the prefix holds, not
  pinned: a program that earlier planted a native copy there could fake a marker or an override.
- **EULA acceptance on the user's behalf.** A vendor's silent installer accepts the vendor's own licence terms. The
  prompt says so, but the terms themselves are not shown (the manifest carries only a licence label); the user reads
  them at the vendor.
- **Path-based operations (TOCTOU).** Extraction, backups, removal and staging check and use paths, not held
  directory descriptors; `O_NOFOLLOW` covers only the last component. A process running inside `drive_c` at the same
  time could race a check and redirect a write or delete (an install refuses while the app runs, see below, which
  narrows but does not close this). An `--unsandboxed` app reaches the host directly anyway (`\\?\unix\...`), so
  `deps-backup` is reachable from inside the prefix too. Now that the prefix is the sandbox's only writable path,
  these must move to `openat`/`renameat`/`unlinkat` against held parent descriptors (Phase 5B).
- **Busy-prefix and lock limits.** An install holds `<app>/deps.lock` exclusively, so it refuses while any
  `runtime run` of the app lives (the run holds the lock shared until the program has ended, sandboxed or not, even
  when the program keeps no `wineserver`). As a second, weaker check for Wine processes NOT started by `runtime run`,
  it also refuses while any `wineserver` serves the prefix (checked before the download and again before installing):
  a `/proc` scan by `WINEPREFIX` and Wine's server directory, which a program started another way can evade. The lock
  is released as `runtime run` exits; when `bwrap` dies of a signal, or `runtime` itself is SIGKILLed, the kernel
  tears the sandbox's PID namespace down at the same moment. That window is below what could be observed: polling
  every millisecond after `runtime` exited (Ctrl-C and SIGKILL, real Wine) never found a process of the sandbox. If `deps.lock` cannot be locked by anyone (a symlink or directory in its place, or a file
  system without `flock`: `ENOLCK`, `EOPNOTSUPP`, `ENOSYS`), `run`, `remove` and `uninstall` warn and continue, and
  dependency installs refuse.
- **Wine builtin versus native DLLs.** A DLL in `system32` is not necessarily loaded: Wine prefers its own builtins for
  many names. Each package declares its `dll_overrides`, set to `native,builtin` in `HKCU\Software\Wine\DllOverrides`
  through the prefix's `reg.exe` (for an installer package in the installer sandbox, for an archive package through
  the backend like any Wine helper). There is no per-DLL policy beyond that list, and overrides are never removed
  (there is no dependency removal).
- **Dependencies of a denied package still install** (spec rule: only the denied package and what needs it are
  skipped).
- **Upgrades are not supported.** A package recorded at another version or sha256 is refused before any download;
  the user recreates the environment to get the new version.
- **Recorded state is the runtime's own record**, never inferred from the prefix. An installer package whose marker is
  already present (usually from the app's own installer) is skipped and not recorded, and the runtime sets NONE of
  its DLL overrides (Ruling 18): Wine may keep loading its builtin copies. `deps` and `doctor` say so; recreating the
  environment is the only way to get the runtime's own install of it today.
- **x64 only.** Archives install their 64-bit DLLs; a 32-bit app keeps Wine's builtins (the plan warns).

**Residual risks.** A compromised upstream serving the pinned bytes cannot happen without breaking SHA-256; a
compromised upstream serving other bytes fails the pin (safe, but the package cannot be installed until a release
refreshes it; the weekly `verify-pins` workflow notices). TLS uses rustls with the bundled Mozilla roots: frozen at
build time, no revocation checks, system and enterprise CAs ignored (a TLS-intercepting proxy fails closed); TLS is
defence in depth behind the pin. The trust placed in a pinned vendor installer is trust in the vendor. The download
cache is shared by all apps of the user and trusted only after re-verification.

**Zstd archives (Phase 4B).** VKD3D-Proton ships only `.tar.zst`. It goes through the same bounded tar walker as gzip,
with a pure-Rust decoder (`ruzstd`, no C code). Caps: the frame's window (64 MiB, `max_zstd_window`; refused before
decoding), decompressed bytes (total, per entry, and the decompressed/compressed ratio after a floor, all as for
gzip), compressed input, exactly one frame (a second is `TooManyFrames`, other trailing bytes `TrailingGarbage`),
skippable and dictionary frames refused, a truncated frame is an error. The content checksum is not verified by the
decoder; the package's sha256 already covers the bytes.

**Host graphics probe (Phase 4B).** `runtime graphics info` and `doctor` run `vulkaninfo --summary` on the host,
outside the sandbox (a read-only query). The runner scrubs the environment (only PATH, HOME, XDG_RUNTIME_DIR,
DISPLAY, WAYLAND_DISPLAY, VK_ICD_FILENAMES and VK_DRIVER_FILES pass), closes stdin, discards stderr, gives the tool
its own process group, and bounds the run: 10 s, 64 KiB of output; the reader is never joined (a descendant in its
own session can hold the pipe), so every wait is bounded. The output is untrusted and is used for nothing but a
yes/no/unknown verdict on Vulkan (and the device lines shown to the user); it never blocks anything when unknown, and
the verdict only gates the plan's `blocked` state for packages with `min_vulkan`.

**Graphics driver setting (Phase 4C).** `runtime display <app> <auto|x11|wayland>` runs the prefix's own `reg.exe`
through Wine, unsandboxed and unpinned (a program can plant a native one), like `runtime run`, so it is not a
privilege escalation in this phase. Reads (`display`, `doctor`) go through `WineReg`: no-follow, regular file,
size-capped. The write is re-validated under the exclusive app lock and refused while a `wineserver` runs for the
prefix (a fail-closed `/proc` scan; the lock alone only excludes other runtime commands). The `reg.exe` arguments
are fixed (`x11`, `wayland` or a delete), never taken from the prefix or the user's free text.

## App sandbox (Phase 5A)

`runtime run` wraps the program's Wine process in bubblewrap (`crates/sandbox/src/render.rs` has the exact profile
and why each piece is there; `runtime sandbox <app>` prints the command line for an app). Only the program's own
spawn is sandboxed: the install of a file target and the backend's `wineboot`/`wineserver -k` helpers are not
(they run before the program, on a prefix the runtime just created, or are not a Wine session; see below).

**What it gives.** A fresh mount namespace in which the host is invisible except: read-only `/usr`, `/bin`, `/lib*`,
a small `/etc` set and Wine's DLL directories; the app's `prefix` and `runtime/home`, the ONLY writable host paths
(the app root itself, with `permissions.toml`, `metadata.json` and the logs, is never bound; nor is the real home,
another app or the data root); a private `/tmp` and an empty `0700` runtime directory holding only the requested
sockets; per switch, the Wayland socket, the X11 socket directory and a copy-bound X cookie (display), the PulseAudio
socket (audio), the GPU device nodes and the `/sys` parts drivers read (gpu); the granted host directories. New PID,
UTS and IPC namespaces, a new session (no TIOCSTI into your terminal), no network namespace access unless
`network = "allow"`, `--die-with-parent`. The environment is the launcher's allowlist again, minus D-Bus always and
minus the variables of a switch that is off. The sandbox's root is remounted read-only after the mounts, so the
directories bwrap creates to hold them (the path of the app root, the data root, your home) cannot be written even
in the sandbox's memory.

**Fail closed.** `bwrap` missing, or unable to create a sandbox (user namespaces disabled or restricted, checked
with a real throwaway sandbox before every run): `run` exits 1 with `cannot start the sandbox: <reason>. Install
bubblewrap (`sudo apt install bubblewrap`) or rerun with --unsandboxed (NOT sandboxed)`, and nothing is installed or
started. A `permissions.toml` that no longer validates (a grant that moved, a new symlink, a nested grant) stops the
run with its reason; it is never silently narrowed. There is no environment variable that turns the sandbox off.

**Ctrl-C.** The program is in its own session, so the terminal's SIGINT reaches `bwrap` (still in the terminal's
process group), which dies of it, and `--die-with-parent` plus the PID namespace take the program and its
`wineserver` down with SIGKILL. SIGINT/SIGTERM sent to `runtime` itself are forwarded to `bwrap` with the same
effect (real-Wine test `e2e_real_wine_ctrl_c_ends_a_sandboxed_console_program`). The program is killed, not asked: it
gets no Windows Ctrl-C event and cannot save its state.

**What is printed.** A sandboxed run prints one `note:` line per thing its profile cannot enforce; an unsandboxed
run prints `warning: running WITHOUT a sandbox (--unsandboxed)`.

**What it does NOT protect** (known limits, not vulnerabilities):
- **X11 is shared with the host.** With display on and `DISPLAY` set, the program is an ordinary X11 client of your
  X server: it can read and inject the keyboard and mouse input of every other X11 window (XTEST, XSendEvent), which
  reaches code execution as you. `runtime run` prints this as a note. On a Wayland session with XWayland (`DISPLAY`
  set) the X11 socket is bound too: `runtime display <app> wayland` makes Wine draw through Wayland (which isolates
  clients), but the program can still connect to X11 itself; only `runtime permissions <app> --set display=off`
  removes the socket (and Wayland with it), which suits a console program.
- **`network = "allow"` is the host network namespace.** Abstract unix sockets live in the network namespace, not
  the filesystem, so X11's `@/tmp/.X11-unix/X<n>`, abstract D-Bus or other session sockets, and every service on the
  host's loopback (CUPS, development servers, a TCP Docker API) are reachable. With network allowed, `display = off`
  CANNOT be enforced (only the X server's cookie check remains). Both are printed as notes.
- **Display, audio and GPU are attack surface.** The Wayland compositor, PulseAudio/PipeWire and the GPU kernel
  driver are reachable when switched on (the default), and `/sys/devices` is readable with gpu on.
- **Same uid.** The program holds no capabilities (bubblewrap leaves the effective, permitted and bounding sets
  empty) and runs with `no_new_privs`, but it is your uid: whatever that uid can reach through what is bound is
  reachable. Phase 5B adds seccomp and Landlock (next section), which narrow the kernel surface; a kernel bug in a
  syscall that stays allowed is still an escape. Resource limits (a task limit by default, memory and CPU on request)
  are in "Resource limits (Phase 5B)"; disk use and IO are never limited.
- **Host directory grants** are what they say: an `rw` grant can be destroyed. `$HOME`, `/`, the data root, secret
  directories (`~/.ssh`, `~/.gnupg`, ...) and system trees (`rw`) are refused, and **all of `/tmp` is refused as a
  grant** (at or below it, by its written and its resolved path): other programs' sockets (tmux, ssh-agent, editor
  and browser IPC) live there under arbitrary names, so no name list could keep them out.
- **Everything inside the prefix** is the program's: it can rewrite its own registry, DLLs and files.

### The escape suite

`crates/cli/tests/e2e_sandbox.rs` (`e2e_real_wine_sandbox_*`, real Wine, real bubblewrap; required with
`RUNTIME_REQUIRE_BWRAP=1` in the `wine-e2e` CI job, which is `continue-on-error` and has not yet run on a hosted
runner, so these tests currently gate nothing in CI: they were run locally) runs `probe64.exe` (`tools/fixtures/probe.c`), a Windows console program that attempts
ONE action and exits 0 if it succeeded, 1 if it failed, printing the Windows error. Host files are named with Wine's
`\\?\unix\<host path>` NT paths, which reach any host file the process can see (see "Wine's `\\?\unix\` escape"
above). **The oracle:** each action is run against the same target twice, under the default sandbox, where it must
fail, and with `runtime run --unsandboxed`, where it must succeed. A control that also fails fails the test, so
the result cannot come from Wine, a missing file or file permissions. The "real home" is a fake `HOME` in the
test's temporary directory, given to `runtime` itself, so the grant checks use it as well. The developer's real
`~/.ssh` is never touched. The data directory is also outside `/tmp`, like the real `~/.local/share/runtime`.

| Test | Target | What it shows |
|---|---|---|
| 1 | read `$HOME/.ssh/id_test` | a secret in the home is not visible |
| 2 | write `$HOME/escape.txt` | the home cannot be written; the file is not there afterwards |
| 3 | read another app's `drive_c/canary.txt`; list the apps directory | other prefixes are not visible (inside, the list shows only the app's own id; with Landlock it cannot be listed at all) |
| 4 | read and write `<app root>/permissions.toml` | the profile can be neither read nor rewritten; it is byte-identical afterwards |
| 5 | TCP connect to a listener on the host's `127.0.0.1` | no network by default; the same connect works after `--set network=allow` |
| 6 | read/write in a granted directory; read a file next to it | `ro` reads but cannot write, `rw` writes to the host, and the parent directory's other entries stay hidden (with Landlock the parent cannot be listed at all) |
| 7 | `runtime permissions --set fs+=$HOME/.ssh:ro` | refused with the reason, nothing written (a harmless grant as the control is accepted) |
| 8 | `--unsandboxed` | it really is unsandboxed and prints its warning |
| 9 | the Wine process's own `/proc/self/status` | it runs with `Seccomp: 2` and `NoNewPrivs: 1` (unsandboxed: `Seccomp: 0`) |
| 10 | `ReadProcessMemory`/`WriteProcessMemory` of a second process; Set/GetThreadContext (registers, Dr0/Dr7) | what wineserver does with `ptrace` still works under the filter (with Landlock; without it the memory modes must fail) |
| 11 | a CreateProcess loop (100 copies) under `tasks = 64` | stopped after ~23 copies inside the app's scope; the same bounded loop finishes 40 copies under the default limit and unsandboxed; the user manager and a new process still start afterwards |
| 12 | touching 512 MiB under `memory = 128` | OOM-killed inside the scope (exit 143 and the journal note), a 32 MiB hog under the same limit finishes, 64 MiB unsandboxed finishes; the desktop is unaffected |
| 13 | two concurrent runs | each is bwrap in its own `run-p<pid>-*.scope`, the program in the same scope, exit statuses pass through |
| `syscall_escape_1` | 36 denied system calls (every class of spec criterion 1) and 6 allowed ones from a Linux helper | EPERM (`clone3`: ENOSYS) through the real shim; with the shim cut out, a different answer for the 28 rows that have an oracle on the test host; see "Syscall-level escape tests" |
| `syscall_escape_2` | `ptrace`/`/proc/<pid>/mem` of a process outside the Landlock domain | refused; the same process in the same domain is reachable (what wineserver needs) |

Test 4 found a real gap while it was being written. bwrap's root is a writable tmpfs holding the directories it
creates for its mount points, so the write to `<app root>/permissions.toml` "succeeded" in that memory. The host
file never changed. The profile now ends with `--remount-ro /`. Forcing every sandboxed run of the suite to
`--unsandboxed` makes tests 1-6 and 8 fail with `SANDBOX HOLE` (test 7 is a CLI refusal and runs no program).

**What the suite does NOT prove.**
- **Same uid.** It tests the mount, network and PID views, (9, 10) that the seccomp filter is on and what it
  lets through for Wine, and (the `syscall_escape_*` tests) a sample of the denied calls through the real shim. The
  whole filter is tested entry by entry in `rt_sandbox` (a BPF interpreter and real filtered processes), not from a
  Windows program; a kernel bug in an allowed syscall is not covered.
- **Granted sockets are shared.** The display, audio and GPU pieces are the host's, and the suite does not attack
  them: the X11 server (shared input), the Wayland compositor, PulseAudio/PipeWire and the GPU driver.
- **`network = "allow"` is the host network.** Test 5 only shows that the switch changes something. With it on,
  every loopback service and abstract socket is reachable.
- **`/tmp` is refused as a grant.** The suite tests grants below the build directory only.
- **Only the listed paths are tested,** not every host path. The general claim ("only what is bound is visible")
  rests on bwrap and on the renderer's unit tests of the exact command line.

### Wine helpers in a prefix the app has written

A sandboxed program can write its own prefix, including registry `Run`/`RunOnce` keys, services and `DllOverrides`
naming a native DLL it dropped. Wine executes those at the start of the NEXT Wine session in that prefix, whatever
program that session was started for: measured on Wine 10.0, a `Run` key written into a prefix ran as soon as a
plain `wine reg query ...` started a session there (and on every `wineboot`). Outside a sandbox that is code with
your full access (`\\?\unix\` paths reach every file). Which commands start a Wine session in an app's prefix:

| Command | Wine session in the prefix | Sandboxed? |
|---|---|---|
| `runtime run <app>` | the program | yes, the app sandbox |
| `runtime run --unsandboxed <app>` | the program | NO, by request (it says so) |
| `runtime run <file>` | `wineboot -u` in a brand-new prefix, then the program | install: no (nothing app-written yet); program: yes |
| `runtime display <app> <choice>` | `reg.exe` | once the app ran sandboxed: yes, the app sandbox; before: no |
| `runtime deps <app> --install` (archive package) | `reg.exe` (DLL overrides, rollback) | once the app ran sandboxed: yes, the app sandbox; before: no |
| `runtime deps <app> --install` (installer package) | the installer, `reg.exe` | yes, the installer sandbox (offline) |
| `runtime uninstall <app>` | the recorded uninstaller | yes, the installer sandbox |
| `runtime remove`/`uninstall` (stop) | `wineserver -k`: not a session, runs no Windows code | no (not needed) |
| `runtime doctor` | `wine --version`: no prefix | no (not needed) |
| `runtime install` | `wineboot -u` in a brand-new prefix; the installer in the installer sandbox | installer: yes (installer sandbox); wineboot: not app-written yet |

"Ran sandboxed" is a marker file `ran-sandboxed` in the app root (never visible to the program: no sandbox binds
the app root). It is written whenever the runtime runs Windows code from outside your trust in the prefix inside a
sandbox: the first `runtime run`, AND `runtime install` of an installer (before the installer's own code starts),
`runtime deps <app> --install` whenever its plan may run an installer package (UP FRONT, before any package is
fetched and before the run's helper launcher is chosen, so an archive package's `reg.exe` that follows an installer
package in the same run is sandboxed too; and again before the installer and each of its own `reg.exe` steps), and
`runtime uninstall` (before the recorded uninstaller). It is written BEFORE that code runs and its failure fails the
operation (fail closed: nothing is fetched, installed or run if the marker cannot be written), so a prefix a
sandboxed installer or uninstaller touched is never later reached by an unsandboxed helper. From then on `display` and archive-package
`reg.exe` run through the same `AppSandbox` (the app's own profile, so they get nothing the app does not have) and
refuse, changing nothing, when bubblewrap is unavailable (a marker-path error other than "not found" also refuses).
Residual risk: an app that has NEVER run through any of those sandboxed paths is unmarked, so a prefix written by
`runtime run --unsandboxed`, or created before Phase 5A/Task 6 and never touched sandboxed since, still has its
`display`/archive-package `reg.exe` sessions run unsandboxed; and `runtime run --unsandboxed` runs whatever the app
wrote with your full access. `runtime sandbox <app>` warns about the latter.

**A running sandboxed app is invisible to `wineserver -k`.** Its `wineserver` keeps its socket in the sandbox's
private `/tmp`, so the stop of `runtime remove`/`uninstall` cannot reach it. Both therefore check the host's `/proc`
after the stop (the scan `deps`, `display` and `permissions` use too, by `WINEPREFIX` and Wine's server directory)
and REFUSE while a `wineserver` still serves the prefix, or when `/proc` cannot be read: `<id> is running
(wineserver pid N); quit it (Ctrl-C its runtime run) first; nothing was removed`. Nothing is deleted and no
uninstaller runs (real-Wine test: `e2e_real_wine_ctrl_c_ends_a_sandboxed_console_program`).

## seccomp and Landlock (Phase 5B)

bubblewrap no longer starts the program directly. It starts `runtime sandbox-init` (a hidden subcommand; the
runtime's own executable, bound read-only at its own path), which hardens itself and then `execve`s the program, so
everything the program starts (the Wine loader, `wineserver`, every Windows process) inherits the same layers. Its
only input is its argument block, written by the renderer and strictly checked (`--v1`, at most 256 `ro:`/`rw:`
rules with absolute paths, `--`, an absolute program; no NUL bytes); it reads no configuration file and no
environment variable for it. It is safe for anyone to run: it only takes rights away from itself and then runs a
program its caller could have run directly. Every refusal exits **126** with one `runtime: sandbox-init: ...` line on
the program's stderr, which a normal run writes to the app's log (`runtime logs <app>`; `--debug` shows it). In
order (`crates/sandbox/src/init.rs`):

1. `RLIMIT_CORE = 0`: no core dumps of Windows program memory.
2. **Landlock** (best effort): the filesystem ruleset below. Landlock missing from the kernel or disabled at boot:
   the run goes on without it, and `runtime sandbox` and `doctor` say so (a host-side probe; the shim prints
   nothing). Any other Landlock failure (a probe error, a rule that cannot be added) refuses the run.
3. **seccomp** (mandatory, fail closed): the deny-list in `crates/sandbox/src/seccomp.rs` (a table with a reason per
   syscall; `runtime sandbox` shows the count). Denied calls return `EPERM` (`clone3`: `ENOSYS`, so glibc falls
   back to `clone`, whose namespace flags are checked). The architecture is checked first: on x86-64 the x32 ABI is
   refused outright and the i386 ABI (`int 0x80`) except `set_thread_area`, the one call Wine makes through it: 32-bit
   Windows programs run in 64-bit processes (new WoW64), but Wine 10.0 allocates their 32-bit `%fs` selector with
   i386 `set_thread_area` (found when `hello32.exe` crashed under the first filter: "failed to allocate %fs
   selector"). It only sets a TLS descriptor of the calling thread. A filter that cannot be built for the host refuses the run at
   render time; one that cannot be installed refuses it in the shim.

**What they add.** seccomp closes kernel interfaces a Windows program has no business using and that have a long
record of escapes or host effects: `ptrace` (see below), `process_vm_readv`/`writev`, `kcmp`, the keyring calls,
`bpf`, `perf_event_open`, `userfaultfd`, every mount and namespace call (`unshare`, `setns`, `clone` with a
`CLONE_NEW*` flag, `clone3`), `open_by_handle_at`, module and kexec loading, `io_uring_setup` (io_uring requests
bypass seccomp), terminal injection (`ioctl` `TIOCSTI`/`TIOCLINUX`, next to `--new-session`), `personality` other
than the plain Linux/32-bit personas, and the `AF_VSOCK`/`AF_ALG`/`AF_KEY` socket families. Landlock enforces the
file layout a second time, in the kernel's LSM layer, so a mistake in the mount list is not a hole: the rules mirror
the bwrap binds exactly (`crates/sandbox/src/render.rs`, "Landlock"), and a real-bwrap test binds an extra file on
purpose, without a rule, and sees Landlock refuse to read it.

**The Landlock rules** (paths as they are INSIDE the sandbox, where bwrap's mount points are real directories even
when the host's `/lib` is a symlink): read+execute for the read-only binds (`/usr`, `/bin`, `/lib`, `/lib64`,
`/etc/alternatives`, the `/etc` files, Wine's DLL directories, with gpu the `/sys` parts and `/run/opengl-driver`,
each `ro` grant, the runtime executable); read-write (every right the kernel's ABI handles, including device ioctls
from ABI 5) for `/proc`, the device nodes of bwrap's `/dev` one by one (`null`, `zero`, `full`, `random`,
`urandom`, `tty`) and its `/dev/pts` and `/dev/shm` directories, `/tmp`, the runtime directory, with gpu `/dev/dri`
and each `/dev/nvidia*` node, each `rw` grant, the prefix and the app's home. `/dev` itself has no rule: a rule on it
would also allow creating entries there, and its links (`fd`, `stdin`, `ptmx`) resolve into paths that have rules.
Found by running, on kernel 7.0 (Landlock ABI 8): Landlock does not govern `connect()` on a unix socket file, so the
Wayland, PulseAudio and X11 sockets need no rule (what is bound is what is reachable); and bwrap's skeleton
directories (the parents of a bound path: the apps directory, a grant's parent, the directories above the runtime
executable) have no rule, so they cannot be listed from inside, which is stricter than bubblewrap alone (it shows
them with only the bound entry).

**`ptrace`, decided.** wineserver implements `ReadProcessMemory` and `WriteProcessMemory` on another process with
`ptrace`. Measured on Wine 10.0: with `ptrace` denied both fail with `ERROR_ACCESS_DENIED` (escape-suite probes
`readmem`/`writemem`, test 10), and strace shows wineserver's `PTRACE_ATTACH` refused. That breaks debuggers,
psapi's `GetModuleFileNameEx`/`EnumProcessModules` on another process, .NET's process list, crash reporters,
launchers and mod loaders that inject into a child. Same-process Set/GetThreadContext (registers, debug registers
of a suspended thread) does not need it. So `ptrace` is allowed for exactly the requests Wine's `server/ptrace.c`
makes: `ATTACH` was observed; `PEEKDATA`, `POKEDATA`, `CONT` and `DETACH` come from reading that file (the
cross-process memory tests pass with them); `PEEKUSER`/`POKEUSER` (debug registers of ANOTHER process's thread
through Get/SetThreadContext) come from the same file and are exercised by no test. `TRACEME`, `SEIZE`, `GETREGS`
and the rest stay denied. It is allowed **only when the Landlock domain is enforced**: Landlock refuses both
`ptrace` and `/proc/<pid>/mem` of any process outside the tracer's domain, which confines them to the program's own
process tree (verified by experiment). Without Landlock `ptrace` stays denied and cross-process memory access fails.

**Without Landlock the seccomp layer can be shed on hosts where Yama `ptrace_scope` is 0, via `/proc/1/mem`.**
bubblewrap's own PID 1 inside the sandbox (its reaper) is dumpable, has the same uid and carries no filter; opening
its `/proc/1/mem` (the sandbox's `/proc` is a fresh read-write procfs) is checked by `ptrace_may_access`, i.e. by
Yama and the LSMs, never by seccomp, so a program can write code into it and run unfiltered, still inside the
bubblewrap namespaces. Keeping `ptrace` denied there is still right (one fewer path), but it does not close this
one. `runtime sandbox` and `doctor` show, and `runtime run` (and any command that runs Windows code in the installer
sandbox) prints as one `note:` line at the start, `seccomp can be bypassed through /proc/1/mem on this host (no
Landlock, no Yama)` exactly when Landlock is unavailable and Yama's `ptrace_scope` is 0 or Yama is absent (Debian
and Fedora default to 0). With Landlock, or with Yama at 1 or more, the path is closed. `/proc` stays read-write
because bwrap mounts it that way; no test proves read-only would be enough.

**What they do NOT add.**
- **Same uid, same kernel.** A bug in a syscall the filter allows (the GPU driver's ioctls, the filesystem, the
  network stack, futexes) is still an escape; the deny-list narrows the surface, it does not close it.
- **Display, audio and GPU stay shared.** The X11, Wayland and PulseAudio sockets and the GPU nodes are reachable as
  before (Landlock does not restrict unix-socket `connect`, and the GPU needs its device ioctls).
- **Landlock is best effort.** Linux 5.13+ with Landlock in the boot-time LSM list; on older or differently
  configured kernels the mounts are the only file boundary and `ptrace` stays denied. Landlock's network rules are
  not used (`--unshare-net` already covers deny, and `allow` means all).
- **The runtime executable's path** is visible inside (read-only), and so are the names of the directories above it
  (empty; not listable with Landlock).
- **Inherited descriptors.** Landlock checks at `open`: the terminal and pipes the program inherits keep full rights.
- **Follow-up:** run the shim as the filtered PID 1 (`--as-pid-1`) once its signal handling is designed, which
  removes the unfiltered process from the sandbox. Not done now: an init without handlers ignores SIGINT/SIGTERM
  from inside the namespace, which would break the Ctrl-C forwarding of Phase 5A.

## Resource limits (Phase 5B)

**What runs.** When a limit applies, `runtime run` starts bwrap inside a transient systemd user scope:
`systemd-run --user --scope --collect --quiet --expand-environment=no -p TasksMax=<n> [-p MemoryMax=<m>M -p
MemorySwapMax=0] [-p CPUQuota=<p>%] -- bwrap ...` (cgroup v2). `runtime sandbox <app>` prints the limits, whether
scopes work, and that command line. The point is the desktop: a buggy or hostile app cannot take the session down
with a fork bomb (or, when asked for, by eating the memory or the CPU).

| `permissions.toml` `[limits]` | `--set` | Scope property | Default |
|---|---|---|---|
| `tasks = <n>` (16..65536) or `"unlimited"` | `tasks=<n>\|unlimited\|default` | `TasksMax=<n>` | 4096, best effort |
| `memory_mb = <MiB>` (64..1048576) | `memory=<MiB>\|off` | `MemoryMax=<MiB>M`, `MemorySwapMax=0` | none |
| `cpu_percent = <p>` (1..409600; `--set`: 1..100 x CPUs) | `cpu=<percent>\|off` | `CPUQuota=<p>%` | none |

**Needs systemd 254 or newer** (for `--expand-environment`): on older systemd the default task limit is skipped
with a note and a `doctor` warning, and explicit limits refuse the run. The CPU bound of a stored profile is fixed
(409600, i.e. 4096 CPUs), so a profile loads on any host and under any CPU affinity or quota `runtime` is started
with; `--set cpu=` also checks the CPUs this process may use, and a quota above the host's total just never
throttles. A 143 exit under a memory limit prints a note pointing at `journalctl --user -u 'run-p*.scope'`.

**Default vs requested.** Without a `tasks` key every run gets `TasksMax=4096`, best effort: when `systemd-run --user`
does not work (no user manager: a container, an SSH session without lingering; no cgroup v2; systemd older than 254,
which lacks `--expand-environment`) or the user manager does not delegate the `pids` controller, the run goes ahead
without a scope, prints `note: resource limits unavailable: <why>`, and `doctor` warns. ANY key written in the file
(including `tasks = 4096`, the default's own value) is a request and fails closed: if the scope cannot be created
with every controller it needs, the run is refused with the reason and the way out (`runtime permissions <app>
--set memory=off --set cpu=off --set tasks=default`, or start the app from a desktop/user session); `doctor` says
"runs of <app> will be refused". `systemd-run` is found on `PATH` and probed once per command (a throwaway scope,
5 s at most, the same options and only `PATH` and `XDG_RUNTIME_DIR` in its environment, like the real command); the
probe reads which controllers the user manager offers its scopes.

**Signals and exit codes** (measured with systemd 259). With `--scope`, `systemd-run` registers the scope and then
EXECS the command in place: the process `runtime` started keeps its pid, and it is bwrap (the scope is named
`run-p<that pid>-i<n>.scope`; asserted by the escape suite), so the Phase 5A forwarding of Ctrl-C/SIGTERM reaches
bwrap exactly as before (the real-Wine Ctrl-C test still ends the program within ~2 ms with 130/143). The exit
status is the command's own (the program's code, 130/143 for a forwarded signal). Scope names are unique per pid, so
concurrent runs of one app get separate scopes; `--collect` removes a finished scope even when it failed.
`--expand-environment=no` matters: by default `systemd-run` expands `$VAR`/`${VAR}` in the command line (`$$`
becomes `$`), which would change the program's arguments. `systemd-run` adds `INVOCATION_ID` to the environment the
program sees (a random id, harmless). A `systemd-run` failure after the probe (the user manager went away) ends the
run with its message and exit 1, before bwrap starts.

**What the limits give, and what they do not.**
- **They are per scope, i.e. per run.** Every process of one run (Wine, `wineserver`, whatever the program starts)
  shares one budget. Two concurrent runs of one app get two budgets. The task limit protects the desktop, not the
  app from itself: a fork bomb inside a run still starves that run's own processes.
- **`TasksMax` counts threads as well as processes.** A Wine process has several threads, so `tasks = 64` allows
  about twenty Windows processes (measured: a CreateProcess loop stopped after 21-23 copies); the default 4096 is
  well above what real programs use.
- **`MemoryMax` is a limit, not a reservation.** Nothing is set aside for the app; at the limit the kernel reclaims
  and then OOM-kills inside the scope (with no swap: `MemorySwapMax=0`), and systemd then stops the whole scope
  (its default `OOMPolicy=stop`): the program ends, `runtime` reports 143 (the scope's SIGTERM to bwrap), and
  `journalctl --user` shows `Failed with result 'oom-kill'`. Measured: a 512 MiB hog under `memory = 128` ended after
  ~1 s; the test process and the session were unaffected.
- **`CPUQuota` is a throttle.** `cpu_percent = 150` is one and a half CPUs' worth of time per period; the program
  runs slower, it is never killed for it.
- **Not limited:** disk space, IO bandwidth, GPU time and GPU memory, network bandwidth, open files beyond the
  kernel's per-process defaults. Processes the program reaches OUTSIDE the scope (the X server, the compositor,
  PulseAudio/PipeWire, the GPU driver's kernel work) are charged to themselves, not to the app.
- **Only the app sandbox.** `runtime run` and the Wine helpers that run in an app's sandbox (once it ran sandboxed)
  get the scope; the installer sandbox and `--unsandboxed` runs do not.

## What the hardening layers add and do not

The app sandbox is four layers, each a kernel mechanism that holds if the one before it has a mistake. None of them
is Wine: Wine only translates the program's calls, and a hostile program can bypass it completely.

| Layer | Mandatory? | What it adds | What it does not |
|---|---|---|---|
| bubblewrap (5A) | yes: no bwrap, no run | its own mount, PID, IPC, UTS (and without `network = "allow"`, network) namespaces; only the profile's paths, devices and sockets; no capabilities, `no_new_privs`; a new session | the same uid and the same kernel; the bound sockets and devices are the host's |
| seccomp (5B) | yes: a filter that cannot be built or installed refuses the run | EPERM for the calls below | no protection from a bug in an allowed call (file systems, the network stack, futexes, the GPU driver's ioctls); not a sandbox by itself |
| Landlock (5B) | best effort, reported | the file layout a second time, in the LSM layer; `ptrace` and `/proc/<pid>/mem` confined to the program's own processes | nothing on kernels without it (older than 5.13, or Landlock not in the boot-time LSM list); no network or unix-socket rules |
| cgroup limits (5B) | the default task limit is best effort; any limit in `permissions.toml` is mandatory | a task limit (4096) against fork bombs; memory and CPU on request | disk, IO, GPU time and memory, network bandwidth; work done for the app by processes outside its scope (X server, compositor, audio server, GPU driver) |

**The seccomp deny-list.** Denied calls return `EPERM` (the program sees an ordinary error and can degrade; nothing
is killed). This table is `rt_sandbox::seccomp::DENIED` itself (a test fails when they differ):

<!-- deny-list: rt_sandbox::seccomp::DENIED, checked by the_security_document_lists_the_deny_list -->
| syscall | refused when | why |
| `ptrace` | always | inspects and rewrites the memory and registers of other processes of the same user |
| `process_vm_readv` | always | reads another process's memory directly |
| `process_vm_writev` | always | writes another process's memory directly |
| `kcmp` | always | compares kernel objects (files, memory maps) of other processes, leaking how they are shared |
| `keyctl` | always | manages kernel keyrings, which hold credentials and are shared with the session outside the sandbox |
| `add_key` | always | adds keys to the kernel keyrings (see keyctl) |
| `request_key` | always | looks up keyring keys and can make the kernel run the host's request-key helper |
| `bpf` | always | loads eBPF programs and maps, a large kernel attack surface |
| `perf_event_open` | always | performance counters: a large kernel attack surface and a side channel |
| `userfaultfd` | always | lets a program stall page faults (even the kernel's) at will, a standard kernel-exploit primitive |
| `mount` | always | mounts filesystems; the sandbox's mount layout is fixed by bubblewrap |
| `umount2` | always | unmounts filesystems, which could uncover what the sandbox's mounts hide |
| `pivot_root` | always | changes the root mount |
| `chroot` | always | changes the root directory |
| `unshare` | always | creates namespaces; a new user namespace grants capabilities inside it |
| `setns` | always | joins other namespaces |
| `open_by_handle_at` | always | opens files by handle, bypassing path-based confinement (the 'shocker' container escape) |
| `name_to_handle_at` | always | produces the file handles open_by_handle_at consumes |
| `kexec_load` | always | loads a new kernel to boot into |
| `kexec_file_load` | always | loads a new kernel to boot into |
| `init_module` | always | loads a kernel module |
| `finit_module` | always | loads a kernel module |
| `delete_module` | always | unloads a kernel module |
| `syslog` | always | reads or clears the kernel log, which leaks kernel addresses and host activity |
| `acct` | always | switches process accounting on or off |
| `quotactl` | always | manages filesystem quotas |
| `quotactl_fd` | always | manages filesystem quotas (by file descriptor) |
| `swapon` | always | enables a swap area |
| `swapoff` | always | disables a swap area |
| `reboot` | always | reboots or halts the machine |
| `settimeofday` | always | sets the system clock |
| `clock_settime` | always | sets a system clock |
| `clock_adjtime` | always | adjusts a system clock |
| `adjtimex` | always | adjusts the system clock |
| `sethostname` | always | renames the host |
| `setdomainname` | always | renames the host's NIS domain |
| `vhangup` | always | hangs up the current terminal |
| `iopl` | always | grants direct access to hardware I/O ports (x86-64) |
| `ioperm` | always | grants direct access to hardware I/O ports (x86-64) |
| `lookup_dcookie` | always | obsolete profiling interface that turns kernel directory cookies into paths |
| `nfsservctl` | always | obsolete NFS server control (removed from Linux in 3.1) |
| `move_pages` | always | moves the memory pages of other processes between NUMA nodes |
| `mbind` | always | NUMA memory policy: unused by desktop programs, historically buggy kernel code |
| `set_mempolicy` | always | NUMA memory policy: unused by desktop programs, historically buggy kernel code |
| `get_mempolicy` | always | NUMA memory policy: unused by desktop programs, historically buggy kernel code |
| `migrate_pages` | always | moves the memory pages of other processes between NUMA nodes |
| `fanotify_init` | always | watches file access across whole mounts or filesystems |
| `mount_setattr` | always | new mount API: changes mount attributes |
| `move_mount` | always | new mount API: attaches or moves mounts |
| `open_tree` | always | new mount API: clones mount trees |
| `fsopen` | always | new mount API: creates a filesystem context |
| `fsconfig` | always | new mount API: configures a filesystem context |
| `fsmount` | always | new mount API: creates a mount from a filesystem context |
| `fspick` | always | new mount API: reconfigures a mounted filesystem |
| `pidfd_getfd` | always | copies a file descriptor out of another process |
| `process_madvise` | always | gives memory advice for another process's address space |
| `uselib` | always | obsolete a.out library loader (x86-64) |
| `io_uring_setup` | always | io_uring runs operations without seccomp seeing them (it could open the sockets denied below) |
| `clone3` | always (`ENOSYS`) | its flags live behind a pointer seccomp cannot read; ENOSYS makes glibc fall back to clone |
| `clone` | arg0 has any bit of 0x7e020080 | creates namespaces (CLONE_NEW* flags); threads and plain forks are allowed |
| `ioctl` | arg1 is one of 0x5412, 0x541c | TIOCSTI and TIOCLINUX push input into a terminal, e.g. keystrokes into the user's shell |
| `personality` | arg0 is none of 0x0, 0x8, 0xffffffff | only PER_LINUX, PER_LINUX32 and the query are allowed; other flags weaken exploit mitigations |
| `socket` | arg0 is one of 0x28, 0x26, 0xf | AF_VSOCK (hypervisor), AF_ALG (kernel crypto, a recurring exploit vector), AF_KEY (IPsec keys): no Windows API uses them |
<!-- /deny-list -->

Three things are not in the table:
- **The architecture check comes first.** On x86-64 the x32 ABI (any number with bit 30 set) is refused, and so is
  every i386 call (`int 0x80`) except `set_thread_area` (243), which Wine 10.0's new WoW64 makes to set up a 32-bit
  program's `%fs` selector (without it every 32-bit program crashes) and which only sets a TLS descriptor of the
  calling thread.
- **`ptrace` when Landlock is enforced.** The shim then installs a second variant of the filter that lets exactly
  Wine's requests through (`ATTACH`, `DETACH`, `PEEKDATA`, `POKEDATA`, `PEEKUSER`, `POKEUSER`, `CONT`;
  `rt_sandbox::seccomp::WINE_PTRACE`), because Landlock confines them to the program's own processes; `TRACEME`,
  `SEIZE`, `GETREGS` and the rest stay refused ("`ptrace`, decided" above).
- **The residual without Landlock.** bubblewrap's pid 1 inside the sandbox carries no filter. Without Landlock,
  where Yama's `ptrace_scope` is 0, the program can write into it through `/proc/1/mem` and run code without the
  filter (still inside the namespaces). `runtime sandbox` and `doctor` say so on such a host.

**Landlock, what exactly.** File-system rights only, negotiated with the kernel's ABI (1 to 8 are known; the rights a
newer kernel adds are not used): read+execute for the read-only binds, every handled right (from ABI 5 including
device ioctls) for the writable ones and the device nodes; the rule list is in "The Landlock rules" above. What it
breaks: the parent directories bubblewrap creates for a bound path (the apps directory, a grant's parent, the
directories above the runtime executable) cannot be listed, so a Windows file dialog cannot browse above a granted
folder. What it does not do: restrict `connect()` on a unix socket file (measured on ABI 8), restrict the network,
or take rights away from descriptors the program inherited (its terminal and pipes).

**What still reaches the host from inside, with every layer on.**
- **Your uid.** Anything bound is reachable as you: the prefix, the app's home, each grant (`rw` grants can be
  destroyed).
- **Kernel code behind every allowed call.** The deny-list removes the interfaces with the worst record; a bug in
  what stays allowed (and Wine needs a lot) is an escape.
- **Display, audio and GPU** (on by default). The X11 server is shared: the program can read and inject the input of
  every other X11 window, which is code execution as you (`display = off` removes it). The Wayland compositor,
  PulseAudio/PipeWire and the GPU driver's kernel code are reachable; Landlock does not restrict unix-socket
  `connect`, and the GPU needs its device ioctls.
- **`network = "allow"` is the host's network namespace**, including abstract unix sockets (X11's among them) and
  every loopback service.
- **The installer sandbox has seccomp and Landlock but no resource limits** ("Installer sandbox" above), and
  `--unsandboxed` runs have no layer at all.

### Syscall-level escape tests

A Windows program cannot make raw Linux system calls, so `crates/cli/tests/e2e_sandbox.rs` (`syscall_escape_1`,
`syscall_escape_2`, `syscall_escape_4`; no Wine needed, so they run in the ordinary `cargo test` on glibc hosts) uses a Linux helper: the
test binary itself, re-executed inside the sandbox and bound read-only through the renderer's ordinary read-only
binds. The command is the one `runtime run` renders for the default profile (the systemd-run scope, bwrap, and the
real `runtime` binary as `sandbox-init`); nothing test-only is added to the production code. Each call runs in its
own forked child with arguments that do nothing even if the filter let the call through (NULL or bad pointers, fd
-1, invalid flags or magic numbers). **The oracle** is the same command with the shim's words cut out: bwrap alone,
the same binds and namespaces, no Landlock and no seccomp. The tests skip visibly without bwrap, seccomp, Landlock
(the Landlock half of `syscall_escape_2`) or IA32 emulation (the `int 0x80` rows); **`RUNTIME_REQUIRE_BWRAP=1` (set
by CI's `test` job) turns each of those skips into a failure**, so it requires seccomp, Landlock and IA32 emulation
too. Yama `ptrace_scope` 2 or 3 stays a visible skip of `syscall_escape_2` even then: no unprivileged attach can
succeed there, so there is nothing to observe.

**Which layer of tests covers what.**
- **The BPF interpreter** (`crates/sandbox/src/seccomp/tests.rs`): every `DENIED` entry, with all-ones arguments,
  and every argument rule's refused and allowed values; the only layer that proves, for every entry, that the
  FILTER refuses it.
- **Real kernel, outside bubblewrap** (`crates/sandbox/src/seccomp/tests/kernel.rs`):
  `every_denied_entry_is_refused_by_a_real_filtered_call` calls every `DENIED` entry (63 on x86-64) for real in a
  filtered child and requires EPERM (`clone3`: ENOSYS). Only the filtered answers are checked. With the filter
  removed (measured, then reverted) 46 of the 63 answer something else. The other 17 are EPERM for an unprivileged
  caller anyway, because the kernel checks a capability first: `kexec_load`, `kexec_file_load`, `init_module`,
  `finit_module`, `delete_module`, `syslog`, `acct`, `swapoff`, `reboot`, `sethostname`, `setdomainname`,
  `vhangup`, `fanotify_init`, `move_mount`, `fsopen`, `fsmount`, `fspick`. For those, only the interpreter
  distinguishes the filter from the kernel. A second test there runs 35 probes (on x86-64) WITH and WITHOUT the filter and
  requires a different answer where the kernel's own is deterministic.
- **The real pipeline** (`syscall_escape_1`, the table below): 42 rows, 36 of them denied calls covering every class
  of spec criterion 1, EPERM through the shim except `clone3` (ENOSYS). A **strict** row requires a specific
  non-EPERM answer from bwrap alone, where the kernel's argument checks answer before any permission check. A
  **host** row accepts whatever bwrap alone answers, because host policy decides it (Yama, AppArmor's user-namespace
  restriction, sysctls, loaded modules, the kernel version). When that answer is also EPERM, the test prints "NO
  ORACLE here" instead of failing, and the row rests on the tests above. The row names and classes below are checked
  against the test's own list by `syscall_escape_3_the_security_table_is_the_test_list`. Measured on 2026-09-26
  (kernel 7.0, bubblewrap 0.11.1, systemd 259, Landlock ABI 8, Yama 1, AppArmor's user-namespace restriction on,
  `dev.tty.legacy_tiocsti` 0): **28 of the 36 denied rows had an oracle.** With the shim also cut out of the
  "through the shim" run, exactly those 28 fail; the 8 without an oracle pass either way.

<!-- pipeline-rows: the ROWS of crates/cli/tests/e2e_sandbox.rs, checked by syscall_escape_3 -->
| Row (the helper's call) | Class | Through the shim | bwrap only (here) | Oracle here |
|---|---|---|---|---|
| `getpid` | allowed | 0 | 0 | same answer both ways |
| `thread (clone3 -> clone fallback)` | allowed | 0 | 0 | same answer both ways |
| `mmap(PROT_EXEC)` | allowed | 0 | 0 | same answer both ways |
| `socket(AF_UNIX)` | allowed | 0 | 0 | same answer both ways |
| `ioctl(TCGETS) on a pty` | allowed | 0 | 0 | same answer both ways |
| `int 0x80 set_thread_area(NULL)` | allowed | EFAULT | EFAULT | the kernel answered, not the filter |
| `ptrace(TRACEME)` | host | EPERM | 0 | yes |
| `ptrace(SEIZE, 0)` | strict | EPERM | ESRCH | yes |
| `unshare(NEWUSER)` | host | EPERM | 0 | yes |
| `unshare(NEWUSER\|PARENT)` | strict | EPERM | EINVAL | yes |
| `clone(NEWUSER\|SIGCHLD)` | host | EPERM | 0 | yes |
| `clone(thread flags\|PIDFD\|NEWUSER)` | strict | EPERM | EINVAL | yes |
| `clone3(NULL, 0)` | host | ENOSYS | EINVAL | yes |
| `mount(bad type)` | strict | EPERM | EFAULT | yes |
| `keyctl(9999)` | strict | EPERM | EOPNOTSUPP | yes |
| `bpf(9999)` | host | EPERM | EINVAL | yes |
| `perf_event_open(NULL)` | strict | EPERM | EACCES | yes |
| `userfaultfd(USER_MODE_ONLY)` | host | EPERM | 0 | yes |
| `open_by_handle_at(NULL)` | host | EPERM | EFAULT | yes |
| `io_uring_setup(1, NULL)` | host | EPERM | EFAULT | yes |
| `ioctl(TIOCSTI) into its own terminal` | strict | EPERM | EIO | yes |
| `pivot_root(NULL, NULL)` | host | EPERM | EFAULT | yes |
| `chroot(NULL)` | strict | EPERM | EFAULT | yes |
| `setns(-1, 0)` | strict | EPERM | EBADF | yes |
| `umount2(NULL, bad flags)` | strict | EPERM | EINVAL | yes |
| `kexec_load(1000 segments, bad flag)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `syslog(SIZE_BUFFER)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `acct(bad pointer)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `quotactl(bad type)` | strict | EPERM | EINVAL | yes |
| `swapon(NULL, bad flags)` | strict | EPERM | EINVAL | yes |
| `swapoff(bad pointer)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `reboot(bad magic)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `init_module(NULL)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `finit_module(-1)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `delete_module(NULL)` | host | EPERM | EPERM | **no**: EPERM without the filter too |
| `add_key(NULL)` | strict | EPERM | EFAULT | yes |
| `request_key(NULL)` | strict | EPERM | EFAULT | yes |
| `ioctl(TIOCLINUX) on a pty` | strict | EPERM | ENOTTY | yes |
| `socket(AF_VSOCK)` | host | EPERM | 0 | yes |
| `socket(AF_ALG)` | host | EPERM | 0 | yes |
| `int 0x80 getpid` | strict | EPERM | 0 | yes |
| `x32 getpid` | strict | EPERM | ENOSYS | yes |
<!-- /pipeline-rows -->

`syscall_escape_2` covers the Landlock half of the `ptrace` decision without Yama in the way: the helper forks a
child and attaches it (`PTRACE_ATTACH`) and opens its `/proc/<pid>/mem`. From the same Landlock domain both work
(0, 0: what wineserver does). After the helper enters a new, nested domain through a second `runtime sandbox-init`,
the same child is outside it and both are refused (EPERM, EACCES). The tracer is the child's parent both times, so
Yama at 1 allows it, as the first run shows. With the nested domain removed, the test fails.

`syscall_escape_4` runs every row of the table through the INSTALLER sandbox (`rt_installer::InstallerSandbox::new`
and `wrap`, the production path, with the helper bound like a dll directory and the real `runtime` as the shim) with
the same expectations and the same bwrap-only oracle; measured the same answers as the table's two columns. The
bwrap-only column is what the installer sandbox was before Phase 5B Task 6.

Not covered by any of these tests: `ptrace` of bwrap's own pid 1 on a host without Landlock (the residual above;
Yama at 1 here hides it), and a kernel bug behind an allowed call.

## Roadmap

Phase 5B's layers are in place for the app sandbox (seccomp, Landlock, resource limits and their escape tests) and,
without resource limits, for the installer sandbox (Task 6). Later: resource limits for installers; the dependency
engine's path-based prefix operations move to held directory descriptors; the shim as the filtered pid 1 (removing
the unfiltered bubblewrap reaper, and with it the no-Landlock `/proc/1/mem` residual).

## Reporting

Please report a hole in any of the measures above as an issue or privately to the maintainer. Bypasses of the
"still NOT covered" and "does NOT protect" lists are known and are not vulnerabilities.
