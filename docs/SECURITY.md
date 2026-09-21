# Security model (Phase 2)

**Phase 2 is NOT a sandbox.** A Windows program started by `runtime run` runs as your Linux user, with your
network, GPU, audio and display, and can read and write everything that user can. The measures below make
accidents less likely and remove Wine's most obvious host exposure. They do not stop a program that wants out.
The real boundary is planned for Phase 5. Every command that runs Windows code prints a note saying so.

## Threat model

Assume the installer or application is **malicious**. It will run Windows code inside Wine as your uid. What this
project tries to protect is the *runtime's own* handling of untrusted input (archives, PE files, `metadata.json`,
file names, program output) so that merely installing, listing, inspecting or removing something cannot hurt you.
What it does not protect is anything a running program can reach on its own. Do not run software you would not run
directly on your account. Treat the isolation between apps (separate prefixes) as accident prevention, not a
guarantee: a hostile program can go around it (below).

## What Phase 2 does

Each item below is covered by unit or hostile-input tests; the ones marked (e2e) are also checked against real
Wine by the `#[ignore]`d tests (`crates/cli/tests/e2e_wine.rs`, `crates/backend-wine/tests/e2e_wine.rs`).

- **One Wine prefix per app**, under `$RUNTIME_DATA_DIR/apps/<id>/prefix` (default `~/.local/share/runtime`).
  A second app does not see the first app's `C:` files (e2e).
- **Prefix hardening** after creation (`crates/backend-wine/src/harden.rs`): `dosdevices` is reduced to `c:`, so
  there is no `Z:` drive (e2e: `Z:\etc\hostname` is not found from inside the app); the profile symlinks Wine
  creates (Desktop, Documents, Downloads, Music, Pictures, Videos, Templates) are replaced by empty real
  directories (e2e). It never follows symlinks and refuses a symlinked prefix or `drive_c`. `runtime doctor <app>`
  audits the same state read-only.
- **Environment allowlist**: the program is started with `env_clear()` plus `PATH HOME USER LOGNAME LANG LANGUAGE
  LC_* TERM DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_RUNTIME_DIR XDG_SESSION_TYPE DBUS_SESSION_BUS_ADDRESS
  PULSE_SERVER`. API keys, `SSH_AUTH_SOCK`, `LD_PRELOAD` and any host `WINE*` variable are dropped, and so is any
  value containing NUL (e2e: a host variable is not visible inside the app). The variables that are passed are
  visible to Wine and to the program's host-side processes. On Wine 10.0 the app's Windows environment shows `HOME` as unset
  (the e2e test prints this, it does not assert it); that is a Wine detail, not a guarantee.
- **Zip extraction defences** (`crates/core/src/unzip.rs`): the archive's end record and central directory are
  validated strictly *before* the zip library sees the file (one valid end record at the exact end of the file,
  consistent counts, at most 20 000 entries, directory at most 64 MiB, zip64 checked); at most 4 GiB total and per
  entry; a compression-ratio limit; only regular files and directories are extracted, symlink and special entries
  are skipped; names are parsed with the same rules as Windows paths (no `..`, absolute or drive paths, reserved
  device names, backslash tricks) and never trusted as given; files are created with `create_new` (no overwrite,
  never through a link) and archive permission bits are ignored.
- **`AppId` and Windows path containment**: app ids match `^[a-z0-9][a-z0-9._-]*$` (at most 64, no `..`), and
  `remove`/`logs` accept ids only, never paths. Windows paths from metadata or archives are parsed
  (`winpath.rs`) and resolved case-insensitively under the prefix's `drive_c` without traversing symlinks.
- **Atomic, bounded metadata**: `metadata.json` is written to a temporary file, synced and renamed; reads are
  size-capped and non-blocking, the schema version is checked, string fields are capped.
- **Read-only `doctor`**: it installs and changes nothing, and reports what it could not check.
- **No shell anywhere**: every child process is started from an argument vector; arguments reach the program
  verbatim (tested with quotes, `;`, `$(...)` and newlines).
- **Terminal-escape sanitising**: everything printed that came from a file, archive, log or metadata (names, PE
  strings, Wine's output, `logs`, `doctor`) is escaped for control and bidi characters. `--json` output is
  escaped for C1 and bidi characters too, but consumers must still sanitise before display.
- **Cleanup**: `remove` stops the app's `wineserver` first; the e2e tests assert that no `wineserver` for the app
  is left behind.

## What Phase 2 does NOT do

- **No sandbox boundary.** No seccomp, namespaces, Landlock or bubblewrap. The program shares the host's network
  (it can connect anywhere), GPU, audio and display sockets.
- **Wine's `\\?\unix\` escape.** Wine maps the host filesystem into the NT namespace regardless of drive letters.
  From a Windows program, `\\?\unix\etc\hostname` (in a C string `"\\\\?\\unix\\etc\\hostname"`) opens the
  host's `/etc/hostname`, and `\\?\unix\home` and `\\?\unix\etc\passwd` are found the same way, with the
  `Z:` drive gone. Verified by hand on Wine 10.0 with the `fs64.exe` fixture (`stat` prints `EXISTS`). Removing
  `Z:` and the profile links is defence in depth against casual access, nothing more, and there is deliberately
  no test that claims isolation from `\\?\unix\`. This also means one app can read another app's prefix.
- **`com*` links come back.** Wine recreates `dosdevices/com1..` (links to `/dev/ttyS*`) every time a prefix
  starts. Only `c:` is left after `prepare`; the e2e tests allow `com*` after a run. This cannot be prevented
  without a sandbox.
- **Races (TOCTOU).** Checks such as "not a symlink" are followed by uses without `openat2`/`O_PATH`
  confinement, and a same-uid process (the app itself) that keeps swapping directories for links can win a race
  against `run`, `logs`, `doctor` or `remove`. Some cases are narrowed (`O_NOFOLLOW`, `O_NONBLOCK`, lstat before
  use, `remove_dir_all` does not follow links), none are closed. `wineboot` runs before hardening, so on an already
  existing prefix it could follow links planted by an earlier run.
- **Zip rules stricter than the format.** These valid archives are refused on purpose: self-extracting archives
  (data before the first entry), archives with signature records, and an archive that contains a stored
  (uncompressed) zip in its last 64 KiB. So are archives with more than 20 000 entries or a directory over 64 MiB.
- **Memory.** `analyze`, `install` and `doctor` read a whole file into memory, up to 4 GiB.
- **Logs.** One log per run under `logs/`, 20 kept per app, no size limit on a single log (a program can fill
  the disk). `logs` prints only the end of the newest one.
- **No locking.** `remove` can race `run` (or a second `run`); the last writer wins and a run can lose its
  prefix. Do not run several commands on one app at once.
- **Run-by-path installs every time.** `runtime run some.exe` creates a *new* app on each invocation
  (`some-2`, `some-3`, ...) with its own prefix. Use `install` once and `run <id>` afterwards.
- **.NET, Mono and Gecko are disabled** (`WINEDLLOVERRIDES=mscoree=d;mshtml=d;winemenubuilder.exe=d`), so .NET
  and HTML-embedding programs fail until Phase 4 provides a dependency mechanism. `doctor` warns about .NET.
- **Installers and MSI are refused** (Phase 3); only portable `.exe` files and `.zip` archives are handled.
- **`--debug` copies the program's stderr to your terminal as it is** (not sanitised): a hostile program can
  write terminal escape sequences there. The log file keeps the same bytes; `logs` sanitises them.

## Roadmap

Phase 5 adds the actual boundary: run Wine inside bubblewrap (mount and PID namespaces, a private filesystem
view without the host), Landlock rules as a second layer where bubblewrap is unavailable, and a seccomp filter,
with the network and device access decided per app. The `Launcher::wrap` hook in `rt_core` is the seam
prepared for it (an identity function today). Until then, this document is the truth and the README says the
same.

## Reporting

Please report a hole in any of the measures above as an issue or privately to the maintainer. Bypasses of the
"does NOT do" list are known and are not vulnerabilities in Phase 2.
