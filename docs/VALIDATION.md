# Validation record — 2026-10-14 through 2026-10-16

Source checked: local `main` at `f0d67be` (Phase 6F merged). The working tree was clean before this documentation
update. The recorded `origin/main` is `f9c8246` (Phase 6D), 21 commits behind. No commits were pushed during this
check. API version: 0.2.3; app metadata schema: 5; backend interface: 2.

## Local checks

Host: x86-64 Linux, kernel `7.0.0-38-generic`, Rust 1.98.1, Wine 10.0
(`10.0~repack-12ubuntu1`), GTK 4.22.4, libadwaita 1.9.1. The initial baseline used existing generated Windows
fixtures in `tests/fixtures/build`; the follow-up Wine validation rebuilt them with `tools/build-fixtures.sh`.

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | Passed |
| `cargo clippy --locked --offline --workspace --exclude runtime-gui --all-targets -- -D warnings` | Passed |
| `cargo clippy --locked --offline -p runtime-gui --all-targets -- -D warnings` | Passed |
| `cargo test --locked --offline --workspace --exclude runtime-gui` | 1,953 passed, 0 failed, 49 explicitly ignored |
| Same tests with `RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1` | 1,953 passed, 0 failed, 49 explicitly ignored |
| `cargo build --locked --offline -p runtime-daemon -p runtime-cli` | Passed; supplies the binaries used by GUI integration tests |
| `RUNTIME_REQUIRE_DISPLAY=1 xvfb-run -a cargo test --locked --offline -p runtime-gui` | 53 standard tests and 15 widget tests passed; no failures |

The initial non-GUI attempt inside the coding agent's sandbox failed process-launch tests with `Operation not
permitted`. The successful test runs above used approved execution outside that sandbox. The strict non-GUI run
requires the project's sandbox and desktop facilities instead of allowing their usual skip paths.

The initial checks above do not run the explicitly ignored Wine, real-download, GPU-rendering or real-binary oracle suites.
Xvfb widget tests do not replace manual GNOME/KDE checks. No real-application records were added during that initial pass, and it did not rerun `cargo deny`.
The 2026-10-15 follow-up below adds both an advisory audit and real-application evidence.

The follow-up rebuilt the native Windows fixtures, then ran:

```sh
RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1 \
  cargo test --locked --offline -p runtime-backend-wine -p runtime-cli -- \
  --ignored --skip real_net_ --test-threads=1 --nocapture
```

All 27 tests passed (3 backend, 6 installer, 13 sandbox, 5 app-lifecycle), with no explicit skip messages. This
run included the task-limit and memory-limit probes: the 64-task limit stopped the bounded process-spawning
probe after 22 copies, and the 128 MiB scope terminated the 512 MiB allocation probe with exit 143.
The full run used the original helper-escape test; the strengthened version below was verified separately.

The dependency engine's real-Wine suite also passed all 10 tests, with no ignored tests or prerequisite skips:

```sh
RUNTIME_REQUIRE_BWRAP=1 cargo test --locked --offline -p runtime-deps --lib -- \
  --ignored e2e_real_wine --test-threads=1 --nocapture
```

This covers fixture archive formats, DLL overrides, installer markers and deadlines, service containment,
consent and download-hash enforcement using the local HTTPS test server, interrupted-install recovery, and
dependency removal. The removal test restored both a previous `builtin` override and an empty override, while
preserving and reporting a DLL modified since installation. These tests do not download the real bundled
redistributables or establish real-application compatibility.

## Follow-up: helper sandbox regression test

The planted-`reg.exe` test in `crates/cli/tests/e2e_installers.rs` could pass on headless CI without exercising
the sandboxed payload. It requested `runtime display APP wayland`, which refuses before launching a helper
without a Wayland session. The test only asserted that no outside canary appeared, so that refusal looked like
successful containment. Adding an exit-status assertion reproduced the failure with `DISPLAY` and
`WAYLAND_DISPLAY` unset.

The test now clears both display variables itself and requests `x11` in both the sandboxed and control runs;
that setting permits a headless registry helper. The fixture writes an in-prefix marker after attempting the
outside write. The test requires `blocked` inside and no host canary when sandboxed, removes the inside marker,
then requires `escaped` inside and the expected host canary contents in the unsandboxed control. Both commands
must exit successfully. The target now lives under `CARGO_TARGET_TMPDIR`, outside `/tmp`: the sandbox's private
`/tmp` can otherwise accept a write to a private copy of the path without touching the host.

The corrected test passed under Wine 10.0 with both display variables unset and
`RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1`. The changed C fixture compiled with
`-Wall -Wextra -Werror`; formatting and Clippy for the installer integration-test target passed.
This closes a test-coverage gap; it is not a production sandbox change or a diagnosis of the hosted CI failures.

## Sequential follow-up — 2026-10-15

These are local checks of the working tree based on `f0d67be`, not a release or hosted-CI result.
Existing phase implementations were validated in order; their unfulfilled exit requirements remain open.

### Phase 0: dependency security and baseline

A fresh `cargo deny check` found five new advisories in the lockfile:
[ruzstd RUSTSEC-2026-0344](https://rustsec.org/advisories/RUSTSEC-2026-0344) and
[rustls RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346),
[0347](https://rustsec.org/advisories/RUSTSEC-2026-0347),
[0348](https://rustsec.org/advisories/RUSTSEC-2026-0348),
[0349](https://rustsec.org/advisories/RUSTSEC-2026-0349).
The workspace minimums and lockfile now use ruzstd 0.9.1 and rustls 0.23.46. No advisory exceptions were added.
The subsequent audit passed advisories, bans, licenses and sources; existing duplicate-version warnings remain.

A small malformed zstd frame now proves that a compressed sequence block expanding beyond its advertised window
is rejected. Its valid-window control passes. The same malformed block was accepted by 0.9.0 (`Ok(1028)`) in an
isolated reproduction; 0.9.1 rejects it. Another regression verifies the outer output cap on a literal-only block.
The patched decoder still accepts a literal-only block exceeding its advertised window, so the documentation no
longer claims that the frame window alone caps total decoder memory. This bounded literal path is distinct from
the fixed unbounded sequence expansion. All 111 tarball tests passed.

After updating dependencies, the strict non-GUI workspace suite passed 1,954 tests, with 49 explicitly ignored.
That run included the sequence regression but preceded the second (literal-only) regression and the two ignored
real-app tests below. The latter additions were checked separately. Workspace Clippy passed with warnings denied.

### Phase 1: PE analysis

```sh
RUNTIME_SAMPLES=/usr/lib/x86_64-linux-gnu/wine/x86_64-windows:/usr/lib/x86_64-linux-gnu/wine/i386-windows \
  cargo test --locked --offline -p runtime-pe --test real_world -- --ignored --nocapture
```

The `file` oracle agreed on 1,447 Wine PE files: zero non-PE or unreadable samples, zero unchecked architectures,
and no mismatches. The oracle deliberately omits kind comparisons for 32 native-subsystem files. These are a
parser corpus, not 1,447 independent application compatibility results.

### Phases 2–3: real portable application and MSI lifecycle

The official [7-Zip download page](https://www.7-zip.org/download.html) links the 26.04 release (2026-10-05).
Both samples below were downloaded from the vendor's GitHub release and checked against its
[release asset digests](https://api.github.com/repos/ip7z/7zip/releases/tags/26.04).

| Sample | SHA-256 |
|---|---|
| [7zr.exe, x86 portable console](https://github.com/ip7z/7zip/releases/download/26.04/7zr.exe) | `256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282` |
| [7z2604-x64.msi](https://github.com/ip7z/7zip/releases/download/26.04/7z2604-x64.msi) | `0b01334a418654293513449f61d6bfc99e5196ca371e3c3dc961eda57cd535c6` |

To reproduce with those downloaded files:

```sh
RUNTIME_7ZIP_EXE=/tmp/runtime-7zr-26.04.exe \
RUNTIME_7ZIP_MSI=/tmp/runtime-7zip-26.04-x64.msi \
RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1 \
  cargo test --locked --offline -p runtime-cli --test e2e_real_apps -- \
  --ignored --test-threads=1 --nocapture
```

Both tests passed on Wine 10.0. Each creates, tests and extracts a 7z archive through `runtime run` under the
default sandbox, then checks a 64 KiB binary payload and a text file with spaces in its name byte-for-byte.
The portable test installs and removes the x86 executable. The MSI test silently installs the x64 package with
an explicit `Program Files\7-Zip\7z.exe` entry, validates its desktop file, requires a recorded uninstall command,
and uninstalls without warnings; both the environment and desktop entry disappear. All state and desktop files
are in disposable directories. The tests require the pinned hashes before execution and never download files.
They are explicitly ignored in ordinary runs and excluded by CI's existing `--skip real_net_` fixture filter.

The matrix now has two 7-Zip observations and the existing 18 fixture observations. This is **one real application
family**, not two apps toward the 25-app requirement. GUI behavior, shell integration and all archive formats
other than this 7z roundtrip are untested.

### Phases 4–5: dependencies and isolation

The Phase 4 dependency Wine suite passed all 10 tests again with the patched TLS and archive libraries:

```sh
RUNTIME_REQUIRE_BWRAP=1 cargo test --locked --offline -p runtime-deps --lib -- \
  --ignored e2e_real_wine --test-threads=1 --nocapture
```

No prerequisite skips occurred. ZIP, gzip and zstd archive installation/removal, installer containment and
timeouts, local HTTPS consent/hash enforcement, interrupted-install recovery, override restoration and
preservation of modified files passed. The earlier Phase 5 escape/resource-limit evidence above remains
relevant: those production paths did not change. The real 7-Zip tests also exercised the default app sandbox.

### Phase 6: daemon and desktop client

The GUI suite was rerun with rebuilt CLI/daemon binaries and passed all 68 tests under Xvfb.
On 2026-10-16, both real-Wine daemon tests passed with no skips:

```sh
RUNTIME_REQUIRE_BWRAP=1 cargo test --locked --offline -p runtime-daemon --test e2e_jobs -- \
  --ignored --test-threads=1 --nocapture
```

The output test received the Windows program's stdout and its intentional exit code 7 through job events.
The cancellation test waited for the sandboxed program to print before cancelling it, then successfully removed
the app, proving that the run released its lock and Wine processes. Formatting and workspace/all-targets
Clippy with `-D warnings` also passed on this final working tree.

The final non-GUI workspace run on 2026-10-16 passed **1,955 tests, zero failures, 51 explicitly ignored**, with
`RUNTIME_REQUIRE_BWRAP=1 RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE=1 cargo test --locked --offline --workspace
--exclude runtime-gui`. This includes both new zstd regressions and the regenerated compatibility matrix;
the two new real-app tests account for the increased ignored count and were run explicitly above.

Manual GNOME/KDE checks, a real game and .NET Framework GUI app, the 25-app target, authenticated hosted-CI
diagnosis, and API stabilization remain open. Native phases 7–9 remain behind the roadmap's post-1.0 gate.

## GUI dependency removal follow-up — 2026-10-16

The Phase 6F GUI follow-up now uses the existing `apps.get` installed package list and `deps.remove` method.
No backend, API or metadata schema changed. Confirmation captures the app/package pair; read-only, disconnected,
busy and older daemons cannot send removal. Cancel is the default; a stale confirmation cannot remove a package
from a different app. The old install plan is discarded and completion reloads the app.

The GUI suite passed under `RUNTIME_REQUIRE_DISPLAY=1 xvfb-run -a cargo test --locked --offline -p runtime-gui`:
56 standard tests and 16 widget scenarios. New coverage includes version/connection/busy guards, duplicate clicks,
stale dialogs, literal text, cancellation, and the real CLI/daemon removal path with fake Wine. The latter checks
actual file deletion, byte-preserving retention of a modified DLL, refusal of an old record, job output, and the
reloaded installed-package list. GUI/all-targets Clippy, formatting and diff whitespace checks passed.

Removal is one package per GUI action; dependency-group refusals retain the CLI's multi-package instructions.
Installer packages and older records remain unsupported. Xvfb does not complete the manual GNOME/KDE checklist.

## Hosted CI evidence

GitHub's public Actions job metadata was read on 2026-10-14:

| Run | Commit | Result |
|---|---|---|
| [Full CI, 2026-09-26](https://github.com/prabhuramkarki/native-windows-application-runtime-on-linux/actions/runs/36228837680) | `9cf1e27` | `test` failed at `cargo test --workspace`; `wine-e2e` and `deny` passed |
| [Full CI, 2026-09-28](https://github.com/prabhuramkarki/native-windows-application-runtime-on-linux/actions/runs/36387272941) | `f9c8246` | `test`, `gui`, and `wine-e2e` failed; `deny` passed |
| [Pin verification, 2026-10-12](https://github.com/prabhuramkarki/native-windows-application-runtime-on-linux/actions/runs/38246047754) | `f9c8246` | `verify-pins` passed; this does not run the application test suites |

In the latest full CI run, the failing steps were:

- `test`: `cargo test --workspace --exclude runtime-gui`.
- `gui`: `xvfb-run -a cargo test -p runtime-gui`.
- `wine-e2e`: the ignored backend/CLI tests, before the dependency-engine Wine tests ran.

The full log endpoint for the older failed test job returned HTTP 403 without authentication. Its public
annotations, and the newer GUI and Wine job annotations, only report exit code 101, not a failing test or root
cause. No authenticated GitHub CLI, GitHub token environment variable, or Git credential-helper entry is available
in this environment (credential values were not printed). The Phase 6E user-namespace and user-systemd-manager workarounds remain hypotheses awaiting
hosted validation; the newer full CI run predates those changes. Local success does not establish their efficacy
on a hosted runner.

## Next validation work

1. Read authenticated logs from the latest full CI run and identify the first actual failure in each failed job.
2. Validate the current 6E/6F code on a hosted runner, with targeted changes only where the logs justify them.
3. Run and record the manual GNOME/KDE checklist and real-application compatibility tests toward the 25-app bar.
4. Decide API stability after these checks; keep native-backend research behind the existing post-1.0 gate.
