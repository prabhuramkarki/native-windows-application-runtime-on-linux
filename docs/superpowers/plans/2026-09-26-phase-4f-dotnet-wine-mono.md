# Phase 4F .NET through Wine Mono Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Managed programs run: a bundled, verified `wine-mono` MSI package is installed per app through the sandboxed installer pipeline, and `mscoree` is enabled only for apps that have it.

**Architecture:** One manifest entry (the MSI path and the `dotnet` capability already exist); `RunOpts.dotnet` plumbs the recorded package into the Wine environment; doctor becomes state-aware; a network e2e proves the whole chain under the hardened sandbox.

**Tech Stack:** Rust workspace, Wine 10.0 + Wine Mono 9.4.0, the existing deps engine, real Wine + bwrap + seccomp + Landlock.

**Spec:** `docs/superpowers/specs/2026-09-26-dotnet-wine-mono-design.md`

## Global Constraints

- Every pin (url, sha256, exact size) is verified by an actual download in the task that commits it: url `https://dl.winehq.org/wine/wine-mono/9.4.0/wine-mono-9.4.0-x86.msi`, size 84639232, sha256 `cf6173ae94b79e9de13d9a74cdb2560a886fc3d271f9489acb1cfdbd961cacb2` (re-verify; do not trust this text).
- Enabling `mscoree` is decided ONLY from the runtime's own recorded dependency (`Metadata.dependencies`), never from prefix files; installer and helper Wine sessions keep `mscoree=d`.
- The installer runs in the installer sandbox with the seccomp/Landlock shim, offline, exactly like every installer package (nothing special-cased); a filter/rule change needed by Mono or msiexec is a FINDING with a written reason.
- Untrusted text is sanitised; no new dependency; fmt/clippy/test stay green after every task; network/Wine tests are `#[ignore]` with names starting `real_net_wine_` (never picked up by CI's `e2e_real_wine` filter) and skip visibly without network.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## Review Focus

- A native app must keep `mscoree=d` byte-for-byte (env test), including installer/helper sessions of a managed app (Task 2).
- `wine-mono` recorded but its files later deleted: the run still enables mscoree (recorded state decides) and Wine's own error surfaces; doctor must not claim success it cannot verify beyond the record (Task 2).
- A hostile/oversized `Metadata.dependencies` (duplicate ids, 10,000 records): `dotnet` detection is a bounded lookup (Task 2).
- Consent and plan semantics for `wine-mono` (no consent, plan order, `--yes` refusals) identical to DXVK's (Task 1).

---

### Task 1: the `wine-mono` package

**Files:** Modify `crates/deps/packages.toml`, `crates/deps/src/capabilities.rs` (comment + tests), `crates/deps/src/manifest/tests.rs` or the bundled-invariant test files as needed. Test: `cargo test -p runtime-deps`.

- [ ] **Step 1: Verify the pin.** Download the MSI (`curl -L`), check size and `sha256sum` against the constants above and against dl.winehq.org's listing; list what the MSI contains only through the spike's known facts (do not install here). Record the real values in the report.
- [ ] **Step 2: Failing tests:** (a) the bundled manifest contains `wine-mono` with `kind = installer`, `provides == ["dotnet"]`, no `requires`, `requires_consent == false`, marker file `windows/mono/mono-2.0/bin/libmono-2.0-x86_64.dll`, silent_args `["/qn"]`, no dll_overrides; (b) `resolve` for `Facts { imports: ["mscoree.dll"] }` plans exactly `[wine-mono]` (Action::Install, ConsentState::NotNeeded); (c) `capabilities.rs`'s comment "No package provides `dotnet` yet" and the unprovided-list tests (`["dotnet"]`) are updated to the new truth (no unprovided capability remains — adjust the invariant test that lists unprovided capabilities); (d) the licence string is accepted by the manifest validator and printed by `runtime deps list`.
- [ ] **Step 3: Implement** the manifest entry with a header comment recording: the pin's provenance (verified by download on today's date), the Wine-version coupling (Wine 10.0 expects Mono 9.4.0), the marker verification (absent in a fresh prefix, present after `msiexec /i ... /qn`), that the package is installed per app (231 MiB) and provides the C# compiler used by the test fixture.
- [ ] **Step 4:** the ignored real-net refetch test (`real_net_bundled_packages_refetch_and_match`) covers the new pin — run it (`cargo test -p runtime-deps --lib -- --ignored real_net_bundled_packages_refetch_and_match --test-threads=1`, network) and paste; full gate; commit `feat(deps): bundle Wine Mono 9.4.0 as the dotnet package`.

---

### Task 2: enable `mscoree` per app; state-aware doctor

**Files:** Modify `crates/core/src/backend.rs` (`RunOpts.dotnet`), `crates/core/src/run.rs`, `crates/backend-wine/src/lib.rs` (override constants), `crates/core/src/meta.rs` (`DOTNET_PACKAGE_ID` + a bounded `Metadata::has_dependency(&str)`), `crates/core/src/doctor.rs` + `crates/cli/src/doctor.rs`, README, docs/SECURITY.md. Test: unit + rig tests.

**Interfaces:**
- Produces: `RunOpts { debug: bool, dotnet: bool }` (update every constructor: grep `RunOpts {`); `pub const DOTNET_PACKAGE_ID: &str = "wine-mono";` in `rt_core`; backend override strings `WINEDLLOVERRIDES` (unchanged, with `mscoree=d`) and `WINEDLLOVERRIDES_DOTNET` (without it) chosen in `command()` from `opts.dotnet` ONLY; doctor input carries `dotnet: DotnetState { NotManaged | ManagedNeedsMono | ManagedMonoInstalled }` computed by the CLI from `PeInfo.dotnet` + recorded dependency.

- [ ] **Step 1: Failing tests:** backend env tests (`backend-wine`): `command(.., RunOpts{dotnet:false})` env `WINEDLLOVERRIDES` == the existing exact string (frozen); `dotnet:true` == `winemenubuilder.exe=d;mshtml=d` exactly; helper/`prepare`/`stop`/installer-command constructors (`wine_command` users other than `command()`) always use the disabled string; core `run` sets `dotnet` from Metadata (fake backend records opts): true only when a `DependencyRecord` with id `wine-mono` exists; 10,000 records / duplicates handled boundedly; doctor: managed + recorded => `Ok` ("managed (.NET) program: Wine Mono 9.4.0 is installed for this app"; version from the record), managed + not recorded => `Warn` with "run `runtime deps <app> --install`" (the id is validated app id, escaped), native => no check; the old ".NET ... mscoree=d ... fails" text is gone everywhere (grep) and the file-target doctor case says Wine Mono is installed per app by `runtime deps` (a file target is not installed: Warn-free Info-level text? use `Ok` "managed program; Wine Mono is not installed (file targets are not installed apps)" — pick and test).
- [ ] **Step 2: Implement**; keep `Copy` on `RunOpts`; update the plan/hint output (`runtime deps <managed app>` already plans `wine-mono` via Task 1); README (.NET section: what works, the 231 MiB per app, Mono 9.4.0 with Wine 10.0), SECURITY.md (Mono adds a JIT to the sandboxed process set: seccomp/Landlock apply as for any program; the package is a pinned upstream MSI; still installer-sandboxed).
- [ ] **Step 3:** full gate; commit `feat(core,backend-wine,doctor): enable mscoree for apps with Wine Mono recorded`.

---

### Task 3: managed fixture and the end-to-end proof under the hardened sandbox

**Files:** Create `tools/build-managed-fixture.sh`, `tools/fixtures/hello-managed.cs`; Modify `.gitignore` if needed (the built exe lives under the existing gitignored `tests/fixtures/build/`), `crates/cli/tests/e2e_dotnet.rs` (new, `#[ignore]`, `real_net_wine_`), `crates/cli/compat.toml` + `docs/COMPAT.md`, README, docs/SECURITY.md.

- [ ] **Step 1: Fixture script** (network + Wine 10): in a scratch `WINEPREFIX` under `mktemp -d`, download and VERIFY the pinned MSI (size + sha256 from the manifest values), `wine msiexec /i <msi> /qn` with `WINEDLLOVERRIDES=winemenubuilder.exe=d;mscoree=d;mshtml=d`, then run the package's `C:\windows\mono\mono-2.0\lib\mono\4.5\csc.exe /nologo /out:C:\hello-managed.exe C:\hello-managed.cs` with `mscoree` enabled, copy `hello-managed.exe` to `tests/fixtures/build/`, delete the scratch prefix. `hello-managed.cs`: prints `hello from .NET <Environment.Version> args=<n>` plus each argument on its own line, writes nothing else, returns exit code 7; a second mode `threads` spawns 4 threads incrementing a shared counter under a lock and prints the total (exercises JIT + threads under seccomp), and `alloc` allocates and touches ~64 MiB (GC under the sandbox). The script refuses to run without Wine or network (clear message) and is idempotent (skips when the exe exists unless `--force`).
- [ ] **Step 2: e2e** `real_net_wine_dotnet_runs_under_the_default_sandbox` (ignored; needs network, Wine, bwrap; skip visibly without `hello-managed.exe`): fresh data root via the rig; `runtime install hello-managed.exe`; assert `runtime doctor <app>` says Wine Mono is needed (Warn) and `runtime deps <app>` plans `wine-mono`; run `runtime run <app>` first and assert it FAILS (mscoree disabled: the program does not print the greeting — this documents the "before"); `runtime deps <app> --install` (real download through the engine, ~85 MB; the installer sandbox with the shim) succeeds, the record exists in metadata, `doctor` says installed; `runtime run <app> a b` prints `hello from .NET`, argument echo, exit code 7, under the default sandbox (seccomp + Landlock; assert via `runtime sandbox <app>` that both are enforced on this host); then the `threads` and `alloc` modes; a native app run in a second env still has `mscoree=d` (assert through the env of a probe: the existing `fs env WINEDLLOVERRIDES` fixture mode prints it). Cleanup the data root. If a denied syscall or a Landlock rule breaks Mono, find it with `strace -f`/`SECCOMP_RET_LOG` in a scratch build and adjust the FILTER/RULES with a written reason (never weaken the test) and list every change in the report.
- [ ] **Step 3: Records and docs:** add compat records ONLY for what ran today: `.NET console fixture (tools/fixtures/hello-managed.cs) under Wine Mono 9.4.0, default sandbox` (`manual:<today>`, status per the real run, exact `wine --version`), regenerate `docs/COMPAT.md`; README/SECURITY.md updated; ROADMAP status table row 4F and the Phase 4 exit-criteria paragraph updated to what is now true (".NET runs: met for Mono-compatible console programs; a real .NET Framework 4.8 GUI app is not claimed").
- [ ] **Step 4:** full gate + paste the e2e output; commit `test(cli): managed program runs under Wine Mono in the hardened sandbox`.

---

## Self-Review

- Criteria: 1 -> Tasks 1 and 3; 2 -> Task 2; 3 -> Task 3; 4 -> Task 2.
- Placeholders: none; the empirical points (Mono under the filters) are an explicit find-and-record step.
- Types: `RunOpts.dotnet`, `DOTNET_PACKAGE_ID`, `WINEDLLOVERRIDES_DOTNET`, `DotnetState` are named identically across tasks.
