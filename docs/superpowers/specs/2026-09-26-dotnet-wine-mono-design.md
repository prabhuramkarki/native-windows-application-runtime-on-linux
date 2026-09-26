# Phase 4F: .NET through Wine Mono (design)

Status: approved by the controller on the user's standing instruction (2026-09-25: self-approve with recommended
choices; 2026-09-26: "continue recommended"). Closes the unmet Phase 4 exit criterion "a .NET app runs".

## 1. Purpose and success criteria

Managed (.NET) programs fail today: the runtime sets `WINEDLLOVERRIDES=...;mscoree=d;...` on every Wine process, so
Wine's `mscoree` (the .NET loader) is disabled, and `doctor` says so. Wine runs managed code through Wine Mono, a
free, redistributable Mono build that Wine looks for at `C:\windows\mono\mono-2.0` inside the prefix.

A spike on this host (Wine 10.0, Ubuntu repack; scratch prefix, no runtime code) established the facts:
- Wine 10.0 expects `wine-mono-9.4.0-x86.msi` (appwiz.cpl names it). It is 84,639,232 bytes, SHA-256
  `cf6173ae94b79e9de13d9a74cdb2560a886fc3d271f9489acb1cfdbd961cacb2`, served from
  `https://dl.winehq.org/wine/wine-mono/9.4.0/wine-mono-9.4.0-x86.msi`.
- `wine msiexec /i <msi> /qn` installs it in about 4 s into `C:\windows\mono\mono-2.0` (2,920 files, 231 MiB;
  the runtime DLL is `bin\libmono-2.0-x86_64.dll`).
- With `mscoree` NOT disabled, Wine loads it: `csc.exe` (Roslyn, shipped inside the package at
  `lib\mono\4.5\csc.exe`) compiled a C# program under Wine and the result ran and printed
  `hello from .NET 4.0.30319.42000` with the arguments passed through. So the test fixture can be built inside Wine
  from the package itself; no host Mono, no committed binary.

The deps engine already installs `.msi` installer packages through `msiexec /i <staged> <silent_args>` and the
import table already maps `mscoree` to a `dotnet` capability that no package provides yet.

Success criteria:
1. `runtime deps <managed app>` plans `wine-mono`; `--install` downloads, verifies, and installs it through the
   sandboxed installer pipeline (offline, seccomp + Landlock shim, marker-confirmed) and records it.
2. For an app with `wine-mono` recorded, `runtime run` starts Wine WITHOUT `mscoree=d`; every other app keeps it.
3. `runtime run` of a managed program under the full sandbox (seccomp deny-list, Landlock, limits) works on real Wine
   (JIT and threads under the filters), with exit code and arguments passed through.
4. `doctor <managed app>` says what is true: Ok when Wine Mono is installed for the app, Warn with the exact
   command when it is not; nothing for native programs.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Distribution | The official `.msi`, as an `installer` package (`silent_args = ["/qn"]`), not the `.tar.xz` | The archive installer needs an explicit per-file `extract` list (2,920 files) and an xz decoder (new dependency); the MSI path exists, is hardened, and is what Wine itself uses. |
| Success marker | file `windows/mono/mono-2.0/bin/libmono-2.0-x86_64.dll` (absent in a fresh prefix, present after install: verified) | The engine confirms installs by marker, never by exit code. |
| Where it lives | A per-app copy (231 MiB) | Simple and matches Wine. A shared read-only mount is a possible later optimisation (bwrap bind over `C:\windows\mono`); not needed to be correct. |
| Enabling | `RunOpts.dotnet: bool`, set by the run service from the app's recorded dependencies (`id == "wine-mono"`); the Wine backend omits `mscoree=d` only when set | The recorded state, not prefix files, decides (same trust rule as 4A). Installer and helper sessions keep `mscoree=d`. |
| Version | One pin, 9.4.0, matched to Wine 10.0 (the tested Wine) | Wine expects a specific Mono; a mismatch is a known Wine caveat. Documented; `doctor` does not try to guess other pairings. |
| Consent | `requires_consent = false`, licence text `LGPL-2.1-or-later AND MIT AND GPL-2.0-or-later` style SPDX-like string (free software; nothing is redistributed by the project, the file is fetched from the upstream url) | Same rule as DXVK/VKD3D-Proton in 4A/4B. |
| Test fixture | Built on demand by a script that installs the pinned MSI in a scratch prefix and runs the package's own `csc.exe` | No committed binary, no host toolchain. |

Non-goals: .NET Framework 4.8 proper (Microsoft's own runtime is proprietary and known-flaky on Wine), .NET
(Core) 5+ runtimes, WinForms/WPF GUI coverage claims, Mono version selection per app, sharing Mono between apps,
Wine Gecko (mshtml).

## 3. Components

- `crates/deps/packages.toml`: the `wine-mono` entry (`provides = ["dotnet"]`), verified pins; tests: bundled
  manifest invariants, `mscoree.dll` import plans `wine-mono`, the ignored real-net refetch covers it.
- `crates/core/src/backend.rs`: `RunOpts { debug, dotnet }`; `crates/core/src/run.rs`: `dotnet` from
  `Metadata.dependencies` (constant `DOTNET_PACKAGE_ID = "wine-mono"`); `crates/backend-wine/src/lib.rs`: the
  override string without `mscoree=d` when `opts.dotnet` (two constants, no string surgery).
- doctor: the existing .NET check (`PeInfo.dotnet`) becomes state-aware.
- `tools/build-managed-fixture.sh` (network + Wine): produces `tests/fixtures/build/hello-managed.exe`.
- Ignored real-net e2e: `runtime install hello-managed.exe` -> `deps --install` -> `run` under the default sandbox.

## 4. Risks

- Mono under seccomp/Landlock (JIT `mprotect`, signals, `memfd`, threads): tested for real in Task 3; a denied
  syscall Mono needs is a FINDING handled like the ptrace one (trade-off written down, not silent).
- 85 MB download and a 231 MiB per-app footprint: documented; the fetch deadline already scales with size.
- Managed apps depend on more than the CLR (WinForms, WCF, third-party native calls): the compat matrix records
  what actually ran; nothing broader is claimed.
