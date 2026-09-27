# Documentation index

Start with the top-level [README](../README.md) (what the runtime does, the commands, how to test), then
[ARCHITECTURE.md](ARCHITECTURE.md).

## Reference

| Document | What it is |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The crates, their dependency graph, the install, run and daemon-job flows, the trust boundaries and the backend seam. |
| [SECURITY.md](SECURITY.md) | The security model: the threat model, what each sandbox layer enforces and does not, dependency downloads, the daemon, the GUI, backends and `.wrun` packages, and the known bounds. |
| [API.md](API.md) | The `runtimed` JSON-RPC API: methods, types, errors, jobs, versioning (0.2.1) and setup. |
| [WRUN.md](WRUN.md) | The `.wrun` v1 package format for package authors: the container, the manifest, `runtime pack` and what a package cannot do. |
| [COMPAT.md](COMPAT.md) | The compatibility matrix: only what was really run, with its evidence (generated from `crates/api/compat.toml`). |
| [THIRD_PARTY.md](THIRD_PARTY.md) | The project's licence, every third-party crate with its licence and purpose, and the bundled dependency packages. |
| [GUI-CHECKLIST.md](GUI-CHECKLIST.md) | The manual GUI checks to run on GNOME and KDE. |

## Roadmap and plans (`superpowers/plans/`)

| Plan | Scope |
|---|---|
| [runtime-master-roadmap](superpowers/plans/2026-09-21-runtime-master-roadmap.md) | Every phase, its status, the strategic decisions, the open decisions and the v1.0 exit criteria. |
| [phase-0-1](superpowers/plans/2026-09-21-phase-0-1-foundations-and-pe-analysis.md) | Workspace, CI, fixtures and the hardened PE parser. |
| [phase-2](superpowers/plans/2026-09-21-phase-2-environments-and-wine-backend.md) | App environments, the store, the Wine backend and the `Launcher`. |
| [phase-3](superpowers/plans/2026-09-22-phase-3-installers-and-desktop-integration.md) | The sandboxed installer pipeline, desktop entries and uninstall. |
| [phase-4a](superpowers/plans/2026-09-23-phase-4a-dependency-engine.md) | The dependency engine: the pinned manifest, consent and the verified fetcher. |
| [phase-4b](superpowers/plans/2026-09-25-phase-4b-graphics-backends.md) | Vulkan probe, DXVK and VKD3D-Proton, the `.tar.zst` reader. |
| [phase-4c](superpowers/plans/2026-09-26-phase-4c-audio-and-display.md) | Audio checks and the per-app Wine graphics driver. |
| [phase-4d](superpowers/plans/2026-09-26-phase-4d-doctor-compat-render.md) | Doctor prediction, the compatibility matrix and the D3D11 render fixture. |
| [phase-4f](superpowers/plans/2026-09-26-phase-4f-dotnet-wine-mono.md) | .NET through Wine Mono. |
| [phase-5a](superpowers/plans/2026-09-26-phase-5a-app-sandbox-profile.md) | Per-app permissions and the bubblewrap run sandbox. |
| [phase-5b](superpowers/plans/2026-09-26-phase-5b-seccomp-landlock-limits.md) | seccomp, Landlock and resource limits. |
| [phase-6a](superpowers/plans/2026-09-27-phase-6a-api-and-daemon.md) | The typed API crate and the read-only `runtimed`. |
| [phase-6b](superpowers/plans/2026-09-27-phase-6b-daemon-write-and-jobs.md) | The daemon's write methods and jobs. |
| [phase-6c](superpowers/plans/2026-09-27-phase-6c-gui-client.md) | The GTK 4 + libadwaita GUI client. |
| [phase-6d](superpowers/plans/2026-09-27-phase-6d-backend-and-wrun.md) | The backend contract and conformance suite, `.wrun` packages, licences and these docs. |

The Phase 6 plans end with an "As built" section, and the roadmap's status table records where earlier phases departed from their plans.

## Designs (`superpowers/specs/`)

| Spec | Scope |
|---|---|
| [dependency-engine](superpowers/specs/2026-09-23-dependency-engine-design.md) | Phase 4A: the package manifest, consent and the fetcher. |
| [graphics-backends](superpowers/specs/2026-09-25-graphics-backends-design.md) | Phase 4B: DXVK, VKD3D-Proton and the Vulkan probe. |
| [audio-and-display](superpowers/specs/2026-09-26-audio-and-display-design.md) | Phase 4C: the audio path and the Wine graphics driver. |
| [doctor-compat-and-render](superpowers/specs/2026-09-26-doctor-compat-and-render-design.md) | Phases 4D and 4E: doctor prediction, the matrix, the render fixture. |
| [dotnet-wine-mono](superpowers/specs/2026-09-26-dotnet-wine-mono-design.md) | Phase 4F: Wine Mono per app. |
| [app-sandbox-profile](superpowers/specs/2026-09-26-app-sandbox-profile-design.md) | Phase 5A: `permissions.toml` and the bubblewrap sandbox. |
| [seccomp-landlock-limits](superpowers/specs/2026-09-26-seccomp-landlock-limits-design.md) | Phase 5B: the `sandbox-init` shim, seccomp, Landlock and cgroup limits. |
| [api-and-daemon](superpowers/specs/2026-09-27-api-and-daemon-design.md) | Phase 6A: `rt_api` and the read-only daemon. |
| [daemon-write-methods](superpowers/specs/2026-09-27-daemon-write-methods-design.md) | Phase 6B: write methods, jobs and consent by plan digest. |
| [gui-client](superpowers/specs/2026-09-27-gui-client-design.md) | Phase 6C: `runtime-gui`. |
| [backend-interface-and-wrun](superpowers/specs/2026-09-27-backend-interface-and-wrun-design.md) | Phase 6D: the backend contract, capabilities, the registry and `.wrun` v1. |
