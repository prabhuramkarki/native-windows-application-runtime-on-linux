# Phase 4, sub-projects D and E: doctor prediction, compatibility matrix, D3D11 render fixture (design)

Status: approved by the controller on the user's standing instruction (2026-09-25: self-approve with recommended
choices). Closes Phase 4 (4A dependency engine, 4B graphics backends, 4C audio and display are merged). 4D and 4E
are small and share a theme (say what will work, and record what did), so they are one spec, three tasks.

## 1. Purpose and success criteria

Roadmap Phase 4 leftovers: "full `doctor app` (arch, PE, imports vs prefix, graphics, audio, runtimes, .NET, env)",
"compatibility matrix v1 (`docs/COMPAT.md`, machine-readable, statuses only from CI/manual test records)", and the
D3D11 rendering fixture and FPS smoke moved here from 4B. Exit criterion: "`doctor` correctly predicts a deliberately
broken env".

`doctor <app>` already has Architecture, PE, Imports, Graphics, Audio, Runtime, Prefix and Program checks.
What is missing: it says nothing about (a) managed .NET programs and (b) which Direct3D route the app will actually
take.

Success criteria:

1. `doctor <app>` for a managed (.NET) program warns that it needs a .NET runtime and that the runtime bundles none
   (Wine's own Mono is not verified by doctor), instead of reporting its native imports as if that settled it.
2. `doctor <app>` reports the Direct3D route per API family the app imports (D3D8/9/10/11 and D3D12): DXVK (or
   VKD3D-Proton) when the package is installed for the app AND the host Vulkan verdict is not Unusable, Wine's
   built-in wined3d/vkd3d otherwise with the reason (package not installed: run `runtime deps`; Vulkan unusable:
   <reason>; package blocked), and nothing for families the app does not import.
3. `runtime compat` prints the compatibility matrix from bundled machine-readable records; `docs/COMPAT.md` is the
   same rendering and a test fails when they drift. A record cannot claim `works` or `partial` without evidence.
4. A tiny D3D11 fixture renders offscreen through DXVK on real Wine and verifies a pixel and reports a frame time;
   its real run on this host is recorded in the matrix as a manual record.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Matrix format | TOML records (`crates/cli/compat.toml`, embedded like the package manifest), not YAML | The workspace already parses TOML with `toml`+`serde`; YAML would add a dependency for no benefit. The roadmap's "machine-readable" is met. |
| Where it renders | `runtime compat` (text table, `--json`) plus a committed `docs/COMPAT.md` checked by a drift test | One source of truth; the doc cannot go stale silently. |
| Evidence rule | `status` in `works|partial|broken|untested`; `works` and `partial` require `evidence` (`ci:<job>` or `manual:<date>`) and `gpu` when the record is about graphics | "Statuses only from CI/manual test records" (roadmap section 35). |
| Seeding | Only records that actually happened: the console/GUI fixtures CI runs, and the D3D11 fixture run done in Task 3 on this host. No invented third-party app results. | A matrix with made-up entries would be worse than an empty one. |
| Prediction inputs | Import list, the runtime's own recorded installed packages (never the prefix files), the Vulkan verdict and the existing plan | Same trust rule as 4A: a hostile installer cannot forge "DXVK installed". |
| Render fixture in CI | Not in CI (needs network for the DXVK download and a Vulkan device); ignored test + documented manual command | 4B ruling; CI has no GPU. Frame time is printed, not thresholded. |

Non-goals: benchmarks with thresholds, per-app compatibility scraping, a .NET/Mono package, GUI.

## 3. Components

- `crates/core/src/doctor.rs`: `DoctorInput` gains `d3d_routes: Option<&[D3dRoute]>` (typed, computed by the CLI from
  the plan/state/Vulkan verdict; `None` for a system report) and uses the existing `PeInfo.dotnet` flag for the .NET
  check. New pure `enum D3dRoute { Dxvk{family}, Vkd3dProton, Wined3d{family, reason: String} }`, rendered by one
  new check per imported family, bounded and escaped like the rest of doctor.
- `crates/cli/src/doctor.rs`: builds `d3d_routes` from `rt_deps::plan_for_pe` entries and the Vulkan verdict.
- `crates/cli/src/compat.rs` + `crates/cli/compat.toml`: strict parser (deny unknown fields, size caps, status/evidence
  rules), `runtime compat [--json]`, and the drift test against `docs/COMPAT.md`.
- `tools/fixtures/d3d11.c` + `tools/build-fixtures.sh`: `d3d11_64.exe` (mingw): D3D11 device on the default adapter,
  renders a clear to an offscreen texture, copies to a staging texture, reads a pixel, prints `pixel ok` and the
  frame time of N=100 clears+flushes in ms, exits 0 (non-zero on any failure or wrong pixel).
- Ignored e2e `real_net_wine_d3d11_renders_via_dxvk` (crates/deps tests): fresh app env, installs the bundled DXVK
  through `install_archive` with a real download, runs the fixture under Wine with the app's normal launch path,
  asserts exit 0 and `pixel ok`.

## 4. Testing

Doctor unit tests for the .NET check and every route/verdict combination; a CLI doctor test with a `d3d11.dll`
importing fixture on the rig; compat parser hostile/strict tests and the drift test; the fixture e2e run manually
here and recorded.

## 5. Risks

- DXVK 3.x on a host without Vulkan 1.4 features: the fixture run may fail on a weak driver; the record says
  `broken` with the GPU/driver, which is the point of the matrix.
- Wine 10.0 vs DXVK 3.x (wiki wants Wine 10.1+ for winevulkan): the manual run either works or the record says so.
