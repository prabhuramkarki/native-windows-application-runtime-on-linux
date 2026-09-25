# Phase 4, sub-project B: graphics backends (design)

Status: draft for review. Second of five Phase 4 sub-projects (4A dependency engine is merged). Builds on
`2026-09-23-dependency-engine-design.md`; nothing here changes 4A's trust model.

## 1. Purpose and success criteria

4A already maps imports to packages (`d3d8/9/10/11/dxgi` -> `dxvk`) and installs the bundled DXVK per app. What is
missing: D3D12 (VKD3D-Proton), any knowledge of the host GPU/Vulkan, and a way to say "this host cannot run DXVK,
use Wine's built-in wined3d".

Success criteria:

1. `runtime graphics info` prints the host's Vulkan devices (name, type, driver, API version) or says clearly that
   Vulkan is missing or unknown. No writes, no network.
2. `runtime deps <app>` plans `vkd3d-proton` for an app importing `d3d12.dll` and installs it on real Wine.
3. When the probe says Vulkan is definitely unusable (no loader, or no device, or API version below the package's
   `min_vulkan`), the plan marks `dxvk`/`vkd3d-proton` `blocked{reason}` with a one-line explanation; the app keeps
   Wine's wined3d. An unknown probe (tool missing) never blocks.
4. A D3D11 fixture renders through DXVK in the wine-e2e CI job (already the gate for 4A's archive install).

## 2. Decisions (with reasoning)

| Decision | Choice | Why |
|---|---|---|
| Backend choice | No new per-app setting. DXVK/VKD3D installed = used; not installed = wined3d. Opt-out is `runtime deps <app> --remove <pkg>` (the archive remover already exists). | The prefix state IS the choice; a second setting could disagree with it. Avoids a Metadata v4 migration. |
| Vulkan probe | Run `vulkaninfo --summary` (bounded time and output, sandbox not needed: read-only host query), parse; fall back to "loader present" from the existing doctor check. Not `ash`. | `ash` means `dlopen` of a driver stack in our process. A bounded subprocess keeps driver crashes out of the runtime. |
| `.tar.zst` | Add `ruzstd` (pure Rust) as a streaming decoder in front of the existing hardened `tarball::walk`, with a window-size cap, output cap and the same ratio guard as gzip. | VKD3D-Proton ships only `.tar.zst`. Pure Rust adds no C attack surface; the tar layer is already hardened. |
| 32-bit DXVK | Deferred to Phase 9 (WoW64). | Prefix is win64; 32-bit needs its own design. Recorded as a known gap, unchanged. |

Non-goals: per-game tuning (`DXVK_HUD`, config files), shader-cache management, GPU selection, FPS benchmarks
(roadmap's smoke benchmark moves to 4E), removing the DXVK 32-bit gap.

## 3. Components

- `crates/deps/src/zstd_tar.rs` (new): `format = "tar.zst"` support. Adds `TarLimits`-style caps for zstd (max
  window, max total bytes, ratio floor and max ratio); reuses `walk`'s entry rules by making its reader generic over
  the decompressed stream. Hostile-input tests mirror the gzip ones (bomb, oversized window, truncated frame,
  trailing garbage, multiple frames).
- `crates/deps/packages.toml`: add `vkd3d-proton` (pinned url, sha256, size verified by download; `requires =
  ["dxvk"]` for dxgi; provides `d3d12`, `d3d12core`; x64 DLLs only; `dll_overrides`). New optional field
  `min_vulkan = "1.3"` on `dxvk` and `vkd3d-proton`, taken from the upstream release notes at pin time. Remove
  `d3d12` from the "known unprovided" list in `capabilities.rs` tests.
- `crates/core/src/graphics.rs` (new, pure): `parse_vulkaninfo_summary(&str) -> Vec<VulkanDevice>` and
  `Verdict { Usable, Unusable(reason), Unknown }` from devices + `min_vulkan`. No I/O; fuzzed with the same mutation
  harness used for other parsers.
- `crates/core/src/host.rs` or the CLI: the bounded `vulkaninfo` runner (timeout, 64 KiB output cap, environment
  scrubbed). Injected into the planner as a `&dyn Fn() -> Verdict` so resolver tests stay pure.
- `resolve`: a package with `min_vulkan` becomes `blocked{"Vulkan unusable: <reason>"}` on `Unusable`; `Unknown`
  and `Usable` change nothing. `resolve` stays I/O-free (verdict passed in).
- CLI: `runtime graphics info`; `runtime deps <app> --remove <pkg>`; `doctor` reuses the verdict (one Vulkan
  check, the existing loader check stays as its fallback).

## 4. Testing

- Unit: `vulkaninfo --summary` parser against frozen real outputs (NVIDIA, Mesa/radv, llvmpipe, no devices, garbage).
- Hostile: zstd bomb/oversized-window/truncated/trailing/multi-frame; a hostile `vulkaninfo` (huge, non-UTF-8,
  hangs) is bounded by the runner.
- Resolver: blocked/unblocked matrix for Usable/Unusable/Unknown x dxvk/vkd3d-proton; `d3d12` import plans it.
- Real: the ignored real-net test re-fetches the new pin; wine-e2e installs vkd3d-proton archive on real Wine and
  renders the D3D11 fixture (D3D12 rendering needs a GPU runner, so it is a manual check recorded for 4E).

## 5. Risks

- VKD3D-Proton only runs on real GPU drivers (needs Vulkan 1.3 + specific extensions); CI can verify install, not
  render. Mitigation: state that plainly in `graphics info` output and the docs; matrix (4E) records GPU/driver.
- `vulkaninfo` output format drift between versions: the parser is tolerant of unknown lines and yields `Unknown`
  rather than `Unusable` when it cannot find the fields it needs.
