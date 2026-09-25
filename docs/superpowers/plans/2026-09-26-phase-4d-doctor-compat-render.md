# Phase 4D/4E Doctor Prediction, Compat Matrix and Render Fixture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `doctor <app>` predicts .NET needs and the Direct3D route; a validated, drift-checked compatibility matrix exists; a D3D11 fixture proves DXVK rendering on real Wine and is recorded.

**Architecture:** Typed `D3dRoute` computed in the CLI from the existing plan, recorded state and Vulkan verdict feeds one doctor check per API family. Compat records are embedded TOML with strict validation, rendered by `runtime compat` and diffed against `docs/COMPAT.md` in a test. The fixture is a mingw C program run by an ignored e2e.

**Tech Stack:** Rust workspace, `toml`+`serde` (present), mingw-w64 (`x86_64-w64-mingw32-gcc`, `d3d11.h` present on this host), real Wine 10.0, DXVK bundled package.

**Spec:** `docs/superpowers/specs/2026-09-26-doctor-compat-and-render-design.md`

## Global Constraints

- doctor stays read-only and injected-input; nothing new touches the FS/process inside `rt_core::doctor`.
- "Installed" means recorded in `Metadata.dependencies` (`rt_deps::state::installed_set`), never inferred from prefix files.
- Untrusted text (import names, reasons) passes `clean`/`quote_max`; check texts <= 300 chars; the number of checks is bounded by code (one per API family: at most 5) plus the .NET check.
- Compat records: strict TOML (`deny_unknown_fields`), at most 500 records, strings capped, no record may claim `works`/`partial` without evidence; statuses only from real runs — never invent an app result.
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` stay green after every task.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## Review Focus

- App importing `d3d11.dll` + `d3d12.dll` on a host with Vulkan Unusable: both families report the wined3d/builtin route with the Vulkan reason, never "DXVK" (Task 1).
- DXVK recorded installed but Vulkan Unknown: route says DXVK with "Vulkan not verified" (Task 1).
- Managed .NET exe (CLR header) with only `mscoree.dll` imports: .NET warning, no false "imports missing" noise beyond what already exists (Task 1).
- Hostile compat TOML (unknown field, 10 MB, 100 000 records, `works` without evidence, control chars in notes): rejected cleanly, no panic (Task 2).
- `docs/COMPAT.md` edited by hand: drift test fails with a diff hint (Task 2).
- Fixture wrong pixel or device creation failure: non-zero exit, test fails, record says `broken` rather than being skipped (Task 3).

---

### Task 1: doctor .NET check and Direct3D route prediction

**Files:**
- Modify: `crates/core/src/doctor.rs` (`D3dRoute`, `DoctorInput.d3d_routes`, new checks, module docs), `crates/core/src/lib.rs` (re-export), `crates/cli/src/doctor.rs` (compute routes), every `DoctorInput` construction (grep) with `d3d_routes: None`
- Test: `crates/core/src/doctor/tests.rs`, `crates/cli/tests/apps.rs`

**Interfaces:**
- Consumes: `PeInfo.dotnet` (crates/pe/src/analyze.rs `dotnet: dir(DIR_CLR).0 != 0`), `rt_deps::plan_for_pe`/`Action`/`PlanEntry`, `rt_core::graphics::{VulkanVerdict, host_verdict}` and the CLI's shared `graphics::verdict_for`/`host()`.
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum D3dFamily { D3d8, D3d9, D3d10, D3d11, D3d12 }
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum D3dRoute { Dxvk, Vkd3dProton, Wined3d { reason: String } }
  // DoctorInput.d3d_routes: Option<&'a [(D3dFamily, D3dRoute)]>  (None: system report / not an app)
  ```
  Families come from the import names (`d3d8.dll`, `d3d9.dll`, `d3d10.dll`/`d3d10_1.dll`/`d3d10core.dll`, `d3d11.dll`, `d3d12.dll`, case-insensitive, via `rt_deps::capability_for` where it already maps them). Route rules (CLI): family provider package = `dxvk` for D3D8-11, `vkd3d-proton` for D3D12; if the plan entry for that package is `AlreadyInstalled` (or the package is in `installed_set`) and `host_verdict(min)` is not `Unusable` => `Dxvk`/`Vkd3dProton`; `Install` => `Wined3d{reason:"DXVK not installed: run `runtime deps <app> --install`"}` (VKD3D analogous); `Blocked{reason}` => `Wined3d{reason}`; installed but Vulkan `Unusable(r)` => `Wined3d{reason:"Vulkan unusable: r"}`.

- [ ] **Step 1: Failing core tests**
  - `PeInfo` with `dotnet: true` => one `Area::Runtime` (or `Area::Imports`; follow where doctor puts runtime/prefix advice — pick `Area::Runtime`) `Status::Warn` check whose text contains ".NET" and "no .NET runtime is bundled" (assert both substrings), and NO such check when `dotnet: false`.
  - `d3d_routes = Some(&[(D3d11, Dxvk), (D3d12, Wined3d{reason:"Vulkan unusable: x"})])` => two `Area::Graphics` checks: `Ok` "Direct3D 11: DXVK" and `Warn` "Direct3D 12: Wine's built-in vkd3d (Vulkan unusable: x)"; `Some(&[])` and `None` => none; a reason with control chars/very long is cleaned and the text stays <= 300 chars.
- [ ] **Step 2: Run to verify failure** (`cargo test -p runtime-core doctor`), implement, run to pass. Update the module docs (checks per area, the fixed bound) and every `DoctorInput` construction.
- [ ] **Step 3: Failing CLI tests** (fake-Wine rig, `RUNTIME_VULKAN_LOADER=present`, fake `vulkaninfo` as the neighbouring tests do): (a) app importing `d3d11.dll` with dxvk NOT installed => Graphics line says built-in route and names `runtime deps`; (b) with `dxvk` recorded in `Metadata.dependencies` (write it via the rig's metadata helper / `rt_deps::state::record`) and Vulkan usable => "DXVK"; (c) same with loader `absent` => built-in + "Vulkan unusable"; (d) an app whose exe has a CLR header (build the PE fixture bytes the way pe tests do: minimal PE with data directory 14 set) => the .NET warning; JSON areas still `graphics`/`runtime`.
- [ ] **Step 4: Implement** the CLI computation in `crates/cli/src/doctor.rs` reusing the plan already computed for the hint (no second PE read) and the shared Vulkan host probe (at most one probe per invocation).
- [ ] **Step 5: Deliberately-broken-env test** (roadmap exit criterion): an app with a missing executable / missing prefix drive_c / a symlinked home => doctor verdict `fail` with the specific check named; if such tests already exist say which and add only what is missing.
- [ ] **Step 6:** full gate; commit `feat(doctor): warn about managed .NET programs and predict the Direct3D route`.

---

### Task 2: compatibility matrix (`runtime compat`, `docs/COMPAT.md`)

**Files:**
- Create: `crates/cli/src/compat.rs`, `crates/cli/compat.toml`, `docs/COMPAT.md`
- Modify: `crates/cli/src/main.rs` (subcommand), README (one paragraph)
- Test: `crates/cli/src/compat.rs` tests (+ drift test)

**Interfaces:**
- Produces: `pub fn bundled() -> &'static Compat` (parsed once, like `Manifest::bundled`), `Compat::parse(&str) -> Result<Compat, CompatError>`, `pub fn render_table(&Compat) -> String` (markdown table used for BOTH `runtime compat` and `docs/COMPAT.md`), `pub fn render_json(&Compat) -> String`. Record fields (all `deny_unknown_fields`): `app` (<=80), `version` (<=40, optional), `status` (`works|partial|broken|untested`), `wine` (<=40), `gpu` (<=120, optional; required for records with `graphics = true`), `graphics` (bool, default false), `evidence` (`ci:<job>` or `manual:<YYYY-MM-DD>`, <=80; REQUIRED for `works`/`partial`/`broken`), `notes` (<=300, optional). Caps: file <= 256 KiB, <= 500 records, strings without control chars.

- [ ] **Step 1: Failing tests** for: a valid file parses and renders a stable markdown table (frozen expected string); rejections (each its own assertion with the error variant): unknown field, `works` without evidence, `untested` with evidence allowed, bad evidence format (`ci:` empty, `manual:31-02-2026`, `other:x`), `graphics = true` without `gpu`, control character in notes, 501 records, > 256 KiB, duplicate (app,version,wine,gpu) tuple; no-panic mutation loop over the valid file.
- [ ] **Step 2: Implement** (`toml` + `serde` as in `crates/deps/src/manifest.rs`; date check without a date crate: `YYYY-MM-DD` digits and month 1-12, day 1-31).
- [ ] **Step 3: Seed `compat.toml`** with ONLY real records: the fixtures CI executes headlessly (look at `.github/workflows/ci.yml` and the wine e2e tests to name the exact jobs: e.g. console `hello64.exe`, `fs64.exe` on Wine 10.0 with `evidence = "ci:<job name>"`), each `status = "works"`. Leave the GUI/7-Zip/Notepad++ apps out (manual checks nobody recorded). Task 3 adds the D3D11 record.
- [ ] **Step 4:** `runtime compat [--json]` prints the render; generate `docs/COMPAT.md` from `render_table` with a header saying it is generated (`cargo run -q -p runtime-cli -- compat > docs/COMPAT.md` documented in the file); drift test `compat_md_matches_records` reads `../../docs/COMPAT.md` via `include_str!` and asserts equality with the render, with a failure message naming the regenerate command.
- [ ] **Step 5:** full gate; commit `feat(cli): runtime compat and a drift-checked compatibility matrix`.

---

### Task 3: D3D11 render fixture and real DXVK run

**Files:**
- Create: `tools/fixtures/d3d11.c`
- Modify: `tools/build-fixtures.sh`, the e2e test file used by the other `real_net_*`/wine tests (find with `grep -rn real_net_wine crates/deps`), `crates/cli/compat.toml`, `docs/COMPAT.md` (regenerate), README (manual command)
- Test: ignored e2e `real_net_wine_d3d11_renders_via_dxvk`

**Interfaces:**
- Consumes: bundled `dxvk` package + `install_archive` + the real-download helper the `real_net_*` tests use; the compat record schema (Task 2).
- Produces: `tests/fixtures/build/d3d11_64.exe` (x86_64 only; DXVK x64-only is a known gap).

- [ ] **Step 1: Write `tools/fixtures/d3d11.c`**: `D3D11CreateDevice` (hardware driver type, feature level 11_0, no debug), create a 64x64 `R8G8B8A8_UNORM` render-target texture, a `RenderTargetView`, loop 100 times `ClearRenderTargetView` with (0.25, 0.5, 0.75, 1.0) + `Flush`, timing the loop with `QueryPerformanceCounter`; copy to a `D3D11_USAGE_STAGING` texture, `Map`, read pixel (0,0) and require each channel within +-1 of (64,128,191,255), print `pixel ok` or `pixel BAD r g b a`, then `frame ms: <total/100>` and `adapter: <DXGI adapter description narrowed>`; exit 0 only on `pixel ok`. Every failing HRESULT prints `fail: <call> 0x%08lx` and exits 2. Link `-ld3d11 -ldxgi` (mingw import libs; if the mingw sysroot lacks `libd3d11.a`, use `LoadLibraryA("d3d11.dll")`+`GetProcAddress` for `D3D11CreateDevice` instead — pick whichever builds).
- [ ] **Step 2: Build script:** add the x86_64 build line next to the others (`-O1 -Wall`, no `-mwindows`, console app so stdout is capturable); run `sh tools/build-fixtures.sh` (needs wixl/makensis too; if those are missing here, build just this fixture with the same flags by hand and say so).
- [ ] **Step 3: The ignored e2e** (`#[ignore]`, name starts `real_net_wine_`, so CI's `e2e_real_wine` filter and verify-pins skip it): create a fresh app env with the fixture's `install`-equivalent used by `e2e_real_wine_*` tests, install bundled `dxvk` (real download via the fetcher, verified against the manifest pin as `real_net_wine_bundled_vkd3d_proton_installs_and_removes` does), run `d3d11_64.exe` through the backend's `command()`/Launcher with a timeout (60 s), capture stdout, assert exit 0, stdout contains `pixel ok`, and print `frame ms` and `adapter` lines with `--nocapture`. Also assert DXVK really was the renderer: `adapter:` line must not contain `llvmpipe` unless the host only has it, and set `DXVK_LOG_LEVEL=info`? — only if the launcher lets the test add an env var; otherwise drop this and instead assert `d3d11.dll` in system32 is DXVK's (size/hash equals the extracted file).
- [ ] **Step 4: Run it here** (host has a Vulkan GPU): `cargo test -p runtime-deps --lib -- --ignored real_net_wine_d3d11 --test-threads=1 --nocapture`. Record the REAL outcome (GPU/driver from `vulkaninfo --summary`, `wine --version`) as a record in `crates/cli/compat.toml`: `app = "d3d11 clear fixture (tools/fixtures/d3d11.c)"`, `graphics = true`, `gpu = "<device> / <driver>"`, `evidence = "manual:<today>"`, `status` = `works` if it passed, `broken` if it failed with the failure reason in notes. If DXVK 3.x fails on Wine 10.0 (winevulkan needs Wine 10.1+ per the DXVK wiki) that is a legitimate `broken` record, not a reason to hide it; report it prominently. Regenerate `docs/COMPAT.md`.
- [ ] **Step 5:** README: the manual command and what it proves/does not prove (no CI GPU). Full gate; commit `test(deps): D3D11 render fixture through DXVK on real Wine, recorded in the matrix`.

---

## Self-Review

- Spec criteria: 1 and 2 -> Task 1; 3 -> Task 2; 4 -> Task 3. The roadmap's "doctor predicts a deliberately broken env" -> Task 1 Step 5.
- Placeholders: none; API-dependent choices (mingw import lib vs GetProcAddress; where `Area` for .NET) are explicit decisions with a stated fallback.
- Types: `D3dFamily`, `D3dRoute`, `d3d_routes`, `Compat`, `render_table`, `bundled` are used with identical names across tasks.
