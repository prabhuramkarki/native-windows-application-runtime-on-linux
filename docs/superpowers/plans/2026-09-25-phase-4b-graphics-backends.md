# Phase 4B Graphics Backends Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect the host's Vulkan capability, block DXVK/VKD3D-Proton in the plan when Vulkan is definitely unusable (the app then keeps wined3d), and add D3D12 through a hardened `.tar.zst` VKD3D-Proton package.

**Architecture:** A pure parser/judge in `rt_core::graphics` turns `vulkaninfo --summary` text into a `VulkanVerdict`. A bounded subprocess runner supplies the text. The manifest gains an optional `min_vulkan`; a post-resolve pure function (same pattern as `drop_present_installers`) turns `Install` entries whose package needs Vulkan into `Blocked` on an `Unusable` verdict. `tarball` gains a zstd codec so the existing hardened tar walker reads `.tar.zst`.

**Tech Stack:** Rust workspace, `ruzstd` (pure Rust zstd decoder, new), existing `flate2`/`tarball`/`install_archive`.

**Spec:** `docs/superpowers/specs/2026-09-25-graphics-backends-design.md`. **Deviation from the spec (decided while planning):** `runtime deps <app> --remove <pkg>` is dropped from 4B. `remove_archive` exists but the CLI never calls it and the `ArchiveInstalled` record is not persisted in `Metadata` (only `DependencyRecord` is), so removal needs a schema change and its own design. The spec's opt-out line is amended in Task 5. A user who wants wined3d back deletes and recreates the environment until removal lands.

## Global Constraints

- HTTPS-only manifest, pinned `sha256` and exact `size` for every package; a new pin is only committed after downloading the artifact and checking both (spec §3, 4A spec §3.1).
- `resolve` stays I/O-free: the Vulkan verdict is applied after it, never read inside it.
- Unknown probe never blocks; only `Unusable` does.
- New dependency (`ruzstd`) gets a `docs/THIRD_PARTY.md` row, passes `cargo deny check`, and hostile-input tests before it is trusted.
- All untrusted text (device names, `vulkaninfo` output) goes through the existing `rt_core` sanitiser (`clean`/`safe`) before reaching a terminal.
- `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --check` stay green after every task.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## Review Focus

- `vulkaninfo` missing, not executable, hangs, exits non-zero or prints megabytes: verdict `Unknown`, runtime never blocks and never hangs (Task 2).
- Device list with only `PHYSICAL_DEVICE_TYPE_CPU` (llvmpipe): usable for DXVK, so not blocked; but `graphics info` says it is software rendering (Task 1).
- `apiVersion` below `min_vulkan` on every device: `Unusable` with a reason naming both versions (Task 1, Task 3).
- One usable GPU plus one too-old GPU: `Usable` (any device that qualifies is enough) (Task 1).
- Hostile `.tar.zst`: decompression bomb, window size above the cap, truncated frame, trailing bytes, second frame, skippable frame (Task 4).
- A `d3d12` importing app on a host with Vulkan unusable: plan shows `vkd3d-proton` blocked, not "unsatisfied" (Task 3).

---

### Task 1: Vulkan summary parser and verdict (pure)

**Files:**
- Create: `crates/core/src/graphics.rs`
- Modify: `crates/core/src/lib.rs` (add `pub mod graphics;` and re-export `VulkanDevice, VulkanVerdict, parse_vulkaninfo_summary, judge`)
- Test: same file (`#[cfg(test)] mod tests`)

**Interfaces:**
- Produces:
  ```rust
  pub struct VulkanDevice { pub name: String, pub device_type: String, pub api: (u32, u32), pub driver: String }
  pub enum VulkanVerdict { Usable, Unusable(String), Unknown }
  pub fn parse_vulkaninfo_summary(text: &str) -> Vec<VulkanDevice>   // at most 16 devices, fields clipped to 128 bytes
  pub fn judge(devices: &[VulkanDevice], min: Option<(u32, u32)>) -> VulkanVerdict
  ```
  `judge`: empty device list -> `Unknown` (the tool ran but printed nothing we understand; a missing loader is decided by the runner in Task 2, not here). Otherwise `Usable` if any device has `api >= min` (or `min` is `None`), else `Unusable("no Vulkan device supports API 1.3 (best is 1.1)")`.

- [ ] **Step 1: Capture real fixtures.** Run `vulkaninfo --summary > /tmp/vk-real.txt` on this machine and paste its `Devices:` section into a `const REAL: &str` in the tests. Add two hand-written constants: `LLVMPIPE` (one device, `deviceType = PHYSICAL_DEVICE_TYPE_CPU`, `apiVersion = 1.3.274`) and `OLD` (`apiVersion = 1.1.0`, `deviceType = PHYSICAL_DEVICE_TYPE_DISCRETE_GPU`). Format of each device block (tab-indented `key = value`):
  ```
  GPU0:
  	apiVersion         = 1.3.274
  	driverVersion      = 0.0.1
  	deviceType         = PHYSICAL_DEVICE_TYPE_CPU
  	deviceName         = llvmpipe (LLVM 15.0.7, 256 bits)
  	driverName         = llvmpipe
  ```

- [ ] **Step 2: Write the failing tests**

```rust
#[test]
fn parses_a_real_summary() {
    let d = parse_vulkaninfo_summary(REAL);
    assert!(!d.is_empty());
    assert!(d.iter().all(|d| d.api.0 >= 1 && !d.name.is_empty()));
}
#[test]
fn llvmpipe_is_usable_and_typed_cpu() {
    let d = parse_vulkaninfo_summary(LLVMPIPE);
    assert_eq!(d.len(), 1);
    assert_eq!(d[0].api, (1, 3));
    assert!(d[0].device_type.ends_with("CPU"));
    assert_eq!(judge(&d, Some((1, 3))), VulkanVerdict::Usable);
}
#[test]
fn too_old_is_unusable_and_the_reason_names_both_versions() {
    let d = parse_vulkaninfo_summary(OLD);
    match judge(&d, Some((1, 3))) {
        VulkanVerdict::Unusable(r) => assert!(r.contains("1.3") && r.contains("1.1"), "{r}"),
        v => panic!("{v:?}"),
    }
}
#[test]
fn one_good_device_among_bad_is_usable() {
    let mut d = parse_vulkaninfo_summary(OLD);
    d.extend(parse_vulkaninfo_summary(LLVMPIPE));
    assert_eq!(judge(&d, Some((1, 3))), VulkanVerdict::Usable);
}
#[test]
fn garbage_and_empty_are_unknown_not_unusable() {
    for t in ["", "not vulkaninfo", "GPU0:\n\tapiVersion = banana\n", "\0\u{1b}[31m"] {
        assert_eq!(judge(&parse_vulkaninfo_summary(t), Some((1, 3))), VulkanVerdict::Unknown, "{t:?}");
    }
}
#[test]
fn no_minimum_means_any_device_is_usable() {
    assert_eq!(judge(&parse_vulkaninfo_summary(OLD), None), VulkanVerdict::Usable);
}
#[test]
fn bounded_devices_and_fields() {
    let big = (0..100).map(|i| format!("GPU{i}:\n\tapiVersion = 1.3.0\n\tdeviceName = {}\n", "x".repeat(10_000))).collect::<String>();
    let d = parse_vulkaninfo_summary(&big);
    assert_eq!(d.len(), 16);
    assert!(d.iter().all(|d| d.name.len() <= 128));
}
#[test]
fn never_panics_on_mutations() {
    // same style as the other parsers' mutation tests: flip/truncate bytes of REAL, only assert no panic
    let b = REAL.as_bytes();
    for i in (0..b.len()).step_by(7) {
        let mut m = b.to_vec();
        m[i] ^= 0xff;
        let _ = parse_vulkaninfo_summary(&String::from_utf8_lossy(&m));
        let _ = parse_vulkaninfo_summary(&String::from_utf8_lossy(&b[..i]));
    }
}
```

- [ ] **Step 3: Run to verify failure:** `cargo test -p runtime-core graphics` -> compile error (module missing).

- [ ] **Step 4: Implement.** Line-based: a line matching `^GPU\d+:$` (after `trim_end`) starts a device (cap 16, ignore the rest). Inside a device, `split_once('=')` on trimmed lines, trim both sides; keys `apiVersion` (parse `major.minor[.patch]` as u32s, ignore patch; on failure leave the device without an api), `deviceType`, `deviceName`, `driverName`. A device is only kept if it has a parsed `api`. Clip each string with the crate's existing `clean(&s, 128)` (see `crates/core/src/doctor.rs` for its use; if it is private, use the same helper module it comes from). Lines longer than 512 bytes are skipped.

- [ ] **Step 5: Run to verify pass:** `cargo test -p runtime-core graphics` -> PASS. Then `cargo clippy -p runtime-core --all-targets -- -D warnings`.

- [ ] **Step 6: Commit**

```bash
git add crates/core/src/graphics.rs crates/core/src/lib.rs
git commit -m "feat(core): parse vulkaninfo --summary and judge Vulkan usability"
```

---

### Task 2: Bounded `vulkaninfo` runner and `runtime graphics info`

**Files:**
- Modify: `crates/core/src/graphics.rs` (add `probe_host`)
- Create: `crates/cli/src/graphics.rs`
- Modify: `crates/cli/src/main.rs` (add `Graphics` subcommand next to `Deps`, dispatch), `crates/core/src/doctor.rs` (`vulkan()` uses the verdict when the runner result is supplied)
- Test: `crates/core/src/graphics.rs` tests, `crates/cli/tests/` (follow the style of the existing `doctor`/`deps` CLI tests)

**Interfaces:**
- Consumes: `parse_vulkaninfo_summary`, `judge` (Task 1); the existing bounded-process helper. Before writing a new one, look in `crates/backend-wine/src/lib.rs` and `crates/core/src/launch.rs` for how `Launcher` runs a command with a timeout and output cap and reuse it; only write `probe_host` from scratch if `Launcher` cannot run an arbitrary host tool.
- Produces:
  ```rust
  pub struct HostVulkan { pub tool_found: bool, pub loader_found: bool, pub devices: Vec<VulkanDevice> }
  pub fn probe_host(run: &dyn Fn() -> Option<String>, loader_found: bool) -> HostVulkan
  pub fn host_verdict(h: &HostVulkan, min: Option<(u32, u32)>) -> VulkanVerdict
  ```
  `run` returns the tool's stdout, or `None` if it is missing, timed out, failed or exceeded the cap. `host_verdict`: `!loader_found` -> `Unusable("Vulkan loader (libvulkan.so.1) not found")`; loader found and `run` returned `None` -> `Unknown`; otherwise `judge(devices, min)`.
  In the CLI: `fn run_vulkaninfo() -> Option<String>` spawns `vulkaninfo --summary` with `env_clear()` plus `PATH`, `HOME`, `XDG_RUNTIME_DIR`, `DISPLAY`, `WAYLAND_DISPLAY`, `VK_ICD_FILENAMES`, `VK_DRIVER_FILES` passed through, stdin null, a 10 s timeout (kill on expiry) and stdout capped at 64 KiB (read at most 64 KiB, then kill and return `None`).

- [ ] **Step 1: Write failing unit tests for `host_verdict`** (pure, no process):

```rust
#[test]
fn no_loader_is_unusable() {
    let h = HostVulkan { tool_found: true, loader_found: false, devices: vec![] };
    assert!(matches!(host_verdict(&h, Some((1, 3))), VulkanVerdict::Unusable(_)));
}
#[test]
fn loader_but_tool_failed_is_unknown() {
    let h = probe_host(&|| None, true);
    assert_eq!(host_verdict(&h, Some((1, 3))), VulkanVerdict::Unknown);
}
#[test]
fn tool_output_is_judged() {
    let h = probe_host(&|| Some(LLVMPIPE.to_string()), true);
    assert_eq!(host_verdict(&h, Some((1, 3))), VulkanVerdict::Usable);
}
```

- [ ] **Step 2: Run to verify failure, implement** `probe_host`/`host_verdict` (about 15 lines), run to verify pass.

- [ ] **Step 3: Write the failing CLI test** in the existing CLI test file style: `runtime graphics info` with `PATH` set to a temp dir holding a fake `vulkaninfo` shell script that prints `LLVMPIPE`, exit 0, stdout contains `llvmpipe` and `software`. A second test: fake script `sleep 30` -> the command returns within 15 s, exit 0, stdout contains `unknown`. A third: script printing 1 MiB of `x` -> returns, output contains `unknown`, and stdout is shorter than 4 KiB.

- [ ] **Step 4: Implement** `crates/cli/src/graphics.rs`: `pub fn info() -> Result<u8, CmdError>`. Output shape (all device strings already clipped by the parser, then passed through the CLI's existing `safe` sanitiser):
  ```
  Vulkan: usable
    GPU0  llvmpipe (LLVM 15.0.7, 256 bits)   Vulkan 1.3   software rendering (CPU)
  DXVK and VKD3D-Proton need Vulkan 1.3 (bundled versions).
  ```
  or `Vulkan: unusable  (<reason>)` / `Vulkan: unknown  (vulkaninfo not available; the loader is present)`. The required version printed is the maximum `min_vulkan` over the bundled manifest (from Task 3; until then hard-code nothing: print the line only when the manifest has one, and this step's test uses `None`). Exit code 0 always (it is information).

- [ ] **Step 5: Make `doctor` use it.** In `crates/core/src/doctor.rs` `DoctorInput` add `pub vulkan: Option<&'a HostVulkan>`; `vulkan()` keeps the loader check when it is `None`, otherwise adds `Status::Ok` with the device count, `Status::Warn` on `Unusable(reason)`, and the old loader line on `Unknown`. `crates/cli/src/doctor.rs` fills it in from the same runner. Update the existing doctor tests that build `DoctorInput` (add `vulkan: None`), and add one test per verdict.

- [ ] **Step 6: Run** `cargo test --workspace` -> PASS, clippy and fmt clean.

- [ ] **Step 7: Commit**

```bash
git add crates/core crates/cli
git commit -m "feat(cli): runtime graphics info and a bounded vulkaninfo probe used by doctor"
```

---

### Task 3: `min_vulkan` in the manifest and blocking in the plan

**Files:**
- Modify: `crates/deps/src/manifest.rs` (`RawPackage`, `Package`, validation, tests), `crates/deps/src/resolve.rs` (new `block_for_vulkan`), `crates/deps/src/orchestrate.rs` (`plan_for_app`, `plan_for_pe` take the verdict), `crates/cli/src/deps.rs` (callers), `crates/cli/src/doctor.rs` (caller), `crates/deps/packages.toml` (`min_vulkan = "1.3"` on `dxvk`; keep the value the upstream release notes give for DXVK 3.1.1 - check them and correct it if it is not 1.3)
- Test: `crates/deps/src/manifest.rs`, `crates/deps/src/resolve/tests.rs`

**Interfaces:**
- Consumes: `rt_core::graphics::VulkanVerdict` (Task 1), `host_verdict` (Task 2).
- Produces:
  ```rust
  // manifest.rs: Package gains
  pub min_vulkan: Option<(u32, u32)>,
  // resolve.rs
  pub fn block_for_vulkan(plan: &mut Plan, manifest: &Manifest, verdict: &VulkanVerdict)
  // orchestrate.rs: signatures change to
  pub fn plan_for_app(env: &AppEnv, md: &Metadata, manifest: &Manifest, vulkan: &VulkanVerdict) -> AppPlan
  pub fn plan_for_pe(md: &Metadata, exe: Result<&pe::PeInfo, &str>, manifest: &Manifest, vulkan: &VulkanVerdict) -> AppPlan
  ```
  The verdict is computed by the caller as `host_verdict(&probe, manifest.max_min_vulkan())`... but each package has its own minimum, so callers pass `VulkanVerdict` computed per package instead: change the parameter to `vulkan: &dyn Fn(Option<(u32, u32)>) -> VulkanVerdict` and evaluate it lazily, once per distinct `min_vulkan`, so the subprocess runs at most once (the CLI closure caches the `HostVulkan`). Use that closure type in all three signatures above in place of `&VulkanVerdict`.

- [ ] **Step 1: Failing manifest tests**

```rust
#[test]
fn min_vulkan_parses_major_dot_minor() {
    let m = Manifest::parse(&with_min_vulkan("1.3")).unwrap();
    assert_eq!(m.get("p").unwrap().min_vulkan, Some((1, 3)));
}
#[test]
fn min_vulkan_rejects_junk() {
    for v in ["1", "1.3.0", "a.b", "", "1.99999999999", "-1.3", "1. 3"] {
        assert!(Manifest::parse(&with_min_vulkan(v)).is_err(), "{v}");
    }
}
#[test]
fn min_vulkan_is_optional() {
    assert_eq!(Manifest::parse(&minimal_valid()).unwrap().get("p").unwrap().min_vulkan, None);
}
```
(`with_min_vulkan`/`minimal_valid` reuse the module's existing test manifest builder; add the field line to it.)

- [ ] **Step 2: Implement.** `RawPackage`: `#[serde(default)] min_vulkan: Option<String>`. Parse with `split_once('.')`, both halves `u32::from_str` with `bytes().all(is_ascii_digit)` and length 1..=4; error variant `ManifestError::BadInstall`-style new variant `BadMinVulkan { id: String }` following how the neighbouring variants are declared. Set `Package.min_vulkan`. Update every place that constructs `Package` (tests, `pkg()` helper in `resolve/tests.rs`) with `min_vulkan: None`. Run `cargo test -p runtime-deps manifest` -> PASS.

- [ ] **Step 3: Failing resolver tests** in `crates/deps/src/resolve/tests.rs` using its existing `pkg(...)` helper extended with a `min_vulkan` argument or a `.with_vulkan((1,3))` builder:

```rust
#[test]
fn unusable_vulkan_blocks_install_entries_that_need_it() {
    let m = manifest_of(vec![pkg_vk("dxvk", &[], &["d3d11"], (1, 3)), pkg("other", &[], &["x"], false)]);
    let mut plan = resolve(&facts_with_caps(&["d3d11", "x"]), &InstalledSet::default(), &[], &m);
    block_for_vulkan(&mut plan, &m, &|_| VulkanVerdict::Unusable("no device".into()));
    assert_eq!(action_of(&plan, "dxvk"), Action::Blocked { reason: "Vulkan is unusable: no device; Wine's built-in Direct3D will be used".into() });
    assert_eq!(action_of(&plan, "other"), Action::Install);
}
#[test]
fn unknown_and_usable_change_nothing() {
    for v in [VulkanVerdict::Usable, VulkanVerdict::Unknown] {
        let m = manifest_of(vec![pkg_vk("dxvk", &[], &["d3d11"], (1, 3))]);
        let mut plan = resolve(&facts_with_caps(&["d3d11"]), &InstalledSet::default(), &[], &m);
        let before = plan.clone();
        block_for_vulkan(&mut plan, &m, &|_| v.clone());
        assert_eq!(plan, before);
    }
}
#[test]
fn an_already_installed_package_is_never_blocked() { /* installed set contains dxvk; verdict Unusable; entry stays AlreadyInstalled */ }
#[test]
fn a_package_requiring_a_blocked_one_is_blocked_too() {
    // vkd3d-proton requires dxvk, only dxvk has min_vulkan: vkd3d entry becomes Blocked with reason mentioning dxvk
}
#[test]
fn the_verdict_closure_runs_once_per_distinct_minimum() { /* counter in the closure; two packages with (1,3) -> 1 call */ }
```

- [ ] **Step 4: Implement `block_for_vulkan`**

```rust
pub fn block_for_vulkan(plan: &mut Plan, manifest: &Manifest, verdict_for: &dyn Fn(Option<(u32, u32)>) -> VulkanVerdict) {
    let mut cache: HashMap<Option<(u32, u32)>, VulkanVerdict> = HashMap::new();
    let mut blocked: Vec<String> = Vec::new();
    for e in &mut plan.entries {
        if e.action != Action::Install { continue; }
        let Some(p) = manifest.get(&e.package) else { continue };
        let needs_blocked_dep = p.requires.iter().any(|r| blocked.contains(r));
        if let Some(min) = p.min_vulkan {
            let v = cache.entry(Some(min)).or_insert_with(|| verdict_for(Some(min)));
            if let VulkanVerdict::Unusable(why) = v {
                e.action = Action::Blocked { reason: clip(&format!("Vulkan is unusable: {why}; Wine's built-in Direct3D will be used")) };
                blocked.push(e.package.clone());
                continue;
            }
        }
        if needs_blocked_dep {
            e.action = Action::Blocked { reason: "needs a package that is blocked (Vulkan is unusable)".into() };
            blocked.push(e.package.clone());
        }
    }
}
```
Entries are dependency-first, so one pass is enough. Run the tests -> PASS.

- [ ] **Step 5: Wire the callers.** `plan_for_app`/`plan_for_pe` call `block_for_vulkan(&mut plan, manifest, vulkan)` after `resolve`. In `crates/cli/src/deps.rs` (`run_app`, `missing_hint` callers) and `crates/cli/src/doctor.rs` build one `HostVulkan` lazily (a `OnceCell<HostVulkan>` filled by `probe_host(&run_vulkaninfo, loader_found)`) and pass `&|min| host_verdict(cell.get_or_init(...), min)`. `runtime deps <app>` with an unusable host must print the blocked reason through the existing `format_plan` (add a CLI test using the fake `vulkaninfo` from Task 2 and an app importing `d3d11.dll`: output contains `blocked` and `Wine's built-in Direct3D`, exit 0, and no network is touched because `--install` is absent).

- [ ] **Step 6: Set `min_vulkan` on `dxvk` in `packages.toml`; update the `bundled_manifest_invariants` test if it enumerates fields.** Run `cargo test --workspace`, clippy, fmt.

- [ ] **Step 7: Commit**

```bash
git add crates docs
git commit -m "feat(deps): block Vulkan-only packages in the plan when Vulkan is unusable"
```

---

### Task 4: `.tar.zst` support in the hardened tar reader

**Files:**
- Modify: `Cargo.toml` (workspace: `ruzstd = { version = "0.9", default-features = false, features = ["std"] }`; check the crate's real feature names with `cargo metadata`/its Cargo.toml and keep only what is needed), `crates/deps/Cargo.toml`, `crates/deps/src/tarball.rs`, `crates/deps/src/manifest.rs` (`ArchiveFormat::TarZst`, url extension `.tar.zst`, `format = "tar.zst"`, error text), `crates/deps/src/install_archive.rs` (`install_tar` picks the codec), `docs/THIRD_PARTY.md`, `deny.toml` (only if the licence is not already allowed)
- Test: `crates/deps/src/tarball.rs` tests, `crates/deps/src/manifest.rs` tests

**Interfaces:**
- Consumes: the existing `tarball::walk`, `TarLimits`, `TarError`.
- Produces:
  ```rust
  pub enum Codec { Gzip, Zstd }
  pub fn walk_codec<R: Read>(codec: Codec, src: R, limits: &TarLimits, select: ..., sink: ...) -> Result<u64, TarError>
  // walk(...) stays as the Codec::Gzip shorthand so existing callers and tests do not change
  // TarLimits gains: pub max_zstd_window: u64  (production: 64 MiB)
  // TarError gains: Zstd(String), TooManyFrames
  ```

- [ ] **Step 1: Read `ruzstd`'s real API** (`cargo doc -p ruzstd --open` or `~/.cargo/registry/src/*/ruzstd-*/src`): find the streaming `Read` decoder over a `Read` source, how to cap the window size (a `FrameDecoder` setting or a check on the frame header's window size before decoding), how it treats multiple frames, skippable frames and a truncated frame, and its licence (must be MIT/Apache-2.0-compatible with `deny.toml`). If it has no window cap, read the frame header yourself first (zstd frame header layout: magic `28 B5 2F FD`, descriptor byte, optional window descriptor byte; `windowSize = (1 << (10 + exp)) + (window/8) * mantissa`; single-segment frames use the content size) and refuse when it exceeds `max_zstd_window` before handing the stream to the decoder. Record what you found in the module docs.

- [ ] **Step 2: Failing tests.** Build fixtures at test time from an in-memory tar (the existing gzip tests show how they build tars) compressed with `ruzstd`'s encoder if it has one; if it does not, commit small binary fixtures under `crates/deps/tests/fixtures/` generated once with the host `zstd` CLI and note the command in a comment. Cases, each expecting the named result through `walk_codec(Codec::Zstd, ...)`:
  - a normal tar.zst with two files: both reported and readable, byte-exact;
  - bomb: 512 MiB of zeros compressed (a few KiB) with `max_total_bytes` lowered: `TarError::TooLarge` or `RatioExceeded`;
  - frame header declaring a 1 GiB window with `max_zstd_window` at 64 MiB: `TarError::Zstd(_)` (no allocation of that size: assert with a test that completes in under a second and small RSS is not measured, just that it errors);
  - truncated in the middle of a frame: `TarError::Truncated`;
  - one valid frame followed by 100 arbitrary bytes: `TarError::TrailingGarbage`;
  - two valid concatenated frames (with `max_frames` default 1): `TarError::TooManyFrames`;
  - a skippable frame (`50 2A 4D 18`) first: refused as `TarError::Zstd(_)`;
  - compressed input over `max_compressed_bytes`: `CompressedTooLarge`;
  - random bytes: some `TarError`, never a panic (mutation loop over a valid archive, flip every 13th byte).

- [ ] **Step 3: Implement.** Generalise `Stream<R>`: replace the `dec: Option<GzDecoder<...>>` field by an enum `Dec<R> { Gz(GzDecoder<BufReader<Counted<R>>>), Zst(ruzstd StreamingDecoder over BufReader<Counted<R>>), Done }`, keep `total`/ratio/limit accounting in the shared `read`, and keep the gzip member logic in the `Gz` arm only. `Counted` already counts compressed bytes; for the ratio guard on zstd use the same `input.n - buffered` computation (the zstd decoder reads through the same `BufReader<Counted<R>>`, so it works the same way). Map decoder errors: `UnexpectedEof` -> `Truncated`, everything else -> `Zstd(e.to_string())`; after the first frame ends, peek the next byte: none -> end, more -> `TooManyFrames` if it looks like a zstd magic else `TrailingGarbage`. `walk` calls `walk_codec(Codec::Gzip, ...)`. Update `TarLimits::for_package` with `max_zstd_window: 64 * MIB`.

- [ ] **Step 4: Manifest + install wiring.** `ArchiveFormat::TarZst` (`"tar.zst"`, url ends `.tar.zst`); fix the doc comment "There is intentionally no zstd support" and the `UnsupportedFormat` error text; `install_tar` gets the codec from the format (rename it `install_tarball(codec, ...)`); both passes use `walk_codec`. Add manifest tests: `format = "tar.zst"` with a `.tar.zst` url parses, with a `.tar.gz` url is `FormatMismatch`.

- [ ] **Step 5: Docs and licence.** Add a `docs/THIRD_PARTY.md` row for `ruzstd` in the style of the `zip` row: licence, what it is used for, the hazards handled (window size cap, output/ratio caps, single frame, no skippable frames), and that no C code is added. Run `cargo deny check` (installed for earlier phases; if not, `cargo install cargo-deny` is out of scope: report that and stop).

- [ ] **Step 6: Run** `cargo test -p runtime-deps`, then `cargo test --workspace`, clippy, fmt. Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock crates docs deny.toml
git commit -m "feat(deps): read .tar.zst packages through the hardened tar walker"
```

---

### Task 5: VKD3D-Proton package, tests, docs

**Files:**
- Modify: `crates/deps/packages.toml`, `crates/deps/src/capabilities.rs` (drop `d3d12` from the known-unprovided list and its comment), `crates/deps/src/resolve/tests.rs` (the fixture comment), `docs/SECURITY.md`, `README.md`, `docs/superpowers/specs/2026-09-25-graphics-backends-design.md` (amend the `--remove` lines), `.github/workflows/*` wine-e2e job only if it lists packages explicitly (look first)
- Test: `crates/deps/src/capabilities.rs`, the bundled-manifest invariant tests, the ignored real-net test, the wine-e2e test file that already installs DXVK (find with `grep -rn dxvk crates/*/tests tests`)

**Interfaces:**
- Consumes: `ArchiveFormat::TarZst` (Task 4), `min_vulkan` (Task 3).

- [ ] **Step 1: Pin the release.** Find the latest VKD3D-Proton release (`https://github.com/HansKristian-Work/vkd3d-proton/releases`), download its `vkd3d-proton-<ver>.tar.zst` with `curl -L`, compute `sha256sum` and `stat -c %s`, list its layout with `zstd -dc <file> | tar -t | head -30` to get the exact wrapper directory and the `x64/d3d12.dll`, `x64/d3d12core.dll` paths. Write the manifest entry modelled on `dxvk`:

```toml
[[package]]
id = "vkd3d-proton"
version = "<ver>"
sha256 = "<64 hex from your download>"
size = <bytes from your download>
licence = "LGPL-2.1-or-later"
url = "https://github.com/HansKristian-Work/vkd3d-proton/releases/download/v<ver>/vkd3d-proton-<ver>.tar.zst"
kind = "archive"
requires_consent = false
requires = ["dxvk"]
provides = ["d3d12", "d3d12core"]
min_vulkan = "1.3"

[package.install]
format = "tar.zst"
extract = [
    { from = "vkd3d-proton-<ver>/x64/d3d12.dll", to = "windows/system32/d3d12.dll" },
    { from = "vkd3d-proton-<ver>/x64/d3d12core.dll", to = "windows/system32/d3d12core.dll" },
]
dll_overrides = ["d3d12", "d3d12core"]
```
Confirm the licence string from the release's `LICENSE` (it must be an SPDX id); if it is not permissive enough for `requires_consent = false` under the 4A consent model (the 4A spec gives permissive archives `false`), set `true` and explain in a comment. Add the same "verified by downloading on <date>" comment style the other entries use.

- [ ] **Step 2: Failing tests first.** In `capabilities.rs` the test listing unprovided capabilities becomes `["dotnet"]`; a new test asserts `capability_for("d3d12.dll") == Some("d3d12")` resolves through the bundled manifest to `vkd3d-proton` and that the plan for `Facts{imports:["D3D12.dll"]}` is `[dxvk, vkd3d-proton]` in that order (dependency first). Run: FAIL until the entry exists; after Step 1 -> PASS.

- [ ] **Step 3: Real-net and real-Wine checks.** The ignored `real_net_bundled_packages_refetch_and_match` test iterates the manifest, so it covers the new pin: run `cargo test -p runtime-deps -- --ignored real_net` and expect PASS. Extend the existing wine-e2e archive test (the one that installs DXVK through `install_archive` on real Wine) with a `vkd3d-proton` case asserting `windows/system32/d3d12.dll` exists and the `d3d12` override registry value is `native,builtin`. Run it locally if Wine is present (`cargo test -p runtime-deps --test <name> -- --ignored`; find the exact invocation in the wine-e2e workflow).

- [ ] **Step 4: Docs.** `README.md`: one paragraph for `runtime graphics info` and for D3D12 (install works everywhere, rendering needs a GPU with Vulkan 1.3; not verified in CI). `docs/SECURITY.md`: the zstd reader's caps and the `vulkaninfo` runner (scrubbed env, 10 s, 64 KiB, never trusted for anything except a yes/no/unknown). Amend the spec: replace the "Opt-out is `--remove`" sentence in the decisions table with "Opt-out is deferred: removal needs the `ArchiveInstalled` record persisted (a Metadata change) and its own design", and delete `--remove` from §3's CLI bullet.

- [ ] **Step 5: Full gate**: `cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace` -> all green; report the test count.

- [ ] **Step 6: Commit**

```bash
git add crates docs README.md .github
git commit -m "feat(deps): bundle VKD3D-Proton for Direct3D 12; document graphics and zstd hardening"
```

---

## Self-Review

- **Spec coverage:** criterion 1 (`graphics info`) -> Task 2; 2 (`vkd3d-proton` planned/installed) -> Tasks 4-5; 3 (blocked when Vulkan unusable, Unknown never blocks) -> Task 3; 4 (D3D11 fixture through DXVK in CI) -> already gated by 4A's wine-e2e; Task 5 Step 3 extends it. Components list: `zstd_tar` became a codec inside `tarball.rs` (one reader, not two); `min_vulkan` -> Task 3; doctor reuse -> Task 2. `--remove` dropped, with reasons, in the header and Task 5.
- **Placeholders:** the only values left to fill are the ones that must come from a real download (`<ver>`, sha256, size, licence) and `ruzstd`'s real API; both are explicit steps with commands.
- **Type consistency:** `VulkanVerdict`, `HostVulkan`, `host_verdict`, `block_for_vulkan`, the `&dyn Fn(Option<(u32, u32)>) -> VulkanVerdict` parameter, `Codec`/`walk_codec`, `ArchiveFormat::TarZst` are used with the same names throughout.
