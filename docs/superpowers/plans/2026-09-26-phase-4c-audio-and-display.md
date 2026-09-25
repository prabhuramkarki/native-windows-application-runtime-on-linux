# Phase 4C Audio and Display Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `doctor` report the audio path Wine will really use, and let users read and set an app's Wine graphics driver (`auto|x11|wayland`) with `runtime display`.

**Architecture:** A pure `rt_core::display` module (driver enum, `user.reg` reader) feeds `doctor` and the CLI. The setter reuses the DLL-override `reg.exe` helper in `rt_deps`. State lives in the prefix registry, not `Metadata`.

**Tech Stack:** Rust workspace; existing bounded `.reg` parser (`rt_installer::reg::WineReg`), `Launcher::run_helper`, doctor's injected `FsProbe`.

**Spec:** `docs/superpowers/specs/2026-09-26-audio-and-display-design.md`

## Global Constraints

- Nothing downloads; `display` and `doctor` never touch the network.
- All untrusted text (registry values, directory names) goes through `text::clean` / `quote_max` before a terminal.
- `doctor` stays read-only and injected-input: no new direct file or process access inside `rt_core::doctor`.
- The `Graphics` registry value is only ever written as `x11` or `wayland`, or deleted (`auto`); an unknown existing value is reported as "custom: <clean value>", never rewritten unless the user sets a new one.
- Setting requires the app not running and holds the app lock exclusively (same as `deps --install`).
- `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` stay green after every task.
- Commit trailer: `Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>`.

## Review Focus

- Prefix `user.reg` missing, unreadable, huge or hostile: `display` says `auto` (or "could not read") and never panics or hangs (Task 2).
- `Graphics` value with unexpected content (`x11,wayland`, empty, non-ASCII, very long): shown escaped as `custom`, and re-setting works (Task 1, Task 2).
- `wayland` requested with no `WAYLAND_DISPLAY` / no `winewayland` module: refused, nothing written (Task 2).
- App currently running when setting: refused, nothing written (Task 2).
- Audio: PipeWire socket present but no `pulse/native`: Warn that Wine 10 needs the PulseAudio-compatible socket (Task 3).
- Wine drivers directory unlistable: "not verified", never "missing" (Task 3).

---

### Task 1: `rt_core::display` — driver enum and registry reader (pure)

**Files:**
- Create: `crates/core/src/display.rs`
- Modify: `crates/core/src/lib.rs` (`pub mod display;` + re-export `GraphicsDriver, read_graphics_driver`)
- Test: same file

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq)]
  pub enum GraphicsDriver { Auto, X11, Wayland, Custom(String) } // Custom holds clean(value, 60)
  impl GraphicsDriver { pub fn parse_choice(s: &str) -> Option<GraphicsDriver> /* only "auto"|"x11"|"wayland", exact lowercase */; pub fn as_str(&self) -> &str }
  pub const DRIVERS_KEY: &str = r"HKCU\Software\Wine\Drivers"; // as reg.exe takes it
  pub fn read_graphics_driver(user_reg: &[u8]) -> Result<GraphicsDriver, String>
  ```
  `read_graphics_driver` parses with `installer::reg::WineReg::parse` (check its API in `crates/installer/src/reg.rs`; if `rt_core` cannot depend on `rt_installer`, take the already-parsed value list as input instead and let the caller parse — decide from the crate graph and keep this module pure). Missing key or value => `Auto`. Value `x11` => `X11`, `wayland` => `Wayland`, anything else => `Custom(clean(v, 60))`. Parse failure => `Err(clean(e, 120))`.

- [ ] **Step 1: Write failing tests** with frozen `user.reg` literals (copy the header and section format from an existing `.reg` fixture in `crates/installer/src/reg.rs` tests): no Drivers key => Auto; `"Graphics"="x11"` => X11; `"Graphics"="wayland"` => Wayland; `"Graphics"="x11,wayland"` => Custom("x11,wayland"); `"Graphics"=""` => Custom(""); a 10 000-char value => Custom clipped to <= 60 chars; control characters in the value are stripped; garbage bytes => Err or Auto without panic (mutation loop over the good literal, every 7th byte flipped); `parse_choice` accepts exactly the three lowercase words ("X11", " x11", "auto\n", "" => None).
- [ ] **Step 2: Run to verify failure:** `cargo test -p runtime-core display` -> compile error.
- [ ] **Step 3: Implement** the module (about 60 lines plus tests).
- [ ] **Step 4: Run** `cargo test -p runtime-core display`, clippy, fmt -> PASS.
- [ ] **Step 5: Commit:** `git commit -m "feat(core): read the Wine graphics driver setting from user.reg"`

---

### Task 2: `runtime display` (read and set)

**Files:**
- Create: `crates/deps/src/wine_config.rs`, `crates/cli/src/display.rs`
- Modify: `crates/deps/src/lib.rs` (`pub mod wine_config;`), `crates/deps/src/install_archive.rs` (make `reg` `pub(crate)`), `crates/cli/src/main.rs` (subcommand), README (usage + Wine 10 Wayland caveat)
- Test: `crates/deps/src/wine_config.rs` (fake-Wine unit test if the crate's test rig allows, plus an `e2e_real_wine_display_driver` ignored test with that prefix), `crates/cli/tests/` (follow `apps.rs` rig)

**Interfaces:**
- Consumes: `GraphicsDriver`, `read_graphics_driver`, `DRIVERS_KEY` (Task 1); `install_archive::reg` (signature at `crates/deps/src/install_archive.rs` ~1064: `reg(args:&[&str], env:&AppEnv, backend:&dyn CompatBackend, launcher:&Launcher, sandbox:Option<&Path>) -> Result<(bool,String), ArchiveError>`); `lock_app`/`refuse if running` helpers used by `deps --install` (`crates/cli/src/deps.rs` `lock_or_refuse`).
- Produces: `pub fn set_graphics_driver(env:&AppEnv, backend:&dyn CompatBackend, launcher:&Launcher, d:&GraphicsDriver) -> Result<(), WineConfigError>` (`Auto` => `reg delete DRIVERS_KEY /v Graphics /f`, tolerating "value not found" via a follow-up `reg query` as `delete_override` does; `X11`/`Wayland` => `reg add DRIVERS_KEY /v Graphics /d <x11|wayland> /f`; `Custom` is refused as `WineConfigError::NotSettable`).
  CLI: `runtime display <app>` prints `graphics driver: <auto|x11|wayland|custom: ...>` plus, on a second line, the host session (Wayland socket / DISPLAY, reusing doctor's session detection or a small shared helper) and whether the Wine build has `winewayland` (list the backend's unix dll dir(s) via `backend.dll_dirs()`; "not verified" if unlistable). `runtime display <app> <choice>` sets it.

- [ ] **Step 1: Failing unit tests** for `set_graphics_driver` argument construction (test through the backend/launcher rig the neighbouring `install_archive` tests use; assert the exact reg argv for x11, wayland, auto; `Custom` refused; a non-zero `reg` exit => error naming the value).
- [ ] **Step 2: Failing CLI tests** (fake-Wine rig): (a) `display <app>` on a fresh app prints `auto`; (b) `display <app> wayland` with `WAYLAND_DISPLAY` unset in the rig env => refused, exit 1, message mentions the missing Wayland session, `user.reg` unchanged; (c) with a socket present and a fake `winewayland.so` in the fake Wine dll dir => succeeds and a re-read prints `wayland`; (d) `display <app> bogus` => usage error listing the three choices; (e) app running (rig's running marker / lock) => refused; (f) `display ../x` => invalid app id error like `deps`.
- [ ] **Step 3: Implement** `wine_config.rs` and the CLI module. Policy in the CLI: `wayland` requires a Wayland session (socket exists, as doctor's `display()` decides) AND `winewayland` found in the Wine dll dirs (unlistable => allowed with a warning line, per the "not verified, never missing" rule); `x11` without `DISPLAY` => warning line, still sets; take the app lock exclusively for a set; validate before locking and writing.
- [ ] **Step 4: wine-e2e** `e2e_real_wine_display_driver` (ignored, `e2e_real_wine` prefix; model on `e2e_real_wine_vkd3d_manifest_shape`): set `wayland`, stop wineserver, read `user.reg` => Wayland; set `auto` => Auto; set `x11` => X11. Run locally: `cargo test -p runtime-deps --lib -- --ignored e2e_real_wine_display --test-threads=1 --nocapture`.
- [ ] **Step 5: README:** usage, that `auto` is Wine's default, that Wayland is experimental in Wine 10.0 and opt-in per app.
- [ ] **Step 6: Run** the full gate; **Commit:** `git commit -m "feat(cli): runtime display reads and sets an app's Wine graphics driver"`

---

### Task 3: doctor audio and driver reporting

**Files:**
- Modify: `crates/core/src/doctor.rs` (`DoctorInput`, `audio()`, `display()`), `crates/cli/src/doctor.rs` (gather inputs), tests in `crates/core/src/doctor/tests.rs`
- Test: same

**Interfaces:**
- Consumes: `GraphicsDriver`, `read_graphics_driver` (Task 1).
- Produces: `DoctorInput` gains `pub wine_drivers: Option<&'a [String]>` (file names found in the backend's unix DLL directories that start with `wine` and end with `.so`/`.drv`, at most 200, gathered by the CLI through the existing listing helper; `None` = could not list) and `pub graphics_driver: Option<GraphicsDriver>` (the app's setting, `None` for a system report or unreadable prefix). Update every construction of `DoctorInput` (grep) with `None` defaults.

- [ ] **Step 1: Failing doctor unit tests** using the injected `FsProbe`/env:
  - pulse socket `$XDG_RUNTIME_DIR/pulse/native` exists => `Status::Ok`, text names the PulseAudio-compatible socket;
  - only `pipewire-0` => `Warn`, text says Wine 10 needs the PulseAudio-compatible socket (`pipewire-pulse`);
  - neither, `winealsa` listed => `Warn` "ALSA only";
  - neither, no driver => `Warn` "no audio path";
  - `wine_drivers = Some(&[])` (listed, no `winepulse`) with a pulse socket => `Warn` "Wine build has no PulseAudio driver";
  - `wine_drivers = None` => text says "driver modules not verified", never "missing";
  - graphics: app setting `Wayland` with no Wayland socket => `Warn` (cannot honour); `Wayland` with socket but `winewayland` absent from a listed `wine_drivers` => `Warn`; `X11` with no `DISPLAY` => `Warn`; `Auto` => no extra check; `Custom("x")` => `Warn` "custom graphics driver setting".
- [ ] **Step 2: Run to verify failure, implement, run to pass.** Keep each check text <= 300 chars and pass any registry-derived text through `clean`.
- [ ] **Step 3: CLI:** in `crates/cli/src/doctor.rs` gather `wine_drivers` from `backend.dll_dirs()` (bounded listing, same helper as the DLL listing) and `graphics_driver` for an app target by reading its `user.reg` through the same bounded reader `display` uses (share the helper; do not duplicate). Add a CLI test (rig) asserting the audio line for a rig with only `pipewire-0`.
- [ ] **Step 3b:** update the `docs/SECURITY.md` / README doctor description of the audio check if either names `pipewire-0`.
- [ ] **Step 4: Full gate; Commit:** `git commit -m "feat(doctor): report the audio path Wine really uses and the app's graphics driver setting"`

---

## Self-Review

- Spec criteria: 1 -> Task 3; 2 and 3 -> Task 2; 4 -> Task 3. Non-goals respected.
- Placeholders: none; API-dependent points (`WineReg` reachability from `rt_core`) are explicit decisions for the implementer with a stated fallback.
- Types: `GraphicsDriver`, `read_graphics_driver`, `DRIVERS_KEY`, `set_graphics_driver`, `wine_drivers`, `graphics_driver` are named identically across tasks.
