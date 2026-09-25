# Phase 4, sub-project C: audio and display driver (design)

Status: approved by the controller on the user's standing instruction (2026-09-25: self-approve with recommended
choices). Third of five Phase 4 sub-projects (4A dependency engine and 4B graphics backends are merged).

## 1. Purpose and success criteria

Roadmap: "verify Wine's PipeWire/PulseAudio path works; `doctor` reports; no own audio code" and "enable Wine's
native Wayland driver where supported; fall back to XWayland; expose in config."

Facts checked on the target host (Wine 10.0): the Wine build ships `winepulse`, `winealsa` and `winewayland`
drivers and NO native PipeWire driver. Wine audio therefore needs a PulseAudio-protocol server
(`$XDG_RUNTIME_DIR/pulse/native`, which `pipewire-pulse` provides) or ALSA. `doctor`'s current audio check looks
for `pipewire-0`, which is the wrong socket for Wine.

Success criteria:

1. `doctor` audio reports the path Wine will really use: PulseAudio-compatible socket present (Ok, and whether it
   is served by PipeWire is not asserted), else ALSA only (Warn), else nothing (Warn); and whether the Wine build
   has `winepulse` / `winealsa` drivers (from the backend's unix-side directory), never guessing.
2. `runtime display <app>` prints the app's graphics driver setting (`auto`, `x11` or `wayland`) read from the
   prefix's `user.reg`; `runtime display <app> <auto|x11|wayland>` sets it. No network, no download.
3. Setting `wayland` on a host without a Wayland session, or without `winewayland`, is refused with a reason;
   `x11` without `DISPLAY` is a warning, not a refusal (XWayland may start later).
4. `doctor <app>` reports the app's graphics driver setting next to the session type and flags a setting the
   current session cannot honour.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Where the setting lives | The prefix registry (`HKCU\Software\Wine\Drivers`, value `Graphics`), read with the bounded `.reg` parser and written with Wine's `reg.exe` through the same helper the DLL overrides use | The prefix state is the truth Wine reads; a second setting in `Metadata` could disagree with it and would need a schema v4. Same reasoning as 4B's "installed = chosen". |
| `auto` | Deletes the `Graphics` value (Wine's own default order) | Never invents a default that could diverge from Wine's. |
| Audio driver selection | Not exposed. `doctor` reports only. | The roadmap says no audio code; Wine picks pulse then alsa itself. YAGNI until a real app needs an override. |
| Wayland status | Documented as experimental in Wine 10.0 (winewayland has known gaps); `wayland` is opt-in per app, never automatic | A silent default that breaks clipboard or input would be worse than XWayland. |

Non-goals: per-app audio device choice, latency tuning, PipeWire-native audio, X11 tuning, HiDPI scaling.

## 3. Components

- `crates/core/src/doctor.rs`: `audio()` rewritten; `DoctorInput` gains `wine_drivers: Option<&'a [String]>` (names of
  `*.drv`-style driver modules found in the backend's unix DLL dir, gathered by the CLI) and
  `graphics_driver: Option<GraphicsDriver>` (the app's setting). New pure `enum GraphicsDriver { Auto, X11, Wayland }`
  with `parse`/`as_str` in `rt_core` (new small module `display.rs`, also holding `read_graphics_driver(&WineReg)`).
- `crates/deps/src/wine_config.rs` (new, small): `set_graphics_driver(env, backend, launcher, GraphicsDriver)` using
  `install_archive::reg` (made `pub(crate)`); rejects nothing itself (policy lives in the CLI).
- `crates/cli/src/display.rs` (new) and `main.rs`: `runtime display <app> [auto|x11|wayland]`, taking the app lock
  exclusively for a set (as `deps --install` does) and refusing while the app runs.

## 4. Testing

Frozen `user.reg` byte literals for read; doctor unit tests for each audio/driver combination via the injected
`FsProbe`/env; CLI tests with the fake-Wine rig; a wine-e2e test that sets and reads back `wayland` and `auto` in a
real prefix (filter prefix `e2e_real_wine`).

## 5. Risks

- `winewayland` maturity in Wine 10.0: documented, opt-in.
- Detecting the driver modules relies on Wine's directory layout; when the directory cannot be listed the check
  says "not verified", never "missing" (the same rule doctor already uses for DLLs).
