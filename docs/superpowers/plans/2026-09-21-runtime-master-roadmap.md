# Native Windows Application Runtime for Linux — Master Roadmap

> **For agentic workers:** This is the *roadmap* (phase-level). It is NOT executable task-by-task. Before starting any phase, write that phase's own bite-sized TDD plan with `superpowers:writing-plans` (one plan per phase, saved beside this file as `YYYY-MM-DD-phase-N-<name>.md`), then execute it with `superpowers:subagent-driven-development` or `superpowers:executing-plans`.

**Goal:** A Linux-native runtime where `runtime install setup.exe` + `runtime run <app>` is enough — no prefixes, DLLs, registry or DXVK knowledge required from the user.

**Architecture:** The runtime is the *platform* (own PE analysis, environments, installer pipeline, dependency engine, sandbox, CLI/daemon/GUI). Execution of Windows code is delegated to a swappable **`CompatBackend`** — initially Wine + DXVK/VKD3D-Proton ("Compatibility Mode"), later individual subsystems and eventually a native loader ("Native Mode"). Replacement happens one subsystem at a time behind stable traits.

**Tech Stack:** Rust (core, everything through Phase 6), C/mingw-w64 (Windows test executables), Wine (external process, not linked), DXVK, VKD3D-Proton, bubblewrap + Landlock, PipeWire, Wayland, TypeScript/Tauri or GTK4-rs (GUI, Phase 6).

**Spec:** The "Master Prompt" pasted into the 2026-09-21 planning session. `§N` below refers to its section numbers. (Suggested: save it as `docs/master-prompt.md` so it travels with this plan.)

## Global Constraints

(Verbatim from the master prompt; every phase inherits these.)

- Never require root for normal applications (§47, §50.6).
- Never modify the host globally; every app gets an isolated env at `~/.local/share/runtime/apps/<app-id>/` (§14, §23, §50.5).
- Do not rely on file extensions — detect format from headers (§6).
- Design for Wayland first; design graphics around Vulkan (§50.15–16).
- Do not silently download proprietary components; no proprietary runtime without user consent/licence (§21, §47).
- Untrusted installers/apps are sandboxed; never auto-elevate (§28).
- If an API can't be implemented correctly, return `STATUS_NOT_IMPLEMENTED` — no fake implementations (§51).
- Do not claim an app works without testing it; compat matrix is the only source of truth (§35, §50.19).
- Keep CPU translation separate from OS compatibility (§31, §50.17).
- Maintain a third-party dependency + licence inventory (§40, §50.13).
- Write tests before complex compatibility behaviour (§50.9); benchmark before optimising (§44).

---

## 1. Strategic decisions (read first)

| # | Decision | Why |
|---|----------|-----|
| D1 | **Compatibility Mode first (Wine backend).** Native Mode is a research track that starts only after Phase 6 ships. | A real app runs in weeks, not years. Matches your recommendation (§41). |
| D2 | **Own PE code in Phase 1 is for *analysis*, not execution.** Wine cannot be handed a pre-mapped PE; it does its own load. The own loader (`loader` crate) becomes an *execution* component only in Phase 8. | Avoids the trap of building a loader that the Wine backend can't use. The PE parser still earns its keep: `analyze`, `doctor`, dependency detection, installer detection, icon extraction. |
| D3 | **Replacement granularity = "hybrid mode" via Wine DLL overrides.** Own subsystems are built as PE DLLs (Rust target `x86_64-pc-windows-gnu`) and dropped into a prefix as `native` overrides. | This is the only realistic way to replace Wine *piecewise*. Gives incremental Native Mode (Phase 7) before a full native loader (Phase 8). |
| D4 | **Wine is invoked as a separate process, never linked.** | LGPL boundary stays clean; runtime can pick any licence. |
| D5 | **CLI-first, daemon later.** Phases 1–5 are a library + CLI. `runtimed` (IPC) arrives in Phase 6 when the GUI needs progress streams. | Prompt §38 daemon is right long-term but pure overhead for the first 5 phases. |
| D6 | **Crates are created when a phase needs them**, not all 21 up front (§49 is the *target* layout). | Empty crates rot. |
| D7 | **Sandbox hook exists from Phase 2, real sandbox from Phase 3 (installers) / Phase 5 (full).** All launches go through one `Launcher` seam. | Untrusted installers are the first real risk; don't bolt security on at the end. |
| D8 | **Wine's default `Z:` → `/` mapping is removed in every prefix from day one.** | Wine is not a sandbox; `Z:` hands the app your whole disk. |

### Assumptions (confirm or correct)

- Host: **x86-64 Linux, Wayland**, Rust stable installed (verified: cargo present, `XDG_SESSION_TYPE=wayland`).
- Guest apps: **x86-64 Windows first**; 32-bit via Wine's WoW64 mode in Phase 9; ARM64 last.
- Not installed yet (Phase 0): `wine`, `mingw-w64`, `vulkaninfo`. Present: `bwrap`, `pipewire`, `gcc`.

### Open decisions for you

1. **Project licence** (MIT/Apache-2.0 vs GPL). Permissive keeps Native Mode clean-room-able; if permissive, never copy Wine/ReactOS code into own components.
2. **Wine sourcing:** system `wine` only (simple) vs runtime-managed Wine builds downloaded with consent (reproducible; needed by Phase 4).
3. **GUI toolkit** for Phase 6: Tauri (TypeScript, matches §37) vs GTK4-rs (native look on GNOME/KDE).
4. **Project/binary name** (`runtime` is a placeholder and collides with generic names).

---

## 2. Phase overview

| Phase | Name | Release | Est. (solo) | Delivers | Native-ness |
|-------|------|---------|-------------|----------|-------------|
| 0 | Foundations | — | 1 wk | Workspace, CI, fixtures, toolchain, licence inventory | — |
| 1 | PE analysis | v0.0.1 | 2–3 wk | `runtime analyze`, `pe` crate | Own |
| 2 | Environments + Wine backend | **v0.1 (MVP)** | 3–4 wk | `install`(portable/zip) `run` `list` `remove` `logs` `doctor`(basic) | Own core, Wine exec |
| 3 | Installers + desktop integration | v0.2 | 4–6 wk | exe/msi installers, app discovery, `.desktop`, icons, MIME | Own |
| 4 | Dependencies, graphics, audio | v0.3 | 4–6 wk | Dependency engine, DXVK/VKD3D, `graphics info`, full `doctor` | Own engine, mature backends |
| 5 | Sandbox + permissions | v0.4 | 3–4 wk | bwrap/Landlock profiles, permissions, limits, portals | Own |
| 6 | Daemon, API, plugins, GUI | v0.5 → v1.0 | 4–8 wk | `runtimed`, stable `Backend` API, GUI manager, `.wrun` | Own |
| 7 | Hybrid Native Mode | post-1.0 | open-ended | Own DLLs replacing Wine builtins one by one | Own, per-DLL |
| 8 | Full Native Mode | research | open-ended | Own PE loader + ntdll + kernel32 running apps without Wine | Fully own |
| 9 | Multi-arch | parallel from 6 | open-ended | 32-bit, ARM64 host (FEX/Box64), CPU backend trait | Mixed |

Estimates assume one focused developer; they're for ordering, not commitments. **Gate after Phase 2:** if the MVP can't run a portable app + a console app, stop and fix before Phase 3.

### Dependency graph

```text
P0 ──► P1 ──► P2 ──► P3 ──► P4 ──► P5 ──► P6 ──► P7 ──► P8
                │      │      │             │
                │      └──────┴─(minimal bwrap for installers, D7)
                └─ Launcher seam ───────────►(P5 fills it in)
                                            P9 (32-bit can start after P4; ARM64 after P6)
```

Crate arrival: P1 `pe`,`cli` · P2 `core`,`filesystem`(path/env layout),`backend`,`backend-wine`,`diagnostics` · P3 `installer`,`desktop` · P4 `dependency`,`graphics`,`audio`(detect/config only) · P5 `sandbox` · P6 `api`,`runtimed`,`gui`,`package` · P7+ `registry`,`win32`,`ntdll`,`user32`,`gdi`,`com`,`networking` · P8 `loader`,`memory`,`process`.

---

## Phase 0 — Foundations (≈1 week)

**Goal:** Anyone can clone, build, test, and produce Windows test binaries.

- Cargo workspace (`crates/`), `rust-toolchain.toml`, `cargo fmt`/`clippy -D warnings`, CI (build + test + clippy + `cargo deny` for licences).
- `tests/fixtures/`: **built** Windows test executables from `tools/fixtures/*.c` via `x86_64-w64-mingw32-gcc` / `i686-w64-mingw32-gcc` (hello console, GUI msgbox, DLL with exports, TLS, delay-load, .NET-shaped stub, PE32, PE32+). Commit sources + a build script; do not commit unknown third-party binaries.
- `docs/THIRD_PARTY.md` (licence inventory; Wine LGPL-2.1, DXVK zlib, VKD3D-Proton LGPL-2.1, FEX/Box64 MIT, Mesa MIT), `docs/adr/` with D1–D8 above as ADRs.
- `tracing` setup with the §33 categories as targets (`pe`, `loader`, `installer`, …) — one small module, reused by every crate.
- Host tooling: install `wine`, `mingw-w64`, `vulkan-tools`.

**Exit criteria:** `cargo test --workspace` green in CI; `make fixtures` produces ≥6 PE variants; `wine hello.exe` runs manually on your machine.
**Risks:** mingw missing (blocks all PE tests) → install first. Run `! sudo apt install mingw-w64 wine vulkan-tools` yourself.

---

## Phase 1 — PE analysis (`pe` crate + `runtime analyze`) (≈2–3 weeks)

**Goal (§6, §36 Stage 1, §48):** Correct, header-based understanding of any Windows binary.

**Interfaces first:** `PEImage`, `PESection`, `PEImport`, `PEExport`, `PERelocation`, `PEArchitecture` (§6 names). Parse with an existing crate (`goblin` or `object`) behind these types — write your own parser only where the crate lacks a field. Own types keep Phase 8's loader unblocked.

**Scope:**
- DOS + NT headers, magic-based detection (never extension), PE32 / PE32+, machine: x86, x86-64, ARM64 (+ARM64EC flag).
- Sections, imports (normal, **delay-load**, bound), exports (incl. forwarders), relocations, TLS directory, resources (version info, icon groups, manifest), Authenticode presence (not verification).
- Classifiers: **.NET** (COM descriptor dir), **installer family** (Inno Setup, NSIS, InstallShield, WiX/MSI bootstrapper, Squirrel — by signatures/overlay), **MSI** (OLE compound file magic), **subsystem** (console/GUI/native → kernel driver = "unsupported", §29).
- CLI: `runtime analyze <file> [--json]`.

**Tests (write first):** golden JSON per fixture; cross-check against `llvm-readobj`/`objdump -p` on the fixture set; fuzz the parser (`cargo fuzz` on truncated/malformed headers — this is a security boundary, malware will be fed to it). Property: no panic on any input.

**Exit criteria:** `runtime analyze` correct on all fixtures + ≥10 real-world binaries you supply (7-Zip, Notepad++ portable, VC++ redist, a .NET app, an Inno and an NSIS installer). Parser never panics under 10 min of fuzzing.
**Risks:** overlay/installer-signature heuristics are fuzzy → report as `confidence`, never as fact.

**Amendments after spiking (see `2026-09-21-phase-0-1-foundations-and-pe-analysis.md`, the detailed plan for Phases 0–1):** parser is `pelite` (not goblin/object; it covers resources and TLS) wrapped behind own types, with hand-written delay-import and import-thunk walking plus alignment guards for hostile files; installer detection reports the matched `evidence` marker instead of a numeric confidence; a 30k-iteration mutation test replaces `cargo fuzz` for now (needs nightly); icons/manifest extraction moves to Phase 3 where `.desktop` generation consumes it; bound imports are not parsed.

---

## Phase 2 — Environments + Wine backend → **MVP v0.1** (≈3–4 weeks)

**Goal (§22–23, §36, §48):** `runtime install portable.exe|zip` → `runtime run app` works, in an isolated env.

**Interfaces first (the seams every later phase plugs into):**
```text
trait CompatBackend { fn prepare(&self, env: &AppEnv) -> Result<()>;
                      fn spawn(&self, env: &AppEnv, exe: &WinPath, args: &[String]) -> Result<Child>;
                      fn kill_all(&self, env: &AppEnv) -> Result<()>;
                      fn capabilities(&self) -> Capabilities; }   // graphics/audio/arch it supports
struct Launcher  // sole place that builds the final Command; sandbox wrapper slots in here (D7)
struct AppEnv    // id, root dir, metadata.json, backend id, arch
```
**Scope:**
- `AppEnv` + `metadata.json` (§23 schema; add `schemaVersion` from day one — you'll migrate it), layout `apps/<id>/{drive_c,registry,config,cache,logs,runtime,prefix}`.
- `WineBackend`: locate system wine, create prefix at `apps/<id>/prefix`, set `WINEPREFIX`, `WINEARCH`, `WINEDEBUG`, `WINEDLLOVERRIDES` (disable `winemenubuilder` — we own desktop integration), **remove `Z:` and dosdevices to `/`** (D8), symlink-free home isolation, own `wineserver` lifecycle (wait/kill on exit).
- Commands: `install` (portable exe / zip only; format by header), `run <path|name>`, `list`, `remove`, `logs`, `doctor` (basic: PE ok, Wine present, missing DLLs from imports vs prefix, Wayland/Vulkan/PipeWire presence), `run --debug`.
- stdout/stderr capture to `logs/`, exit-code propagation, clean Ctrl-C.
- Filesystem crate: Windows path parsing (drive letters, UNC, `\\?\`, reserved names CON/NUL…, case-insensitive lookup) — **as a pure library with tests**; Wine does the real translation at runtime, but installer diffing (Phase 3) and Native Mode (Phase 8) reuse it.

**Tests:** integration tests that install+run the hello-console fixture and assert stdout/exit code; env-isolation test (app cannot read `~`); `remove` leaves nothing behind; path-semantics table tests.
**Exit criteria:** hello.exe, a GUI msgbox fixture, and 7-Zip/Notepad++ portable run on Wayland; `list/remove` clean; second app cannot see first's files.
**Risks:** Wine version drift → pin & record Wine version in `metadata.json`; wineserver zombies → supervise and test.

---

## Phase 3 — Installers + desktop integration → v0.2 (≈4–6 weeks)

**Goal (§22, §24, §27):** `runtime install setup.exe|msi` yields a launcher entry in GNOME/KDE.

- **Pipeline stages as separate functions** (§22): detect → analyze → create env → run installer (sandboxed, D7) → **snapshot diff** → discover → integrate → register.
- Installer execution: family-aware silent flags as *opt-in* (`/VERYSILENT`, `/S`, `msiexec /i … /qn`); default = show installer GUI.
- **Minimal bwrap wrapper** for installers only: no host `$HOME`, `Downloads` read-only, network configurable. (Full profiles in Phase 5.)
- Discovery: before/after diff of `drive_c` + Wine `.reg` files (text format — parse `system.reg`/`user.reg`); parse Start Menu `.lnk` (shell-link parser), Uninstall keys, App Paths; rank candidate executables.
- Icons: extract from PE resources → PNG (hicolor sizes).
- `.desktop` generation into `~/.local/share/applications/`, MIME + `.exe/.msi` association, "Open with Runtime"/"Install with Runtime" (§27), `runtime uninstall` (uses recorded uninstaller, then removes env), `update-desktop-database` handling.
- `.zip` packages.

**Tests:** fixtures for Inno + NSIS + MSI (build with `iscc` under Wine / `makensis` / `wixl`); desktop-file validity via `desktop-file-validate`; uninstall leaves no `.desktop`/icon residue.
**Exit criteria:** 3 real installers (one each Inno/NSIS/MSI) install, appear in the launcher, launch, uninstall cleanly.
**Risks:** discovery heuristics wrong for weird installers → always allow `runtime install --exe "C:\…"` manual override; MSI needs Wine's msiexec + possibly Mono/Gecko (Phase 4 handles).

---

## Phase 4 — Dependencies, graphics, audio → v0.3 (≈4–6 weeks)

**Goal (§17–18, §21, §32):** Games and .NET apps work without user tweaking; `doctor` is trustworthy.

- **Dependency engine:** imports/manifests/installer metadata → required components (`vcruntime`, `d3dcompiler_47`, `dotnet48`, `mono`, `gecko`, `webview2`, fonts). **Package source system:** signed/hashed manifest → `{name, version, sha256, licence, url, requires_consent}`. Proprietary items *never* auto-download: prompt, record consent in metadata (§21).
- **Graphics:** `GraphicsBackend` capability model (D3D9/10/11 → DXVK, D3D12 → VKD3D-Proton, GDI/OpenGL → Wine). Install into prefix per-app, choose by PE imports (`d3d9/d3d11/d3d12.dll`), Vulkan probe via `ash`, `runtime graphics info`. Don't write translation — reuse (§17).
- **Audio:** verify Wine's PipeWire/PulseAudio path works; `doctor` reports; no own audio code yet.
- **Wayland:** enable Wine's native Wayland driver where supported; fall back to XWayland; expose in config.
- Full `doctor app` (§32 format): arch, PE, imports vs prefix, graphics, audio, runtimes, .NET, env.
- **Compatibility matrix v1** (`docs/COMPAT.md`, machine-readable YAML → rendered table). Statuses only from CI/manual test records (§35).

**Tests:** D3D9/D3D11 fixtures (tiny mingw programs); FPS/frame-time smoke benchmark recorded (§44); dependency resolver unit tests incl. consent-denied paths.
**Exit criteria:** a D3D11 sample and one real D3D9/11 game render via DXVK; a .NET 4.8 app runs; `doctor` correctly predicts a deliberately broken env.
**Risks:** upstream packaging churn (DXVK/VKD3D versions) → pin versions in manifest; GPU-specific bugs → matrix records GPU/driver.

---

## Phase 5 — Sandbox + permissions → v0.4 (≈3–4 weeks)

**Goal (§28, §45):** Windows apps get least privilege by default.

- `sandbox` crate: **profile model** (`permissions.toml` per app: filesystem allow/ask/deny, network, GPU, audio, camera, USB) → renderer to **bubblewrap** args + **Landlock** rules + seccomp deny-list; **`systemd-run --user --scope`** (cgroup v2) for memory/CPU limits.
- GPU/audio pass-through correctness under bwrap (`/dev/dri`, PipeWire socket, Wayland socket) — the fiddly part.
- "ASK" flows via **xdg-desktop-portal** (file chooser, camera), which also delivers native file dialogs (§27).
- Commands: `runtime permissions <app> [--set …]`, `runtime sandbox <app>`.
- Threat-model doc: assume the installer/app is malicious; Wine is *not* a boundary; bwrap+Landlock is.
- Security tests: attempts to read `~/.ssh`, write outside prefix, connect out when denied — must fail.

**Exit criteria:** all Phase 2–4 exit apps still work under default sandbox; escape-attempt test suite green.
**Risks:** games needing broad access → per-app relaxed profile with explicit user grant, never a silent default.

---

## Phase 6 — Daemon, public API, plugins, GUI → v0.5 → v1.0 (≈4–8 weeks)

**Goal (§26, §38–39, §42–43):** Stable surface so the backend can change underneath.

- **Public Rust API crate** (`Runtime`, `Application`, `Environment`, `Process`, `Dependency`, §42) — the CLI is re-implemented as a thin client of it.
- **`runtimed`** on a **Unix domain socket** with systemd user socket activation; JSON-RPC (or varlink) with **event streams** (install progress, logs). No TCP.
- **Backend plugin interface** frozen & versioned: `CompatBackend`, `GraphicsBackend`, `WindowBackend`, `AudioBackend`, `CpuBackend`. Register by capability (§39).
- **GUI manager** (toolkit per Open Decision 3): apps, environments, dependencies, logs, permissions, diagnostics (§26 screens).
- **`.wrun` package** (§43): manifest + reproducible env recipe; `.exe`/`.msi` remain first-class.
- Notifications (D-Bus `org.freedesktop.Notifications` via `zbus`), clipboard/drag-drop via Wine's Wayland support (verify; document gaps).
- Compat CI: nightly headless smoke runs (weston headless / Xvfb) of matrix apps.

**Exit (v1.0 bar):** ≥25 matrix apps tested with statuses; API semver-stable; install → launch → uninstall from the GUI on GNOME and KDE.

---

## Phase 7 — Hybrid Native Mode (open-ended, post-1.0)

**Goal (§41):** Replace Wine builtins one DLL at a time, invisibly to the user.

- Build own subsystems as **PE DLLs from Rust (`x86_64-pc-windows-gnu`)**, installed as `native` overrides (D3). Candidate order = lowest coupling first: `version` → `winmm`/audio→PipeWire → `xinput`/controllers → own `registry` store → `ws2_32` shim → GDI CPU renderer → `d3d11` (own translator, long).
- Each replacement ships behind a per-DLL feature flag (`backend.native = ["winmm"]`), gated by its own compat suite passing *and* not regressing any matrix app.
- Test discipline: differential tests — same Windows test exe run against Wine builtin vs own DLL; outputs must match.
- **Go/no-go review** after first 2 DLLs: if per-DLL cost is >> benefit, stay in Compatibility Mode.

## Phase 8 — Full Native Mode (research track)

**Goal (§6–12, §36 Stage 2–4):** Run Windows console apps on Linux with no Wine.

- `loader`: map sections, relocations, imports, TLS callbacks, API-set (`api-ms-win-*`) resolution.
- **Hard parts to plan for up front:** Windows x64 ABI vs SysV (`extern "win64"` shims); **TEB/PEB via `GS`** (`arch_prctl(ARCH_SET_GS)`; Linux uses `FS`, so `GS` is free); own thread stacks; **SEH/x64 unwinding from `.pdata`** and Linux signal → Windows exception mapping; low-address reservation; handle table; NT layer (`NtCreateFile`, `NtAllocateVirtualMemory`, …) on `mmap/futex/openat`.
- Staged targets: (a) no-CRT exe → (b) mingw msvcrt console → (c) files/threads/sync → (d) registry + COM basics → (e) GUI over Wayland (`user32`/`gdi`) — (e) alone is Wine-scale; treat as separate multi-year effort.
- UCRT/MSVC runtime licensing: apps expect `ucrtbase.dll`; decide own impl vs. redistributable-with-consent before starting (b).
- Every unimplemented API returns `STATUS_NOT_IMPLEMENTED` + a log line (§51).

## Phase 9 — Multi-architecture (parallel track)

- **32-bit x86:** use Wine's WoW64 mode so no 32-bit host libs are needed; env records `arch`; never mix 32/64-bit DLLs (§30). Feasible from Phase 4.
- **ARM64 host:** define `CpuBackend { Native, Translate(FEX|Box64) }`, kept strictly separate from OS compat (§31). Start with FEX/Box64 as external processes.
- **Windows-ARM64 guest on x86-64:** experimental, last.

---

## 3. Cross-cutting tracks (every phase)

| Track | Rule |
|-------|------|
| Tests | Each API/feature: unit + behaviour + regression; Windows behaviour verified against a real `mingw` test exe. Integration tests live in `tests/integration/`. |
| Compat matrix | Updated only by recorded runs; includes GPU/driver/Wine version. |
| Logging | Structured `tracing`, §33 categories; `runtime logs`, `--debug`. |
| Security | Fuzz all parsers (PE, `.lnk`, MSI, `.reg`); never run installers outside sandbox after Phase 3. |
| Perf | Benchmarks (startup, install time, frame time, IPC latency) recorded per release before any optimisation (§44). |
| Licensing | Update `THIRD_PARTY.md` in the same PR as any new dependency; `cargo deny` in CI. |
| PR template | §52's seven questions (what/why/Windows behaviour/Linux mapping/limits/tests/apps tested). |

## 4. Top risks

1. **Installer discovery heuristics** (Phase 3) are the biggest UX risk — mitigate with manual override + snapshot diff rather than guessing.
2. **Wine version/packaging drift** — pin versions, record in metadata, CI matrix over 2 Wine versions.
3. **Sandbox vs GPU/audio** (Phase 5) breaks games easily — per-app relaxed profiles with explicit consent.
4. **Scope creep into Native Mode** — Phases 7–8 are gated by explicit go/no-go; v1.0 ships without them.
5. **Legal:** DRM/anti-cheat/licence bypass are non-goals (§47); redistributables need consent; keep clean-room discipline if choosing a permissive licence.

## 5. Immediate next step

Write the detailed TDD plans for **Phase 0 + Phase 1** (≈15–20 bite-sized tasks: workspace, fixtures, `pe` types, header/section/import/export parsing, classifiers, `analyze` CLI, fuzz target). Phase 2's plan is written only after Phase 1's exit criteria pass.
