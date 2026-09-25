# Phase 4, sub-project A: dependency engine and package source (design)

Status: draft for review. Part of roadmap Phase 4 ("Dependencies, graphics, audio"). This is the first of five
Phase 4 sub-projects; the others (graphics selection, audio/Wayland, full `doctor app`, compatibility matrix) each
get their own spec, plan and build cycle and are out of scope here.

## 1. Purpose and success criteria

Apps often need components a bare Wine prefix lacks: the VC++ runtime, `d3dcompiler_47`, .NET, Mono, Gecko,
WebView2, and the graphics translation layers (DXVK, VKD3D-Proton). Phase 3 deliberately deferred all of this.
This sub-project adds the machinery to work out what an app needs, fetch it safely, and install it into the app's
prefix, with the user's explicit consent for anything proprietary. It introduces the runtime's first network
access, so the trust model is the central design concern.

Success criteria:

1. `runtime deps <app>` correctly plans what is missing for an app, and with consent installs an `archive` package
   and an `installer` package end to end on real Wine.
2. A tampered or truncated download, or any hash or size mismatch, installs nothing.
3. Denied or missing consent installs nothing and never downloads the package.
4. `install`, `run` and `doctor` never download anything; at most they print a hint.

## 2. Decisions already made (with the reasoning)

| Decision | Choice | Why |
|---|---|---|
| First sub-project | Dependency engine + package source | DXVK, VKD3D, .NET, Mono and Gecko all arrive through it; the other sub-projects depend on it. |
| Manifest trust | Bundled, pinned manifest compiled into the binary | No signing infrastructure and no remote manifest to compromise. Updates ship with releases. Smallest attack surface. |
| Install method | Two package kinds, `archive` and `installer` | DXVK/VKD3D are plain DLL archives; vcruntime/.NET/Mono/Gecko ship as vendor installers. Each kind reuses already-hardened code. |
| Resolution flow | Explicit `runtime deps` command; other commands only hint | Never downloads implicitly; works non-interactively and in CI; keeps prompts out of core commands. |
| Download mechanism | In-process Rust HTTPS client (`ureq` + `rustls`) | Streaming with size caps and in-flight hashing, no dependence on host curl, no argv-injection surface. |

Non-goals here: choosing graphics backends per app, audio, Wayland, the full `doctor app` report, the
compatibility matrix, runtime-managed Wine builds (system Wine stays), a remote manifest, user-supplied manifests.

## 3. Architecture

New crate `crates/deps` (package `runtime-deps`, lib `rt_deps`). Pure logic plus one network edge.

### 3.1 `manifest`

The manifest is `crates/deps/packages.toml`, embedded with `include_str!`. Each package:

```
id, version, sha256 (64 hex), size (bytes, exact), licence (SPDX or "proprietary-redistributable"),
url (https only), kind = "archive" | "installer", requires_consent (bool),
requires = [package ids], provides = [capability names / dll names],
install = { ... kind-specific ... }
```

Kind-specific fields: `archive` has an `extract` list of `{from, to}` prefix-relative destinations and the DLL
overrides to write; `installer` has the silent flags (reusing `installer::family` conventions) and the expected
result marker used to confirm success.

Parsing is strict: unknown fields, duplicate ids, dependency cycles, a non-HTTPS `url`, a malformed `sha256`, or a
`requires`/`provides` reference to an unknown id are all errors. The same checks run as a build-time test over the
real bundled manifest so a bad manifest cannot be released.

### 3.2 `resolve`

A pure function `resolve(facts, state, manifest) -> Plan` with no I/O.

- `facts`: what the runtime already knows about the app: PE imports (`pe::analyze`), installer family and MSI facts,
  and `Metadata`.
- `state`: the packages and consent the runtime itself recorded for this app (see 3.5). It is never inferred by
  looking at the prefix's files, so a hostile installer cannot forge "already installed".
- `Plan`: an ordered list (dependencies first) of entries `{package, action, consent}` where `action` is
  `install`, `already-installed` or `blocked{reason}` and `consent` is `not-needed`, `needed` or `denied`.

Import to capability mapping is a small table in the manifest crate (for example `d3d11.dll` requires the
`d3d11` capability, satisfied by the `dxvk` package); the table is data, unit-tested, and versioned with the
manifest.

### 3.3 `fetch` (the only network code)

Built on `ureq` with `rustls`. Rules, all enforced in code and tested:

- HTTPS only; a redirect must also be HTTPS; at most 3 redirects.
- The byte cap is the manifest `size`; the connection is aborted the instant more bytes arrive than declared, and
  also if fewer arrive than declared. `Content-Length` is never trusted on its own.
- Connect timeout and a total deadline; a per-read stall timeout so a slow-drip body cannot hold the process.
- Bytes stream into a temp file inside the app cache directory (created `0600`, `O_EXCL`) while SHA-256 is computed
  in flight. On any mismatch the temp file is deleted and the fetch fails hard. There is no retry and no HTTP
  fallback.
- On success the file is renamed to `cache/<sha256>` and is read-only.
- A cache hit is re-verified against the manifest hash before use; it is never trusted.

### 3.4 `install`

- `archive`: extraction goes through the existing hardened zip path (`rt_core::unzip`: containment, entry-count and
  size caps, no symlinks). Destinations come only from the package's `extract` list, resolved with the existing
  containment-safe path helpers under `drive_c`. DLL overrides are written only for names listed in `provides`.
- `installer`: the verified file is staged inside `drive_c` and run through the Phase 3 sandboxed pipeline with
  `allow_network = false`, including the in-sandbox `wineserver` wait so registry effects persist. Success is
  confirmed by the package's declared marker (a file or registry value), not by exit code alone.

### 3.5 `state`

Per-app installed packages and consent are stored in `Metadata` as a new `dependencies` field: for each package
`{id, version, sha256, installed_at, consent: {given_at, licence_text_sha256}}`. This is `Metadata` schema v3. The
migration keeps v1 and v2 files readable (`dependencies` defaults to empty) and is tested against frozen v1 and v2
byte literals, not bytes regenerated from current code. Writes use the existing atomic write path.

### 3.6 CLI

- `runtime deps <app>`: print the plan (no network, no writes).
- `runtime deps <app> --install [--yes <pkg>]...`: fetch and install. Interactive runs prompt per consent-gated
  package showing licence and URL. Non-interactive runs need `--yes <pkg>` for each named package; a bare `--yes`
  is rejected so nothing installs by accident.
- `runtime deps list`: show the bundled manifest.
- `runtime deps cache [--clear]`: show or clear the download cache.
- `install`, `run`, `doctor`: print a one-line hint when something is missing; never download.

All untrusted text (package names from installers, error strings) goes through the existing `safe` sanitizer before
reaching a terminal.

## 4. Consent model

- Proprietary or redistributable-licensed packages (VC++ runtime, .NET, WebView2) have `requires_consent = true`.
  Permissively licensed archives (DXVK, VKD3D-Proton) have `false`, but still appear in the plan and still need an
  explicit `--install`.
- Consent is per package and per version. The record stores a hash of the exact licence text that was shown.
- A denied or missing consent leaves that package `blocked`; packages that do not depend on it still install.
  Nothing is downloaded for a blocked package.

## 5. Security and hardening

Threat model: the network, the downloaded file and the vendor installer inside it are untrusted. The only trusted
input is the bundled manifest.

- Network edge as in 3.3, with a local in-process HTTPS test server exercising: lying and oversized
  `Content-Length`, short bodies, slow-drip bodies, redirect loops, HTTPS to HTTP downgrade, chunked-encoding
  oddities, wrong hash, TLS failure. No real internet in CI; one `#[ignore]`d real-download smoke test.
- The new dependency `ureq` (with `rustls`) gets a `docs/THIRD_PARTY.md` row, a `cargo deny` licence check, and
  hostile-response testing as above before it is trusted (the standard used for `pelite`, the `.lnk` crates and the
  MSI crates in earlier phases).
- Installers run only in the Phase 3 sandbox, offline, in the app's own prefix.
- Prefix effects of a package are limited to its declared `extract`, `provides` and marker; the resolver treats
  anything else as not installed.
- Fuzz the manifest parser and the import-to-capability table loader.

## 6. Error handling

Every failure is a typed error with a clear message and leaves the prefix unchanged where possible: fetch failure
deletes its temp file; an extraction failure removes what that package created (tracked by the extract list, no
globbing); an installer failure or missing marker marks the package `failed` in the plan output and records
nothing in `state`. A partial multi-package install stops at the first failure and reports which packages were
completed, which failed, and which were skipped.

## 7. Testing

- Unit: manifest parser (valid, invalid, cycles, duplicates, hostile TOML), resolver table tests (including
  consent-denied, diamond dependencies, blocked-by-dependency), state migration against frozen v1 and v2 literals.
- Network: the local HTTPS test server suite in section 5.
- Real Wine e2e (`#[ignore]`d, in the `wine-e2e` job and runnable locally): install an `archive` fixture (a tiny DLL
  zip built locally) and an `installer` fixture (a tiny NSIS installer built locally) into a real prefix; assert
  the files, DLL overrides, marker and consent record; assert a denied package installs nothing and a tampered
  download installs nothing; assert no stray `wineserver`.
- Process standards carried from Phase 3: every new guard is mutation-checked with a named failing test; CI installs
  and requires every real tool any job needs from the start (no piecemeal gaps); e2e assertions check outcomes, not
  just exit codes; a final whole-branch review with real experiments before merge.

## 8. Known risks and open questions

- Upstream URLs and versions churn; the manifest pins version, size and hash, so a moved file fails safely rather
  than installing something else. Refreshing the manifest is a release task.
- Some vendor installers cannot be silenced or need a display (the Phase 3 sandbox has none); such packages are
  marked `interactive-unsupported` in the manifest and are reported, not attempted.
- The first release ships a small manifest (DXVK, VKD3D-Proton, `d3dcompiler_47`, VC++ runtime, one .NET package);
  which exact packages and versions are in scope for the plan is decided when the plan is written, against what can
  actually be verified on real Wine.
- CI has not yet run on a hosted runner; the new network tests use only a local server so they do not depend on it.
