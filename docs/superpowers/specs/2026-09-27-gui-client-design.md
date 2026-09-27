# Phase 6, sub-project C: the GUI client `runtime-gui` (design)

Status: approved by the controller on the user's standing instruction (self-approve with the recommended choices;
the user pre-approved the six decisions this spec builds on, 2026-09-27). Third of four Phase 6 sub-projects (6A API
+ read-only daemon, 6B mutating methods + jobs, **6C GUI client**, 6D plugin interfaces + `.wrun`). Roadmap: "GUI
manager: apps, environments, dependencies, logs, permissions, diagnostics"; Open Decision 3 is settled as GTK4 +
libadwaita (roadmap Phase 6 row).

## 1. Purpose and success criteria

A desktop user must be able to see their installed Windows apps, run and stop one, install a program from a file,
remove an app, review and install an app's dependencies with explicit per-package consent, change its permissions,
and watch what a job prints, without a terminal. The GUI adds no new way around anything 6B guards: it is one more
same-uid client of `runtimed`.

Success criteria:

1. `runtime-gui` talks **only** to `runtimed`, through `rt_daemon::client::Client`. It never runs `runtime`, never
   calls `rt_api::Runtime` (the in-process implementation), and never starts a service or a privileged helper.
2. The toolkit-free **view model** (`crates/gui/src/vm/`) holds every decision (what is enabled, what a click sends,
   what a consent contains, how a string is cleaned) and is unit-tested without a display, and end to end against the
   real `runtimed` binary with a fake and a real `runtime`.
3. Consent: the GUI sends `deps.install` with the plan `digest` exactly as `deps.plan` returned it and only the
   `{package, version, sha256}` of entries the user accepted one by one, after the full `consentText` was shown.
   There is no "accept all" control, no pre-checked box, and no code path that builds a consent item from anything
   but a shown plan entry.
4. Every string that came from the daemon is cleaned again (`rt_core::clean_text`) before display, and is never
   parsed as Pango markup.
5. A read-only daemon shows every write control insensitive with the reason; no daemon shows an empty state saying how
   to start it; the GUI never auto-starts anything (socket activation by `runtimed.socket`, if the user enabled it, is
   the user's choice and not a privilege change).
6. The core crates and their gates (fmt, clippy `-D warnings`, `cargo deny`, tests) do not need GTK: a host or CI job
   without GTK development files builds and tests everything except `runtime-gui` unchanged.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Toolkit | GTK 4 + libadwaita through gtk-rs: `gtk4 =0.11.5` (feature `v4_12`), `libadwaita =0.9.2` (feature `v1_5`); the crates' own `glib`/`gio` via `gtk4::glib`/`gtk4::gio` (no direct `glib` dependency) | Pre-approved toolkit. Exact pins: gtk-rs minor releases change APIs. `v4_12`/`v1_5` is the lowest level that has everything used (`GtkFileDialog` 4.10, `AdwNavigationSplitView`/`AdwToolbarView` 1.4, `AdwAlertDialog` 1.5), so it builds on Ubuntu 24.04 (GTK 4.14, libadwaita 1.5: the hosted CI image) and on this host (GTK 4.22.4, libadwaita 1.9.1). |
| Crate | `crates/gui`, package `runtime-gui`, binary `runtime-gui`, `rust-version = "1.92"` (gtk4 0.11 needs it; the workspace's 1.88 stays for every other crate) | Pre-approved. |
| Isolation | Workspace member (the `crates/*` glob), **excluded from `default-members`**; CI's existing jobs use `--workspace --exclude runtime-gui`; a new `gui` CI job builds, lints and tests it with GTK installed; `cargo deny` and `cargo fmt --all` keep covering the whole workspace (neither builds GTK) | See D1. |
| Main-loop bridge | Worker threads send `vm::Msg` over `futures_channel::mpsc::unbounded` (`futures-channel =0.3.34`, already in the lock through `gio`); the GTK side awaits it in `glib::spawn_future_local` | glib 0.22 has no `MainContext::channel` any more (the "glib channel" of the brief); this is its documented replacement and adds no new crate to the lock. |
| Threads | One request thread (one `Client`, commands in order) + one follower thread per followed job (its own `Client`, `jobs.poll` with `waitMs = 10000`), at most 4 followers | A waiting poll holds its connection (6B 5.5); 4 = the daemon's running-job cap, so the GUI never takes more than 4 of the daemon's 8 waiting-poll slots. |
| Testing | View-model unit tests; end-to-end against the real `runtimed` (6B's rig); widget smoke tests under `xvfb-run` in a `harness = false` test binary; manual checklist `docs/GUI-CHECKLIST.md` | Pre-approved. GTK must be initialised and used on one thread; libtest runs tests on worker threads. |

Non-goals (pre-approved): settings UI beyond the screens below, themes, an icon pipeline, packaging (flatpak, deb),
portals as a requirement, localisation, accessibility beyond GTK/libadwaita defaults (a follow-up: an accessibility
pass with Orca and keyboard-only use), a TUI. Also not in 6C: the display-driver setting (`display.set`; the CLI has
it), resource limits editing (shown, not edited), `uninstall`, `compat.list` browsing, the GUI starting or stopping
`runtimed`.

### Decisions made while writing this spec (unspecified by the brief; safest simple option)

- **Decision D1: isolation by `default-members` + `--exclude` in CI, not a feature or a second workspace.** A feature
  (`gtk` optional) puts `cfg` on every widget file and `--all-features` would pull GTK back into the core gates. A
  separate workspace (`exclude = ["crates/gui"]`) needs its own `Cargo.lock`, its own `cargo deny` run and resolves
  `serde`/`libc` separately from the core. As a member it shares the one lock file (the probe showed the GUI only
  ADDS 44 packages; no existing package changes version), `cargo deny check` covers its licences, and `cargo fmt
  --all` formats it without GTK. `default-members` lists the ten core crates explicitly, so plain `cargo build` /
  `cargo test` at the root never needs GTK. CI does not rely on `default-members` (a new crate missing from that list
  would silently drop out of the gates): it keeps `--workspace` and adds `--exclude runtime-gui`.
- **Decision D2: the one licence exception.** Everything the GUI adds is MIT or MIT OR Apache-2.0 except
  `target-lexicon 0.13.5` (`Apache-2.0 WITH LLVM-exception`), a **build-time** dependency of `system-deps` (via
  `cfg-expr`) in every gtk-rs `-sys` build script; it is never linked into the binary. `deny.toml` gets a
  crate-scoped `[[licenses.exceptions]]` for it, not a global allow: the LLVM exception only relaxes Apache-2.0's
  attribution for compiled output. With it, `cargo deny check` passes (probe, below).
- **Decision D3: the GTK and libadwaita C libraries are system components, dynamically linked** (LGPL-2.1-or-later),
  listed in THIRD_PARTY.md's external table like Mesa. Nothing is vendored or statically linked.
- **Decision D4: the GUI links `rt_api` for its wire types and `rt_core` for `clean_text` only.** A test in the crate
  (a source scan) fails if `crates/gui/src` names `Runtime::`, `rt_api::Runtime`, `std::process::Command` or
  `runtime_cli`.
- **Decision D5: application id `local.runtime.Gui`** (valid reverse-DNS, owns no real domain) until the project
  name decision in the roadmap; `GApplication` uniqueness (a second launch raises the first window) is the default.
- **Decision D6: connection states.** `Unreachable` (no socket / connection refused; `ClientError::Unreachable` or
  `NoRuntimeDir`): an `AdwStatusPage` "runtimed is not running" with the selectable command
  `systemctl --user start runtimed.socket` and a Retry button. `Refused` (`ClientError::Unsafe`: wrong owner or mode):
  a different page quoting the client's reason; Retry only. The GUI never runs `systemctl`. Connecting to an
  enabled `runtimed.socket` starts the user's own service by activation; that is the socket unit's documented
  behaviour, not a GUI action.
- **Decision D7: write mode** comes from `rpc.version.write`. `false`, or an API older than 0.2 => read-only: every
  write control is insensitive with a tooltip and an `AdwBanner` "This runtimed is read-only (started without
  `--write`). The shipped unit passes `--write`; see docs/API.md, Running it under systemd." Read screens work.
- **Decision D8: Stop = `jobs.cancel` of the app's live `run` job** found in `jobs.list` (kind `run`, `app == id`,
  state `queued|running`). An app started from a terminal is not a job: Run shows the daemon's `app_busy` or the
  CLI's lock refusal from the job's events, and Stop is absent. Said in the checklist.
- **Decision D9: permissions editing composes EXPRs only from typed choices**: switches `network=allow|deny`,
  `display|audio|gpu=on|off`; a folder grant from `GtkFileDialog.select_folder` as `fs+=<abs>:ro|rw`; a remove
  button per grant `fs-=<path as shown by permissions.get>`; Reset => `permissions.reset`. No free-text entry. A
  folder path that is not absolute, not UTF-8, contains `:` or a control/format character is refused in the view
  model with a message (the CLI's grant rules stay the real guard: its refusal arrives as the job's `stderr`).
  Limits are shown read-only.
- **Decision D10: install form.** `GtkFileDialog.open` (filter `*.exe *.msi *.zip`, "All files" too); the path must
  be absolute UTF-8 (`InstallParams.path` is a `String`; else refused with a message); optional name (entry, trimmed,
  at most 256 bytes, cleaned check: refused if it has control/format characters); switches `silent` (off) and
  `network` (off, subtitle: "gives the installer network access"). `exe` is not offered (CLI default).
- **Decision D11: log view.** A `GtkTextView` (not editable) per followed job, text inserted as plain text; at most
  5,000 lines per job (oldest dropped, one "[earlier lines dropped]" line), daemon `dropped` counts shown as
  "[N lines were dropped by the daemon]". Jobs panel lists `jobs.list` plus live followers, with Cancel on live jobs.
- **Decision D12: refresh model.** No push: the app list and app page reload after each job this GUI followed ends,
  on Retry, and on a Refresh button. No timer polling of `apps.list`.
- **Decision D13: widget smoke tests skip loudly without a display** unless `RUNTIME_REQUIRE_DISPLAY=1` (the `gui`
  CI job sets it and runs under `xvfb-run -a`), mirroring `RUNTIME_REQUIRE_BWRAP`. A screenshot (`GtkWidgetPaintable`
  -> `gsk::Renderer::render_texture` -> `save_to_png`) is written to `target/gui-smoke/` when `RUNTIME_GUI_SHOTS` is
  set, and uploaded as a CI artifact; not asserted on.

### Probe run while writing this spec (2026-09-27, this host)

- `pkg-config`: gtk4 4.22.4, libadwaita-1 1.9.1, graphene-gobject-1.0 1.10.8, glib-2.0 2.88.0; rustc 1.98.1.
- **cargo fetched gtk4-rs and libadwaita-rs**: `gtk4 0.11.5` (MIT, rust-version 1.92), `libadwaita 0.9.2` (MIT),
  `glib/gio 0.22.10`. A scratch crate with `adw::ApplicationWindow` built in 44 s and ran to a clean exit under
  `xvfb-run -a` (one harmless Adwaita warning about `gtk-application-prefer-dark-theme` from the host settings).
- Added to the workspace (throwaway worktree): `Cargo.lock` gained 44 packages, removed or changed none; `cargo deny
  check` failed only on `target-lexicon` (licence), and passed (`advisories ok, bans ok, licenses ok, sources ok`)
  with the D2 exception. New duplicate-version warnings (`syn` 2/3, `system-deps` 7/9) are warnings, as today's
  `miniz_oxide`.
- No `MainContext::channel` in glib 0.22.10; `futures_channel::mpsc::UnboundedReceiver::recv` exists in 0.3.34.

## 3. Screens

All inside one `adw::ApplicationWindow` with an `AdwNavigationSplitView` (sidebar: apps; content: app page) and a
header bar with Install, Jobs (toggles a bottom panel) and a menu with Refresh and About.

- **Apps list** (sidebar): an `AdwActionRow` per app (name, id and version as subtitle), a `GtkSearchEntry` filtering
  by name or id (case-insensitive, in the view model), an empty state "No apps installed" with an Install button;
  `skipped > 0` shows "N app entries could not be read".
- **App page**: title, status line (running job or not); Run / Stop; doctor summary (`doctor.app`: verdict and each
  check's area, status, text); graphics (`graphics.info` verdict and reason) and sandbox (`sandbox.info`: bwrap,
  seccomp, landlock, hardening complete, refused reason); permissions (view + D9 edit); dependencies (Plan button
  -> the plan list; Install dependencies -> the consent dialog); Remove (an `AdwAlertDialog` naming the app id, the
  destructive response is not the default).
- **Consent dialog** (`AdwAlertDialog` with extra child): per entry package, version, action; for each `needed`
  entry the sha256 (monospace, selectable) and the full `consentText` in a scrolled plain label, and an unchecked
  `GtkCheckButton` "I accept the terms above for <package> <version>"; `denied`/`blocked` entries with their reason;
  `unsatisfied` and `warnings`. Responses: Cancel (default) and "Install" (label with the count accepted, e.g.
  "Install (1 of 2 accepted)"). An empty plan shows "Nothing to install".
- **Install dialog**: D10.
- **Jobs panel**: D11.
- **About / daemon status**: `adw::AboutDialog` with GUI version, and the daemon's `api`, `runtime`, mode, socket path.

## 4. Components

- `Cargo.toml` (workspace): `default-members` (D1). `deny.toml`: the D2 exception. `.github/workflows/ci.yml`: the
  `--exclude` and the `gui` job.
- `crates/gui/Cargo.toml`: `runtime-daemon`, `runtime-api`, `runtime-core` (path), `gtk4`, `libadwaita`,
  `futures-channel` (exact pins); dev: `tempfile`, `libc`, `serde_json` (workspace).
- `crates/gui/src/vm/mod.rs` (no GTK import; enforced by the D4 scan): `Model`, `Msg`, `Cmd`, `update`, the
  consent, permissions and install-form logic, `shown()`.
- `crates/gui/src/backend.rs` (no GTK import): `Backend` (request thread, followers, reconnect), emits `Msg` through
  a `Fn(Msg) + Send + Sync` sink.
- `crates/gui/src/ui/*.rs`: widgets built from the `Model`; `ui/text.rs` the markup-safe helpers.
- `crates/gui/src/main.rs`: `adw::Application`, the bridge, `--socket PATH` (same meaning as the CLI's).
- `crates/gui/tests/e2e.rs` (real `runtimed`), `crates/gui/tests/widgets.rs` (`harness = false`, display).
- `crates/daemon/tests/support/mod.rs`: the rig from `e2e_jobs.rs` (Scratch, `install_exe`, fake `runtime` and fake
  Wine scripts), parameterised by the `runtimed` path, shared by the daemon's e2e and the GUI's through `#[path]`.
- `docs/GUI-CHECKLIST.md`, README, `docs/SECURITY.md` (GUI section), `docs/THIRD_PARTY.md`, roadmap row.

## 5. Behaviour

### 5.1 View model

`Model::update(&mut self, Msg) -> Vec<Cmd>` is the only place state changes. `Msg` is either a user intent
(`Search`, `Open(id)`, `Run`, `Stop`, `Remove` after confirm, `Plan`, `Accept(package, bool)`, `InstallDeps`,
`Install(InstallForm)`, `Permission(PermChange)`, `ResetPermissions`, `Cancel(jobId)`, `Retry`, `Refresh`) or a
backend result (`Connected(VersionInfo)`, `ConnectFailed(ConnError)`, `Apps`, `AppLoaded`, `Plan(DepsPlanView)`,
`JobStarted`, `JobEvents`, `JobList`, `Failed { what, error }`). `Cmd` is what the backend executes (one per client
helper, plus `Follow(jobId)`). Widget code reads the model through getters that return display-ready values
(already cleaned) and `enabled()` flags; it decides nothing.

Error display: `ClientError::api_error()` kinds map to fixed sentences (`read_only`, `busy` "4 jobs are already
running; try again when one ends", `app_busy`, `consent_mismatch` 5.3, `not_found`, `invalid_argument` + the cleaned
daemon message); other errors print the cleaned `Display` of the error. Everything bounded (1,024 chars).

### 5.2 Backend and threads

`Backend::spawn(socket, sink)` starts the request thread: connect (`Client::connect`), `rpc.version`, then serve
`Cmd`s from a `std::sync::mpsc` queue in order. A `ClientError` other than `Rpc` drops the client and reports
`ConnectFailed`; the next command (or Retry) reconnects. `Follow(jobId)` starts a follower thread (queued if 4 are
running) that loops `job_poll(id, next_seq, 10000)` until the job state is final, sending each `JobEvents` as a
`Msg`; on a connection error it reconnects with backoff (0.5 s doubling to 8 s) and resumes from `nextSeq`;
`not_found` (daemon restarted) ends the follower with a message. Dropping the `Backend` sets a stop flag; followers
exit after their current poll (at most 10 s + the client's deadline; the process exit does not wait for them).
Nothing blocks the GTK main loop: the UI only calls `Backend::send`, which never blocks.

### 5.3 Consent

1. `Plan` => `deps.plan`; the model keeps the `DepsPlanView` as received (its `digest` string untouched) and builds
   one `ConsentChoice { package, version, sha256, text, accepted: false }` per entry with `action == install`,
   `consent == needed`. An entry missing `version`, `sha256` or `consentText` gets `acceptable: false` and a reason;
   it can never be accepted.
2. `Accept(package, true|false)` flips only that entry; there is no message that changes several.
3. `InstallDeps` sends `DepsInstall { id, digest: plan.digest.clone(), consent: accepted items as
   ConsentItem { package, version, sha256 } copied from the entry }`. The model drops the plan after sending, so a
   second install needs a fresh plan. An empty digest (API 0.1) disables Install with the client's own reason.
4. `consent_mismatch` => a notice "The dependency plan changed since it was shown. Review it again." and a fresh
   `Plan`; nothing is re-sent automatically.
5. What is displayed is the cleaned text; what is sent is the daemon's raw `package`/`version`/`sha256` (the daemon
   compares them byte for byte; cleaning cannot change a manifest id or a hex digest, and if it would, the model
   marks the entry unacceptable instead of sending text the user did not see).

### 5.4 Strings on screen

- `vm::shown(s, max)` = `rt_core::clean_text(s, max)`: control and format (bidi, zero-width) characters removed,
  bounded. Every daemon string passes it before reaching a widget, event texts included.
- No daemon string is ever interpreted as markup. `ui/text.rs` builds labels with `use_markup(false)` and rows with
  `set_use_markup(false)` (`AdwPreferencesRow`'s `use-markup` defaults to true); widgets whose text is always markup
  (`AdwStatusPage` description, `AdwToast` title, `AdwAlertDialog` body with `body-use-markup`) get
  `glib::markup_escape_text` of the cleaned string, or keep `*-use-markup` false. A widget test shows an app named
  `<b>x</b> &amp; <span size="99999">` literally.

### 5.5 Security properties

Same-uid trust model unchanged (SECURITY.md 6A/6B): the GUI is a client with the user's own rights; it holds no
secret and stores nothing (no settings file in 6C). It opens no network connection (only the Unix socket, plus
whatever GTK itself uses: the session bus for accessibility, portals and application uniqueness). File chooser
results are passed as absolute paths; the daemon validates them (6B 5.1) and the CLI opens them. The GUI never builds
an argv, never passes an environment, and cannot request `--unsandboxed` (the API has no such parameter).

## 6. Testing

- **View model** (unit, no display): search filter; connection states from each `ClientError` shape; read-only
  (`write: false` and API `0.1.0`) makes every write intent a no-op with the reason and `enabled()` false; Run/Stop
  availability from `jobs.list`; consent: nothing accepted by default, each `Accept` touches one entry, `InstallDeps`
  sends the digest byte-identical and exactly the accepted `{package, version, sha256}`, unacceptable entries never
  sent, plan dropped after sending, `consent_mismatch` triggers a new plan and no resend; permissions EXPR
  composition and refusals (`:` in a path, relative, control chars); install form validation; log buffer cap and
  dropped notes; `shown()` on ESC, U+202E, U+200B, NUL, 1 MiB strings; hostile `DepsPlanView`/`AppList` JSON.
- **Backend e2e** (`crates/gui/tests/e2e.rs`, no display): the real `runtimed` found next to the test binary
  (`target/<profile>/runtimed`; fails loudly with "run `cargo build -p runtime-daemon -p runtime-cli`"), in a
  scratch `XDG_RUNTIME_DIR`/HOME/data dir from the shared rig. (a) No daemon => `ConnectFailed(Unreachable)`. (b)
  Read-only daemon => `Connected { write: false }`, and the model sends no write `Cmd`. (c) `--write` + fake
  `runtime`: Remove sends `remove -- <id>`, a `sleep` job is followed and cancelled (`cancelled`), events arrive in
  order through the sink, the follower reconnects after the daemon is restarted and ends on `not_found`. (d) `--write`
  + real `runtime` + fake Wine: install `hello64.exe` from the install form, the app appears after the job ends,
  permissions `network=allow` round trip, `deps.plan` + `InstallDeps` of the (empty) plan succeeds, a tampered digest
  => `consent_mismatch` => a new `Plan` command, Remove. Consent with a needed package end to end is not possible
  without a fixture importing `vcruntime140.dll` (none exists): covered by unit tests with canned plans.
- **Widget smoke** (`tests/widgets.rs`, `harness = false`, one GTK thread, D13): the main window against (i) no
  daemon: the status page and its command text; (ii) a read-only daemon with one installed app: one sidebar row,
  Install/Run/Remove insensitive, the banner visible; (iii) a write daemon: those sensitive; (iv) the consent dialog
  built from a canned plan with two needed entries: both checkboxes unchecked, the full text present, the Install
  label "Install (0 of 2 accepted)"; (v) the hostile-name row shows the literal text. Widget lookup by `widget_name`
  set in the UI code (stable test handles).
- **Manual** (`docs/GUI-CHECKLIST.md`, the user runs it on GNOME and KDE): launch, empty state, start the socket,
  install a real program with its installer UI, run/stop, a consent with vcrun2022 on a real app, permissions edit
  and refusal, remove, read-only daemon, dark mode, window resize to phone width (split view collapses), keyboard
  navigation spot check.

## 7. Risks

- **A heavy native dependency tree** (gtk-rs `-sys` crates, 44 packages) in the workspace's lock file. Contained by
  D1: it is never built by the core gates, and `cargo deny` checks it.
- **gtk-rs API churn**: exact pins; an upgrade is a deliberate task.
- **Consent presentation** was 6B's stated residual risk; 5.3 and its tests are the answer. Remaining: the licence
  text is shown, not proven read (no scroll-to-end gate; deliberate, noted in the checklist).
- **Portal paths**: in a sandboxed session a file chooser may return a document-portal path under
  `/run/user/<uid>/doc/`; it is absolute and passed as is; whether the CLI can read it there is a manual checklist
  item, not handled specially.
- **Hung daemon**: every call has the client's deadline (40 s, also for a 10 s poll: `poll_timeout`): a hung daemon shows as a failed command,
  never a frozen window (the main loop never calls the client).
