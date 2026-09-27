# Phase 6C GUI client (`runtime-gui`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A GTK4 + libadwaita desktop client that lists, runs, stops, installs, removes and configures apps, and installs their dependencies with explicit per-package consent, talking only to `runtimed` through `rt_daemon::client::Client`.

**Architecture:** A toolkit-free view model (`vm`: `Model::update(Msg) -> Vec<Cmd>`) holds every decision; a `Backend` (request thread + job followers, no GTK) executes `Cmd`s against the daemon and reports `Msg`s through a sink; the GTK layer forwards the sink into the main loop (`futures_channel` + `glib::spawn_future_local`) and renders the model. The crate is a workspace member outside `default-members`, gated by its own CI job.

**Tech Stack:** Rust; `gtk4 =0.11.5` (`v4_12`), `libadwaita =0.9.2` (`v1_5`), `futures-channel =0.3.34` (already in the lock through `gio`); `rt_daemon::client`, `rt_api` wire types, `rt_core::clean_text`. System: GTK >= 4.12, libadwaita >= 1.5 (probe host: 4.22.4 / 1.9.1). Tests: `xvfb-run` for widget smoke tests.

**Spec:** `docs/superpowers/specs/2026-09-27-gui-client-design.md`

## Global Constraints

- The GUI talks only to `runtimed` via `rt_daemon::client::Client`: no `rt_api::Runtime`, no `std::process::Command`, no `runtime-cli` (the D4 source scan test, Task 2, stays green).
- `vm` and `backend` import no GTK (`gtk4`, `libadwaita`, `glib`, `gio`); the same scan enforces it.
- Every daemon string passes `vm::shown()` before a widget; no daemon string is parsed as markup (`use_markup(false)` or `glib::markup_escape_text`).
- Consent: the digest is sent exactly as `deps.plan` returned it; consent items are copied from shown, individually accepted entries only; nothing pre-checked; no "accept all".
- The GTK main loop never calls the client or blocks; the GUI never starts a process or a service.
- Core gates unchanged and GTK-free: `cargo fmt --all -- --check`, `cargo clippy --workspace --exclude runtime-gui --all-targets -- -D warnings`, `cargo test --workspace --exclude runtime-gui`, `cargo deny check`. GUI gates: `cargo clippy -p runtime-gui --all-targets -- -D warnings`, `cargo build -p runtime-daemon -p runtime-cli && RUNTIME_REQUIRE_DISPLAY=1 xvfb-run -a cargo test -p runtime-gui`. All green after every task.
- Every new third-party crate is exact-pinned, has a THIRD_PARTY.md row and passes `cargo deny check`.
- Tests never touch the user's `$XDG_RUNTIME_DIR`, data dir or a running `runtimed`; every daemon-backed test has a deadline.
- Commit trailer: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- Consent: any path to `deps.install` whose digest or items did not come verbatim from a shown plan and one-by-one acceptance; a default-checked box; an entry accepted without its text shown (Tasks 2, 5).
- Markup and text: a daemon string reaching a widget uncleaned, or through a markup-parsing property (`AdwActionRow` title/subtitle default to markup) (Tasks 2, 4, 5).
- Threads: the main loop blocking on the client; a follower that never exits, reconnects in a tight loop, or exceeds 4; a `Msg` delivered off the GTK thread to a widget (Tasks 3, 4).
- Read-only and unreachable: a write control sensitive on a read-only daemon; any code that starts `runtimed`/`systemctl` (Tasks 2, 4).
- Isolation: a core gate that now needs GTK; the lock file changing an existing package's version; `deny.toml` loosened beyond the one crate (Task 1).

---

### Task 1: dependency spike, crate skeleton, isolation, THIRD_PARTY and deny

**Files:**
- Create: `crates/gui/Cargo.toml`, `crates/gui/src/main.rs` (an empty `adw::ApplicationWindow`, `--socket PATH` parsed but unused), `crates/gui/tests/widgets.rs` (`harness = false`: the display gate of spec D13 and one test that the window opens and closes)
- Modify: `Cargo.toml` (`default-members` = the ten core crates, listed), `Cargo.lock`, `deny.toml`, `.github/workflows/ci.yml`, `docs/THIRD_PARTY.md`

**Interfaces:**
- Produces: package `runtime-gui` (`rust-version = "1.92"`, bin `runtime-gui`), deps `runtime-daemon`, `runtime-api`, `runtime-core` (path), `gtk4 = { version = "=0.11.5", features = ["v4_12"] }`, `libadwaita = { version = "=0.9.2", features = ["v1_5"] }`, `futures-channel = "=0.3.34"`; dev: `tempfile`, `libc`, `serde_json` (workspace). `[[test]] name = "widgets", harness = false`. `deny.toml`: `[[licenses.exceptions]] crate = "target-lexicon", allow = ["Apache-2.0 WITH LLVM-exception"]` with a comment (build-only, via `system-deps`/`cfg-expr`). CI: the `test` job's clippy/test get `--exclude runtime-gui`; new job `gui` (ubuntu-latest: `libgtk-4-dev libadwaita-1-dev xvfb` + the `test` job's packages for fixtures, `tools/build-fixtures.sh`, clippy `-p runtime-gui`, `cargo build -p runtime-daemon -p runtime-cli`, `RUNTIME_REQUIRE_DISPLAY=1 xvfb-run -a cargo test -p runtime-gui`, upload `target/gui-smoke/` as an artifact when present).
- Consumes: nothing new.

- [ ] **Step 1: Spike (report before building on it).** Re-run the spec's probe inside the repo: `pkg-config --modversion gtk4 libadwaita-1`; add the crate; `git diff Cargo.lock` must only ADD packages (record the count; stop and report if any existing package changes version); `cargo deny check` fails only on `target-lexicon` before the exception and passes after it; `cargo tree -i target-lexicon -e normal` is empty (build-only). If crates.io cannot be reached, stop: commit nothing but a note in this plan's "As built" and report (the rest of the plan depends on the pins).
- [ ] **Step 2: Failing test:** `widgets.rs` opens the window, iterates the main context until it is mapped, closes it; skips with a loud line when neither `DISPLAY` nor `WAYLAND_DISPLAY` is set, fails instead when `RUNTIME_REQUIRE_DISPLAY=1`.
- [ ] **Step 3: Implement** the skeleton and the isolation. Check on this host: `cargo build` (default members) does not compile any `gtk4*` crate; `env PKG_CONFIG_PATH=/nonexistent PKG_CONFIG_LIBDIR=/nonexistent cargo clippy --workspace --exclude runtime-gui --all-targets -- -D warnings` passes (simulates a host without GTK).
- [ ] **Step 4: THIRD_PARTY.md:** rows for `gtk4 0.11`, `libadwaita 0.9`, `futures-channel 0.3` (licence, use, features, why exact pins, the transitive gtk-rs family by name and licence, `target-lexicon` build-only with its exception); external-components row "GTK 4, libadwaita, GLib, Pango, Cairo, Graphene, gdk-pixbuf | LGPL-2.1-or-later (Cairo: LGPL-2.1 OR MPL-1.1) | 6 | system libraries, dynamically linked by `runtime-gui` only".
- [ ] **Step 5:** both gate sets green; commit `feat(gui): runtime-gui skeleton on gtk4 0.11 / libadwaita 0.9, outside default-members, its own CI job`.

---

### Task 2: the view model (`vm`)

**Files:**
- Create: `crates/gui/src/vm/mod.rs` (+ `vm/consent.rs`, `vm/perms.rs` if `mod.rs` passes ~600 lines), `crates/gui/src/lib.rs` (`pub mod vm; pub mod backend;` so tests reach them; `main.rs` uses the lib)
- Test: unit tests in `vm`; `crates/gui/tests/scan.rs` (D4 source scan)

**Interfaces:**
- Produces:
  ```rust
  pub fn shown(s: &str, max: usize) -> String;                 // rt_core::clean_text
  pub enum Conn { Connecting, Unreachable { socket: String }, Refused(String), Ready { write: bool, api: String, runtime: String } }
  pub const START_HINT: &str = "systemctl --user start runtimed.socket";
  pub enum Msg { /* user intents and backend results, spec 5.1 */ }
  pub enum Cmd { Connect, ListApps, LoadApp(String), Plan(String), Run(String), Cancel(String), Remove(String),
                 Install(InstallParams), DepsInstall { id: String, digest: String, consent: Vec<ConsentItem> },
                 PermSet { id: String, set: Vec<String> }, PermReset(String), ListJobs, Follow(String) }
  pub struct Model { /* conn, apps, filter, page: Option<AppPage>, plan: Option<ConsentState>, jobs, notice */ }
  impl Model {
      pub fn new() -> Model;
      pub fn update(&mut self, msg: Msg) -> Vec<Cmd>;
      pub fn visible_apps(&self) -> Vec<AppRow>;                 // cleaned, filtered
      pub fn can(&self, action: Action) -> Result<(), &'static str>;   // Err = the reason shown as tooltip
      pub fn consent(&self) -> Option<&ConsentState>;           // entries, accepted count, install label
      pub fn log(&self, job: &str) -> Option<&LogBuffer>;       // <= 5,000 lines, dropped notes
  }
  pub enum PermChange { Network(bool), Display(bool), Audio(bool), Gpu(bool), Grant { path: PathBuf, rw: bool }, Revoke(String) }
  pub struct InstallForm { pub path: PathBuf, pub name: String, pub silent: bool, pub network: bool }
  ```
- Consumes: `rt_api::{VersionInfo, AppList, AppDetail, DoctorView, GraphicsView, SandboxView, PermissionsView, DepsPlanView, ErrorKind}`, `rt_api::jobs::{ConsentItem, JobEvents, JobInfo, JobState}`, `rt_daemon::client::{ClientError, InstallParams}`.

- [ ] **Step 1: Failing tests** (spec 6, view model list): every `ClientError` variant -> the right `Conn`; `write: false` and `api: "0.1.0"` => `can(Run|Install|Remove|InstallDeps|EditPermissions)` all `Err` with the read-only reason and the matching intents return no `Cmd`; search is case-insensitive over name and id; Stop only with a live `run` job for the app in the job list; consent: a plan with two needed entries (one with ESC/U+202E in its text) and one `notNeeded` => two choices, both unaccepted, label "Install (0 of 2 accepted)"; `Accept("a", true)` touches only `a`; `InstallDeps` => exactly one `Cmd::DepsInstall` whose `digest` is byte-identical to the plan's and whose items equal `a`'s raw `{package, version, sha256}`; the plan is gone afterwards (a second `InstallDeps` sends nothing); an entry without `sha256` or `consentText` is not acceptable; `Failed(consent_mismatch)` => a notice and `Cmd::Plan`, no `DepsInstall`; permissions: `Network(true)` => `["network=allow"]`, `Grant{"/a/b", rw}` => `["fs+=/a/b:rw"]`, paths with `:`, relative, `\n`, U+202E, non-UTF-8 refused with a message and no `Cmd`; install form: relative/non-UTF-8 path refused, name > 256 bytes or with a control char refused, `network` false by default; log buffer: 5,001 lines keep the newest 5,000 plus one note, `dropped: 7` adds a daemon-dropped note; `shown` removes ESC, U+202E, U+200B, NUL and bounds a 1 MiB string. `scan.rs`: no file under `crates/gui/src` contains `Runtime::`, `rt_api::Runtime`, `process::Command`, `runtime_cli`; no file under `src/vm` or `src/backend.rs` contains `gtk4`, `libadwaita`, `adw::`, `glib`, `gio`.
- [ ] **Step 2: Implement.** Pure data; no I/O, no threads, no clock.
- [ ] **Step 3:** gates; commit `feat(gui): the view model: connection and write-mode states, per-package consent, permission and install forms`.

---

### Task 3: the backend and the shared daemon rig

**Files:**
- Create: `crates/gui/src/backend.rs`, `crates/daemon/tests/support/mod.rs`, `crates/gui/tests/e2e.rs`
- Modify: `crates/daemon/tests/e2e_jobs.rs` (move `Scratch`, `install_exe`, `alive`, the fake `runtime`/Wine scripts into `support`, parameterised by the `runtimed` path; behaviour unchanged)

**Interfaces:**
- Produces:
  ```rust
  pub struct Backend { /* cmd sender, stop flag */ }
  impl Backend {
      pub fn spawn(socket: PathBuf, sink: Arc<dyn Fn(Msg) + Send + Sync>) -> Backend;   // starts with Cmd::Connect
      pub fn send(&self, cmd: Cmd);                                                       // never blocks
  }
  impl Drop for Backend { /* stop flag; threads end after their current call */ }
  pub const MAX_FOLLOWERS: usize = 4;
  pub const POLL_WAIT_MS: u32 = 10_000;
  ```
  `crates/gui/tests/e2e.rs` has `#[path = "../../daemon/tests/support/mod.rs"] mod support;` and finds `runtimed` as `current_exe()/../../runtimed` (fails loudly: "run `cargo build -p runtime-daemon -p runtime-cli`").
- Consumes: Task 2's `Msg`/`Cmd`/`Model`; `Client` helpers from 6B.

- [ ] **Step 1: Failing tests** (spec 6, backend e2e (a)-(d)), driving `Model` + `Backend` together: the sink pushes into an `mpsc::Sender`, the test loop feeds each `Msg` to `update` and each returned `Cmd` to `send`, with a 20 s deadline per scenario. Plus unit tests with a stub socket-less path: `send` after the request thread died does not panic; a 5th `Follow` waits until one of 4 ends; reconnect backoff never below 0.5 s (injected sleep recorder).
- [ ] **Step 2: Implement** (spec 5.2). `ClientError::Rpc` keeps the client; anything else drops it and reports `ConnectFailed`. Followers stop on a final state, `not_found`, or the stop flag.
- [ ] **Step 3:** `cargo test -p runtime-daemon` unchanged after the rig move; gates; commit `feat(gui): the backend: one request thread, long-poll followers, reconnect; e2e against the real runtimed`.

---

### Task 4: the GTK shell: window, bridge, apps list, empty states, About

**Files:**
- Create: `crates/gui/src/ui/{mod.rs,text.rs,window.rs,apps.rs,about.rs}`
- Modify: `crates/gui/src/main.rs`, `crates/gui/tests/widgets.rs`

**Interfaces:**
- Produces: `ui::text::{label(&str) -> gtk::Label, row(title, subtitle) -> adw::ActionRow, escaped(&str) -> String}` (labels `use_markup(false)`, rows `set_use_markup(false)`, `escaped` = `glib::markup_escape_text(&vm::shown(..))` for always-markup properties); `ui::window::build(app, backend, model: Rc<RefCell<Model>>) -> adw::ApplicationWindow`; `ui::render(&Model)` updates widgets from the model. The bridge in `main.rs`: `futures_channel::mpsc::unbounded::<Msg>()`, the sink `move |m| { let _ = tx.unbounded_send(m); }`, `glib::spawn_future_local` loop `update` -> `backend.send` each `Cmd` -> `render`. Widget names (`set_widget_name`) as test handles: `apps-list`, `status-unreachable`, `status-refused`, `banner-read-only`, `btn-install`, `btn-run`, `btn-stop`, `btn-remove`, `btn-deps`, `jobs-panel`.
- Consumes: Tasks 2-3.

- [ ] **Step 1: Failing widget tests** (`widgets.rs`, one GTK thread, the daemon rig from Task 3): (i) no daemon => `status-unreachable` visible and its text contains `START_HINT`; (ii) read-only daemon with one app (installed through the real `runtime` + fake Wine rig before `runtimed` starts) => `apps-list` has 1 row, `btn-install` insensitive, `banner-read-only` revealed; (iii) write daemon => `btn-install` sensitive; (v) an app named `<b>x</b> &amp; <span size="99999">` (via `--name`) => the row title reads exactly that string. Screenshot per scenario when `RUNTIME_GUI_SHOTS` is set.
- [ ] **Step 2: Implement.** Sidebar with search, Refresh, About (daemon `api`, `runtime`, mode, socket), status pages (spec D6), read-only banner (D7).
- [ ] **Step 3:** gates; run `runtime-gui` once by hand against the user's daemon if present (note the result in the commit body); commit `feat(gui): main window, apps list with search, daemon status and empty states`.

---

### Task 5: app page, dialogs, jobs panel

**Files:**
- Create: `crates/gui/src/ui/{app.rs,consent.rs,install.rs,permissions.rs,jobs.rs}`
- Modify: `crates/gui/src/ui/{window.rs,mod.rs}`, `crates/gui/tests/widgets.rs`

**Interfaces:**
- Produces: the app page (Run/Stop, status, doctor, graphics, sandbox, permissions view + D9 edit, deps plan, Remove with an `AdwAlertDialog` whose default response is Cancel); `ui::consent::dialog(&ConsentState, on_accept: Fn(package, bool), on_install: Fn()) -> adw::AlertDialog` (widget names `consent-check-<package>`, `consent-text-<package>`, response id `install`); the install dialog (`gtk::FileDialog` open with the filters of spec D10, name entry, silent and network switches, both off); the jobs panel (`jobs.list` + followed jobs, Cancel on live ones, a plain `GtkTextView` log per job, spec D11).
- Consumes: Tasks 2-4.

- [ ] **Step 1: Failing widget tests:** (iv) the consent dialog from a canned `DepsPlanView` (two needed entries, one `denied` with a reason): both checks unchecked, each `consent-text-*` holds every line of its text (cleaned), the `install` response label is "Install (0 of 2 accepted)" and becomes "(1 of 2 accepted)" after one `set_active(true)`; activating `install` produces exactly one `Cmd::DepsInstall` (captured through a recording backend sink) with that one item; read-only => Run, Remove, Install dependencies, the permission switches insensitive; a followed fake job's lines appear in its log view in order, an ESC in a line does not.
- [ ] **Step 2: Implement.** The file dialogs are async (`gio::Cancellable`, `glib::spawn_future_local`); their results go through `vm` validation as `Msg`s, never straight to the backend.
- [ ] **Step 3:** gates; commit `feat(gui): app page, consent, install and remove dialogs, permissions edit, jobs and logs`.

---

### Task 6: docs and the manual checklist

**Files:**
- Create: `docs/GUI-CHECKLIST.md`
- Modify: `README.md` (a "GUI (`runtime-gui`)" section: build needs GTK 4.12+/libadwaita 1.5+ dev packages, `cargo build -p runtime-gui`, needs `runtimed --write` for changes; Layout: `crates/gui`; Tests: the GUI gates), `docs/SECURITY.md` (section "The GUI client (Phase 6C)": trust model unchanged, what the GUI never does, consent presentation, text cleaning and markup, known bounds: no scroll-to-read proof, terminal-started apps invisible to Stop, GTK's own session-bus use), `docs/superpowers/plans/2026-09-21-runtime-master-roadmap.md` (Phase 6 row: 6C), this plan's "As built"
- Test: none new (docs); the gates stay green

- [ ] **Step 1:** `GUI-CHECKLIST.md`: numbered steps with expected results, for the user to run on GNOME and on KDE (spec 6 manual list), each with a result column (pass/fail/notes, date, desktop, GTK/libadwaita versions): first launch with no daemon; `systemctl --user start runtimed.socket` then Retry; install a real installer (visible installer UI) and a portable exe; run and stop; a real app whose plan needs `vcrun2022`: read the text, accept, install, check the job log shows the licence text; decline instead and check nothing is installed; a permissions grant of a folder and a refused grant (`~/.ssh`); remove; restart the daemon without `--write` and check every write control is disabled with the reason; dark mode; narrow window; keyboard-only pass (Tab/Enter/Escape reach every control; note gaps as accessibility follow-ups); a file chosen through the portal (if the desktop uses one).
- [ ] **Step 2:** README, SECURITY.md, roadmap row, "As built".
- [ ] **Step 3:** gates; commit `docs: runtime-gui in README and SECURITY.md, the manual GUI checklist, roadmap`.

---

## Dependency order

Task 1 first (the pins everything else builds on; stop there if crates cannot be fetched). Task 2 needs 1. Task 3 needs 2. Task 4 needs 3. Task 5 needs 4. Task 6 last. Tasks 2 and the rig move of Task 3 (support module only) may run in parallel.

## Self-Review

- Spec criteria: 1 -> Tasks 2 (scan), 3; 2 -> Tasks 2, 3; 3 -> Tasks 2, 5; 4 -> Tasks 2, 4, 5; 5 -> Tasks 2, 4; 6 -> Task 1.
- Pre-approved decisions: toolkit and crate (1), isolation and third-party policy (1), view model, consent, job runner, cleaning, read-only and empty states (2-5), screens (4, 5), testing incl. the checklist (2-6), security (2, 5, 6).
- Placeholders: none. One open fork decided by Task 1's spike: whether crates.io is reachable in the implementing environment (it was when this plan was written).
- Types: `Model`, `Msg`, `Cmd`, `Conn`, `PermChange`, `InstallForm`, `ConsentState`, `LogBuffer`, `Backend`, `shown`, `START_HINT` are named identically across tasks.

## As built

Commits on `phase-6c-gui`: Task 1 `bcbbf03`, Task 2 `f285342`, Task 3 `2e5e325`, Task 4 `ce93b1c`, Task 5 `7331bbc`,
Task 6 (docs). Where the code departs from the plan above:

- **Task 1.** The lock file gained 43 packages (plus `runtime-gui`) and changed none. `futures-channel` was not in
  the lock before: it arrives with gio in the same change, so it adds no package of its own. With `default-members`
  set, `cargo tree` needs `--workspace`. The widget test binary points HOME and every XDG directory at a tempdir,
  sets `GSETTINGS_BACKEND=memory` and `GTK_A11Y=none`, and drops `DBUS_SESSION_BUS_ADDRESS` before GTK starts:
  the first run read the host's GTK settings.
- **Task 2.**
  - Message names: the plan result is `Msg::PlanLoaded { id, plan }` (the intent is `Msg::Plan`);
    `Msg::ConnectFailed(ConnError { socket, error })`; `Msg::Failed { what: Cmd, error }`.
  - Added: `Msg::Dismiss`; `AppLoaded(Box<AppData>)`, whose probes fail one by one.
  - Connection states: Io, Protocol, Rpc and other errors on connect map to `Unreachable`, with the reason as the
    notice.
  - A live job of any kind for the open app disables its other writes (`app_busy`).
  - `not_found` while loading the open app closes its page.
  - `jobs.list` is a write method, so it is asked only on a write daemon.
- **Task 3.** The client-refused-unsent errors (`Unsupported`, `TooLarge`) keep the connection, like `Rpc`. A
  follower stops on a final state with an empty poll: the daemon pages at 500 events, so a final state alone does not
  mean every event has been read. An immediate empty poll on a live job waits 0.5 s. The rig gained
  `Scratch::start(write, ..)` and `Scratch::plant` (over `rt_core::Store`).
- **Task 4.**
  - Scenarios (ii) and (v) plant the app with `Scratch::plant` instead of installing it through the real `runtime`.
  - `ui::Ui::new(send, socket)` takes a command sink (the backend, or a recorder in tests); `ui::start(socket)` wires
    a real backend.
  - Each split pane has its own header bar, so a collapsed window gets a back button, and the page title (the app's
    name) is drawn by the header: tested literally.
  - The binary was run by hand under Xvfb against a scratch runtime dir, not against the user's own daemon.
- **Task 5.**
  - The view model gained display-ready page lines, permission rows (the raw grant path kept for revoke), a cap of
    16 followed logs, and `LogBuffer::version` for incremental redraws.
  - The consent dialog acts only while the model's plan has the digest it was built from.
  - The install dialog's Install response is disabled until a file is chosen.
  - Widget tests (canned model, recorded commands): the consent dialog, read-only page controls, the remove
    confirmation, the install dialog defaults. With the real daemon: a followed job's output.
- **Task 6.** README (GUI section; the core `--workspace` commands now `--exclude runtime-gui`, since `--workspace`
  ignores `default-members`), SECURITY.md "The GUI client (Phase 6C)", `docs/GUI-CHECKLIST.md`, the roadmap row and
  Open Decision 3.
- **Not done:** the manual checklist on GNOME and KDE (the user runs it); the `gui` CI job's first hosted run.
