# runtime-gui manual checklist

The automated tests cover the view model, the backend against a real `runtimed`, and widget smoke tests under Xvfb
(README, "Tests"). They cannot cover a real desktop session, a real installer's own windows, a real licence, the
file chooser portal, dark mode, window resizing or the keyboard. Run this list by hand on **GNOME** and on **KDE**
before a release, and after any change to `crates/gui`.

Record each run:

| Date | Desktop (and version) | Session (Wayland / X11) | GTK | libadwaita | runtime-gui commit | Tester |
|---|---|---|---|---|---|---|
| | | | | | | |

Get the GTK and libadwaita versions with `pkg-config --modversion gtk4 libadwaita-1`. Build with
`cargo build --release -p runtime-daemon -p runtime-cli -p runtime-gui`. Put `runtime` and `runtimed` where the
systemd units expect them (docs/API.md, "Running it under systemd"). Use a user account whose apps you can lose, or
set `RUNTIME_DATA_DIR` to a scratch directory in the unit and in your shell.

For each step, write **pass**, **fail** or **n/a** in each desktop's column, with a note for anything that is not a
plain pass. A failure in steps 5-8 (consent) or 11 (read-only) is a release blocker.

| # | Step | Expected result | GNOME | KDE |
|---|---|---|---|---|
| 1 | Stop the daemon (`systemctl --user stop runtimed.socket runtimed.service`), then start `runtime-gui`. | The page "runtimed is not running" appears. It shows `systemctl --user start runtimed.socket` as selectable text, the socket path, and Retry. Nothing starts a daemon (`systemctl --user status runtimed.service` stays inactive). | | |
| 2 | Run `systemctl --user start runtimed.socket` in a terminal, then press Retry. | The main window appears: the apps list, or "No apps installed" with an Install button. No read-only banner (the unit passes `--write`). | | |
| 3 | Install a real installer (for example an NSIS or Inno Setup `.exe`) with Install…: choose the file and leave silent and network off. Open the Jobs panel. | The file chooser offers ".exe, .msi, .zip" and "All files". The installer's own window appears and can be completed. The job's output appears in the Jobs panel, in order. When the job ends, the app appears in the list without pressing Refresh. | | |
| 4 | Install a portable `.exe` with a name typed in the Name field. | It appears under that name. A name with a control character, or longer than 256 bytes, is refused with a message, and nothing is sent. | | |
| 5 | Open an app and press Run. Then press Stop. | Run starts a job (the status line reads "Running (job …)"). Stop cancels it (the job ends "cancelled"). An app started from a terminal instead is not a job: there is no Stop, and a Run from the GUI fails with the CLI's lock refusal in that job's log (the daemon's own "still running" notice only covers its own jobs). | | |
| 6 | Open an app whose plan needs `vcrun2022` (a real app that imports `vcruntime140.dll`). Press Plan, then Install dependencies…. | The dialog lists `vcrun2022` with its version, its sha256 in full, the full terms text (scrollable), and an **unchecked** box "I accept the terms above for vcrun2022 …". There is no "accept all". The Install button reads "Install (0 of 1 accepted)". Cancel is the default (Enter and Escape cancel). | | |
| 7 | Tick the box and press Install. | The button reads "Install (1 of 1 accepted)" before you press it. A job runs, and its log shows the package being installed. `runtime deps <app>` in a terminal afterwards shows it as installed. | | |
| 8 | On another app that needs it, open the dialog and press Install **without** ticking the box (or Cancel). Then open it again, tick, press Cancel, open it once more and press Install without ticking. | Nothing consent-gated is installed: the job installs only packages that need no consent, or nothing is sent at all (Cancel). A box ticked in a cancelled dialog is unticked on reopening and the button says "0 of 1". `runtime deps <app>` still lists `vcrun2022` as needed. | | |
| 9 | Permissions: switch Network access on, then grant a folder under your home read-only with "Grant a folder (read-only)…". | Each change runs a job. After it ends, the page shows the new state (a switch shows the real state, so it may flip back until the job ends). The grant is listed with a remove button, which removes it. | | |
| 10 | Grant `~/.ssh` (or your home directory itself). | Refused. The job fails, and the CLI's reason (for example "home directory") is in its log. A path with `:` is refused before anything is sent. | | |
| 11 | Remove an app: press Remove…, check the dialog, then press Remove. | The dialog names the app and its id, and Cancel is the default. After Remove, the app disappears from the list and its page closes. | | |
| 12 | Restart the daemon **without** `--write`: `systemctl --user stop runtimed.socket runtimed.service; runtimed &`. Then press Refresh (menu). | A banner reads "This runtimed is read-only (started without `--write`)…". Install…, Run, Remove…, Install dependencies…, the permission switches, grant, remove and Reset are all insensitive, and hovering one shows the same reason. Plan still works. | | |
| 13 | Switch the desktop to dark mode, and back. | The window follows the style without a restart. Everything stays readable. | | |
| 14 | Resize the window to phone width (about 360 px). | The split view collapses to one pane. Choosing an app shows its page, and the header's back button returns to the list. | | |
| 15 | Keyboard only: Tab, Shift+Tab, arrows, Enter, Space, Escape. | Every control is reachable (search, list, Run/Stop/Remove, switches, dialogs, their checkboxes and responses), and Escape closes dialogs. Note every gap as an accessibility follow-up (Orca and a full keyboard pass are a separate task). | | |
| 16 | In a sandboxed or portal-using session, choose a file through the file chooser (the path may be under `/run/user/<uid>/doc/`). | The install either works, or its job log says why the CLI cannot read that path. This is recorded, not handled specially. | | |
| 17 | Name an app `<b>x</b> &amp; <span size="99999">` (Install… with that name). | The list, the page heading, the header and the remove dialog all show those characters literally, never bold or huge. | | |

Known, deliberate bounds (docs/SECURITY.md, "The GUI client (Phase 6C)"):
- The terms are shown in full, but nothing proves they were read: there is no scroll-to-end gate.
- A program started from a terminal is not a job, so Stop cannot end it.
- GTK itself uses the session bus (accessibility, portals, single instance).
