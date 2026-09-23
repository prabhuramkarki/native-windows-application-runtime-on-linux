//! End-to-end tests of the REAL `runtime` binary against REAL Wine, a REAL `bwrap` sandbox
//! (`rt_installer::sandbox::InstallerSandbox`, Task 5) and the REAL installer fixtures built by
//! `wixl`/`makensis` (`tools/build-fixtures.sh`): the Task 6/7 installer pipeline (`.msi`/`.exe`
//! silent install, `.desktop`/icon generation, `runtime uninstall`), Phase 3 Task 8.
//!
//! **`#[ignore]`d**: they need Wine, `bwrap` on `$PATH`, and `hello.msi`/`hello-nsis.exe`
//! (`tools/build-fixtures.sh`, which itself needs `msitools`/`wixl`/`nsis`). Run them with
//!
//! ```text
//! cargo test -p runtime-cli --test e2e_installers -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! `Rig` (the "no stray wineserver" drop-guard) is shared with `e2e_wine.rs` via `tests/support/mod.rs`
//! (Task 8) — reused exactly, not reimplemented. Its [`support::Rig::xdg_data_home`] scratch directory
//! (mirrors `apps.rs`'s `plant_desktop_entry` convention) is what every install/uninstall call in this
//! file passes as `XDG_DATA_HOME`, so `.desktop`/icon writes never touch the real user's directories.
//!
//! **Registry-derived outcomes are asserted, not just files.** Both install tests check that
//! `metadata.json`'s `installer.productName`/`installer.uninstallCommand` were recorded, and the MSI test
//! checks that `runtime uninstall` really ran the recorded uninstaller. Until the Phase 3 final review's C1
//! fix, `bwrap --unshare-pid` killed `wineserver` the instant the installer exited, before it flushed the
//! registry to disk: the registry diff was always empty, no `uninstallCommand` was ever recorded, and
//! `runtime uninstall` silently degraded to `runtime remove` — while every file-only assertion here still
//! passed. `CompatBackend::settle` (`wineserver -w` inside the same sandboxed process tree) fixed it.
//!
//! **The NSIS test uses auto-discovery (no `--exe`).** `hello-nsis.exe` installs both `hello64.exe` and
//! its own `uninstall.exe` side by side. Discovery used to mis-pick `uninstall.exe`, for two reasons now
//! both fixed: `rt_installer::lnk` did not read a real Wine shortcut's `LinkTargetIDList` (Task 9 fixed
//! that, so tier (1) now finds `hello64.exe` via the Start Menu shortcut), and — with the C1 empty
//! registry diff — tier (2) never fired, so the pick fell through to tier (3)'s GUI-subsystem heuristic
//! (`uninstall.exe` is a GUI PE, `hello64.exe` a console one). `--exe` is still covered by
//! `rt_installer`'s own `exe_override_skips_discovery_and_installs_the_named_file`.
mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use support::{Rig, fixture, installed_id};

const HELLO: &str = "hello from windows";

/// The `installer` object of `<id>`'s `metadata.json`.
fn installer_metadata(rig: &Rig, id: &str) -> serde_json::Value {
    let path = rig.apps().join(id).join("metadata.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let md: serde_json::Value = serde_json::from_str(&text).unwrap();
    md["installer"].clone()
}

/// `~/.local/share/applications/runtime-<id>.desktop` and its 48x48 hicolor icon, under the given
/// scratch `XDG_DATA_HOME` (`rt_desktop::entry`'s own deterministic, id-only naming, Task 7).
fn desktop_paths(xdg: &Path, id: &str) -> (PathBuf, PathBuf) {
    (
        xdg.join("applications").join(format!("runtime-{id}.desktop")),
        xdg.join("icons/hicolor/48x48/apps").join(format!("runtime-{id}.png")),
    )
}

/// Runs the real `desktop-file-validate` subprocess on `path` (never trusts `rt_desktop`'s own internal
/// validation alone): the plan's own text asks for the `.desktop` file to be checked "and validates".
fn assert_desktop_file_validates(path: &Path) {
    let status = Command::new("desktop-file-validate")
        .arg(path)
        .status()
        .expect("desktop-file-validate must be installed for this test (apt install desktop-file-utils)");
    assert!(status.success(), "desktop-file-validate rejected {}", path.display());
}

#[test]
#[ignore = "needs Wine, bwrap and msitools-built fixtures; run with --ignored --test-threads=1"]
fn e2e_msi_silent_install_desktop_entry_run_and_uninstall() {
    let rig = Rig::new();
    let xdg = rig.xdg_data_home();
    let xdg_env = [("XDG_DATA_HOME", xdg.to_str().unwrap())];

    let msi = fixture("hello.msi");
    let ran = rig.rt_env(&["install", msi.to_str().unwrap(), "--silent"], &xdg_env);
    ran.expect_ok();
    let id = installed_id(&ran);

    // hello64.exe is really on disk under the app's own drive_c. `hello.wxs` builds a 32-bit MSI by
    // wixl's default (no `Platform='x64'`), so under a 64-bit Wine prefix `ProgramFilesFolder` resolves
    // to `Program Files (x86)` even though the payload itself is a real 64-bit PE (Task 0's own review
    // already noted this; verified again here against a real install).
    let exe = rig.drive_c(&id).join("Program Files (x86)/RuntimeFixture/hello64.exe");
    assert!(exe.is_file(), "hello64.exe missing under drive_c: {}", exe.display());

    // Registry-derived (C1): msiexec's Uninstall key (Wow6432Node, REG_EXPAND_SZ) reached disk and was read.
    let inst = installer_metadata(&rig, &id);
    assert_eq!(inst["productName"], "Runtime Fixture MSI", "{inst}");
    let uninstall = inst["uninstallCommand"]
        .as_str()
        .unwrap_or_else(|| panic!("no uninstallCommand: {inst}"));
    assert!(uninstall.to_lowercase().starts_with("msiexec.exe "), "{uninstall}");

    let (desktop_path, icon_path) = desktop_paths(&xdg, &id);
    assert!(
        desktop_path.is_file(),
        "no .desktop entry at {}",
        desktop_path.display()
    );
    assert!(icon_path.is_file(), "no hicolor icon at {}", icon_path.display());
    assert_desktop_file_validates(&desktop_path);

    // `runtime run <id>` still works exactly like a Phase 2 portable-exe install: same fixture, same
    // stdout, same exit code.
    let ran = rig.rt(&["run", &id]);
    assert!(ran.out().contains(HELLO), "hello64 stdout: {}", ran.report());
    assert_eq!(ran.code, Some(7), "hello64 exit code: {}", ran.report());

    // `runtime uninstall <id>` runs the recorded uninstaller (no warning that it failed or could not
    // be resolved), then removes the environment AND the desktop entry/icon.
    let ran = rig.rt_env(&["uninstall", &id], &xdg_env);
    ran.expect_ok();
    assert!(
        !ran.err().contains("warning:"),
        "the recorded uninstaller did not run cleanly: {}",
        ran.report()
    );
    assert!(!rig.apps().join(&id).exists(), "app dir still exists after uninstall");
    assert!(
        !desktop_path.exists(),
        "the .desktop entry must be removed by uninstall"
    );
    assert!(!icon_path.exists(), "the icon must be removed by uninstall");

    rig.finish();
}

#[test]
#[ignore = "needs Wine, bwrap and nsis-built fixtures; run with --ignored --test-threads=1"]
fn e2e_nsis_silent_install_desktop_entry_run_and_uninstall() {
    let rig = Rig::new();
    let xdg = rig.xdg_data_home();
    let xdg_env = [("XDG_DATA_HOME", xdg.to_str().unwrap())];

    // No `--exe`: auto-discovery must pick hello64.exe, not uninstall.exe (see the module docs).
    let nsis = fixture("hello-nsis.exe");
    let ran = rig.rt_env(&["install", nsis.to_str().unwrap(), "--silent"], &xdg_env);
    ran.expect_ok();
    let id = installed_id(&ran);

    let exe = rig.drive_c(&id).join("Program Files/RuntimeFixtureNsis/hello64.exe");
    assert!(exe.is_file(), "hello64.exe missing under drive_c: {}", exe.display());
    assert!(
        ran.out()
            .contains(r"Executable: C:\Program Files\RuntimeFixtureNsis\hello64.exe"),
        "auto-discovery picked the wrong executable: {}",
        ran.report()
    );

    // Registry-derived (C1): the NSIS Uninstall key (under Wow6432Node, I1) reached disk and was read.
    let inst = installer_metadata(&rig, &id);
    assert_eq!(inst["productName"], "Runtime Fixture NSIS", "{inst}");
    assert_eq!(
        inst["uninstallCommand"], r"C:\Program Files\RuntimeFixtureNsis\uninstall.exe",
        "{inst}"
    );

    let (desktop_path, icon_path) = desktop_paths(&xdg, &id);
    assert!(
        desktop_path.is_file(),
        "no .desktop entry at {}",
        desktop_path.display()
    );
    assert!(icon_path.is_file(), "no hicolor icon at {}", icon_path.display());
    assert_desktop_file_validates(&desktop_path);

    let ran = rig.rt(&["run", &id]);
    assert!(ran.out().contains(HELLO), "hello64 stdout: {}", ran.report());
    assert_eq!(ran.code, Some(7), "hello64 exit code: {}", ran.report());

    // Not asserted here (a known, reported gap): this fixture's `UninstallString` is an UNQUOTED path
    // with spaces and has no `/S`, so `rt_installer::uninstall` cannot resolve it (it splits on spaces;
    // real Windows' CreateProcess would probe `C:\Program`, then `C:\Program Files\...`) and even a
    // resolved NSIS uninstaller would need a display for its confirmation dialog. `runtime uninstall`
    // warns and falls back to removing the environment, which is what the lines below check.
    let ran = rig.rt_env(&["uninstall", &id], &xdg_env);
    ran.expect_ok();
    assert!(!rig.apps().join(&id).exists(), "app dir still exists after uninstall");
    assert!(
        !desktop_path.exists(),
        "the .desktop entry must be removed by uninstall"
    );
    assert!(!icon_path.exists(), "the icon must be removed by uninstall");

    rig.finish();
}

/// Ruling 4 (task brief): a non-`--silent` install must never silently force `--silent` behaviour. What
/// actually happens is genuinely uncertain until run for real (Task 6's own review already found the
/// sandbox binds no display socket at all, see `docs/SECURITY.md`): this test accepts EITHER "the
/// installer process exits quickly with a display-related failure" OR "the installer hangs and this
/// test's own bounded deadline kills it" as passing, and asserts only the two things the plan actually
/// requires: the pipeline never blocks the test suite indefinitely (the bound below guarantees this
/// regardless of which branch happens), and nothing is ever silently reported as a successful install.
///
/// **NSIS, not MSI, is the fixture here — verified empirically, not assumed.** `hello.wxs` (the MSI
/// fixture) defines no `<UI>` table at all, so `msiexec` has no dialog sequence to show in the first
/// place and completes `hello.msi` successfully with or without `--silent` (confirmed while writing this
/// test: a non-`--silent` `hello.msi` install inside this exact sandbox installs cleanly in ~15s, exit
/// 0) — a real, interesting finding in its own right (see `docs/SECURITY.md`), but it cannot exercise
/// "no display access" at all, since nothing ever needed a display. `hello-nsis.exe` without `/S` DOES
/// try to show its real wizard UI, and confirmed genuinely fails fast (no candidate files written,
/// exit 1, ~12s) for exactly the no-display-socket reason documented in `docs/SECURITY.md`.
#[test]
#[ignore = "needs Wine, bwrap and nsis-built fixtures; run with --ignored --test-threads=1"]
fn e2e_install_without_silent_never_silently_forces_silent_mode() {
    let rig = Rig::new();
    let xdg = rig.xdg_data_home();
    let xdg_env = [("XDG_DATA_HOME", xdg.to_str().unwrap())];
    let nsis = fixture("hello-nsis.exe");

    // No `--silent`: the pipeline runs the installer's own GUI. Bounded at 90 s (well under this
    // project's other e2e deadlines) so a genuine hang cannot stall the suite.
    let (ran, timed_out) = rig.exec(&["install", nsis.to_str().unwrap()], &xdg_env, Duration::from_secs(90));
    if timed_out {
        eprintln!(
            "RECORDED: the non-silent install did not finish within 90s and was killed by this test's own \
             deadline (bounded, never hung the suite)"
        );
    } else {
        eprintln!(
            "RECORDED: the non-silent install exited with {:?} after {:?}",
            ran.code, ran.elapsed
        );
        assert_ne!(
            ran.code,
            Some(0),
            "a non-silent install must never silently succeed as if --silent had been passed: {}",
            ran.report()
        );
    }
    assert!(
        !ran.out().contains("Installed:"),
        "nothing may be reported as installed for a non-silent run that could not complete: {}",
        ran.report()
    );

    // Whatever the outcome, clean up before the strict `finish()` check below: a killed pipeline gets no
    // chance to clean up after itself the way a clean exit does (the ambiguous-discovery path removes
    // its own half-built environment; a hard kill cannot).
    for id in rig.installed_ids() {
        let _ = rig.rt_env(&["uninstall", &id], &xdg_env);
    }
    rig.finish();
}
