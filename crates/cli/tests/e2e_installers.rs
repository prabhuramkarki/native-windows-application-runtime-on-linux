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
//! **The NSIS test uses `--exe`, not auto-discovery — a real, reported gap, not a workaround of
//! convenience.** `hello-nsis.exe`'s own installer script (`tools/fixtures/hello.nsi`) writes BOTH
//! `hello64.exe` (the app) and, via `WriteUninstaller`, a standalone `uninstall.exe` into the same
//! directory, and registers `uninstall.exe` in the `Uninstall` registry key. A real Wine-created Start
//! Menu shortcut (confirmed here, and already documented for a different fixture at
//! `crates/installer/src/lnk/tests.rs`'s `real_wine_shortcut_parses_working_dir_and_icon_location`)
//! carries its target ONLY in `LinkTargetIDList`, which `rt_installer::lnk` deliberately never parses
//! (out of scope, see its module doc) — never in the `RelativePath` string field `discover::rank`'s
//! tier (1) actually reads. So tier (1) never fires for a real Wine shortcut, tier (2) ("named in a new
//! Uninstall registry entry") uniquely matches `uninstall.exe` instead, and `rank` confidently (not
//! ambiguously — no `NeedsChoice` is ever raised) picks the WRONG file as the app's own executable.
//! Verified empirically while writing this test: an auto-discovered `hello-nsis` install records
//! `uninstall.exe` as `Metadata.executable`, so `runtime run <id>` would silently run the uninstaller
//! instead of the app. See `docs/SECURITY.md`'s installer-sandbox section and this task's report for
//! the full story; this is filed as a real finding for the next whole-branch review, not fixed here
//! (fixing it means teaching `rt_installer::lnk` to parse `LinkTargetIDList`, a real parser addition to
//! a hostile-input crate, squarely Task 3/6's scope, not Task 8's). `--exe` sidesteps discovery
//! entirely and also exercises the plan's own separate "`--exe` manual override tested" exit criterion.
mod support;

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use support::{Rig, fixture, installed_id};

const HELLO: &str = "hello from windows";

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

    // `runtime uninstall <id>` removes the environment AND the desktop entry/icon.
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

#[test]
#[ignore = "needs Wine, bwrap and nsis-built fixtures; run with --ignored --test-threads=1"]
fn e2e_nsis_silent_install_desktop_entry_run_and_uninstall() {
    let rig = Rig::new();
    let xdg = rig.xdg_data_home();
    let xdg_env = [("XDG_DATA_HOME", xdg.to_str().unwrap())];

    // `--exe` names the real app deterministically (see the module docs on why: real auto-discovery
    // currently mis-picks `uninstall.exe` for this fixture).
    let nsis = fixture("hello-nsis.exe");
    let ran = rig.rt_env(
        &[
            "install",
            nsis.to_str().unwrap(),
            "--silent",
            "--exe",
            r"Program Files\RuntimeFixtureNsis\hello64.exe",
        ],
        &xdg_env,
    );
    ran.expect_ok();
    let id = installed_id(&ran);

    let exe = rig.drive_c(&id).join("Program Files/RuntimeFixtureNsis/hello64.exe");
    assert!(exe.is_file(), "hello64.exe missing under drive_c: {}", exe.display());

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
