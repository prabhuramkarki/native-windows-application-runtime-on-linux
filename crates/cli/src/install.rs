//! `runtime install <file> [--name N] [--exe PATH] [--silent] [--network]`.
//!
//! **Dispatch.** `rt_core::install` (Phase 2) rejects `.msi` files and any `.exe` carrying a recognised
//! installer marker (Inno Setup, NSIS, InstallShield, WiX Burn) outright: those need the sandboxed installer
//! pipeline (Task 6), not a plain copy into `drive_c`. So before calling either pipeline, this module peeks at
//! the file's real CONTENT (never its extension, matching every other detection in this project) and routes:
//! installer-shaped input goes to [`rt_installer::install_via_installer`]; everything else (a portable exe, a
//! zip archive) keeps going through the unchanged `rt_core::install`, which still refuses MSI/installer input
//! as a backstop should this peek and its own detection ever disagree. The peek itself goes through
//! `rt_core::read_input` (the same `metadata`-then-`O_NONBLOCK`-open, fstat-cap-before-bulk-read discipline
//! `rt_installer::pipeline`'s own reader uses) rather than a hand-rolled `fs::read`, so a file swapped for a
//! FIFO between the two separate syscalls a naive peek would need cannot block this process forever.
//!
//! **No display in the sandbox by default.** `InstallerSandbox` (Task 5) binds no X11/Wayland socket, so an
//! installer run WITHOUT `--silent` (the default: "show its own GUI") likely cannot render a window at all; see
//! the warning `run` prints for that case, and `rt_installer::pipeline`'s own module docs for the full story.
use crate::safe::{safe, warn};
use crate::{CmdError, SANDBOX_NOTE};
use rt_core::{AppId, InstallOpts, InstallOutcome, Store};
use rt_installer::{Candidate, InstallerOpts};
use std::path::Path;

/// Returns the exit code: 0 on a successful install, 1 when the installer pipeline could not tell which
/// installed file is the app (never a fake auto-pick; retry with `--exe`).
pub fn run(
    file: &Path,
    name: Option<String>,
    exe: Option<String>,
    silent: bool,
    network: bool,
) -> Result<u8, CmdError> {
    let store = crate::store()?;
    let launcher = rt_core::Launcher::new();
    let backend = crate::backend(&launcher)?;
    eprintln!("{SANDBOX_NOTE}");
    eprintln!("note: creating the Wine environment can take up to a minute");

    if peek_looks_like_installer(file) {
        if name.is_some() {
            warn("--name is not used for .msi/.exe installers (the app's own name is used instead); ignored");
        }
        if !silent {
            warn(
                "the installer runs in an isolated sandbox with no display access; if it hangs waiting for a \
                 window, retry with --silent",
            );
        }
        let opts = InstallerOpts {
            silent,
            allow_network: network,
            exe_override: exe,
        };
        return match rt_installer::install_via_installer(&store, &backend, launcher, file, opts)? {
            rt_installer::InstallOutcome::Installed {
                id,
                executable,
                warnings,
                ..
            } => {
                print_installed(&store, &id, &executable.to_string(), &warnings)?;
                crate::deps::print_hint(&store, &id);
                Ok(0)
            }
            rt_installer::InstallOutcome::NeedsChoice(candidates) => {
                print_candidates(&candidates)?;
                Ok(1)
            }
        };
    }

    if silent || network {
        warn("--silent/--network only apply to .msi/.exe installers; ignored for a portable exe or a zip archive");
    }
    let outcome = rt_core::install(&store, &backend, file, &InstallOpts { name, exe })?;
    print_installed(&store, &outcome.id, &outcome.executable.to_string(), &outcome.warnings)?;
    crate::deps::print_hint(&store, &outcome.id);
    Ok(0)
}

/// A bounded, TOCTOU-safe peek at `file`'s real content to decide dispatch (see the module docs): reuses
/// `rt_core::read_input`, never a hand-rolled `fs::metadata` + `fs::read` pair (a file swapped for a FIFO
/// between two separate syscalls like that would block this process forever; `read_input` does its
/// `metadata`-then-`O_NONBLOCK`-open-then-cap-checked-read all in one place for exactly this reason). Any
/// problem reading it here (missing, huge, unreadable, a directory, ...) is left for whichever pipeline actually
/// runs to explain with its own proper error; this just answers "installer-shaped or not", defaulting to "not"
/// when it cannot tell. An MSI is recognised from `read_input`'s own `InstallError::Msi` (it refuses to hand
/// back MSI bytes at all, by design: Phase 2 never installs one), so no separate read is needed for that case.
fn peek_looks_like_installer(file: &Path) -> bool {
    match rt_core::read_input(file) {
        Ok(rt_core::Input::Pe(bytes)) => rt_installer::looks_like_installer(&bytes),
        Err(rt_core::InstallError::Msi) => true,
        _ => false,
    }
}

fn print_installed(store: &Store, id: &AppId, executable: &str, warnings: &[String]) -> Result<(), CmdError> {
    let name = display_name(store, id)?;
    crate::emit(&format!(
        "Installed: {id}\nName:       {name}\nExecutable: {exe}\nRun it with: runtime run {id}\n",
        id = safe(id.as_str()),
        name = safe(&name),
        exe = safe(executable),
    ))?;
    for w in warnings {
        warn(w);
    }
    Ok(())
}

/// Numbered candidates and the `--exe` hint; never a fake auto-pick.
fn print_candidates(candidates: &[Candidate]) -> Result<(), CmdError> {
    let mut out = String::from("Could not tell which installed file is the application. Candidates:\n");
    for (i, c) in candidates.iter().enumerate() {
        let name = c.name.as_deref().map(|n| format!(" ({})", safe(n))).unwrap_or_default();
        out.push_str(&format!("  {}. {}{name}\n", i + 1, safe(&c.path)));
    }
    if candidates.is_empty() {
        out.push_str("  (none: the installer did not write any new .exe file this pipeline could see)\n");
    }
    out.push_str("Nothing was installed. Retry with --exe <one of the paths above> to pick one.\n");
    crate::emit(&out)
}

/// The name recorded in the app's metadata.
fn display_name(store: &Store, id: &AppId) -> Result<String, CmdError> {
    Ok(store.read_metadata(&store.get(id)?)?.name)
}

/// What `run` prints when it had to install a file first (on stderr: stdout belongs to the program). Unrelated
/// to this module's installer-pipeline dispatch: `rt_core::start`'s own, Phase-2-only auto-install path.
pub fn report_on_stderr(outcome: &InstallOutcome) {
    eprintln!(
        "note: installed as {} ({}); start it again with `runtime run {}`",
        safe(outcome.id.as_str()),
        safe(&outcome.executable.to_string()),
        safe(outcome.id.as_str())
    );
    for w in &outcome.warnings {
        warn(w);
    }
}
