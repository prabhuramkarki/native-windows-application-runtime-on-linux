//! `runtime install <file> [--name N] [--exe PATH]`.
use crate::safe::{safe, warn};
use crate::{CmdError, SANDBOX_NOTE};
use rt_core::{InstallOpts, InstallOutcome, Store};
use std::path::Path;

pub fn run(file: &Path, name: Option<String>, exe: Option<String>) -> Result<(), CmdError> {
    let store = crate::store()?;
    let backend = crate::backend(&rt_core::Launcher::new())?;
    eprintln!("{SANDBOX_NOTE}");
    eprintln!("note: creating the Wine environment can take up to a minute");
    let outcome = rt_core::install(&store, &backend, file, &InstallOpts { name, exe })?;
    let name = display_name(&store, &outcome)?;
    crate::emit(&format!(
        "Installed: {id}\nName:       {name}\nExecutable: {exe}\nRun it with: runtime run {id}\n",
        id = safe(outcome.id.as_str()),
        name = safe(&name),
        exe = safe(&outcome.executable.to_string()),
    ))?;
    for w in &outcome.warnings {
        warn(w);
    }
    Ok(())
}

/// The name recorded in the app's metadata (the outcome only carries the id and the executable).
fn display_name(store: &Store, outcome: &InstallOutcome) -> Result<String, CmdError> {
    let env = store.get(&outcome.id)?;
    Ok(store.read_metadata(&env)?.name)
}

/// What `run` prints when it had to install a file first (on stderr: stdout belongs to the program).
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
