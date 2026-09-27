//! `runtime remove <id>`: stops the app's Wine processes, best-effort removes its `.desktop` entry/icons, then
//! deletes its whole environment.
//!
//! Only an app id is accepted (`AppId::parse`): never a path, so `..`, `/abs`, `a/b` and the empty string are
//! refused before anything is looked at. `Store::remove` then refuses a symlink or non-directory at the app path.
use crate::CmdError;
use crate::safe::{safe, shorten, warn};
use rt_core::{AppId, Launcher, StoreError};

pub fn run(arg: &str) -> Result<(), CmdError> {
    let id = AppId::parse(arg).map_err(|e| {
        format!(
            "{:?} is not a valid app id ({e}); `remove` takes an id from `runtime list`, never a path",
            shorten(arg, 80)
        )
    })?;
    let store = crate::store()?;
    let env = match store.get(&id) {
        Err(StoreError::NotFound) => return Err(format!("no app named {id} is installed (see `runtime list`)").into()),
        other => other?,
    };
    // Exclusive for the whole removal: refused while a dependency install (or a start) holds the lock, so no
    // package can be recorded into an app that is being deleted (or into a new app of the same id).
    let _deps_lock = crate::deps::lock_or_refuse(&env, false, "remove")?;
    // Wine is only needed to stop what is still running: without it the app is removed anyway.
    match crate::backend_of(&store, &env, &Launcher::new()) {
        Ok(backend) => {
            if let Err(e) = backend.stop(&env) {
                warn(&format!(
                    "could not stop the app's Wine processes ({e}); removing it anyway, a Wine process may still be running"
                ));
            }
        }
        Err(e) => warn(&format!(
            "{e}; removing without stopping any running Wine process of this app"
        )),
    }
    // A sandboxed app's wineserver survives `wineserver -k` (see `refuse_if_running`): never delete under it.
    crate::refuse_if_running(&env)?;
    // Best-effort: an app installed via the Task 6 installer pipeline may have a `.desktop` entry/icons
    // (`installer::pipeline` -> `rt_desktop::entry::write`); `remove` must clean those up too, exactly like
    // `uninstall` does (`crate::remove_desktop_entry`), or they orphan a `runtime run <id>` that no longer works.
    crate::remove_desktop_entry(&id);
    store.remove(&id)?;
    crate::emit(&format!("Removed {}\n", safe(id.as_str())))
}
