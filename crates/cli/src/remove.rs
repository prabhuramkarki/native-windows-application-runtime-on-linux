//! `runtime remove <id>`: stops the app's Wine processes, then deletes its whole environment.
//!
//! Only an app id is accepted (`AppId::parse`): never a path, so `..`, `/abs`, `a/b` and the empty string are
//! refused before anything is looked at. `Store::remove` then refuses a symlink or non-directory at the app path.
use crate::CmdError;
use crate::safe::{safe, shorten, warn};
use rt_core::{AppId, CompatBackend, Launcher, StoreError};

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
    // Wine is only needed to stop what is still running: without it the app is removed anyway.
    match crate::backend(&Launcher::new()) {
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
    store.remove(&id)?;
    crate::emit(&format!("Removed {}\n", safe(id.as_str())))
}
