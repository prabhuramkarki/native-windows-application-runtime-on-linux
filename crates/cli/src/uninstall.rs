//! `runtime uninstall <id>`: runs the app's recorded uninstaller (if any), sandboxed, then ALWAYS removes the
//! app's environment regardless of what that did — mirrors `remove.rs`'s own "stop, warn not fail, remove
//! unconditionally" shape, with one extra step (running `installer.uninstallCommand`) after the stop. The stop comes
//! first so that an app that is still running (a sandboxed app's wineserver survives `wineserver -k`) is refused
//! before its uninstaller runs; the uninstaller's own Wine processes end with its sandbox.
//!
//! **Known limit** (documented, matches the roadmap): an app with no recorded uninstall command — installed as
//! a portable exe, installed before schema v2, or an installer that registered no `Uninstall` entry at all —
//! has nothing to run here and falls back to plain environment removal, same as `runtime remove`.
use crate::CmdError;
use crate::safe::{safe, shorten, warn};
use rt_core::{AppId, CompatBackend, Launcher, StoreError};
use rt_installer::SandboxOpts;

pub fn run(arg: &str) -> Result<(), CmdError> {
    let id = AppId::parse(arg).map_err(|e| {
        format!(
            "{:?} is not a valid app id ({e}); `uninstall` takes an id from `runtime list`, never a path",
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
    let _deps_lock = crate::deps::lock_or_refuse(&env, false, "uninstall")?;
    let launcher = Launcher::new();
    // Wine is only needed to run the recorded uninstaller and to stop what is still running: without it the app
    // is removed anyway, same fallback `remove.rs` already uses.
    let backend = crate::backend(&launcher);
    // Stop, then refuse while anything still runs (a sandboxed app's wineserver survives `wineserver -k`, see
    // `refuse_if_running`): before the uninstaller, so a refusal has run nothing.
    if let Ok(b) = &backend
        && let Err(e) = b.stop(&env)
    {
        warn(&format!(
            "could not stop the app's Wine processes ({e}); removing it anyway, a Wine process may still be running"
        ));
    }
    crate::refuse_if_running(&env)?;
    match backend {
        Ok(backend) => {
            if let Ok(md) = store.read_metadata(&env) {
                let opts = SandboxOpts {
                    extra_ro_binds: backend.dll_dirs(),
                    ..SandboxOpts::default()
                };
                let outcome = rt_installer::uninstall(&backend, &launcher, &env, &md, opts, &crate::runtime_exe());
                match outcome.uninstaller_succeeded {
                    None => {} // a documented limit: no uninstall command was recorded for this app
                    Some(true) => {}
                    Some(false) => {
                        warn("the recorded uninstaller did not complete successfully; removing the environment anyway")
                    }
                }
                for w in &outcome.warnings {
                    warn(w);
                }
            } else {
                warn(
                    "could not read this app's metadata; skipping its recorded uninstaller and removing the environment directly",
                );
            }
        }
        Err(e) => warn(&format!(
            "{e}; removing without running any recorded uninstaller or stopping a running Wine process"
        )),
    }
    // Best-effort, same stance as the desktop entry's own creation (`installer::pipeline`): a `.desktop`/icon
    // removal failure is desktop-shell cosmetics, never a reason to leave the app's environment in place. Shared
    // with `remove::run` (`crate::remove_desktop_entry`) so both removal commands stay in sync.
    crate::remove_desktop_entry(&id);
    store.remove(&id)?;
    crate::emit(&format!("Uninstalled {}\n", safe(id.as_str())))
}
