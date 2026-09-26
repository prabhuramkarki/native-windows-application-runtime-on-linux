//! `runtime permissions <app> [--set EXPR]... [--reset] [--json]`: shows or changes the app's `permissions.toml`
//! (what its sandbox may reach: network, display/audio/gpu, host directories; its resource limits; see
//! `rt_sandbox::permissions`).
//!
//! Reading takes no lock and writes nothing. Changing follows the `display` sequence: every expression is
//! validated against the current profile BEFORE the app lock is taken, the exclusive lock then keeps other
//! runtime commands out, a running app (a wineserver for the prefix; fails closed when `/proc` cannot be read) is
//! refused, and the profile is read and every expression applied again under the lock before one atomic write.
use crate::CmdError;
use crate::safe::{json_safe, safe, safe_lines};
use rt_core::AppEnv;
use rt_sandbox::{Access, GrantCtx, Network, Permissions, Tasks, load_opt, load_opt_raw, reset, store};

pub(crate) fn ctx() -> Result<GrantCtx, CmdError> {
    Ok(GrantCtx::from_env()?)
}

/// A profile that cannot be read is fixed by deleting it.
fn reset_hint(env: &AppEnv, e: rt_sandbox::PermError) -> CmdError {
    format!("{e}; `runtime permissions {} --reset` deletes the profile", env.id()).into()
}

/// The profile with every `--set` applied in order; nothing is written. The stored profile is read WITHOUT
/// checking its grants against the host, so `fs-=` can remove a grant whose directory is gone; what remains (and
/// every added grant) is validated before it is returned.
fn apply(env: &AppEnv, sets: &[String], ctx: &GrantCtx) -> Result<Permissions, CmdError> {
    let mut p = load_opt_raw(env.root())
        .map_err(|e| reset_hint(env, e))?
        .unwrap_or_default();
    for s in sets {
        p.apply_set(s, ctx)?;
    }
    p.validated(ctx).map_err(|e| reset_hint(env, e))
}

fn show(p: &Permissions, source: &str, json: bool) -> Result<(), CmdError> {
    if !json {
        return crate::emit(&format!("{}source: {source}\n", safe_lines(&p.to_toml())));
    }
    let fs: Vec<_> = p
        .filesystem
        .iter()
        .map(|g| {
            serde_json::json!({
                "path": g.path.to_string_lossy(),
                "access": if g.access == Access::Rw { "rw" } else { "ro" },
            })
        })
        .collect();
    let l = &p.limits;
    let tasks = match l.tasks {
        Tasks::Unlimited => serde_json::json!("unlimited"),
        _ => serde_json::json!(l.tasks_max()),
    };
    let doc = serde_json::json!({
        "network": if p.network == Network::Allow { "allow" } else { "deny" },
        "display": p.display, "audio": p.audio, "gpu": p.gpu, "filesystem": fs,
        "limits": {
            "memory_mb": l.memory_mb, "cpu_percent": l.cpu_percent, "tasks": tasks,
            "tasks_default": l.tasks == Tasks::Default,
        },
    });
    crate::emit(&format!("{}\n", json_safe(&serde_json::to_string_pretty(&doc)?)))
}

pub fn run(app: &str, sets: &[String], reset_it: bool, json: bool) -> Result<(), CmdError> {
    let store_ = crate::store()?;
    let env = crate::deps::app_env(&store_, app)?;
    let ctx = ctx()?;
    if sets.is_empty() && !reset_it {
        let p = load_opt(env.root(), &ctx).map_err(|e| reset_hint(&env, e))?;
        let source = if p.is_some() { "permissions.toml" } else { "default" };
        return show(&p.unwrap_or_default(), source, json);
    }
    if reset_it && !sets.is_empty() {
        return Err("--reset and --set cannot be combined".into());
    }
    let refuse = |why: &str| format!("{why}; nothing was changed");
    if !reset_it {
        apply(&env, sets, &ctx).map_err(|e| refuse(&e.to_string()))?;
    }
    let _lock = crate::deps::lock_or_refuse(&env, false, "change the permissions of")?;
    match rt_deps::wineservers_for(&env.prefix()) {
        Ok(pids) if pids.is_empty() => {}
        Ok(pids) => {
            return Err(refuse(&format!(
                "{} appears to be running (wineserver pid {}): stop it first",
                env.id(),
                pids[0]
            ))
            .into());
        }
        Err(e) => {
            return Err(refuse(&format!("cannot check whether {} is running: {e}", env.id())).into());
        }
    }
    if reset_it {
        reset(env.root()).map_err(|e| refuse(&e.to_string()))?;
        return crate::emit(&format!(
            "permissions of {} reset to the default\n",
            safe(env.id().as_str())
        ));
    }
    // Under the lock: the file may have changed since the first check.
    let p = apply(&env, sets, &ctx).map_err(|e| refuse(&e.to_string()))?;
    store(env.root(), &p).map_err(|e| refuse(&e.to_string()))?;
    show(&p, "permissions.toml", json)
}
