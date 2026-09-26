//! The app sandbox as it stands on this host, without running anything: whether bubblewrap works, the in-kernel
//! hardening, whether `systemd-run --user` scopes (the resource limits) work, the app's profile, and what
//! `runtime run` would start ([`status`]); plus the three one-phrase inputs of `doctor`'s Runtime checks.
//!
//! Only throwaway probes are started (bwrap's own probe, the `systemd-run` scope probe); Wine is used only to describe
//! the command when it is found (never started). The texts are raw: callers escape or clean them.
use rt_core::{AppEnv, CompatBackend, Launcher, RunOpts, Store};
use rt_sandbox::{AppSandbox, Hardening, Host, Network, Permissions, RealHost, ScopeSupport, load, load_opt_raw};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

/// bwrap on `PATH` that can really create a sandbox, or why not.
pub fn working_bwrap() -> Result<PathBuf, String> {
    let bwrap = rt_sandbox::find_bwrap_on_path().ok_or("bwrap is not on PATH")?;
    rt_sandbox::probe(&bwrap)?;
    Ok(bwrap)
}

/// The app's profile (the default without a `permissions.toml`) and where it came from (`default` or
/// `permissions.toml`), or why it is refused.
pub fn profile(env: &AppEnv) -> Result<(Permissions, &'static str), String> {
    let refused = |e: rt_sandbox::PermError| {
        format!(
            "the app's permissions.toml is refused: {e} (`runtime permissions {} --reset` deletes it)",
            env.id()
        )
    };
    // The grants are only checked against the host (which needs `HOME`) when there is a file.
    if load_opt_raw(env.root()).map_err(refused)?.is_none() {
        return Ok((Permissions::default(), "default"));
    }
    let ctx = rt_sandbox::GrantCtx::from_env()?;
    Ok((load(env.root(), &ctx).map_err(refused)?, "permissions.toml"))
}

/// `network deny, display on, audio on, gpu on, 0 host directories`.
pub fn summary(p: &Permissions) -> String {
    let on = |b: bool| if b { "on" } else { "off" };
    let n = p.filesystem.len();
    format!(
        "network {}, display {}, audio {}, gpu {}, {n} host director{}",
        if p.network == Network::Allow { "allow" } else { "deny" },
        on(p.display),
        on(p.audio),
        on(p.gpu),
        if n == 1 { "y" } else { "ies" }
    )
}

/// `doctor`'s hardening input: seccomp and Landlock in one phrase, `Err` when either is not fully there.
pub fn doctor_hardening() -> Result<String, String> {
    let h = rt_sandbox::hardening();
    let text = match &h.caveat {
        // First, so the 300-byte cut never drops it.
        Some(c) => format!("{c}; {}; {}", h.seccomp, h.landlock),
        None => format!("{}; {}", h.seccomp, h.landlock),
    };
    if h.complete && h.caveat.is_none() {
        Ok(text)
    } else {
        Err(text)
    }
}

/// `doctor`'s limits input: `systemd-run --user` scopes work, or why not and what that means (with `env`: for that
/// app, whose explicit limits then refuse every run).
pub fn doctor_limits(env: Option<&AppEnv>) -> Result<String, String> {
    // An unreadable profile is the sandbox check's warning; here it counts as the default.
    let limits = env
        .and_then(|e| profile(e).ok())
        .map(|(p, _)| p.limits)
        .unwrap_or_default();
    let refused = |e: &AppEnv| format!("runs of {} will be refused", e.id());
    let not_applied = "the default task limit (fork-bomb guard) is not applied";
    match RealHost.scopes() {
        Ok(s) => match limits
            .controllers()
            .into_iter()
            .find(|c| !s.controllers.iter().any(|h| h == c))
        {
            None => Ok(format!(
                "limits: systemd-run --user available (cgroup controllers: {})",
                s.controllers.join(" ")
            )),
            Some(c) => Err(match env {
                Some(e) if limits.explicit() => format!(
                    "limits: systemd-run --user available, but {}: the {c} cgroup controller is not available to \
                     your user session",
                    refused(e)
                ),
                _ => format!("limits: the {c} cgroup controller is not available to your user session; {not_applied}"),
            }),
        },
        Err(why) => Err(match env {
            Some(e) if limits.explicit() => format!(
                "limits: unavailable: {why}; {} (its permissions.toml sets limits)",
                refused(e)
            ),
            _ => format!("limits: unavailable: {why}; {not_applied}"),
        }),
    }
}

/// `doctor`'s sandbox input: bwrap works (with `env`: and the app's profile in a few words), or why not.
pub fn doctor_state(env: Option<&AppEnv>) -> Result<Option<String>, String> {
    working_bwrap().map_err(|why| format!("unavailable: {why}"))?;
    env.map(|env| profile(env).map(|(p, _)| summary(&p)))
        .transpose()
        .map_err(|why| format!("cannot read the profile: {why}"))
}

/// What `runtime sandbox <app>` shows (see [`status`]). Raw texts.
pub struct Status {
    /// The bwrap that works, or why none does (`runtime run` then refuses).
    pub bwrap: Result<PathBuf, String>,
    pub hardening: Hardening,
    /// The runtime executable bound into the sandbox as its `sandbox-init` shim; `None`: unresolvable (`run` refuses).
    pub shim: Option<PathBuf>,
    pub profile: Permissions,
    /// `default` or `permissions.toml`.
    pub source: &'static str,
    /// Whether `systemd-run --user` scopes work here (the resource limits).
    pub scopes: Result<ScopeSupport, String>,
    /// `Err`: Wine was not found (the discovery error, with its install hint); the command then shows `wine` and no
    /// Wine directories.
    pub wine: Result<(), String>,
    /// Why the sandbox renderer refuses this command, if it does.
    pub refused: Option<String>,
    /// What the host lacks for this profile (left out of the sandbox).
    pub skipped: Vec<String>,
    /// What the profile cannot enforce.
    pub caveats: Vec<String>,
    /// The full command line `run` would start (systemd-run and bubblewrap included).
    pub argv: Vec<OsString>,
}

/// The sandbox of the installed app `env` (module docs). `Err` (as text) when its profile is refused, its program
/// cannot be resolved, or Wine cannot describe the command.
pub fn status(store: &Store, env: &AppEnv) -> Result<Status, String> {
    let bwrap = working_bwrap();
    let hardening = rt_sandbox::hardening();
    let shim = RealHost.runtime_exe();
    let (profile, source) = profile(env)?;
    let scopes = RealHost.scopes();
    let launcher = Launcher::new();
    let p = rt_core::resolve_program(store, env.id(), backend_wine::BACKEND_ID).map_err(|e| e.to_string())?;
    // The command `run` builds (backend command with the app's real `dotnet`, settled, host environment rules);
    // without Wine, its shape.
    let (wine, cmd, dll_dirs) = match backend_wine::WineBackend::discover_with(launcher.clone()) {
        Ok(b) => {
            let cmd = b
                .command(
                    &p.env,
                    &p.exe,
                    &p.cwd,
                    &[],
                    &RunOpts {
                        dotnet: p.metadata.has_dependency(rt_core::DOTNET_PACKAGE_ID),
                        ..RunOpts::default()
                    },
                )
                .map_err(|e| e.to_string())?;
            (Ok(()), b.settle(cmd), b.dll_dirs())
        }
        Err(e) => {
            let mut c = Command::new("wine");
            c.arg(&p.exe)
                .current_dir(&p.cwd)
                .env("WINEPREFIX", env.prefix())
                .env("HOME", backend_wine::app_home(env));
            (Err(e.to_string()), c, vec![])
        }
    };
    let cmd = launcher.finalize(cmd);
    let path = match &bwrap {
        Ok(b) => b.clone(),
        Err(_) => rt_sandbox::find_bwrap_on_path().unwrap_or_else(|| PathBuf::from("bwrap")),
    };
    let sb = AppSandbox::new(path, profile.clone(), dll_dirs, Arc::new(RealHost));
    Ok(Status {
        refused: sb.render(&cmd).err().map(|e| e.to_string()),
        skipped: sb.skipped(&cmd),
        caveats: sb.caveats(&cmd),
        argv: sb.argv_preview(&cmd),
        bwrap,
        hardening,
        shim,
        profile,
        source,
        scopes,
        wine,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rt_sandbox::Access;

    #[test]
    fn summary_names_every_switch_and_counts_grants() {
        let mut p = Permissions::default();
        assert_eq!(
            summary(&p),
            "network deny, display on, audio on, gpu on, 0 host directories"
        );
        p.network = Network::Allow;
        p.gpu = false;
        p.filesystem.push(rt_sandbox::FsGrant {
            path: "/srv/x".into(),
            access: Access::Ro,
        });
        assert_eq!(
            summary(&p),
            "network allow, display on, audio on, gpu off, 1 host directory"
        );
    }
}
