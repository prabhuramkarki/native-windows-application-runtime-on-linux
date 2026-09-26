//! Running an installed app's own uninstaller, sandboxed the same way as [`crate::pipeline`]'s install run.
//!
//! This module never touches the `Store`: it only runs the app's recorded `installer.uninstallCommand`, if any,
//! and reports whether that succeeded. Removing the app's environment stays the caller's job (the CLI's
//! `uninstall.rs`, mirroring `remove.rs`): per the task brief, the environment is ALWAYS removed afterwards,
//! regardless of what happened here, so [`uninstall`] itself never fails — a problem running the uninstaller is
//! a warning, never an error, exactly like the pipeline treats a non-zero installer exit code.
//!
//! **Known limit** (documented, matches the roadmap): an app with no recorded `uninstallCommand` — installed as
//! a portable exe, installed before schema v2, or an installer that registered no `Uninstall` entry at all —
//! has no uninstaller to run; the caller falls back to plain environment removal.
use crate::pipeline::MSIEXEC_RELATIVE;
use crate::sandbox::{InstallerSandbox, SandboxOpts, find_bwrap_on_path};
use rt_core::{AppEnv, CompatBackend, Launcher, LogSink, Metadata, RunOpts, WinPath, resolve_under};
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

/// What [`uninstall`] did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UninstallOutcome {
    /// `None`: no `installer.uninstallCommand` was recorded (see the module docs' "known limit"). `Some(true)`:
    /// the uninstaller ran and exited 0. `Some(false)`: it ran but exited non-zero, or could not be started, or
    /// its command line could not be resolved inside this prefix (`warnings` says which).
    pub uninstaller_succeeded: Option<bool>,
    /// Human text; may quote untrusted data (the recorded command, a backend error), capped, but the caller must
    /// still sanitise it before printing.
    pub warnings: Vec<String>,
}

/// Runs `md`'s recorded uninstall command, sandboxed, if it has one. Never fails: every problem (no command
/// recorded, an unresolvable path, a sandbox/backend/spawn failure, a non-zero exit) becomes part of the
/// returned [`UninstallOutcome`], never a panic or an `Err` — the caller must remove the environment regardless.
pub fn uninstall(
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    env: &AppEnv,
    md: &Metadata,
    opts: SandboxOpts,
    runtime_exe: &Path,
) -> UninstallOutcome {
    let Some(command) = md.installer.as_ref().and_then(|i| i.uninstall_command.as_deref()) else {
        return UninstallOutcome::default();
    };
    let mut warnings = Vec::new();
    let succeeded = run_uninstall_command(backend, launcher, env, command, opts, runtime_exe, &mut warnings);
    UninstallOutcome {
        uninstaller_succeeded: Some(succeeded),
        warnings,
    }
}

fn run_uninstall_command(
    backend: &dyn CompatBackend,
    launcher: &Launcher,
    env: &AppEnv,
    command: &str,
    opts: SandboxOpts,
    runtime_exe: &Path,
    warnings: &mut Vec<String>,
) -> bool {
    let Some((exe_unix, args)) = resolve_uninstaller(env, command) else {
        warnings.push(
            "could not resolve the recorded uninstall command inside this app's prefix; removing the \
             environment directly instead"
                .to_owned(),
        );
        return false;
    };
    let Some(bwrap) = find_bwrap_on_path() else {
        warnings.push("bwrap (bubblewrap) was not found on $PATH: could not run the uninstaller sandboxed".to_owned());
        return false;
    };
    let sandbox = InstallerSandbox::new(bwrap, runtime_exe);
    if let Err(why) = sandbox.check(env, &opts) {
        warnings.push(format!(
            "the installer sandbox refused to start the uninstaller: {why} (nothing was run)"
        ));
        return false;
    }
    // The vendor uninstaller runs sandboxed Windows code in the prefix: mark before it starts (fail closed), so any
    // later Wine helper of this app runs sandboxed too. A crash after the mark leaves it set.
    if let Err(e) = rt_sandbox::mark(env.root()) {
        warnings.push(format!(
            "could not record that the app runs sandboxed ({e}); the uninstaller was not run"
        ));
        return false;
    }
    let sandboxed = launcher.clone().with_sandbox(sandbox.for_launcher(env.clone(), opts));
    let cmd = match backend.command(env, &exe_unix, &env.drive_c(), &args, &RunOpts::default()) {
        Ok(cmd) => cmd,
        Err(e) => {
            warnings.push(format!("could not start the uninstaller: {e}"));
            return false;
        }
    };
    // Same reasoning as `pipeline::run_installer_process`: `settle` before the sandbox sees the command, so a
    // lingering `wineserver` is waited for inside the same PID-namespace process tree, not after it is dead.
    let cmd = backend.settle(cmd);
    let running = match sandboxed.spawn(cmd, env, LogSink::LogOnly) {
        Ok(r) => r,
        Err(e) => {
            warnings.push(format!("could not start the uninstaller: {e}"));
            return false;
        }
    };
    match running.wait() {
        Ok(status) if status.success() => true,
        Ok(status) => {
            warnings.push(format!("the uninstaller exited with {status}"));
            false
        }
        Err(e) => {
            warnings.push(format!("could not wait for the uninstaller: {e}"));
            false
        }
    }
}

/// Splits a Windows command line into (program, args): the minimal subset real `UninstallString`s actually use
/// (`MsiExec.exe /X{GUID}`, `"C:\Program Files\App\uninstall.exe" /S`) — an optionally double-quoted program,
/// then whitespace-separated, optionally double-quoted arguments. No escaped-quote or caret handling: never a
/// shell, so nothing here can inject a second command, only fail to split an unusually exotic string cleanly
/// (which surfaces as `resolve_uninstaller` returning `None`, a warning, never a panic).
pub(crate) fn split_command_line(s: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut chars = s.trim().chars().peekable();
    while chars.peek().is_some() {
        while chars.peek() == Some(&' ') {
            chars.next();
        }
        if chars.peek().is_none() {
            break;
        }
        let mut tok = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            for c in chars.by_ref() {
                if c == '"' {
                    break;
                }
                tok.push(c);
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ' ' {
                    break;
                }
                tok.push(c);
                chars.next();
            }
        }
        tokens.push(tok);
    }
    tokens
}

/// The uninstall command's program, resolved to a real host path inside `env.drive_c()` (never outside it,
/// never a symlink: [`resolve_under`]'s usual containment), plus its arguments verbatim. `MsiExec.exe` (any
/// case, with or without a path: real `UninstallString`s just say `MsiExec.exe`, relying on it being on `PATH`
/// inside Windows) is special-cased to this prefix's own, already-verified `msiexec.exe` (mirrors
/// `crate::pipeline`'s Ruling 2 handling on the way in).
fn resolve_uninstaller(env: &AppEnv, command: &str) -> Option<(PathBuf, Vec<OsString>)> {
    let tokens = split_command_line(command);
    let (program, rest) = tokens.split_first()?;
    let drive_c = env.drive_c();
    let exe_unix = if program.eq_ignore_ascii_case("msiexec.exe") || program.eq_ignore_ascii_case("msiexec") {
        let msiexec = drive_c.join(MSIEXEC_RELATIVE);
        if !fs::symlink_metadata(&msiexec).is_ok_and(|m| m.file_type().is_file()) {
            return None;
        }
        msiexec
    } else {
        let winpath = WinPath::parse(program).ok()?;
        resolve_under(&drive_c, &winpath).ok()?
    };
    Some((exe_unix, rest.iter().map(OsString::from).collect()))
}

#[cfg(test)]
mod tests;
