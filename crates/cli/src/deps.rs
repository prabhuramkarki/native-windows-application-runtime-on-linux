//! `runtime deps <app> [--install [--yes <pkg>]...] [--discard-interrupted <pkg>]`, `runtime deps list`,
//! `runtime deps cache [--clear]`, and the one-line missing-dependency hint `install` and `doctor` print
//! (not `run`: it would read the whole executable on every start).
//!
//! * `runtime deps <app>` prints the plan: no network, no writes.
//! * `--install` fetches and installs it through `rt_deps::install_plan`, behind consent: a consent-gated package
//!   shows its consent text in full, then asks y/N when stdin AND stdout are terminals. Otherwise only
//!   `--yes <pkg>` consents (the text is still printed). Every `--yes` must name a package the plan installs and that needs consent,
//!   checked before anything else happens.
//! * A package you do not consent to is skipped together with everything that needs it; the packages IT needs
//!   still install ([`DENIED_NOTE`], spec §4).
//! * The hint ([`missing_hint`], [`hint_for`]) is computed with `plan_for_app` / `plan_for_pe` only (doctor
//!   reuses the PE it already analysed). It takes no `Fetcher`, so neither command can download through it.
//!
//! Formatting is pure (`format_*` return strings, tested as such); every untrusted string goes through `safe`.
//! Exit codes: 0 when everything planned is installed (or nothing was to do); 1 when anything failed or was
//! skipped for any reason other than "already installed"; usage errors are clap's 2.
use crate::CmdError;
use crate::safe::{safe, safe_lines, shorten, warn};
use clap::{Args, Subcommand};
use rt_core::{AppEnv, AppId, Launcher, Metadata, Store, StoreError};
use rt_deps::{
    Action, AppLock, AppPlan, ConsentProvider, ConsentState, DepsError, Kind, Manifest, NetFetcher, Orchestrator,
    Package, Plan, RunReport,
};
use std::cell::RefCell;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};

/// Printed with every plan that asks for consent (Task 7a minor: documented spec-literal behaviour).
pub(crate) const DENIED_NOTE: &str = "note: a package you do not consent to is skipped together with everything \
                                      that needs it; the packages it needs itself still install";
use rt_deps::ALREADY_INSTALLED as ALREADY;
/// Longest answer read from the terminal; the rest of a longer line is read and dropped (the answer is no).
const MAX_ANSWER: u64 = 256;

#[derive(Args)]
#[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
pub struct DepsArgs {
    #[command(subcommand)]
    sub: Option<DepsSub>,
    /// An app id from `runtime list` (an app named `list` or `cache` is shadowed by those subcommands)
    #[arg(required = true)]
    app: Option<String>,
    /// Download and install what the plan lists (consent-gated packages ask first, or need --yes)
    #[arg(long)]
    install: bool,
    /// Consent to one consent-gated package of the plan without a prompt (its licence text is still printed).
    /// Repeat for each package; it always takes a package name.
    #[arg(long, value_name = "PKG", requires = "install")]
    yes: Vec<String>,
    /// Undo what an interrupted (killed) install of PKG left in the prefix, so it can be installed again
    #[arg(long, value_name = "PKG", conflicts_with = "install")]
    discard_interrupted: Option<String>,
}

#[derive(Subcommand)]
enum DepsSub {
    /// Show the bundled package manifest
    List,
    /// Show the download cache
    Cache {
        /// Delete the cached downloads (only completed `<sha256>` files; downloads in progress are left alone)
        #[arg(long)]
        clear: bool,
    },
}

pub fn run(args: DepsArgs) -> Result<u8, CmdError> {
    match (args.sub, args.app) {
        (Some(DepsSub::List), _) => crate::emit(&format_manifest(Manifest::bundled())).map(|()| 0),
        (Some(DepsSub::Cache { clear }), _) => cache(&cache_dir()?, clear),
        (None, Some(app)) => run_app(&app, args.install, &args.yes, args.discard_interrupted.as_deref()),
        (None, None) => Err("an app id is required (see `runtime deps --help`)".into()),
    }
}

/// Where downloads are kept: `<data root>/deps-cache` (the fetcher creates it 0700 and refuses an unsafe one).
pub(crate) fn cache_dir() -> Result<PathBuf, CmdError> {
    Ok(rt_core::data_root()?.join("deps-cache"))
}

pub(crate) fn app_env(store: &Store, arg: &str) -> Result<AppEnv, CmdError> {
    let id = AppId::parse(arg).map_err(|e| {
        format!(
            "{:?} is not a valid app id ({e}); `deps` takes an id from `runtime list`, never a path",
            shorten(arg, 80)
        )
    })?;
    match store.get(&id) {
        Err(StoreError::NotFound) => Err(format!("no app named {id} is installed (see `runtime list`)").into()),
        other => Ok(other?),
    }
}

fn run_app(app: &str, install: bool, yes: &[String], discard: Option<&str>) -> Result<u8, CmdError> {
    let store = crate::store()?;
    let env = app_env(&store, app)?;
    if let Some(pkg) = discard {
        if Manifest::bundled().get(pkg).is_some_and(|p| p.kind == Kind::Installer) {
            crate::emit(&installer_discard_text(pkg))?;
            return Ok(0);
        }
        let report = rt_deps::discard_interrupted_for(&store, &env, pkg).map_err(|e| discard_error(e, pkg))?;
        crate::emit(&format_discard(pkg, &report))?;
        return Ok(0);
    }
    let manifest = Manifest::bundled();
    let md = store.read_metadata(&env)?;
    let plan = rt_deps::plan_for_app(&env, &md, manifest, &crate::graphics::verdict_for);
    crate::emit(&format_plan(env.id().as_str(), &plan, manifest, install))?;
    if !install {
        return Ok(0);
    }
    check_yes(&plan.plan, yes)?;
    crate::sandbox::print_hardening_caveat();
    // An installer package gets a read-write prefix in the installer sandbox, and the helper launcher below is chosen
    // ONCE for every archive package of this run: mark the app first, so an archive package's `reg.exe` that runs
    // after an installer package in the same run is sandboxed too (fail closed: nothing installs without the mark).
    if may_run_installer(&plan.plan, manifest) {
        rt_sandbox::mark(env.root()).map_err(|e| {
            format!(
                "cannot record that {}'s prefix is about to be written by a sandboxed installer ({e}); nothing was \
                 installed",
                env.id()
            )
        })?;
    }
    let launcher = Launcher::new();
    let backend = crate::backend(&launcher)?;
    // `reg.exe` of archive packages; installer packages replace it with the installer sandbox.
    let launcher = crate::sandbox::helper_launcher(&env, &launcher, &backend)?;
    let cache = cache_dir()?;
    let stdin = io::stdin();
    let answers: Option<Box<dyn BufRead>> =
        can_ask(stdin.is_terminal(), io::stdout().is_terminal()).then(|| Box::new(stdin.lock()) as Box<dyn BufRead>);
    let consent = CliConsent::new(yes, Box::new(io::stdout()), answers);
    let o = Orchestrator {
        manifest,
        cache_dir: &cache,
        env: &env,
        store: &store,
        backend: &backend,
        launcher: &launcher,
        fetcher: &NetFetcher,
        consent: &consent,
        now: rt_deps::unix_now,
        vulkan: &crate::graphics::verdict_for,
        runtime_exe: &crate::runtime_exe(),
    };
    let (text, code) = install_report(&o, &plan)?;
    crate::emit(&text)?;
    Ok(code)
}

/// Runs the install and formats its report.
pub(crate) fn install_report(o: &Orchestrator, plan: &AppPlan) -> Result<(String, u8), CmdError> {
    let report = rt_deps::install_plan(o, plan).map_err(|e| e.to_string())?;
    Ok(format_report(&report))
}

/// Every `--yes` must name a package the plan installs that needs consent: anything else is a mistake (a typo, or
/// a package that needs no consent), refused before anything happens.
/// Whether this `--install` run may start an installer package (any `Installer` package the plan installs, consent
/// not yet asked: conservative).
fn may_run_installer(plan: &Plan, manifest: &Manifest) -> bool {
    plan.entries
        .iter()
        .any(|e| e.action == Action::Install && manifest.get(&e.package).is_some_and(|p| p.kind == Kind::Installer))
}

pub(crate) fn check_yes(plan: &Plan, yes: &[String]) -> Result<(), String> {
    for y in yes {
        let gated = plan
            .entries
            .iter()
            .any(|e| e.package == *y && e.action == Action::Install && e.consent == ConsentState::Needed);
        if !gated {
            return Err(format!(
                "--yes {:?}: not a package this app's plan installs that needs consent (see the plan above); \
                 nothing was installed",
                shorten(y, 64)
            ));
        }
    }
    Ok(())
}

/// Installer packages keep no journal: there is nothing to discard, and nothing is known about the prefix either.
fn installer_discard_text(pkg: &str) -> String {
    format!(
        "{} is an installer package: installer packages keep no journal, so the runtime has nothing to discard. \
         What an interrupted vendor installer left in the prefix is unknown; recreate the environment if in doubt.\n",
        safe(pkg)
    )
}

/// Only a terminal on both ends is asked: the user must see the prompt they answer.
pub(crate) fn can_ask(stdin_tty: bool, stdout_tty: bool) -> bool {
    stdin_tty && stdout_tty
}

fn discard_error(e: DepsError, pkg: &str) -> String {
    let pkg = shorten(pkg, 64);
    match e {
        DepsError::Recorded(_) => format!(
            "package {pkg:?} is recorded as installed, so there is no interrupted install to discard; to undo it, \
             recreate the environment"
        ),
        DepsError::Discard(e) => format!("cannot discard what the interrupted install of {pkg:?} left: {e}"),
        // LockHeld and PrefixBusy say what to do.
        other => other.to_string(),
    }
}

// ------------------------------------------------------------------------------------------------ consent

/// Consent from `--yes` or from the terminal. The consent text is always printed in full first; if that fails, the
/// answer is no ([`ConsentProvider::confirm`]'s contract).
pub(crate) struct CliConsent<'a> {
    yes: &'a [String],
    out: RefCell<Box<dyn Write + 'a>>,
    /// `None`: not a terminal, so only `--yes` consents.
    answers: Option<RefCell<Box<dyn BufRead + 'a>>>,
}

impl<'a> CliConsent<'a> {
    pub(crate) fn new(yes: &'a [String], out: Box<dyn Write + 'a>, answers: Option<Box<dyn BufRead + 'a>>) -> Self {
        CliConsent {
            yes,
            out: RefCell::new(out),
            answers: answers.map(RefCell::new),
        }
    }
}

impl ConsentProvider for CliConsent<'_> {
    fn confirm(&self, pkg: &Package, consent_text: &str) -> bool {
        let id = safe(&pkg.id);
        let mut out = self.out.borrow_mut();
        // The text is trusted manifest text, already escaped by `consent_text`; `safe_lines` only re-escapes
        // anything dangerous, keeping the line breaks, so what is shown is the text itself.
        if write!(out, "\n{}\n", safe_lines(consent_text))
            .and_then(|()| out.flush())
            .is_err()
        {
            return false;
        }
        if self.yes.contains(&pkg.id) {
            let _ = writeln!(out, "Consent given on the command line (--yes {id}).\n");
            return true;
        }
        let Some(answers) = &self.answers else {
            let _ = writeln!(
                out,
                "No consent: {id} is skipped (no terminal to ask on; to consent, run again with --yes {id}).\n"
            );
            return false;
        };
        if write!(out, "Install {id} under this licence? [y/N] ")
            .and_then(|()| out.flush())
            .is_err()
        {
            return false;
        }
        let mut line = Vec::new();
        let mut input = answers.borrow_mut();
        let read = (&mut *input).take(MAX_ANSWER).read_until(b'\n', &mut line);
        // An over-long line: drop the rest of it, so it cannot become the next answer (and it is a no).
        let whole = line.ends_with(b"\n") || matches!(read, Ok(n) if (n as u64) < MAX_ANSWER);
        if !whole {
            let _ = input.skip_until(b'\n');
        }
        let yes = whole
            && matches!(read, Ok(n) if n > 0)
            && matches!(
                String::from_utf8_lossy(&line).trim().to_ascii_lowercase().as_str(),
                "y" | "yes"
            );
        if !yes {
            let _ = writeln!(out, "No consent: {id} is skipped.");
        }
        yes
    }
}

// ------------------------------------------------------------------------------------------------ formatting

fn package_line(pkg: Option<&Package>, id: &str) -> String {
    match pkg {
        Some(p) => format!("{} {} ({})", safe(&p.id), safe(&p.version), safe(&p.licence)),
        None => safe(id),
    }
}

/// The plan, its warnings, and what to do next (nothing more when `install` follows).
pub(crate) fn format_plan(app: &str, ap: &AppPlan, manifest: &Manifest, install: bool) -> String {
    let app = safe(app);
    let mut o = format!("Dependencies of {app}:\n");
    if ap.plan.entries.is_empty() {
        o.push_str("  (none that the runtime can provide)\n");
    }
    let mut gated = Vec::new();
    for e in &ap.plan.entries {
        let what = match &e.action {
            Action::Install if e.consent == ConsentState::Needed => {
                gated.push(safe(&e.package));
                "to install, needs your consent".to_owned()
            }
            Action::Install => "to install".to_owned(),
            Action::AlreadyInstalled => ALREADY.to_owned(),
            Action::Blocked { reason } => format!("blocked: {}", safe(reason)),
        };
        let _ = writeln!(o, "  {}: {what}", package_line(manifest.get(&e.package), &e.package));
    }
    for w in &ap.warnings {
        let _ = writeln!(o, "warning: {}", safe(w));
    }
    if !gated.is_empty() {
        let _ = writeln!(o, "{DENIED_NOTE}");
    }
    if install {
        return o;
    }
    if ap.plan.entries.iter().any(|e| e.action == Action::Install) {
        let yes: String = gated.iter().map(|g| format!(" [--yes {g}]")).collect();
        let _ = writeln!(o, "Install with: runtime deps {app} --install{yes}");
    } else {
        o.push_str("Nothing to install.\n");
    }
    o
}

/// The report of an install run, and its exit code (see the module docs).
pub(crate) fn format_report(r: &RunReport) -> (String, u8) {
    if *r == RunReport::default() {
        return ("Nothing to install.\n".into(), 0);
    }
    let mut o = String::new();
    for id in &r.completed {
        let _ = writeln!(o, "installed: {}", safe(id));
    }
    for (id, why) in &r.failed {
        let _ = writeln!(o, "FAILED:    {}: {}", safe(id), safe(why));
    }
    for (id, why) in &r.skipped {
        let _ = writeln!(o, "skipped:   {}: {}", safe(id), safe(why));
    }
    for (id, why) in &r.warnings {
        let _ = writeln!(o, "warning:   {}: {}", safe(id), safe(why));
    }
    let not_done = r.skipped.iter().filter(|(_, why)| why != ALREADY).count();
    let _ = writeln!(
        o,
        "{} installed, {} failed, {} skipped, {} already installed",
        r.completed.len(),
        r.failed.len(),
        not_done,
        r.skipped.len() - not_done
    );
    (o, u8::from(!r.failed.is_empty() || not_done > 0))
}

fn format_discard(pkg: &str, r: &rt_deps::install_archive::DiscardReport) -> String {
    let pkg = safe(pkg);
    if r.removed_files.is_empty() && r.restored.is_empty() && r.removed_dirs.is_empty() {
        return format!("Nothing to discard for {pkg}.\n");
    }
    let mut o = format!("Discarded what the interrupted install of {pkg} left:\n");
    for (label, paths) in [
        ("removed", &r.removed_files),
        ("restored", &r.restored),
        ("removed dir", &r.removed_dirs),
    ] {
        for p in paths {
            let _ = writeln!(o, "  {label}: {}", safe(&p.to_string_lossy()));
        }
    }
    o
}

pub(crate) fn format_manifest(m: &Manifest) -> String {
    let mut o = String::from("Bundled packages:\n");
    for p in &m.packages {
        let _ = writeln!(
            o,
            "  {} {} ({}{}): provides {}{}",
            safe(&p.id),
            safe(&p.version),
            safe(&p.licence),
            if p.requires_consent { ", needs consent" } else { "" },
            safe(&p.provides.join(", ")),
            if p.requires.is_empty() {
                String::new()
            } else {
                format!("; requires {}", safe(&p.requires.join(", ")))
            }
        );
    }
    o
}

// ------------------------------------------------------------------------------------------------ cache

/// A completed download: a regular file named by its 64-hex sha256.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CacheEntry {
    pub name: String,
    pub size: u64,
}

fn is_sha256_name(name: &str) -> bool {
    name.len() == 64 && name.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The completed downloads in `dir`, sorted. A missing directory is empty; a directory that is a symlink (or not a
/// directory) is refused. Entries are examined with `lstat`: a symlink or directory is never an entry.
pub(crate) fn cache_entries(dir: &Path) -> io::Result<Vec<CacheEntry>> {
    match fs::symlink_metadata(dir) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
        Ok(m) if !m.file_type().is_dir() => {
            return Err(io::Error::other(format!(
                "{} is not a directory (a symlink?); refusing to use it",
                dir.display()
            )));
        }
        Ok(_) => {}
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let Some(name) = entry
            .file_name()
            .to_str()
            .filter(|n| is_sha256_name(n))
            .map(str::to_owned)
        else {
            continue;
        };
        // `DirEntry::metadata` does not follow symlinks.
        let m = entry.metadata()?;
        if m.file_type().is_file() {
            out.push(CacheEntry { name, size: m.len() });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Deletes the completed downloads in `dir` (see [`cache_entries`]): only regular files named as a sha256.
/// `unlink` never follows a symlink, so an entry swapped for one after the check only loses that link. Temp files
/// of a download in progress are not named like that and stay. Returns what was deleted.
pub(crate) fn clear_cache(dir: &Path) -> io::Result<Vec<CacheEntry>> {
    let entries = cache_entries(dir)?;
    for e in &entries {
        fs::remove_file(dir.join(&e.name))?;
    }
    Ok(entries)
}

pub(crate) fn format_cache(dir: &Path, entries: &[CacheEntry], cleared: bool) -> String {
    let total: u64 = entries.iter().map(|e| e.size).sum();
    let mut o = format!("Download cache: {}\n", safe(&dir.to_string_lossy()));
    for e in entries {
        let _ = writeln!(o, "  {}  {} bytes", e.name, e.size);
    }
    let verb = if cleared { "Deleted" } else { "Total:" };
    let _ = writeln!(o, "{verb} {} file(s), {total} bytes", entries.len());
    o
}

fn cache(dir: &Path, clear: bool) -> Result<u8, CmdError> {
    let entries = if clear { clear_cache(dir)? } else { cache_entries(dir)? };
    crate::emit(&format_cache(dir, &entries, clear))?;
    Ok(0)
}

// ------------------------------------------------------------------------------------------------ hint and locks

/// One line when the app's plan has packages that are not installed: computed with `plan_for_app` only (reads
/// the metadata and the executable; no network, no writes, no `Fetcher`).
pub(crate) fn missing_hint(env: &AppEnv, md: &Metadata, manifest: &Manifest) -> Option<String> {
    hint_for(
        env.id().as_str(),
        &rt_deps::plan_for_app(env, md, manifest, &crate::graphics::verdict_for),
    )
}

/// The hint line for `app`'s plan (see [`missing_hint`]).
pub(crate) fn hint_for(app: &str, plan: &AppPlan) -> Option<String> {
    let n = plan
        .plan
        .entries
        .iter()
        // A Blocked entry is not something `deps --install` can fix, so it is not "missing".
        .filter(|e| e.action == Action::Install)
        .count();
    let noun = if n == 1 { "dependency" } else { "dependencies" };
    (n > 0).then(|| format!("hint: {n} {noun} missing: run `runtime deps {}`", safe(app)))
}

/// One `note:` line per installer package the plan dropped because its marker is already in the prefix (Ruling
/// 18): the runtime did not install it and set none of its DLL overrides. `doctor` prints these under the hint.
pub(crate) fn present_notes(plan: &AppPlan) -> Vec<String> {
    plan.warnings
        .iter()
        .filter(|w| w.ends_with(rt_deps::MARKER_PRESENT))
        .map(|w| format!("note: {}", safe(w)))
        .collect()
}

/// Best effort: prints [`missing_hint`] for an installed app on stderr (stdout may belong to a program).
pub(crate) fn print_hint(store: &Store, id: &AppId) {
    let Ok(env) = store.get(id) else { return };
    let Ok(md) = store.read_metadata(&env) else { return };
    if let Some(h) = missing_hint(&env, &md, Manifest::bundled()) {
        eprintln!("{h}");
    }
}

/// Takes the app's dependency lock (shared for starting it, exclusive for removing it) or refuses with a clear
/// message while another command holds it. A lock that cannot be taken for any other reason (e.g. `deps.lock` is
/// not a regular file) is a warning: no dependency install can run without that lock either.
pub(crate) fn lock_or_refuse(env: &AppEnv, shared: bool, what: &str) -> Result<Option<AppLock>, CmdError> {
    let got = if shared {
        rt_deps::lock_app_shared(env)
    } else {
        rt_deps::lock_app(env)
    };
    match got {
        Ok(lock) => Ok(Some(lock)),
        // Nobody can lock such a file (or on such a file system), so no dependency install can be running either.
        Err(e) if e.nobody_can_lock() => {
            warn(&format!("could not take this app's lock ({e}); continuing without it"));
            Ok(None)
        }
        Err(e) => Err(format!("cannot {what} {}: {e}", env.id()).into()),
    }
}

#[cfg(test)]
mod tests;
