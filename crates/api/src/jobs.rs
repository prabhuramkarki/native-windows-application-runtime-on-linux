//! Jobs: the mutating requests of a write-mode `runtimed` (Phase 6B), validated here into a [`JobSpec`] whose
//! [`JobSpec::argv`] is the argument list of the sibling `runtime` binary that performs the change. Nothing here
//! starts a process; the daemon owns those. This module is the injection boundary (spec 5.1):
//!
//! * every app id is an `AppId` that `runtime run` would also read as an id (`x.exe` is refused: a path to it);
//! * every free value either cannot start with `-` (ids, absolute paths) or is passed as `--flag=value`, and every
//!   positional sits after `--`, so no client string can become an option;
//! * no value may hold NUL, a control or a format character (program arguments: no NUL, otherwise verbatim, since
//!   they reach only the program inside its sandbox);
//! * no parameter maps to `--unsandboxed`, `--debug`, or a blanket consent: `--yes=` only ever carries a package id
//!   that [`check_consent`] matched against the recomputed plan and its [`plan_digest`].
//!
//! The wire types of the jobs model ([`JobInfo`], [`JobEvents`], ...) live here too.
use crate::error::{ApiError, ErrorKind};
use crate::runtime::Runtime;
use crate::types::{ConsentView, DepsPlanView, PATH_MAX, PlanAction, TEXT_MAX};
use rt_core::{AppId, TargetKind, classify, is_format};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::path::PathBuf;

/// Longest `name` of `apps.install`, in bytes.
pub const NAME_MAX: usize = 256;
/// Longest `exe` of `apps.install`, in bytes.
pub const EXE_MAX: usize = 1024;
/// Longest installer path, one permission expression, one program argument, in bytes.
pub const VALUE_MAX: usize = PATH_MAX;
/// Most `set` expressions of one `permissions.set`.
pub const MAX_SET: usize = 32;
/// Most program arguments of one `apps.run`, and their total size in bytes.
pub const MAX_ARGS: usize = 64;
pub const ARGS_TOTAL_MAX: usize = 64 * 1024;
/// Most consent items of one `deps.install`.
pub const MAX_CONSENT: usize = 64;

// ------------------------------------------------------------------------------------------------ wire types

/// What a job does (one per write method).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum JobKind {
    Run,
    Install,
    Remove,
    DepsInstall,
    PermissionsSet,
    PermissionsReset,
    DisplaySet,
    /// A value this client does not know (a newer daemon's): deserialisation never fails on it. Never produced.
    #[serde(other)]
    Unknown,
}

/// `succeeded` = exit 0; `failed` = any other exit or a spawn failure; `cancelled` = ended after `jobs.cancel`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum JobState {
    Queued,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    /// A value this client does not know (a newer daemon's): deserialisation never fails on it. Never produced.
    #[serde(other)]
    Unknown,
}

/// `progress` is reserved (never emitted in 0.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum EventKind {
    Stdout,
    Stderr,
    State,
    Progress,
    /// A value this client does not know (a newer daemon's): deserialisation never fails on it. Never produced.
    #[serde(other)]
    Unknown,
}

/// A job's state. Times are Unix milliseconds; `exit_code`/`signal` are `None` until known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobInfo {
    pub job_id: String,
    pub kind: JobKind,
    /// The app the job acts on; `None` for an install (the CLI derives the id).
    pub app: Option<String>,
    pub state: JobState,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub created_at: u64,
    pub started_at: Option<u64>,
    pub ended_at: Option<u64>,
    /// Events evicted from the job's bounded memory so far.
    pub dropped: u64,
}

/// One line of output (cleaned, at most 4 KiB) or a state change. `seq` starts at 1 and grows by 1 per event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobEvent {
    pub seq: u64,
    pub ts: u64,
    pub kind: EventKind,
    pub text: String,
}

/// `jobs.poll`: the events after `afterSeq`, the `seq` to ask after next time, and how many events after
/// `afterSeq` were evicted before this poll.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobEvents {
    pub events: Vec<JobEvent>,
    pub next_seq: u64,
    pub dropped: u64,
    pub job: JobInfo,
}

/// `jobs.list`: live jobs first (oldest first), then finished ones, newest first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobList {
    pub jobs: Vec<JobInfo>,
}

/// What every job-starting method returns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct JobStarted {
    pub job_id: String,
}

/// Consent to one consent-gated package of the plan the client showed: exactly its id, version and sha256.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentItem {
    pub package: String,
    pub version: String,
    pub sha256: String,
}

/// `display.set`'s driver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Driver {
    Auto,
    X11,
    Wayland,
}

impl Driver {
    pub fn as_str(self) -> &'static str {
        match self {
            Driver::Auto => "auto",
            Driver::X11 => "x11",
            Driver::Wayland => "wayland",
        }
    }
}

/// `deps.install`'s params. Not a [`JobSpec`] by themselves: [`Runtime::deps_install_spec`] checks them against the
/// recomputed plan.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DepsInstallParams {
    pub id: String,
    pub plan_digest: String,
    pub consent: Vec<ConsentItem>,
}

impl DepsInstallParams {
    pub fn from_value(params: serde_json::Value) -> Result<DepsInstallParams, JobParamsError> {
        shape(params)
    }
}

// ------------------------------------------------------------------------------------------------ specs

/// A validated mutation. Built only by [`JobSpec::from_request`] and [`Runtime::deps_install_spec`]. Deliberately
/// exhaustive: the CLI's parser-oracle test matches every variant, so a new one cannot ship without its argv check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobSpec {
    Run {
        app: AppId,
        args: Vec<String>,
    },
    Install {
        path: PathBuf,
        name: Option<String>,
        exe: Option<String>,
        silent: bool,
        network: bool,
    },
    Remove {
        app: AppId,
    },
    /// `yes`: package ids AFTER [`check_consent`].
    DepsInstall {
        app: AppId,
        plan_digest: String,
        yes: Vec<String>,
    },
    PermissionsSet {
        app: AppId,
        set: Vec<String>,
    },
    PermissionsReset {
        app: AppId,
    },
    DisplaySet {
        app: AppId,
        driver: Driver,
    },
}

/// Why params were refused: `Shape` (not an object, an unknown member, a missing or mistyped field; the daemon
/// answers -32602, message cleaned) or `Api` (a well-formed value the method refuses: `invalid_argument`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum JobParamsError {
    #[error("{0}")]
    Shape(String),
    #[error(transparent)]
    Api(ApiError),
}

impl From<ApiError> for JobParamsError {
    fn from(e: ApiError) -> Self {
        JobParamsError::Api(e)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RunParams {
    id: String,
    #[serde(default)]
    args: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InstallParams {
    path: String,
    name: Option<String>,
    exe: Option<String>,
    #[serde(default)]
    silent: bool,
    #[serde(default)]
    network: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetParams {
    id: String,
    set: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplayParams {
    id: String,
    driver: Driver,
}

fn shape<T: DeserializeOwned>(params: serde_json::Value) -> Result<T, JobParamsError> {
    if !params.is_object() {
        return Err(JobParamsError::Shape("invalid params: must be an object".into()));
    }
    // serde's message can quote a member name of the client's: cleaned and bounded (as the daemon's own).
    serde_json::from_value(params)
        .map_err(|e| JobParamsError::Shape(rt_core::clean_text(&format!("invalid params: {e}"), 256)))
}

impl JobSpec {
    /// Validates the by-name params of one write method. `deps.install` is not one: its consent needs the plan
    /// ([`Runtime::deps_install_spec`]); asking for it (or any other name) here is the caller's bug (`internal`).
    pub fn from_request(method: &str, params: serde_json::Value) -> Result<JobSpec, JobParamsError> {
        Ok(match method {
            "apps.run" => {
                let p: RunParams = shape(params)?;
                JobSpec::Run {
                    app: app_id(&p.id)?,
                    args: program_args(p.args)?,
                }
            }
            "apps.install" => {
                let p: InstallParams = shape(params)?;
                JobSpec::Install {
                    path: installer_path(&p.path)?,
                    name: p.name.map(|n| value("name", n, NAME_MAX)).transpose()?,
                    exe: p.exe.map(|e| value("exe", e, EXE_MAX)).transpose()?,
                    silent: p.silent,
                    network: p.network,
                }
            }
            "apps.remove" => JobSpec::Remove {
                app: app_id(&shape::<IdParams>(params)?.id)?,
            },
            "permissions.set" => {
                let p: SetParams = shape(params)?;
                let app = app_id(&p.id)?;
                if p.set.is_empty() || p.set.len() > MAX_SET {
                    return Err(bad(format!("set takes 1 to {MAX_SET} expressions")).into());
                }
                JobSpec::PermissionsSet {
                    app,
                    set: p
                        .set
                        .into_iter()
                        .map(|e| value("a permission expression", e, VALUE_MAX))
                        .collect::<Result<_, _>>()?,
                }
            }
            "permissions.reset" => JobSpec::PermissionsReset {
                app: app_id(&shape::<IdParams>(params)?.id)?,
            },
            "display.set" => {
                let p: DisplayParams = shape(params)?;
                JobSpec::DisplaySet {
                    app: app_id(&p.id)?,
                    driver: p.driver,
                }
            }
            _ => return Err(ApiError::new(ErrorKind::Internal, "not a job method").into()),
        })
    }

    pub fn kind(&self) -> JobKind {
        match self {
            JobSpec::Run { .. } => JobKind::Run,
            JobSpec::Install { .. } => JobKind::Install,
            JobSpec::Remove { .. } => JobKind::Remove,
            JobSpec::DepsInstall { .. } => JobKind::DepsInstall,
            JobSpec::PermissionsSet { .. } => JobKind::PermissionsSet,
            JobSpec::PermissionsReset { .. } => JobKind::PermissionsReset,
            JobSpec::DisplaySet { .. } => JobKind::DisplaySet,
        }
    }

    /// The app the job acts on; `None` for an install.
    pub fn app(&self) -> Option<&AppId> {
        match self {
            JobSpec::Install { .. } => None,
            JobSpec::Run { app, .. }
            | JobSpec::Remove { app }
            | JobSpec::DepsInstall { app, .. }
            | JobSpec::PermissionsSet { app, .. }
            | JobSpec::PermissionsReset { app }
            | JobSpec::DisplaySet { app, .. } => Some(app),
        }
    }

    /// The arguments of `runtime` (without argv\[0\]); spec 5.1's table. Never fails. Every client value is an
    /// id or an absolute path (neither starts with `-`), sits after `--`, or is inside `--flag=`.
    pub fn argv(&self) -> Vec<OsString> {
        let flag = |f: &str, v: &str| OsString::from(format!("--{f}={v}"));
        let id = |a: &AppId| OsString::from(a.as_str());
        let mut v: Vec<OsString> = Vec::new();
        match self {
            JobSpec::Run { app, args } => {
                v.extend(["run".into(), id(app), "--".into()]);
                v.extend(args.iter().map(OsString::from));
            }
            JobSpec::Install {
                path,
                name,
                exe,
                silent,
                network,
            } => {
                v.push("install".into());
                v.extend(name.iter().map(|n| flag("name", n)));
                v.extend(exe.iter().map(|e| flag("exe", e)));
                if *silent {
                    v.push("--silent".into());
                }
                if *network {
                    v.push("--network".into());
                }
                v.extend(["--".into(), path.into()]);
            }
            JobSpec::Remove { app } => v.extend(["remove".into(), "--".into(), id(app)]),
            JobSpec::DepsInstall { app, plan_digest, yes } => {
                v.extend(["deps".into(), "--install".into(), flag("plan-digest", plan_digest)]);
                v.extend(yes.iter().map(|y| flag("yes", y)));
                v.extend(["--".into(), id(app)]);
            }
            JobSpec::PermissionsSet { app, set } => {
                v.push("permissions".into());
                v.extend(set.iter().map(|e| flag("set", e)));
                v.extend(["--".into(), id(app)]);
            }
            JobSpec::PermissionsReset { app } => {
                v.extend(["permissions".into(), "--reset".into(), "--".into(), id(app)])
            }
            JobSpec::DisplaySet { app, driver } => {
                v.extend(["display".into(), "--".into(), id(app), driver.as_str().into()])
            }
        }
        v
    }
}

// ------------------------------------------------------------------------------------------------ validators

fn bad(message: impl AsRef<str>) -> ApiError {
    ApiError::new(ErrorKind::InvalidArgument, message)
}

/// An installed-app id as `runtime` reads it: a valid `AppId` that `run` would not take for a path.
pub fn app_id(s: &str) -> Result<AppId, ApiError> {
    let id = AppId::parse(s).map_err(|e| bad(format!("not a valid app id: {e}")))?;
    if classify(s) != TargetKind::Id {
        return Err(bad(
            "not a valid app id: `runtime` would read a name ending in .exe or .zip as a file",
        ));
    }
    Ok(id)
}

fn invisible(s: &str) -> bool {
    s.chars().any(|c| c.is_control() || is_format(c))
}

/// A free value (`name`, `exe`, a permission expression): 1..=`max` bytes, nothing invisible.
fn value(what: &str, s: String, max: usize) -> Result<String, ApiError> {
    if s.is_empty() || s.len() > max {
        return Err(bad(format!("{what} must be 1 to {max} bytes long")));
    }
    if invisible(&s) {
        return Err(bad(format!("{what} contains a control or format character")));
    }
    Ok(s)
}

/// An installer file: absolute, no `.`/`..` component, no trailing `/`, nothing invisible, at most 4,096 bytes.
/// Whether it exists and what it is are the CLI's to judge.
fn installer_path(s: &str) -> Result<PathBuf, ApiError> {
    if s.len() > VALUE_MAX {
        return Err(bad(format!("path is longer than {VALUE_MAX} bytes")));
    }
    if invisible(s) {
        return Err(bad("path contains a control or format character"));
    }
    if !s.starts_with('/') || s.ends_with('/') {
        return Err(bad("path must be an absolute path to a file"));
    }
    if s.split('/').any(|c| c == "." || c == "..") {
        return Err(bad("path must not contain a . or .. component"));
    }
    Ok(PathBuf::from(s))
}

/// Program arguments reach only the program inside its sandbox: bounded, no NUL, otherwise verbatim.
fn program_args(args: Vec<String>) -> Result<Vec<String>, ApiError> {
    if args.len() > MAX_ARGS
        || args.iter().any(|a| a.len() > VALUE_MAX)
        || args.iter().map(String::len).sum::<usize>() > ARGS_TOTAL_MAX
    {
        return Err(bad(format!(
            "at most {MAX_ARGS} program arguments of at most {VALUE_MAX} bytes each, {ARGS_TOTAL_MAX} bytes in all"
        )));
    }
    if args.iter().any(|a| a.contains('\0')) {
        return Err(bad("a program argument contains a NUL character"));
    }
    Ok(args)
}

// ------------------------------------------------------------------------------------------------ consent

/// The digest of a dependency plan (spec 5.3), 64 lowercase hex: what `deps.plan` reports and what `deps.install`
/// and `runtime deps --install --plan-digest` compare. The only implementation. Each entry binds the package, its
/// manifest version and sha256, the sha256 of its consent text (`rt_deps::consent_text`, what a prompt shows and a
/// consent record hashes), its action and consent state; so a client's consent is to exactly that text.
pub fn plan_digest(id: &AppId, plan: &rt_deps::AppPlan, manifest: &rt_deps::Manifest) -> String {
    use rt_deps::{Action, ConsentState};
    let mut h = Sha256::new();
    h.update(format!("rt-deps-plan-v2\n{id}\n"));
    for e in &plan.plan.entries {
        let m = manifest.get(&e.package);
        let action = match e.action {
            Action::Install => "install",
            Action::AlreadyInstalled => "alreadyInstalled",
            Action::Blocked { .. } => "blocked",
        };
        let consent = match e.consent {
            ConsentState::NotNeeded => "notNeeded",
            ConsentState::Needed => "needed",
            ConsentState::Denied => "denied",
        };
        h.update(format!(
            "{}\0{}\0{}\0{}\0{action}\0{consent}\n",
            e.package,
            m.map_or("", |m| &m.version),
            m.map_or("", |m| &m.sha256),
            m.map_or_else(String::new, |m| sha256_hex(rt_deps::consent_text(m).as_bytes()))
        ));
    }
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// A plan digest's form: 64 lowercase hex digits.
pub fn is_digest(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The package ids `--yes=` may carry: `view` (recomputed now) must have `digest`, and every consent item must be
/// exactly `{package, version, sha256}` of an entry the plan installs that needs consent, each package once.
/// Anything else is `consent_mismatch`. A needed entry that is not listed is simply not consented.
pub fn check_consent(view: &DepsPlanView, digest: &str, consent: &[ConsentItem]) -> Result<Vec<String>, ApiError> {
    let mismatch = |m: &str| Err(ApiError::new(ErrorKind::ConsentMismatch, m));
    if view.digest != digest {
        return mismatch("the dependency plan changed since it was shown; show it again (deps.plan)");
    }
    let mut yes: Vec<String> = Vec::new();
    for c in consent {
        if yes.contains(&c.package) {
            return mismatch("a package is consented to more than once");
        }
        let exact = view.entries.iter().any(|e| {
            e.package == c.package
                && e.action == PlanAction::Install
                && e.consent == ConsentView::Needed
                && e.version.as_deref() == Some(c.version.as_str())
                && e.sha256.as_deref() == Some(c.sha256.as_str())
        });
        if !exact {
            return mismatch(
                "a consent item is not exactly {package, version, sha256} of a package this plan installs that \
                 needs consent",
            );
        }
        yes.push(c.package.clone());
    }
    Ok(yes)
}

impl Runtime {
    /// `deps.install`: validates the params, recomputes the plan (as `deps_plan`), then [`check_consent`].
    pub fn deps_install_spec(&self, id: &str, digest: &str, consent: &[ConsentItem]) -> Result<JobSpec, ApiError> {
        let app = app_id(id)?;
        if !is_digest(digest) {
            return Err(bad("planDigest must be 64 lowercase hex digits (deps.plan's digest)"));
        }
        let too_long = |c: &ConsentItem| [&c.package, &c.version, &c.sha256].iter().any(|f| f.len() > TEXT_MAX);
        if consent.len() > MAX_CONSENT || consent.iter().any(too_long) {
            return Err(bad(format!(
                "consent takes at most {MAX_CONSENT} items of at most {TEXT_MAX} bytes per field"
            )));
        }
        let view = self.deps_plan(id)?;
        let yes = check_consent(&view, digest, consent)?;
        Ok(JobSpec::DepsInstall {
            app,
            plan_digest: view.digest,
            yes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::PlanEntryView;
    use serde_json::json;

    fn spec(method: &str, p: serde_json::Value) -> Result<JobSpec, JobParamsError> {
        JobSpec::from_request(method, p)
    }

    fn kind_of(r: Result<JobSpec, JobParamsError>) -> Option<ErrorKind> {
        match r {
            Err(JobParamsError::Api(e)) => Some(e.kind),
            _ => None,
        }
    }

    fn is_shape(r: &Result<JobSpec, JobParamsError>) -> bool {
        matches!(r, Err(JobParamsError::Shape(_)))
    }

    fn argv(s: &JobSpec) -> Vec<String> {
        s.argv().into_iter().map(|a| a.into_string().unwrap()).collect()
    }

    const BAD_IDS: &[&str] = &[
        "-x",
        "--",
        "-",
        "a b",
        "a\nb",
        "a\0b",
        "x.exe",
        "X.ZIP",
        "x.zip",
        "a/b",
        "..",
        "",
        "A",
        "a\u{202e}b",
    ];

    #[test]
    fn app_ids_that_are_not_ids_or_read_as_paths_are_refused() {
        let long = "a".repeat(65);
        for bad in BAD_IDS.iter().copied().chain([long.as_str()]) {
            assert_eq!(app_id(bad).unwrap_err().kind, ErrorKind::InvalidArgument, "{bad:?}");
            for m in ["apps.run", "apps.remove", "permissions.reset"] {
                assert_eq!(
                    kind_of(spec(m, json!({ "id": bad }))),
                    Some(ErrorKind::InvalidArgument),
                    "{m} {bad:?}"
                );
            }
        }
        for ok in ["notepad", "a", "x.exe.d", "7zip", "a-b_c.d", &"a".repeat(64)] {
            assert_eq!(app_id(ok).unwrap().as_str(), ok);
        }
        assert_eq!(
            spec("apps.remove", json!({"id": "notepad"})).unwrap(),
            JobSpec::Remove {
                app: AppId::parse("notepad").unwrap()
            }
        );
    }

    #[test]
    fn installer_paths_are_absolute_plain_and_bounded() {
        let long = format!("/{}", "p".repeat(VALUE_MAX));
        for bad in [
            "setup.exe",
            "./setup.exe",
            "-x",
            "--",
            "",
            "/a/../b",
            "/a/./b",
            "/a/..",
            "/..",
            "/a/",
            "/",
            "/a\0b",
            "/a\nb",
            "/a\rb",
            "/a\u{202e}b.exe",
            "/a\u{1b}[31m",
            long.as_str(),
        ] {
            assert_eq!(
                kind_of(spec("apps.install", json!({ "path": bad }))),
                Some(ErrorKind::InvalidArgument),
                "{bad:?}"
            );
        }
        assert_eq!(long.len(), 4097);
        let max = format!("/{}", "p".repeat(VALUE_MAX - 1));
        for ok in [
            "/tmp/My Setup.exe",
            "/-x/setup.exe",
            "/a/.hidden/..b/c..",
            "/a//b",
            max.as_str(),
        ] {
            match spec("apps.install", json!({ "path": ok })).unwrap() {
                JobSpec::Install { path, .. } => assert_eq!(path, PathBuf::from(ok)),
                other => panic!("{other:?}"),
            }
        }
    }

    #[test]
    fn name_exe_and_expressions_are_bounded_and_visible() {
        let p = |name: serde_json::Value, exe: serde_json::Value| {
            spec("apps.install", json!({"path": "/s.exe", "name": name, "exe": exe}))
        };
        for bad in ["", "a\0b", "a\nb", "a\u{202e}b", "\u{1b}[31m"] {
            assert_eq!(
                kind_of(p(json!(bad), json!(null))),
                Some(ErrorKind::InvalidArgument),
                "{bad:?}"
            );
            assert_eq!(
                kind_of(p(json!(null), json!(bad))),
                Some(ErrorKind::InvalidArgument),
                "{bad:?}"
            );
            let r = spec("permissions.set", json!({"id": "a", "set": [bad]}));
            assert_eq!(kind_of(r), Some(ErrorKind::InvalidArgument), "{bad:?}");
        }
        assert!(p(json!("n".repeat(NAME_MAX)), json!("e".repeat(EXE_MAX))).is_ok());
        assert_eq!(
            kind_of(p(json!("n".repeat(NAME_MAX + 1)), json!(null))),
            Some(ErrorKind::InvalidArgument)
        );
        assert_eq!(
            kind_of(p(json!(null), json!("e".repeat(EXE_MAX + 1)))),
            Some(ErrorKind::InvalidArgument)
        );
        let set = |v: Vec<String>| spec("permissions.set", json!({"id": "a", "set": v}));
        assert!(set(vec!["x".repeat(VALUE_MAX)]).is_ok());
        assert!(set(vec!["network=allow".into(); MAX_SET]).is_ok());
        for bad in [
            vec![],
            vec!["x".repeat(VALUE_MAX + 1)],
            vec!["network=allow".into(); MAX_SET + 1],
        ] {
            assert_eq!(kind_of(set(bad)), Some(ErrorKind::InvalidArgument));
        }
        // Option-looking values are values: they stay inside `--flag=`.
        let s = p(json!("--network"), json!("--silent")).unwrap();
        assert!(matches!(
            &s,
            JobSpec::Install { name: Some(n), exe: Some(e), silent: false, network: false, .. }
                if n == "--network" && e == "--silent"
        ));
    }

    #[test]
    fn program_args_are_bounded_and_otherwise_verbatim() {
        let run = |args: Vec<String>| spec("apps.run", json!({"id": "a", "args": args}));
        let kept: Vec<String> = [
            "--",
            "-x",
            ";",
            "$(id)",
            "a b",
            "`x`",
            "--unsandboxed",
            "tab\there",
            "\u{202e}",
        ]
        .map(String::from)
        .to_vec();
        match run(kept.clone()).unwrap() {
            JobSpec::Run { args, .. } => assert_eq!(args, kept),
            other => panic!("{other:?}"),
        }
        assert!(run(vec!["a".into(); MAX_ARGS]).is_ok());
        assert!(run(vec!["a".repeat(VALUE_MAX)]).is_ok());
        assert!(run(vec!["a".repeat(ARGS_TOTAL_MAX / MAX_ARGS); MAX_ARGS]).is_ok());
        for bad in [
            vec!["a".into(); MAX_ARGS + 1],
            vec!["a".repeat(VALUE_MAX + 1)],
            vec!["a\0b".into()],
            {
                let mut v = vec!["a".repeat(ARGS_TOTAL_MAX / MAX_ARGS); MAX_ARGS];
                v[0].push('x');
                v
            },
        ] {
            assert_eq!(kind_of(run(bad)), Some(ErrorKind::InvalidArgument));
        }
        // no args at all is fine
        assert_eq!(
            spec("apps.run", json!({"id": "a"})).unwrap(),
            JobSpec::Run {
                app: AppId::parse("a").unwrap(),
                args: vec![]
            }
        );
    }

    #[test]
    fn params_of_the_wrong_shape_are_shape_errors() {
        for (m, p) in [
            ("apps.run", json!([])),
            ("apps.run", json!("a")),
            ("apps.run", json!(null)),
            ("apps.run", json!({})),
            ("apps.run", json!({"id": 1})),
            ("apps.run", json!({"id": "a", "args": "x"})),
            ("apps.run", json!({"id": "a", "unsandboxed": true})),
            ("apps.run", json!({"id": "a", "debug": true})),
            ("apps.install", json!({"path": "/a", "silent": "yes"})),
            ("apps.install", json!({"path": "/a", "env": {}})),
            ("apps.install", json!({"name": "x"})),
            ("apps.remove", json!({"id": "a", "force": true})),
            ("permissions.set", json!({"id": "a"})),
            ("permissions.set", json!({"id": "a", "set": "network=allow"})),
            ("permissions.reset", json!({"id": "a", "set": []})),
            ("display.set", json!({"id": "a", "driver": "X11"})),
            ("display.set", json!({"id": "a", "driver": "--reset"})),
            ("display.set", json!({"id": "a"})),
        ] {
            let r = spec(m, p.clone());
            assert!(is_shape(&r), "{m} {p}: {r:?}");
            if let Err(JobParamsError::Shape(msg)) = r {
                assert!(msg.chars().all(|c| !c.is_control() && !is_format(c)) && msg.len() <= 256);
            }
        }
        let e = spec("apps.remove", json!({"id": "a", "x\u{1b}[31m\u{202e}": 1})).unwrap_err();
        let JobParamsError::Shape(msg) = e else { panic!("{e:?}") };
        assert!(!msg.contains('\u{1b}') && !msg.contains('\u{202e}'), "{msg:?}");
        assert!(
            DepsInstallParams::from_value(json!({"id": "a", "planDigest": "x", "consent": [], "yesToAll": true}))
                .is_err()
        );
        assert!(DepsInstallParams::from_value(json!({"id": "a", "planDigest": "x"})).is_err());
        let d = DepsInstallParams::from_value(json!({
            "id": "a", "planDigest": "x", "consent": [{"package": "p", "version": "1", "sha256": "s"}]
        }))
        .unwrap();
        assert_eq!(d.consent[0].package, "p");
        assert!(
            DepsInstallParams::from_value(json!({
                "id": "a", "planDigest": "x", "consent": [{"package": "p", "version": "1", "sha256": "s", "all": 1}]
            }))
            .is_err()
        );
        // not a job method: the caller's bug
        for m in ["deps.install", "apps.uninstall", "rpc.version"] {
            assert_eq!(kind_of(spec(m, json!({"id": "a"}))), Some(ErrorKind::Internal), "{m}");
        }
    }

    #[test]
    fn argv_golden() {
        let id = || AppId::parse("notepad").unwrap();
        let digest_arg = format!("--plan-digest={}", "ab".repeat(32));
        let cases: Vec<(JobSpec, Vec<&str>, JobKind)> = vec![
            (
                JobSpec::Run {
                    app: id(),
                    args: vec!["-x".into(), "--".into(), ";".into()],
                },
                vec!["run", "notepad", "--", "-x", "--", ";"],
                JobKind::Run,
            ),
            (
                JobSpec::Run {
                    app: id(),
                    args: vec![],
                },
                vec!["run", "notepad", "--"],
                JobKind::Run,
            ),
            (
                JobSpec::Install {
                    path: "/tmp/My Setup.exe".into(),
                    name: Some("--network".into()),
                    exe: Some("--silent".into()),
                    silent: false,
                    network: false,
                },
                vec![
                    "install",
                    "--name=--network",
                    "--exe=--silent",
                    "--",
                    "/tmp/My Setup.exe",
                ],
                JobKind::Install,
            ),
            (
                JobSpec::Install {
                    path: "/-x/s.exe".into(),
                    name: None,
                    exe: None,
                    silent: true,
                    network: true,
                },
                vec!["install", "--silent", "--network", "--", "/-x/s.exe"],
                JobKind::Install,
            ),
            (
                JobSpec::Remove { app: id() },
                vec!["remove", "--", "notepad"],
                JobKind::Remove,
            ),
            (
                JobSpec::DepsInstall {
                    app: id(),
                    plan_digest: "ab".repeat(32),
                    yes: vec!["vcrun2022".into(), "-p".into()],
                },
                vec![
                    "deps",
                    "--install",
                    &digest_arg,
                    "--yes=vcrun2022",
                    "--yes=-p",
                    "--",
                    "notepad",
                ],
                JobKind::DepsInstall,
            ),
            (
                JobSpec::PermissionsSet {
                    app: id(),
                    set: vec!["--reset".into(), "network=allow".into()],
                },
                vec!["permissions", "--set=--reset", "--set=network=allow", "--", "notepad"],
                JobKind::PermissionsSet,
            ),
            (
                JobSpec::PermissionsReset { app: id() },
                vec!["permissions", "--reset", "--", "notepad"],
                JobKind::PermissionsReset,
            ),
            (
                JobSpec::DisplaySet {
                    app: id(),
                    driver: Driver::X11,
                },
                vec!["display", "--", "notepad", "x11"],
                JobKind::DisplaySet,
            ),
        ];
        for (s, want, kind) in cases {
            assert_eq!(argv(&s), want, "{s:?}");
            assert_eq!(s.kind(), kind);
            let app = s.app().map(AppId::as_str);
            assert_eq!(app, (kind != JobKind::Install).then_some("notepad"));
        }
    }

    fn entry(pkg: &str, action: rt_deps::Action, consent: rt_deps::ConsentState) -> rt_deps::PlanEntry {
        rt_deps::PlanEntry {
            package: pkg.into(),
            action,
            consent,
        }
    }

    fn app_plan(entries: Vec<rt_deps::PlanEntry>) -> rt_deps::AppPlan {
        rt_deps::AppPlan {
            facts: rt_deps::Facts {
                imports: vec![],
                extra_capabilities: vec![],
            },
            plan: rt_deps::Plan {
                entries,
                unsatisfied: vec![],
            },
            warnings: vec![],
        }
    }

    fn gated_plan() -> rt_deps::AppPlan {
        use rt_deps::{Action, ConsentState};
        app_plan(vec![
            entry("vcrun2022", Action::Install, ConsentState::Needed),
            entry("dxvk", Action::Install, ConsentState::NotNeeded),
            entry("vkd3d-proton", Action::AlreadyInstalled, ConsentState::NotNeeded),
        ])
    }

    #[test]
    fn plan_digest_is_stable_and_every_field_changes_it() {
        use rt_deps::{Action, ConsentState};
        let m = rt_deps::Manifest::bundled();
        let id = AppId::parse("game").unwrap();
        let base = plan_digest(&id, &gated_plan(), m);
        assert_eq!(base.len(), 64);
        assert!(base.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        assert_eq!(base, plan_digest(&id, &gated_plan(), m), "not stable");
        // Pinned: the formula is a contract between runtimed and runtime (spec 5.3).
        let mut text = String::from("rt-deps-plan-v2\ngame\n");
        for (p, a, c) in [
            ("vcrun2022", "install", "needed"),
            ("dxvk", "install", "notNeeded"),
            ("vkd3d-proton", "alreadyInstalled", "notNeeded"),
        ] {
            let pkg = m.get(p).unwrap();
            let licence: String = Sha256::digest(rt_deps::consent_text(pkg).as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            text.push_str(&format!("{p}\0{}\0{}\0{licence}\0{a}\0{c}\n", pkg.version, pkg.sha256));
        }
        let want: String = Sha256::digest(text.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(base, want);

        let mut changed = vec![plan_digest(&AppId::parse("gamf").unwrap(), &gated_plan(), m)];
        let tweak = |f: &dyn Fn(&mut rt_deps::AppPlan)| {
            let mut p = gated_plan();
            f(&mut p);
            plan_digest(&id, &p, m)
        };
        changed.push(tweak(&|p| p.plan.entries[0].consent = ConsentState::Denied));
        changed.push(tweak(&|p| p.plan.entries[1].action = Action::AlreadyInstalled));
        changed.push(tweak(&|p| {
            p.plan.entries[1].action = Action::Blocked { reason: "r".into() }
        }));
        changed.push(tweak(&|p| p.plan.entries.swap(0, 1)));
        changed.push(tweak(&|p| {
            p.plan.entries.pop();
        }));
        changed.push(tweak(&|p| p.plan.entries[2].package = "unknown-pkg".into()));
        let mut m2 = m.clone();
        m2.packages
            .iter_mut()
            .find(|p| p.id == "vcrun2022")
            .unwrap()
            .version
            .push('1');
        changed.push(plan_digest(&id, &gated_plan(), &m2));
        let mut m3 = m.clone();
        let p = m3.packages.iter_mut().find(|p| p.id == "dxvk").unwrap();
        p.sha256 = p
            .sha256
            .replacen(&p.sha256[..1], if p.sha256.starts_with('0') { "1" } else { "0" }, 1);
        changed.push(plan_digest(&id, &gated_plan(), &m3));
        // Only the consent text (the download address it shows) differs: the user consented to another text.
        let mut m4 = m.clone();
        m4.packages
            .iter_mut()
            .find(|p| p.id == "vcrun2022")
            .unwrap()
            .url
            .push('x');
        changed.push(plan_digest(&id, &gated_plan(), &m4));
        for (i, c) in changed.iter().enumerate() {
            assert_ne!(*c, base, "change {i} kept the digest");
        }
        // An entry with no manifest record hashes empty version, sha256 and licence hash.
        let lone = app_plan(vec![entry("nope", Action::Install, ConsentState::NotNeeded)]);
        let want: String = Sha256::digest(b"rt-deps-plan-v2\ngame\nnope\0\0\0\0install\0notNeeded\n")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(plan_digest(&id, &lone, m), want);
    }

    fn view() -> DepsPlanView {
        DepsPlanView::from_plan(
            &AppId::parse("game").unwrap(),
            &gated_plan(),
            rt_deps::Manifest::bundled(),
        )
    }

    fn item(pkg: &str) -> ConsentItem {
        let p = rt_deps::Manifest::bundled().get(pkg).unwrap();
        ConsentItem {
            package: p.id.clone(),
            version: p.version.clone(),
            sha256: p.sha256.clone(),
        }
    }

    #[test]
    fn check_consent_accepts_only_the_exact_plan() {
        let v = view();
        let d = v.digest.clone();
        assert_eq!(check_consent(&v, &d, &[item("vcrun2022")]).unwrap(), vec!["vcrun2022"]);
        assert_eq!(check_consent(&v, &d, &[]).unwrap(), Vec::<String>::new());
        let flip = |s: &str| {
            let mut b = s.as_bytes().to_vec();
            let last = b.len() - 1;
            b[last] = if b[last] == b'0' { b'1' } else { b'0' };
            String::from_utf8(b).unwrap()
        };
        let mismatch = |digest: &str, items: &[ConsentItem]| {
            assert_eq!(
                check_consent(&v, digest, items).unwrap_err().kind,
                ErrorKind::ConsentMismatch,
                "{digest} {items:?}"
            );
        };
        mismatch(&flip(&d), &[item("vcrun2022")]);
        mismatch(&flip(&d), &[]);
        let mut unknown = item("vcrun2022");
        unknown.package = "vcrun2023".into();
        mismatch(&d, &[unknown]);
        let mut ver = item("vcrun2022");
        ver.version = flip(&ver.version);
        mismatch(&d, &[ver]);
        let mut sha = item("vcrun2022");
        sha.sha256 = flip(&sha.sha256);
        mismatch(&d, &[sha]);
        mismatch(&d, &[item("vcrun2022"), item("vcrun2022")]);
        mismatch(&d, &[item("dxvk")]); // notNeeded
        mismatch(&d, &[item("vkd3d-proton")]); // alreadyInstalled
        mismatch(&d, &[item("vcrun2022"), item("dxvk")]);
        // a needed entry that is blocked or already installed cannot be consented to
        use rt_deps::{Action, ConsentState};
        for action in [Action::AlreadyInstalled, Action::Blocked { reason: "r".into() }] {
            let p = app_plan(vec![entry("vcrun2022", action, ConsentState::Needed)]);
            let v = DepsPlanView::from_plan(&AppId::parse("game").unwrap(), &p, rt_deps::Manifest::bundled());
            let e = check_consent(&v, &v.digest.clone(), &[item("vcrun2022")]).unwrap_err();
            assert_eq!(e.kind, ErrorKind::ConsentMismatch);
        }
    }

    #[test]
    fn deps_install_spec_validates_then_recomputes_the_plan() {
        let dir = tempfile::tempdir().unwrap();
        let store = rt_core::Store::new(dir.path().join("apps")).unwrap();
        let rt = Runtime::with_store(store);
        let good = "0".repeat(64);
        for bad in BAD_IDS {
            assert_eq!(
                rt.deps_install_spec(bad, &good, &[]).unwrap_err().kind,
                ErrorKind::InvalidArgument,
                "{bad:?}"
            );
        }
        for d in [
            "",
            "0",
            &"0".repeat(63),
            &"0".repeat(65),
            &"A".repeat(64),
            &"g".repeat(64),
            &format!("-{}", "0".repeat(63)),
        ] {
            assert_eq!(
                rt.deps_install_spec("a", d, &[]).unwrap_err().kind,
                ErrorKind::InvalidArgument,
                "{d:?}"
            );
        }
        let many: Vec<ConsentItem> = (0..=MAX_CONSENT)
            .map(|i| ConsentItem {
                package: format!("p{i}"),
                version: "1".into(),
                sha256: "s".into(),
            })
            .collect();
        assert_eq!(
            rt.deps_install_spec("a", &good, &many).unwrap_err().kind,
            ErrorKind::InvalidArgument
        );
        let huge = ConsentItem {
            package: "p".repeat(TEXT_MAX + 1),
            version: "1".into(),
            sha256: "s".into(),
        };
        assert_eq!(
            rt.deps_install_spec("a", &good, &[huge]).unwrap_err().kind,
            ErrorKind::InvalidArgument
        );
        // well-formed but not installed
        assert_eq!(
            rt.deps_install_spec("a", &good, &[]).unwrap_err().kind,
            ErrorKind::NotFound
        );
    }

    #[test]
    fn deps_install_spec_of_an_installed_app_matches_its_plan() {
        let dir = tempfile::tempdir().unwrap();
        let store = rt_core::Store::new(dir.path().join("apps")).unwrap();
        let id = AppId::parse("plain").unwrap();
        let env = store.create(&id).unwrap();
        let exe = rt_core::WinPath::parse(r"C:\a.exe").unwrap();
        let backend = rt_core::BackendInfo {
            id: "wine".into(),
            version: "10.0".into(),
        };
        let md = rt_core::Metadata::new(id.clone(), "P".into(), None, "x86_64", &exe, backend, "gui");
        store.write_metadata(&env, &md).unwrap();
        let rt = Runtime::with_store(store);
        let v = rt.deps_plan("plain").unwrap();
        assert!(v.entries.is_empty());
        let s = rt.deps_install_spec("plain", &v.digest, &[]).unwrap();
        assert_eq!(
            s,
            JobSpec::DepsInstall {
                app: id,
                plan_digest: v.digest.clone(),
                yes: vec![]
            }
        );
        let e = rt.deps_install_spec("plain", &"0".repeat(64), &[]).unwrap_err();
        assert_eq!(e.kind, ErrorKind::ConsentMismatch);
        let e = rt
            .deps_install_spec("plain", &v.digest, &[item("vcrun2022")])
            .unwrap_err();
        assert_eq!(e.kind, ErrorKind::ConsentMismatch);
    }

    fn round_trip<T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug>(v: T) -> serde_json::Value {
        let j = serde_json::to_value(&v).unwrap();
        assert_eq!(serde_json::from_value::<T>(j.clone()).unwrap(), v);
        j
    }

    #[test]
    fn the_job_wire_types_round_trip_in_camel_case() {
        let info = JobInfo {
            job_id: "0".repeat(32),
            kind: JobKind::DepsInstall,
            app: Some("a".into()),
            state: JobState::Succeeded,
            exit_code: Some(0),
            signal: None,
            created_at: 1,
            started_at: Some(2),
            ended_at: None,
            dropped: 3,
        };
        let j = round_trip(info.clone());
        assert_eq!(
            (j["jobId"].as_str(), j["kind"].as_str(), j["state"].as_str()),
            (
                Some("00000000000000000000000000000000"),
                Some("depsInstall"),
                Some("succeeded")
            )
        );
        assert!(j["exitCode"].is_number() && j["signal"].is_null() && j["createdAt"].is_number());
        assert!(j["startedAt"].is_number() && j["endedAt"].is_null());
        let ev = JobEvents {
            events: vec![JobEvent {
                seq: 1,
                ts: 5,
                kind: EventKind::Stderr,
                text: "t".into(),
            }],
            next_seq: 2,
            dropped: 0,
            job: info,
        };
        let j = round_trip(ev);
        assert_eq!(j["events"][0]["kind"], "stderr");
        assert!(j["nextSeq"].is_number());
        assert_eq!(round_trip(JobStarted { job_id: "x".into() })["jobId"], "x");
        round_trip(item("vcrun2022"));
        for (k, s) in [
            (JobKind::Run, "run"),
            (JobKind::Install, "install"),
            (JobKind::Remove, "remove"),
            (JobKind::DepsInstall, "depsInstall"),
            (JobKind::PermissionsSet, "permissionsSet"),
            (JobKind::PermissionsReset, "permissionsReset"),
            (JobKind::DisplaySet, "displaySet"),
        ] {
            assert_eq!(round_trip(k), s);
        }
        for (k, s) in [
            (JobState::Queued, "queued"),
            (JobState::Running, "running"),
            (JobState::Succeeded, "succeeded"),
            (JobState::Failed, "failed"),
            (JobState::Cancelled, "cancelled"),
        ] {
            assert_eq!(round_trip(k), s);
        }
        for (k, s) in [
            (EventKind::Stdout, "stdout"),
            (EventKind::Stderr, "stderr"),
            (EventKind::State, "state"),
            (EventKind::Progress, "progress"),
        ] {
            assert_eq!(round_trip(k), s);
        }
        // A newer daemon's kind, state or event kind never breaks an older client.
        let j: JobInfo = serde_json::from_value(json!({
            "jobId": "x", "kind": "stop", "app": null, "state": "paused", "exitCode": null, "signal": null,
            "createdAt": 1, "startedAt": null, "endedAt": null, "dropped": 0
        }))
        .unwrap();
        assert_eq!((j.kind, j.state), (JobKind::Unknown, JobState::Unknown));
        let e: JobEvent = serde_json::from_value(json!({"seq": 1, "ts": 1, "kind": "percent", "text": ""})).unwrap();
        assert_eq!(e.kind, EventKind::Unknown);
        // A client-sent driver is never read leniently.
        assert!(serde_json::from_value::<Driver>(json!("vnc")).is_err());
        // A 0.1 daemon's deps.plan has no digest: it reads as empty (such a daemon has no deps.install).
        let old: DepsPlanView =
            serde_json::from_value(json!({"entries": [], "unsatisfied": [], "warnings": []})).unwrap();
        assert_eq!(old.digest, "");
        for (d, s) in [
            (Driver::Auto, "auto"),
            (Driver::X11, "x11"),
            (Driver::Wayland, "wayland"),
        ] {
            assert_eq!(round_trip(d), s);
            assert_eq!(d.as_str(), s);
        }
        for (k, s) in [
            (ErrorKind::ReadOnly, "read_only"),
            (ErrorKind::ConsentMismatch, "consent_mismatch"),
            (ErrorKind::Busy, "busy"),
            (ErrorKind::AppBusy, "app_busy"),
        ] {
            assert_eq!(round_trip(ApiError::new(k, "m"))["kind"], s);
        }
    }

    #[test]
    fn plan_view_carries_digest_hash_and_consent_text_only_where_needed() {
        let v = view();
        assert_eq!(
            v.digest,
            plan_digest(
                &AppId::parse("game").unwrap(),
                &gated_plan(),
                rt_deps::Manifest::bundled()
            )
        );
        let m = rt_deps::Manifest::bundled();
        for e in &v.entries {
            assert_eq!(e.sha256.as_deref(), Some(m.get(&e.package).unwrap().sha256.as_str()));
        }
        let by = |p: &str| -> &PlanEntryView { v.entries.iter().find(|e| e.package == p).unwrap() };
        assert!(by("dxvk").consent_text.is_none() && by("vkd3d-proton").consent_text.is_none());
        let text = by("vcrun2022").consent_text.clone().unwrap();
        let want: Vec<String> = rt_deps::consent_text(m.get("vcrun2022").unwrap())
            .split('\n')
            .map(String::from)
            .collect();
        assert_eq!(text, want, "a benign text is shown whole, line by line");
        let j = serde_json::to_value(&v).unwrap();
        assert!(j["digest"].is_string() && j["entries"][0]["sha256"].is_string());
        assert!(j["entries"][0]["consentText"].is_array() && j["entries"][1]["consentText"].is_null());
        assert_eq!(serde_json::from_value::<DepsPlanView>(j).unwrap(), v);
        // An entry with no manifest record: no hash, no text.
        let p = app_plan(vec![entry(
            "nope",
            rt_deps::Action::Install,
            rt_deps::ConsentState::Needed,
        )]);
        let v = DepsPlanView::from_plan(&AppId::parse("game").unwrap(), &p, m);
        assert_eq!(
            (v.entries[0].sha256.as_ref(), v.entries[0].consent_text.as_ref()),
            (None, None)
        );
    }

    #[test]
    fn a_hostile_consent_text_is_cleaned_line_by_line() {
        let mut m = rt_deps::Manifest::bundled().clone();
        let p = m.packages.iter_mut().find(|p| p.id == "vcrun2022").unwrap();
        p.licence = "evil\u{1b}[31m\u{202e}lic\u{200b}".into();
        p.url = "https://x/\u{9b}31m\r\u{2066}y".into();
        let v = DepsPlanView::from_plan(&AppId::parse("game").unwrap(), &gated_plan(), &m);
        let text = v.entries[0].consent_text.clone().unwrap();
        assert!(text.len() > 3, "{text:?}");
        for line in &text {
            assert!(!line.chars().any(|c| c.is_control() || is_format(c)), "{line:?}");
        }
        assert!(text.iter().any(|l| l.contains("evil")), "{text:?}");
    }
}
