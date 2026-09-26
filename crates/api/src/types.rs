//! The wire types. Every one is `Serialize + Deserialize` (camelCase, like `metadata.json`) and is built from
//! untrusted data only through the `from_*` constructors, which clean every string: `text` removes control and
//! format characters (bidi overrides, zero-width, newlines) and cuts to a bound.
//!
//! Cleaning is LOSSY: removed characters can make two different values display identically (an escaped form
//! may follow). Adding a string field to any type here requires covering it in the `no_string_anywhere_holds_an_
//! invisible_character` test in `runtime.rs`, which walks every serialised string, keys included (the views of
//! `doctor` and `sandbox_info`, which probe the host, are walked by the `api_*` tests of `crates/cli/tests/apps.rs`
//! over the CLI's fake-Wine rig).
use rt_core::{AppEnv, DependencyRecord, InstallerMeta, Metadata, clean_text};
use rt_sandbox::{Access, Network, Permissions, Tasks};
use serde::{Deserialize, Serialize};
use std::fs;

/// Longest names, versions and ids-like fields, in bytes.
pub const TEXT_MAX: usize = 256;
/// Longest executable and uninstall command, in bytes (`rt_core::MAX_FIELD_LEN`, what metadata validation allows).
pub const LONG_MAX: usize = rt_core::MAX_FIELD_LEN;
/// Longest grant path, in bytes (Linux `PATH_MAX`, what the grant validator allows): never shown cut.
pub const PATH_MAX: usize = 4096;

fn text(s: &str) -> String {
    clean_text(s, TEXT_MAX)
}

fn long(s: &str) -> String {
    clean_text(s, LONG_MAX)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionInfo {
    pub api: String,
    pub runtime: String,
    pub protocol: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSummary {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub architecture: String,
    pub executable: String,
    pub created: u64,
}

impl AppSummary {
    pub(crate) fn from_metadata(m: &Metadata) -> AppSummary {
        AppSummary {
            id: m.id.as_str().to_owned(),
            name: text(&m.name),
            version: m.version.as_deref().map(text),
            architecture: text(&m.architecture),
            executable: long(&m.executable),
            created: m.created,
        }
    }
}

/// `apps()`: the usable apps and how many entries of the apps directory were skipped (corrupt metadata, a
/// symlink, a stray file, an id mismatch, too many entries); the API never prints a warning. `skipped` is a
/// lower bound when the store hit its entry cap: that whole tail counts as one skip.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppList {
    pub apps: Vec<AppSummary>,
    pub skipped: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BackendView {
    pub id: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InstallerView {
    pub family: String,
    pub product_name: Option<String>,
    pub uninstall_command: Option<String>,
}

impl InstallerView {
    fn from_meta(i: &InstallerMeta) -> InstallerView {
        InstallerView {
            family: text(&i.family),
            product_name: i.product_name.as_deref().map(text),
            uninstall_command: i.uninstall_command.as_deref().map(long),
        }
    }
}

/// A package the runtime installed into the app (id and version only: hashes and consent records stay private).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DependencyView {
    pub id: String,
    pub version: String,
    pub installed_at: u64,
}

impl DependencyView {
    fn from_record(d: &DependencyRecord) -> DependencyView {
        DependencyView {
            id: text(&d.id),
            version: text(&d.version),
            installed_at: d.installed_at,
        }
    }
}

/// Whether the prefix exists, from two `lstat`s: its contents are never read and a symlink counts as absent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrefixState {
    pub exists: bool,
    pub has_drive_c: bool,
}

impl PrefixState {
    fn probe(env: &AppEnv) -> PrefixState {
        let real_dir = |p: std::path::PathBuf| fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_dir());
        // `lstat` refuses only a symlink in the LAST component: a symlinked prefix must stop the second probe.
        let exists = real_dir(env.prefix());
        PrefixState {
            exists,
            has_drive_c: exists && real_dir(env.drive_c()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppDetail {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub architecture: String,
    pub executable: String,
    pub environment: String,
    pub backend: BackendView,
    pub subsystem: String,
    pub created: u64,
    pub installer: Option<InstallerView>,
    pub dependencies: Vec<DependencyView>,
    pub prefix: PrefixState,
}

impl AppDetail {
    pub(crate) fn from_parts(env: &AppEnv, m: &Metadata) -> AppDetail {
        AppDetail {
            id: m.id.as_str().to_owned(),
            name: text(&m.name),
            version: m.version.as_deref().map(text),
            architecture: text(&m.architecture),
            executable: long(&m.executable),
            environment: text(&m.environment),
            backend: BackendView {
                id: text(&m.backend.id),
                version: text(&m.backend.version),
            },
            subsystem: text(&m.subsystem),
            created: m.created,
            installer: m.installer.as_ref().map(InstallerView::from_meta),
            dependencies: m.dependencies.iter().map(DependencyView::from_record).collect(),
            prefix: PrefixState::probe(env),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum NetworkView {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum AccessView {
    Ro,
    Rw,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GrantView {
    pub path: String,
    pub access: AccessView,
}

/// The limits, with what the file asked for kept apart from what is applied by default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LimitsView {
    /// `None`: no memory limit set.
    pub memory_mb: Option<u64>,
    /// `None`: no CPU limit set.
    pub cpu_percent: Option<u32>,
    /// The task limit that applies (`None` = unlimited).
    pub tasks: Option<u32>,
    /// `tasks` is the built-in default, not something the file set.
    pub tasks_default: bool,
    /// The file sets at least one mandatory limit (memory, CPU or a task count).
    pub explicit: bool,
}

/// Where the profile came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum PermSource {
    /// No `permissions.toml`: the built-in default.
    Default,
    /// A valid `permissions.toml`.
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionsView {
    pub source: PermSource,
    pub network: NetworkView,
    pub display: bool,
    pub audio: bool,
    pub gpu: bool,
    pub filesystem: Vec<GrantView>,
    pub limits: LimitsView,
}

impl PermissionsView {
    pub(crate) fn from_profile(p: &Permissions, source: PermSource) -> PermissionsView {
        let l = &p.limits;
        PermissionsView {
            source,
            network: if p.network == Network::Allow {
                NetworkView::Allow
            } else {
                NetworkView::Deny
            },
            display: p.display,
            audio: p.audio,
            gpu: p.gpu,
            filesystem: p
                .filesystem
                .iter()
                .map(|g| GrantView {
                    path: clean_text(&g.path.to_string_lossy(), PATH_MAX),
                    access: if g.access == Access::Rw {
                        AccessView::Rw
                    } else {
                        AccessView::Ro
                    },
                })
                .collect(),
            limits: LimitsView {
                memory_mb: l.memory_mb,
                cpu_percent: l.cpu_percent,
                tasks: l.tasks_max(),
                tasks_default: l.tasks == Tasks::Default,
                explicit: l.explicit(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatRecord {
    pub app: String,
    pub version: Option<String>,
    pub status: crate::compat::Status,
    pub wine: String,
    pub gpu: Option<String>,
    pub graphics: bool,
    pub evidence: Option<String>,
    pub notes: Option<String>,
}

impl CompatRecord {
    pub(crate) fn from_record(r: &crate::compat::Record) -> CompatRecord {
        let opt = |o: &Option<String>| o.as_deref().map(text);
        CompatRecord {
            app: text(&r.app),
            version: opt(&r.version),
            status: r.status,
            wine: text(&r.wine),
            gpu: opt(&r.gpu),
            graphics: r.graphics,
            evidence: opt(&r.evidence),
            notes: opt(&r.notes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompatView {
    pub records: Vec<CompatRecord>,
}

// ------------------------------------------------------------------------------------------------ doctor

/// What `doctor` checks: the system only, or an installed app too. (A file that is not installed is the CLI's
/// `doctor <file>` only: it reads an arbitrary user-supplied path.)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DoctorTarget {
    System,
    App(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
#[non_exhaustive]
pub enum SubjectView {
    System,
    App {
        id: String,
        name: Option<String>,
        version: Option<String>,
    },
}

/// One check: `area` (`architecture`, `pe`, `imports`, `graphics`, `audio`, `runtime`, `prefix`, `program`) and
/// `status` (`ok`, `warn`, `fail`) are stable, the same strings `doctor --json` prints; `text` is prose for people,
/// not a stable API.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckView {
    pub area: String,
    pub status: String,
    pub text: String,
}

/// `doctor`'s report: `verdict` is `good`, `may_fail` or `fail` (stable, as `doctor --json`). `missing_dependencies`
/// counts what `runtime deps <app> --install` would install (the CLI's hint); `notes` name installer packages
/// already in the prefix that the runtime did not install.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorView {
    pub subject: SubjectView,
    pub verdict: String,
    pub checks: Vec<CheckView>,
    pub missing_dependencies: usize,
    pub notes: Vec<String>,
}

impl DoctorView {
    pub(crate) fn from_report(r: &rt_core::doctor::Report, plan: Option<&rt_deps::AppPlan>) -> DoctorView {
        use crate::host::doctor::{area_id, status_id, verdict_id};
        use rt_core::doctor::Subject;
        DoctorView {
            subject: match &r.subject {
                Subject::App { id, name, version } => SubjectView::App {
                    id: text(id),
                    name: name.as_deref().map(text),
                    version: version.as_deref().map(text),
                },
                // A file subject is never built through the API.
                Subject::System | Subject::File { .. } => SubjectView::System,
            },
            verdict: verdict_id(r.verdict).to_owned(),
            checks: r
                .checks
                .iter()
                .map(|c| CheckView {
                    area: area_id(c.area).to_owned(),
                    status: status_id(c.status).to_owned(),
                    text: long(&c.text),
                })
                .collect(),
            missing_dependencies: plan.map_or(0, |p| {
                p.plan
                    .entries
                    .iter()
                    .filter(|e| e.action == rt_deps::Action::Install)
                    .count()
            }),
            notes: plan.map_or_else(Vec::new, |p| {
                p.warnings
                    .iter()
                    .filter(|w| w.ends_with(rt_deps::MARKER_PRESENT))
                    .map(|w| long(w))
                    .collect()
            }),
        }
    }
}

// ------------------------------------------------------------------------------------------------ graphics

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GpuView {
    pub name: String,
    /// `vulkaninfo`'s `deviceType` without its prefix: `DISCRETE_GPU`, `INTEGRATED_GPU`, `CPU` (software), ...
    pub device_type: String,
    /// `major.minor` of the device's Vulkan API version.
    pub api: String,
    pub driver: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum VulkanState {
    Usable,
    Unusable,
    /// The device list could not be read: that never blocks anything.
    Unknown,
}

/// A bundled package's minimum Vulkan and whether this host meets it (`None`: unknown).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageVulkanView {
    pub id: String,
    pub min_vulkan: String,
    pub ok: Option<bool>,
}

/// `runtime graphics info`: the Vulkan devices and the verdict against the smallest bundled minimum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GraphicsView {
    pub devices: Vec<GpuView>,
    pub verdict: VulkanState,
    /// Why it is unusable or unknown.
    pub reason: Option<String>,
    pub per_package: Vec<PackageVulkanView>,
    /// The Vulkan loader (`libvulkan.so.1`) was found.
    pub loader: bool,
    /// `vulkaninfo` ran and answered in time.
    pub tool_found: bool,
}

impl GraphicsView {
    pub(crate) fn from_host(h: &rt_core::HostVulkan, needs: &[(&str, (u32, u32))]) -> GraphicsView {
        use rt_core::{VulkanVerdict, host_verdict};
        let (verdict, reason) = match host_verdict(h, needs.iter().map(|n| n.1).min()) {
            VulkanVerdict::Usable => (VulkanState::Usable, None),
            VulkanVerdict::Unusable(why) => (VulkanState::Unusable, Some(long(&why))),
            VulkanVerdict::Unknown if !h.tool_found => (
                VulkanState::Unknown,
                Some("vulkaninfo is missing, failed or timed out".to_owned()),
            ),
            VulkanVerdict::Unknown => (VulkanState::Unknown, Some("vulkaninfo listed no devices".to_owned())),
        };
        GraphicsView {
            devices: h
                .devices
                .iter()
                .map(|d| GpuView {
                    name: text(&d.name),
                    device_type: text(
                        d.device_type
                            .strip_prefix("PHYSICAL_DEVICE_TYPE_")
                            .unwrap_or(&d.device_type),
                    ),
                    api: format!("{}.{}", d.api.0, d.api.1),
                    driver: text(&d.driver),
                })
                .collect(),
            verdict,
            reason,
            per_package: needs
                .iter()
                .map(|(id, (major, minor))| PackageVulkanView {
                    id: text(id),
                    min_vulkan: format!("{major}.{minor}"),
                    ok: match host_verdict(h, Some((*major, *minor))) {
                        VulkanVerdict::Usable => Some(true),
                        VulkanVerdict::Unusable(_) => Some(false),
                        VulkanVerdict::Unknown => None,
                    },
                })
                .collect(),
            loader: h.loader_found,
            tool_found: h.tool_found,
        }
    }
}

// ------------------------------------------------------------------------------------------------ sandbox

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase")]
#[non_exhaustive]
pub enum Availability {
    Available,
    Unavailable { reason: String },
}

impl Availability {
    fn of<T>(r: &Result<T, String>) -> Availability {
        match r {
            Ok(_) => Availability::Available,
            Err(why) => Availability::Unavailable { reason: long(why) },
        }
    }
}

/// `runtime sandbox <app>`: what the app's sandbox would be on this host, without running anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxView {
    /// bubblewrap on `PATH` that can really create a sandbox (`runtime run` refuses without it).
    pub bwrap: Availability,
    /// Wine (only used to describe the command; without it the command shows `wine` and no Wine directories).
    pub wine: Availability,
    pub profile: PermissionsView,
    pub seccomp: String,
    pub landlock: String,
    /// seccomp and Landlock are both fully there.
    pub hardening_complete: bool,
    /// `systemd-run --user` scopes (the resource limits) work here.
    pub limits: Availability,
    pub cgroup_controllers: Vec<String>,
    /// Why the sandbox would refuse this app's command, if it would.
    pub refused: Option<String>,
    /// What the host lacks for this profile (left out of the sandbox).
    pub skipped: Vec<String>,
    /// What the host or the profile cannot enforce (the hardening caveat first).
    pub caveats: Vec<String>,
    /// The command line `runtime run` would start, one argument each.
    pub command: Vec<String>,
}

impl SandboxView {
    pub(crate) fn from_status(st: &crate::host::sandbox::Status, source: PermSource) -> SandboxView {
        let h = &st.hardening;
        SandboxView {
            bwrap: Availability::of(&st.bwrap),
            wine: Availability::of(&st.wine),
            profile: PermissionsView::from_profile(&st.profile, source),
            seccomp: long(&h.seccomp),
            landlock: long(&h.landlock),
            hardening_complete: h.complete && h.caveat.is_none(),
            limits: Availability::of(&st.scopes),
            cgroup_controllers: st
                .scopes
                .as_ref()
                .map_or_else(|_| vec![], |s| s.controllers.iter().map(|c| text(c)).collect()),
            refused: st.refused.as_deref().map(long),
            skipped: st.skipped.iter().map(|s| long(s)).collect(),
            caveats: h.caveat.iter().chain(&st.caveats).map(|c| long(c)).collect(),
            command: st
                .argv
                .iter()
                .map(|a| clean_text(&a.to_string_lossy(), PATH_MAX))
                .collect(),
        }
    }
}

// ------------------------------------------------------------------------------------------------ dependency plan

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum PlanAction {
    Install,
    AlreadyInstalled,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum ConsentView {
    NotNeeded,
    Needed,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlanEntryView {
    pub package: String,
    /// The bundled manifest's version of the package (`None`: not in the manifest).
    pub version: Option<String>,
    pub action: PlanAction,
    pub consent: ConsentView,
    pub blocked_reason: Option<String>,
}

/// `runtime deps <app>` without `--install`: dependencies first; `unsatisfied` are needed capabilities no bundled
/// package provides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DepsPlanView {
    pub entries: Vec<PlanEntryView>,
    pub unsatisfied: Vec<String>,
    pub warnings: Vec<String>,
}

impl DepsPlanView {
    pub(crate) fn from_plan(p: &rt_deps::AppPlan, manifest: &rt_deps::Manifest) -> DepsPlanView {
        use rt_deps::{Action, ConsentState};
        DepsPlanView {
            entries: p
                .plan
                .entries
                .iter()
                .map(|e| PlanEntryView {
                    package: text(&e.package),
                    version: manifest.get(&e.package).map(|m| text(&m.version)),
                    action: match e.action {
                        Action::Install => PlanAction::Install,
                        Action::AlreadyInstalled => PlanAction::AlreadyInstalled,
                        Action::Blocked { .. } => PlanAction::Blocked,
                    },
                    consent: match e.consent {
                        ConsentState::NotNeeded => ConsentView::NotNeeded,
                        ConsentState::Needed => ConsentView::Needed,
                        ConsentState::Denied => ConsentView::Denied,
                    },
                    blocked_reason: match &e.action {
                        Action::Blocked { reason } => Some(long(reason)),
                        _ => None,
                    },
                })
                .collect(),
            unsatisfied: p.plan.unsatisfied.iter().map(|u| text(u)).collect(),
            warnings: p.warnings.iter().map(|w| long(w)).collect(),
        }
    }
}
