//! The wire types. Every one is `Serialize + Deserialize` (camelCase, like `metadata.json`) and is built from
//! untrusted data only through the `from_*` constructors, which clean every string: `text` removes control and
//! format characters (bidi overrides, zero-width, newlines) and cuts to a bound.
//!
//! Cleaning is LOSSY: removed characters can make two different values display identically (an escaped form
//! may follow). Adding a string field to any type here requires covering it in the `no_string_anywhere_holds_an_
//! invisible_character` test in `runtime.rs`, which walks every serialised string, keys included.
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
