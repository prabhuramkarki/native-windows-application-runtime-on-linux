//! The bundled package manifest: types, strict TOML parsing and validation.
//!
//! The manifest is the only trusted input of the dependency engine, so everything is checked up front: unknown
//! fields, ids, urls, hashes, sizes, paths, dependency references and cycles. The bundled copy is checked by a
//! test so a bad manifest cannot ship.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

/// Manifest text above this is rejected before parsing (`toml` has no input cap of its own).
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// Largest download a package may declare (4 GiB).
pub const MAX_PACKAGE_SIZE: u64 = 4 * 1024 * 1024 * 1024;
/// Longest relative path (extract `from`/`to`, marker file).
pub const MAX_PATH_LEN: usize = 260;
/// Longest free-text value (silent argument, registry key or value name).
pub const MAX_TEXT_LEN: usize = 512;
/// Longest url.
pub const MAX_URL_LEN: usize = 2048;
/// Most entries in a per-package list (provides, extract, silent_args). `requires` is bounded by uniqueness.
pub const MAX_LIST_LEN: usize = 64;
/// Longest id, version, licence or provided name.
const MAX_NAME_LEN: usize = 64;
/// The one non-SPDX licence value; it forces `requires_consent = true`.
pub const PROPRIETARY: &str = "proprietary-redistributable";
/// Longest attacker-controlled value echoed in an error message.
const MAX_ECHO: usize = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Archive,
    Installer,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Package {
    pub id: String,
    pub version: String,
    pub sha256: String,
    pub size: u64,
    pub licence: String,
    pub url: String,
    pub kind: Kind,
    pub requires_consent: bool,
    pub requires: Vec<String>,
    pub provides: Vec<String>,
    /// The lowest Vulkan API version (`major.minor`) the package needs from the host; `None` if it needs no Vulkan.
    pub min_vulkan: Option<(u32, u32)>,
    pub install: Install,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Install {
    /// A downloaded archive in `format` (the url's extension must agree) whose `extract` entries are copied into
    /// `drive_c`; `dll_overrides` names only DLLs from the package's `provides`.
    Archive {
        format: ArchiveFormat,
        extract: Vec<Extract>,
        dll_overrides: Vec<String>,
    },
    /// A vendor installer run with `silent_args`, confirmed by `marker`; after it succeeded, `dll_overrides`
    /// (optional in the TOML, names from the package's `provides`) are set to `native,builtin` so Wine loads the
    /// installed DLLs instead of its own builtins of the same name.
    Installer {
        silent_args: Vec<String>,
        marker: Marker,
        dll_overrides: Vec<String>,
    },
}

/// Supported archive containers. There is intentionally no zstd (`.tar.zst`) support.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    /// `format = "zip"`, url ending `.zip`.
    Zip,
    /// `format = "tar.gz"`, url ending `.tar.gz` or `.tgz`.
    TarGz,
}

/// Copy `from` (a path inside the archive; ending in `/`, every file below that directory) to `to` (a path
/// relative to `drive_c`). See `install_archive` for the exact semantics.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extract {
    pub from: String,
    pub to: String,
}

/// Evidence that an installer succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Marker {
    /// A file relative to `drive_c`.
    File(String),
    /// Value `name` of `key` exists. With `min_dword`, it must also be a DWORD of at least that value: anything else
    /// (absent, a string, a smaller number such as an older build) counts as ABSENT, so an older version already in
    /// the prefix does not stop the installer from upgrading it, and success needs the new value.
    RegistryValue {
        key: String,
        name: String,
        #[serde(default)]
        min_dword: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    pub packages: Vec<Package>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("manifest is {size} bytes, over the {}-byte limit", MAX_MANIFEST_BYTES)]
    TooLarge { size: usize },
    #[error("manifest is not valid TOML for the schema: {0}")]
    Toml(String),
    #[error("manifest has an unknown field: {0}")]
    UnknownField(String),
    #[error("invalid package id {0:?}")]
    BadId(String),
    #[error("duplicate package id {0:?}")]
    DuplicateId(String),
    #[error("package {id:?}: invalid version {version:?}")]
    BadVersion { id: String, version: String },
    #[error("package {id:?}: invalid licence {licence:?}")]
    BadLicence { id: String, licence: String },
    #[error("package {0:?}: a {PROPRIETARY:?} licence needs requires_consent = true")]
    BadConsent(String),
    #[error("package {id:?}: unsupported archive format {format:?} (zip or tar.gz)")]
    UnsupportedFormat { id: String, format: String },
    #[error("package {id:?}: url {url:?} does not end with the extension of its {format:?} format")]
    FormatMismatch {
        id: String,
        url: String,
        format: ArchiveFormat,
    },
    #[error("package {id:?}: invalid url {url:?} ({reason})")]
    BadUrl {
        id: String,
        url: String,
        reason: &'static str,
    },
    #[error("package {id:?}: sha256 must be 64 lowercase hex characters, got {sha256:?}")]
    BadHash { id: String, sha256: String },
    #[error("package {id:?}: size {size} must be between 1 and {}", MAX_PACKAGE_SIZE)]
    BadSize { id: String, size: u64 },
    #[error("package {id:?}: unsafe {field} path {path:?} ({reason})")]
    BadPath {
        id: String,
        field: &'static str,
        path: String,
        reason: &'static str,
    },
    #[error("package {id:?}: invalid install section ({reason})")]
    BadInstall { id: String, reason: &'static str },
    #[error("package {id:?}: invalid marker ({reason})")]
    BadMarker { id: String, reason: &'static str },
    #[error("package {id:?}: invalid min_vulkan {value:?} (expected major.minor, e.g. \"1.3\")")]
    BadMinVulkan { id: String, value: String },
    #[error("package {id:?}: invalid provides entry {name:?}")]
    BadProvides { id: String, name: String },
    #[error("{name:?} is provided twice (by {first:?} and {second:?})")]
    DuplicateProvides {
        name: String,
        first: String,
        second: String,
    },
    #[error("package {id:?}: dll override {name:?} is not in its provides list")]
    BadDllOverride { id: String, name: String },
    #[error("package {0:?} requires itself")]
    SelfRequire(String),
    #[error("package {id:?} requires {name:?} twice")]
    DuplicateRef { id: String, name: String },
    #[error("package {id:?} requires unknown package {name:?}")]
    UnknownRef { id: String, name: String },
    #[error("dependency cycle through package {0:?}")]
    Cycle(String),
    #[error("destination {path:?} is used by both {first:?} and {second:?} (paths compare case-insensitively)")]
    DuplicateDestination {
        path: String,
        first: String,
        second: String,
    },
    #[error("destination {path:?} of {second:?} overlaps {other:?} of {first:?} (one is a directory of the other)")]
    OverlappingDestination {
        path: String,
        second: String,
        other: String,
        first: String,
    },
}

// Serde shapes. They mirror the TOML exactly; `Package`/`Install` are built from them after validation.

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    #[serde(default)]
    package: Vec<RawPackage>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPackage {
    id: String,
    version: String,
    sha256: String,
    size: u64,
    licence: String,
    url: String,
    kind: Kind,
    requires_consent: bool,
    requires: Vec<String>,
    provides: Vec<String>,
    #[serde(default)]
    min_vulkan: Option<String>,
    install: RawInstall,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawInstall {
    format: Option<String>,
    extract: Option<Vec<Extract>>,
    dll_overrides: Option<Vec<String>>,
    silent_args: Option<Vec<String>>,
    marker: Option<Marker>,
}

impl Manifest {
    /// Parse and fully validate manifest text.
    pub fn parse(text: &str) -> Result<Manifest, ManifestError> {
        if text.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge { size: text.len() });
        }
        parse_uncapped(text)
    }

    /// The manifest shipped in the binary, parsed once.
    pub fn bundled() -> &'static Manifest {
        static BUNDLED: OnceLock<Manifest> = OnceLock::new();
        BUNDLED.get_or_init(|| {
            // A test parses the same file, so this cannot fail in a released build.
            Manifest::parse(include_str!("../packages.toml")).expect("bundled packages.toml is invalid")
        })
    }

    // ponytail: linear scan, fine for a bundled manifest of a few dozen packages; index by id if it grows.
    pub fn get(&self, id: &str) -> Option<&Package> {
        self.packages.iter().find(|p| p.id == id)
    }

    /// The highest `min_vulkan` of any package, if some package has one.
    pub fn max_min_vulkan(&self) -> Option<(u32, u32)> {
        self.packages.iter().filter_map(|p| p.min_vulkan).max()
    }
}

/// Parse without the input size cap. Private: only `parse` (after the cap) and tests call it.
fn parse_uncapped(text: &str) -> Result<Manifest, ManifestError> {
    let raw: RawManifest = toml::from_str(text).map_err(|e| {
        let msg = clip(e.message());
        // serde says "unknown field"; toml says "unexpected keys" for enum struct variants.
        if msg.starts_with("unknown field") || msg.starts_with("unexpected keys") {
            ManifestError::UnknownField(msg)
        } else {
            ManifestError::Toml(msg)
        }
    })?;
    let packages = raw.package.into_iter().map(package).collect::<Result<Vec<_>, _>>()?;
    check_graph(&packages)?;
    Ok(Manifest { packages })
}

/// Truncate an echoed value so an error never carries unbounded attacker text.
pub(crate) fn clip(s: &str) -> String {
    if s.len() <= MAX_ECHO {
        return s.to_owned();
    }
    let mut end = MAX_ECHO;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &s[..end])
}

/// Exactly 64 lowercase hex characters (also guards `fetch`, which uses it as a file name).
pub(crate) fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `[a-z0-9][a-z0-9._-]{0,63}`
pub(crate) fn valid_id(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_NAME_LEN
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

/// Non-empty, bounded, printable text with no control characters.
fn valid_text(s: &str, max: usize) -> bool {
    !s.is_empty() && s.len() <= max && !s.chars().any(char::is_control)
}

fn package(raw: RawPackage) -> Result<Package, ManifestError> {
    let id = raw.id;
    if !valid_id(&id) {
        return Err(ManifestError::BadId(clip(&id)));
    }
    if !valid_text(&raw.version, MAX_NAME_LEN)
        || !raw
            .version
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-' | b'+'))
    {
        return Err(ManifestError::BadVersion {
            id,
            version: clip(&raw.version),
        });
    }
    // Shown in the consent prompt: SPDX-like printable ASCII only.
    if !valid_text(&raw.licence, MAX_NAME_LEN)
        || !raw
            .licence
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-' | b'+' | b' ' | b'(' | b')'))
    {
        return Err(ManifestError::BadLicence {
            id,
            licence: clip(&raw.licence),
        });
    }
    if raw.licence == PROPRIETARY && !raw.requires_consent {
        return Err(ManifestError::BadConsent(id));
    }
    if let Err(reason) = check_url(&raw.url) {
        return Err(ManifestError::BadUrl {
            id,
            url: clip(&raw.url),
            reason,
        });
    }
    if !valid_sha256(&raw.sha256) {
        return Err(ManifestError::BadHash {
            id,
            sha256: clip(&raw.sha256),
        });
    }
    // A url that names a sha256 (a 64-hex path segment, as Microsoft's download urls do) must name this one: a pin
    // copied from another package, or an invented hash, cannot pass.
    let path = raw.url.split(['?', '#']).next().unwrap_or_default();
    if path.split('/').any(|seg| {
        seg.len() == 64 && seg.bytes().all(|b| b.is_ascii_hexdigit()) && !seg.eq_ignore_ascii_case(&raw.sha256)
    }) {
        return Err(ManifestError::BadUrl {
            id,
            url: clip(&raw.url),
            reason: "its path names a sha256 other than the package's",
        });
    }
    if raw.size == 0 || raw.size > MAX_PACKAGE_SIZE {
        return Err(ManifestError::BadSize { id, size: raw.size });
    }
    if raw.provides.len() > MAX_LIST_LEN {
        return Err(ManifestError::BadProvides {
            id,
            name: format!("({} entries)", raw.provides.len()),
        });
    }
    for name in &raw.provides {
        if !valid_provided(name) {
            return Err(ManifestError::BadProvides { id, name: clip(name) });
        }
    }
    let min_vulkan = match &raw.min_vulkan {
        None => None,
        Some(v) => Some(parse_min_vulkan(v).ok_or_else(|| ManifestError::BadMinVulkan {
            id: id.clone(),
            value: clip(v),
        })?),
    };
    let install = install(&id, raw.kind, raw.install, &raw.provides)?;
    if let Install::Archive { format, .. } = install {
        let path = raw
            .url
            .split(['?', '#'])
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        let exts: &[&str] = match format {
            ArchiveFormat::Zip => &[".zip"],
            ArchiveFormat::TarGz => &[".tar.gz", ".tgz"],
        };
        if !exts.iter().any(|e| path.ends_with(e)) {
            return Err(ManifestError::FormatMismatch {
                id,
                url: clip(&raw.url),
                format,
            });
        }
    }
    Ok(Package {
        id,
        version: raw.version,
        sha256: raw.sha256,
        size: raw.size,
        licence: raw.licence,
        url: raw.url,
        kind: raw.kind,
        requires_consent: raw.requires_consent,
        requires: raw.requires,
        provides: raw.provides,
        min_vulkan,
        install,
    })
}

/// `major.minor`, each 1 to 4 ASCII digits (so no sign, space or overflow).
fn parse_min_vulkan(s: &str) -> Option<(u32, u32)> {
    let (a, b) = s.split_once('.')?;
    let num =
        |t: &str| (matches!(t.len(), 1..=4) && t.bytes().all(|c| c.is_ascii_digit())).then(|| t.parse::<u32>().ok())?;
    Some((num(a)?, num(b)?))
}

/// A provided capability or DLL name: `[a-z0-9._+-]{1,64}` (lowercase only, so case variants cannot collide).
fn valid_provided(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_LEN
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-' | b'+'))
}

/// `https://host[:port][/...]`, no userinfo, no whitespace or control characters, no backslashes.
fn check_url(url: &str) -> Result<(), &'static str> {
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("must start with https://");
    };
    if url.len() > MAX_URL_LEN {
        return Err("too long");
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\') {
        return Err("contains whitespace, control or backslash characters");
    }
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err("empty host");
    }
    if !host
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
    {
        return Err("host must be letters, digits, dots and hyphens (no userinfo)");
    }
    if let Some(p) = port
        && (p.is_empty() || p.len() > 5 || !p.bytes().all(|c| c.is_ascii_digit()))
    {
        return Err("invalid port");
    }
    Ok(())
}

/// A plain relative path: `/`-separated, non-empty components, none `.`/`..` or ending in `.`/space (Windows
/// strips those), no backslash, colon (drive letters, streams) or control characters, bounded length.
pub(crate) fn check_rel_path(p: &str) -> Result<(), &'static str> {
    if p.is_empty() || p.len() > MAX_PATH_LEN {
        return Err("empty or too long");
    }
    if p.chars().any(|c| c.is_control() || c == '\\' || c == ':') {
        return Err("backslash, colon or control character");
    }
    // Also rejects absolute paths (leading empty component).
    if p.split('/').any(|c| c.is_empty() || c.ends_with(['.', ' '])) {
        return Err("absolute, or an empty, dot or dot-dot component");
    }
    Ok(())
}

fn install(id: &str, kind: Kind, raw: RawInstall, provides: &[String]) -> Result<Install, ManifestError> {
    let bad = |reason| ManifestError::BadInstall {
        id: id.to_owned(),
        reason,
    };
    let path = |field, p: &str| {
        check_rel_path(p).map_err(|reason| ManifestError::BadPath {
            id: id.to_owned(),
            field,
            path: clip(p),
            reason,
        })
    };
    match (kind, raw) {
        (
            Kind::Archive,
            RawInstall {
                format: Some(format),
                extract: Some(extract),
                dll_overrides: Some(dll_overrides),
                silent_args: None,
                marker: None,
            },
        ) => {
            let format = match format.as_str() {
                "zip" => ArchiveFormat::Zip,
                "tar.gz" => ArchiveFormat::TarGz,
                _ => {
                    return Err(ManifestError::UnsupportedFormat {
                        id: id.to_owned(),
                        format: clip(&format),
                    });
                }
            };
            if extract.is_empty() || extract.len() > MAX_LIST_LEN {
                return Err(bad("extract must have 1 to 64 entries"));
            }
            for e in &extract {
                // One trailing `/` makes `from` a directory prefix (see `install_archive`).
                path("extract.from", e.from.strip_suffix('/').unwrap_or(&e.from))?;
                path("extract.to", &e.to)?;
            }
            check_dll_overrides(id, &dll_overrides, provides)?;
            Ok(Install::Archive {
                format,
                extract,
                dll_overrides,
            })
        }
        (
            Kind::Installer,
            RawInstall {
                format: None,
                extract: None,
                dll_overrides,
                silent_args: Some(silent_args),
                marker: Some(marker),
            },
        ) => {
            let dll_overrides = dll_overrides.unwrap_or_default();
            check_dll_overrides(id, &dll_overrides, provides)?;
            if silent_args.len() > MAX_LIST_LEN {
                return Err(bad("too many silent_args"));
            }
            if !silent_args.iter().all(|a| valid_text(a, MAX_TEXT_LEN)) {
                return Err(bad(
                    "silent_args entries must be non-empty, bounded, without control characters",
                ));
            }
            match &marker {
                Marker::File(p) => path("marker.file", p)?,
                Marker::RegistryValue { key, name, min_dword } => {
                    let bad_marker = |reason| ManifestError::BadMarker {
                        id: id.to_owned(),
                        reason,
                    };
                    // A default (unnamed) value is a string in the hive parser, never a DWORD.
                    if min_dword.is_some() && name.is_empty() {
                        return Err(bad_marker(
                            "min_dword needs a named (DWORD) value, not the default value",
                        ));
                    }
                    if !valid_text(key, MAX_TEXT_LEN) {
                        return Err(bad_marker(
                            "registry key must be non-empty, bounded, without control characters",
                        ));
                    }
                    // An empty name is the key's default value.
                    if name.len() > MAX_TEXT_LEN || name.chars().any(char::is_control) {
                        return Err(bad_marker(
                            "registry value name must be bounded, without control characters",
                        ));
                    }
                }
            }
            Ok(Install::Installer {
                silent_args,
                marker,
                dll_overrides,
            })
        }
        (Kind::Archive, _) => Err(bad(
            "archive needs format, extract and dll_overrides, and no installer fields",
        )),
        (Kind::Installer, _) => Err(bad(
            "installer needs silent_args and marker (dll_overrides optional), and no format or extract",
        )),
    }
}

/// Every DLL override names a DLL from the package's `provides` (same rule for archives and installers).
fn check_dll_overrides(id: &str, names: &[String], provides: &[String]) -> Result<(), ManifestError> {
    match names.iter().find(|n| !provides.contains(n)) {
        Some(name) => Err(ManifestError::BadDllOverride {
            id: id.to_owned(),
            name: clip(name),
        }),
        None => Ok(()),
    }
}

/// No two destinations (`extract.to`, marker file) name the same file, compared ASCII-case-insensitively as Wine
/// does, and none is a directory of another, so each prefix file has exactly one owning package.
fn check_destinations(packages: &[Package]) -> Result<(), ManifestError> {
    // lowercased destination -> (as written, owner); lowercased proper ancestor -> (a destination under it, owner)
    let mut files: HashMap<String, (&str, &str)> = HashMap::new();
    let mut dirs: HashMap<String, (&str, &str)> = HashMap::new();
    for p in packages {
        let dests: Vec<&str> = match &p.install {
            Install::Archive { extract, .. } => extract.iter().map(|e| e.to.as_str()).collect(),
            Install::Installer {
                marker: Marker::File(f),
                ..
            } => vec![f.as_str()],
            Install::Installer { .. } => vec![],
        };
        for d in dests {
            let key = d.to_ascii_lowercase();
            if let Some(&(_, first)) = files.get(&key) {
                return Err(ManifestError::DuplicateDestination {
                    path: clip(d),
                    first: first.to_owned(),
                    second: p.id.clone(),
                });
            }
            let overlap = |other: &str, first: &str| ManifestError::OverlappingDestination {
                path: clip(d),
                second: p.id.clone(),
                other: clip(other),
                first: first.to_owned(),
            };
            if let Some(&(other, first)) = dirs.get(&key) {
                return Err(overlap(other, first));
            }
            // Paths are validated relative paths of at most MAX_PATH_LEN bytes, so this is bounded.
            let ancestors: Vec<&str> = key.match_indices('/').map(|(i, _)| &key[..i]).collect();
            for a in &ancestors {
                if let Some(&(other, first)) = files.get(*a) {
                    return Err(overlap(other, first));
                }
            }
            for a in ancestors {
                dirs.entry(a.to_owned()).or_insert((d, &p.id));
            }
            files.insert(key, (d, &p.id));
        }
    }
    Ok(())
}

/// Unique ids, unique provided names and destinations, known references and no cycles. Linear time, no recursion.
fn check_graph(packages: &[Package]) -> Result<(), ManifestError> {
    let mut index: HashMap<&str, usize> = HashMap::with_capacity(packages.len());
    let mut providers: HashMap<&str, &str> = HashMap::new();
    for (i, p) in packages.iter().enumerate() {
        if index.insert(&p.id, i).is_some() {
            return Err(ManifestError::DuplicateId(p.id.clone()));
        }
        for name in &p.provides {
            if let Some(first) = providers.insert(name, &p.id) {
                return Err(ManifestError::DuplicateProvides {
                    name: name.clone(),
                    first: first.to_owned(),
                    second: p.id.clone(),
                });
            }
        }
    }
    // Kahn's algorithm: count each package's unmet requirements, release dependents as requirements settle.
    let mut pending = vec![0usize; packages.len()];
    let mut dependents: Vec<Vec<usize>> = vec![Vec::new(); packages.len()];
    for (i, p) in packages.iter().enumerate() {
        let mut seen = HashSet::with_capacity(p.requires.len());
        for r in &p.requires {
            if *r == p.id {
                return Err(ManifestError::SelfRequire(p.id.clone()));
            }
            if !seen.insert(r.as_str()) {
                return Err(ManifestError::DuplicateRef {
                    id: p.id.clone(),
                    name: clip(r),
                });
            }
            let Some(&j) = index.get(r.as_str()) else {
                return Err(ManifestError::UnknownRef {
                    id: p.id.clone(),
                    name: clip(r),
                });
            };
            pending[i] += 1;
            dependents[j].push(i);
        }
    }
    let mut ready: Vec<usize> = (0..packages.len()).filter(|&i| pending[i] == 0).collect();
    let mut settled = 0;
    while let Some(j) = ready.pop() {
        settled += 1;
        for &i in &dependents[j] {
            pending[i] -= 1;
            if pending[i] == 0 {
                ready.push(i);
            }
        }
    }
    if settled < packages.len() {
        // Report the smallest id left unsettled so the message is deterministic.
        let id = (0..packages.len())
            .filter(|&i| pending[i] > 0)
            .map(|i| packages[i].id.as_str())
            .min()
            .unwrap_or_default();
        return Err(ManifestError::Cycle(id.to_owned()));
    }
    check_destinations(packages)
}

#[cfg(test)]
mod tests;
