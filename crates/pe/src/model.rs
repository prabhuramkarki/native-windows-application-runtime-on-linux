use serde::{Serialize, Serializer};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    Pe32,
    Pe32Plus,
}

/// Serialises as a string: the snake_case variant name, or `"other"` for `Other(_)`. The raw
/// number is in `PeInfo::machine`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X86,
    X86_64,
    Arm64,
    Arm64Ec,
    Other(u16),
}

impl Arch {
    pub fn from_machine(m: u16) -> Self {
        match m {
            0x014C => Arch::X86,
            0x8664 => Arch::X86_64,
            0xAA64 => Arch::Arm64,
            0xA641 => Arch::Arm64Ec,
            other => Arch::Other(other),
        }
    }
}

impl Serialize for Arch {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Arch::X86 => "x86",
            Arch::X86_64 => "x86_64",
            Arch::Arm64 => "arm64",
            Arch::Arm64Ec => "arm64_ec",
            Arch::Other(_) => "other",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Exe,
    Dll,
}

/// Serialises as a string: the snake_case variant name, or `"other"` for `Other(_)`. The raw
/// number is in `PeInfo::subsystem_raw`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subsystem {
    /// Kernel-mode drivers use this. Unsupported (master prompt §29).
    Native,
    Gui,
    Console,
    Efi,
    Other(u16),
}

impl Subsystem {
    pub fn from_raw(v: u16) -> Self {
        match v {
            1 => Subsystem::Native,
            2 => Subsystem::Gui,
            3 => Subsystem::Console,
            10 => Subsystem::Efi,
            other => Subsystem::Other(other),
        }
    }
}

impl Serialize for Subsystem {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(match self {
            Subsystem::Native => "native",
            Subsystem::Gui => "gui",
            Subsystem::Console => "console",
            Subsystem::Efi => "efi",
            Subsystem::Other(_) => "other",
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportedFn {
    Name(String),
    Ordinal(u16),
}

#[derive(Debug, Clone, Serialize)]
pub struct Import {
    pub dll: String,
    /// True for delay-load imports (resolved on first call, not at load).
    pub delay: bool,
    pub functions: Vec<ImportedFn>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Export {
    pub name: Option<String>,
    pub ordinal: u32,
    /// `DLL.Function` when the export forwards to another module.
    pub forwarder: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Tls {
    pub callback_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub file_version: Option<String>,
    /// ProductName, CompanyName, FileDescription, ...
    pub strings: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallerKind {
    InnoSetup,
    Nsis,
    InstallShield,
    WixBurn,
}

#[derive(Debug, Clone, Serialize)]
pub struct Installer {
    pub kind: InstallerKind,
    /// The marker that matched. Heuristic, not proof.
    pub evidence: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct PeInfo {
    pub format: Format,
    pub arch: Arch,
    /// COFF `Machine` field as written in the file (`arch` is derived from it).
    pub machine: u16,
    pub kind: Kind,
    pub subsystem: Subsystem,
    /// Optional-header `Subsystem` field as written in the file (`subsystem` is derived from it).
    pub subsystem_raw: u16,
    pub image_base: u64,
    pub entry_point_rva: u32,
    pub size_of_image: u32,
    pub aslr: bool,
    pub nx: bool,
    /// An Authenticode blob is present. NOT verified.
    pub signed: bool,
    pub dotnet: bool,
    pub sections: Vec<Section>,
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocation_count: usize,
    pub tls: Option<Tls>,
    pub version: Option<VersionInfo>,
    pub installer: Option<Installer>,
    /// Tables that exist but failed to parse. Analysis continues past them.
    ///
    /// Free-form human text: the wording may change between versions, so consumers must not
    /// parse it. The structured fields of this object are the contract; a warning only says
    /// that the field it concerns may be incomplete.
    pub warnings: Vec<String>,
}
