use crate::model::{Installer, InstallerKind, PeInfo};
use memchr::memmem;

const MARKERS: &[(InstallerKind, &str)] = &[
    (InstallerKind::InnoSetup, "Inno Setup Setup Data"),
    (InstallerKind::Nsis, "NullsoftInst"),
    (InstallerKind::InstallShield, "InstallShield"),
];

pub fn detect(bytes: &[u8], info: &PeInfo) -> Option<Installer> {
    if info.sections.iter().any(|s| s.name == ".wixburn") {
        return Some(Installer {
            kind: InstallerKind::WixBurn,
            evidence: ".wixburn section",
        });
    }
    MARKERS.iter().find_map(|&(kind, marker)| {
        memmem::find(bytes, marker.as_bytes()).map(|_| Installer { kind, evidence: marker })
    })
}
