use crate::model::{Installer, InstallerKind, PeInfo};
use memchr::memmem;

const MARKERS: &[(InstallerKind, &str)] = &[
    (InstallerKind::InnoSetup, "Inno Setup Setup Data"),
    (InstallerKind::Nsis, "NullsoftInst"),
    (InstallerKind::InstallShield, "InstallShield"),
];

/// Guesses the installer family. This is a heuristic and never certain: the `.wixburn` section
/// is a structural hint, but every other marker is an UNANCHORED substring match anywhere in the
/// file (headers, code, resources, overlay). A binary that merely mentions "InstallShield" or
/// "NullsoftInst" matches. `evidence` names what matched so callers can weigh it. The first
/// marker in `MARKERS` order that is present wins.
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
