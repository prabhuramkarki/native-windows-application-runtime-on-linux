mod common;
use common::*;
use pe::InstallerKind;

#[test]
fn installer_markers() {
    let inno = Builder {
        overlay: b"....Inno Setup Setup Data (6.2.0)....".to_vec(),
        ..Builder::x86()
    };
    assert_eq!(analyze(&inno).installer.unwrap().kind, InstallerKind::InnoSetup);
    let nsis = Builder {
        overlay: b"\xef\xbe\xad\xdeNullsoftInst".to_vec(),
        ..Builder::x86()
    };
    assert_eq!(analyze(&nsis).installer.unwrap().kind, InstallerKind::Nsis);
    let burn = Builder::x86().section(".wixburn", DATA_R, vec![0; 16]);
    assert_eq!(analyze(&burn).installer.unwrap().kind, InstallerKind::WixBurn);
    assert!(analyze(&Builder::x86()).installer.is_none());
}

#[test]
fn installshield_marker() {
    let b = Builder {
        overlay: b"....InstallShield....".to_vec(),
        ..Builder::x86()
    };
    let i = analyze(&b).installer.unwrap();
    assert_eq!(i.kind, InstallerKind::InstallShield);
    assert_eq!(i.evidence, "InstallShield");
}
