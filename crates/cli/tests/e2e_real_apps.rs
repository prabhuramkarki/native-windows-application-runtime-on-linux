//! Opt-in checks of externally downloaded, pinned real applications. No download happens in these tests.
//! `real_net_` keeps them out of CI's fixture-only Wine run, like the existing external-package tests.
//! See docs/VALIDATION.md for the official download URL, digest and invocation.
mod support;

use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use support::{Rig, bwrap_works, installed_id};

fn pinned_sample(variable: &str, expected: &str) -> PathBuf {
    let exe = PathBuf::from(std::env::var_os(variable).unwrap_or_else(|| panic!("set {variable}")));
    assert_eq!(
        Sha256::digest(fs::read(&exe).unwrap())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
        expected,
        "expected the pinned official 7-Zip 26.04 asset"
    );
    exe
}

#[test]
#[ignore = "needs official 7zr.exe 26.04 in RUNTIME_7ZIP_EXE, Wine and working bwrap"]
fn real_net_7zip_portable_archive_roundtrip() {
    let exe = pinned_sample(
        "RUNTIME_7ZIP_EXE",
        "256feca8e274e5da655e2a284fabafd9f554365eb164862089dacd4e8276d282",
    );
    assert!(bwrap_works("real_net_7zip_portable_archive_roundtrip"));
    let rig = Rig::new();
    let installed = rig.rt(&["install", exe.to_str().unwrap(), "--name", "sevenzip"]);
    installed.expect_ok();
    let id = installed_id(&installed);
    archive_roundtrip(&rig, &id);
    rig.rt(&["remove", &id]).expect_ok();
    assert!(!rig.apps().join(&id).exists());
    rig.finish();
}

#[test]
#[ignore = "needs official 7z2604-x64.msi in RUNTIME_7ZIP_MSI, Wine, bwrap and desktop-file-validate"]
fn real_net_7zip_msi_install_run_uninstall() {
    let msi = pinned_sample(
        "RUNTIME_7ZIP_MSI",
        "0b01334a418654293513449f61d6bfc99e5196ca371e3c3dc961eda57cd535c6",
    );
    assert!(bwrap_works("real_net_7zip_msi_install_run_uninstall"));
    let rig = Rig::new();
    let xdg = rig.xdg_data_home();
    let xdg_env = [("XDG_DATA_HOME", xdg.to_str().unwrap())];
    rig.set_cleanup_env(&xdg_env);
    let installed = rig.rt_env(
        &[
            "install",
            msi.to_str().unwrap(),
            "--silent",
            "--exe",
            r"Program Files\7-Zip\7z.exe",
        ],
        &xdg_env,
    );
    installed.expect_ok();
    let id = installed_id(&installed);
    let desktop = xdg.join("applications").join(format!("runtime-{id}.desktop"));
    assert!(desktop.is_file(), "installer must create a desktop entry");
    assert!(
        std::process::Command::new("desktop-file-validate")
            .arg(&desktop)
            .status()
            .unwrap()
            .success()
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(rig.apps().join(&id).join("metadata.json")).unwrap()).unwrap();
    assert!(metadata["installer"]["uninstallCommand"].as_str().is_some());
    archive_roundtrip(&rig, &id);
    let removed = rig.rt_env(&["uninstall", &id], &xdg_env);
    removed.expect_ok();
    assert!(!removed.err().contains("warning:"), "{}", removed.report());
    assert!(!rig.apps().join(&id).exists());
    assert!(!desktop.exists());
    rig.finish();
}

fn archive_roundtrip(rig: &Rig, id: &str) {
    let work = rig.drive_c(id).join("compat");
    fs::create_dir_all(work.join("input")).unwrap();
    let payload: Vec<u8> = (0..65_536u32).map(|n| (n % 251) as u8).collect();
    fs::write(work.join("input/payload.bin"), &payload).unwrap();
    fs::write(work.join("input/name with spaces.txt"), "Windows archive roundtrip\n").unwrap();

    let created = rig.run_app(id, &["a", r"C:\compat\roundtrip.7z", r"C:\compat\input\*", "-mx=1"]);
    assert!(created.expect_ok().contains("Everything is Ok"), "{}", created.report());
    let tested = rig.run_app(id, &["t", r"C:\compat\roundtrip.7z"]);
    assert!(tested.expect_ok().contains("Everything is Ok"), "{}", tested.report());
    let extracted = rig.run_app(id, &["x", r"C:\compat\roundtrip.7z", r"-oC:\compat\output", "-y"]);
    assert!(
        extracted.expect_ok().contains("Everything is Ok"),
        "{}",
        extracted.report()
    );
    assert_eq!(fs::read(work.join("output/payload.bin")).unwrap(), payload);
    assert_eq!(
        fs::read_to_string(work.join("output/name with spaces.txt")).unwrap(),
        "Windows archive roundtrip\n"
    );
}
