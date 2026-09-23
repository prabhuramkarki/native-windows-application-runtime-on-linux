use super::*;
use crate::testutil::require_tool;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

fn require_dfv() -> Option<PathBuf> {
    require_tool("desktop-file-validate", "RUNTIME_REQUIRE_DESKTOP_FILE_VALIDATE")
}

fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> + use<> {
    let map: HashMap<String, OsString> = pairs.iter().map(|(k, v)| (k.to_string(), OsString::from(v))).collect();
    move |k| map.get(k).cloned()
}

#[test]
fn render_exact_content() {
    assert_eq!(
        render(),
        "[Desktop Entry]\n\
         Type=Application\n\
         Name=Install with Runtime\n\
         Exec=runtime install %f\n\
         Terminal=false\n\
         Categories=System;\n\
         MimeType=application/x-msdownload;application/x-msi;\n"
    );
}

#[test]
fn render_output_passes_real_desktop_file_validate() {
    let Some(tool) = require_dfv() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("check.desktop");
    fs::write(&path, render()).unwrap();
    let out = std::process::Command::new(tool).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn register_writes_the_file_at_the_documented_xdg_path() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let e = env(&[("XDG_DATA_HOME", xdg.to_str().unwrap())]);
    register_with_env(&e).unwrap();
    let path = xdg.join("applications").join(FILE_NAME);
    assert!(path.is_file());
    let content = fs::read_to_string(&path).unwrap();
    assert_eq!(content, render());
}

#[test]
fn register_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let e = env(&[("XDG_DATA_HOME", xdg.to_str().unwrap())]);
    register_with_env(&e).unwrap();
    register_with_env(&e).unwrap();
    let path = xdg.join("applications").join(FILE_NAME);
    assert_eq!(fs::read_to_string(&path).unwrap(), render());
}

#[test]
fn register_result_is_a_real_installed_file_that_passes_real_validation() {
    let Some(tool) = require_dfv() else { return };
    let tmp = tempfile::tempdir().unwrap();
    let xdg = tmp.path().join("xdg");
    let e = env(&[("XDG_DATA_HOME", xdg.to_str().unwrap())]);
    register_with_env(&e).unwrap();
    let path = xdg.join("applications").join(FILE_NAME);
    assert!(path.is_file(), "not present in the scratch XDG_DATA_HOME");
    let out = std::process::Command::new(tool).arg(&path).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn register_surfaces_xdg_resolution_failures() {
    let err = register_with_env(&env(&[])).unwrap_err();
    assert!(matches!(err, DesktopError::Xdg(_)), "{err:?}");
}
