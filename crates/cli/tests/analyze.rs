use std::{path::PathBuf, process::Command};

fn fixture(name: &str) -> PathBuf {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    assert!(p.exists(), "missing fixture {name}: run tools/build-fixtures.sh");
    p
}

fn runtime(args: &[&std::ffi::OsStr]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_runtime")).args(args).output().unwrap()
}

fn scratch(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("runtime-cli-test-{}-{name}", std::process::id()))
}

#[test]
fn analyze_json_describes_a_pe() {
    let out = runtime(&[
        "analyze".as_ref(),
        "--json".as_ref(),
        fixture("hello64.exe").as_os_str(),
    ]);
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "pe");
    assert_eq!(v["pe"]["format"], "pe32_plus");
    assert_eq!(v["pe"]["arch"], "x86_64");
    assert_eq!(v["pe"]["subsystem"], "console");
}

#[test]
fn analyze_ignores_the_file_extension() {
    let disguised = scratch("disguised.txt");
    std::fs::copy(fixture("hello64.exe"), &disguised).unwrap();
    let out = runtime(&["analyze".as_ref(), "--json".as_ref(), disguised.as_os_str()]);
    let _ = std::fs::remove_file(&disguised);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "pe");
}

#[test]
fn analyze_rejects_a_non_windows_file_even_if_named_exe() {
    let fake = scratch("fake.exe");
    std::fs::write(&fake, "just some text, not a program\n").unwrap();
    let out = runtime(&["analyze".as_ref(), fake.as_os_str()]);
    let _ = std::fs::remove_file(&fake);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognised format"));
}

#[test]
fn analyze_human_output_lists_imports() {
    let out = runtime(&["analyze".as_ref(), fixture("hello64.exe").as_os_str()]);
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Pe32Plus X86_64 Exe (Console)"), "{text}");
    assert!(text.to_lowercase().contains("kernel32.dll"), "{text}");
}
