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
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.contains("Pe32Plus X86_64 Exe (Console)"), "{text}");
    assert!(text.to_lowercase().contains("kernel32.dll"), "{text}");
}

#[test]
fn analyze_rejects_malformed_pe() {
    let malformed = scratch("malformed.exe");
    let hello = fixture("hello64.exe");
    let full_file = std::fs::read(&hello).unwrap();
    let truncated_bytes = &full_file[..512.min(full_file.len())];
    std::fs::write(&malformed, truncated_bytes).unwrap();
    let out = runtime(&["analyze".as_ref(), malformed.as_os_str()]);
    let _ = std::fs::remove_file(&malformed);
    assert_eq!(out.status.code(), Some(1), "Expected exit code 1");
    // Deterministic: the first 512 bytes of hello64.exe cut the section table short (mingw emits
    // far more than the ~3 section headers that would fit), which the parser reports as a bounds failure.
    assert_eq!(
        String::from_utf8_lossy(&out.stderr),
        "error: malformed PE: bounds check failed\n"
    );
}

#[test]
fn analyze_handles_msi_magic() {
    let msi = scratch("test.msi");
    // MSI magic: D0 CF 11 E0 A1 B1 1A E1 (OLE compound document)
    let magic = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1padpadpadpadpadpadpad";
    std::fs::write(&msi, magic).unwrap();
    let out = runtime(&["analyze".as_ref(), "--json".as_ref(), msi.as_os_str()]);
    let _ = std::fs::remove_file(&msi);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "msi");
    assert_eq!(v["pe"], serde_json::json!(null));
}

#[test]
fn analyze_handles_zip_magic() {
    let zip = scratch("test.zip");
    // ZIP magic: 50 4B 03 04
    let magic = b"PK\x03\x04padpadpadpadpadpadpadpadpadpadpad";
    std::fs::write(&zip, magic).unwrap();
    let out = runtime(&["analyze".as_ref(), "--json".as_ref(), zip.as_os_str()]);
    let _ = std::fs::remove_file(&zip);
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["kind"], "zip");
    assert_eq!(v["pe"], serde_json::json!(null));
}

#[test]
fn analyze_rejects_directory() {
    let dir = scratch("test-dir");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let out = runtime(&["analyze".as_ref(), dir.as_os_str()]);
    let _ = std::fs::remove_dir(&dir);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not a regular file"),
        "stderr should contain 'not a regular file': {stderr}"
    );
}

#[test]
fn analyze_output_sanitizes_escape_sequences() {
    // Copy hello64.exe and patch DLL name with escape byte
    let patched = scratch("patched.exe");
    let hello = fixture("hello64.exe");
    let bytes = std::fs::read(&hello).unwrap();

    // Find and patch KERNEL32.dll string in the binary
    let mut patched_bytes = bytes.clone();
    let pos = bytes
        .windows(12)
        .position(|w| w.eq_ignore_ascii_case(b"KERNEL32.dll"))
        .expect("KERNEL32.dll pattern must be found in fixture");
    // Replace first byte with ESC
    patched_bytes[pos] = 0x1b;
    std::fs::write(&patched, &patched_bytes).unwrap();
    let out = runtime(&["analyze".as_ref(), patched.as_os_str()]);
    let _ = std::fs::remove_file(&patched);

    // Check that process succeeded
    assert!(out.status.success(), "analyze should succeed on patched binary");
    // Check that output doesn't contain raw ESC bytes
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains('\x1b'),
        "ESC byte found in stdout at position: {:?}",
        stdout.as_bytes().iter().position(|&b| b == 0x1b)
    );
}

/// Removes the FIFO and reaps the child on drop, so a failing assertion or timeout cannot leak either.
struct FifoGuard {
    path: PathBuf,
    child: std::process::Child,
}

impl Drop for FifoGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn analyze_rejects_fifo_without_blocking() {
    use std::{
        io::Read,
        process::Stdio,
        time::{Duration, Instant},
    };
    let fifo_path = scratch("test.fifo");
    let _ = std::fs::remove_file(&fifo_path);
    match Command::new("mkfifo").arg(&fifo_path).output() {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return, // no mkfifo: skip
        Err(e) => panic!("mkfifo failed: {e}"),
        Ok(o) => assert!(
            o.status.success(),
            "mkfifo failed: {}",
            String::from_utf8_lossy(&o.stderr)
        ),
    }
    let child = Command::new(env!("CARGO_BIN_EXE_runtime"))
        .arg("analyze")
        .arg(&fifo_path)
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn runtime");
    let mut guard = FifoGuard { path: fifo_path, child };

    // A FIFO must be rejected before open(); a blocked open would never exit.
    let start = Instant::now();
    let status = loop {
        if let Some(s) = guard.child.try_wait().expect("try_wait") {
            break s;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "did not exit within 5 s: FIFO open is likely blocking"
        );
        std::thread::sleep(Duration::from_millis(20));
    };
    let mut stderr = String::new();
    guard.child.stderr.take().unwrap().read_to_string(&mut stderr).unwrap();
    assert_eq!(status.code(), Some(1));
    assert!(stderr.contains("not a regular file"), "stderr: {stderr}");
}
