//! `runtime graphics info` through the real binary, with a fake `vulkaninfo` first on `PATH`.
//!
//! The Vulkan loader is looked for in the standard library directories, so these tests need `libvulkan.so.1`
//! on the host; without it they are skipped (the loader-less verdict is covered by the core's unit tests).
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

const LLVMPIPE: &str = "GPU0:\n\tapiVersion         = 1.3.274\n\tdriverVersion      = 0.0.1\n\tdeviceType         = PHYSICAL_DEVICE_TYPE_CPU\n\tdeviceName         = llvmpipe (LLVM 15.0.7, 256 bits)\n\tdriverName         = llvmpipe\n";

fn has_loader() -> bool {
    [
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib64",
        "/usr/lib",
        "/lib/x86_64-linux-gnu",
    ]
    .iter()
    .any(|d| Path::new(d).join("libvulkan.so.1").exists())
}

/// Runs `runtime graphics info` with a fake `vulkaninfo` (the given shell body) as the only thing on `PATH`
/// besides the basic tools the script itself needs.
fn info(script: &str) -> Option<(Output, Duration)> {
    if !has_loader() {
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("vulkaninfo");
    fs::write(&tool, format!("#!/bin/sh\n{script}\n")).unwrap();
    fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
    let t = Instant::now();
    let out = Command::new(env!("CARGO_BIN_EXE_runtime"))
        .args(["graphics", "info"])
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
        .env("RUNTIME_DATA_DIR", dir.path().join("data"))
        .stdin(Stdio::null())
        .output()
        .unwrap();
    Some((out, t.elapsed()))
}

#[test]
fn llvmpipe_is_reported_as_software() {
    let Some((out, _)) = info(&format!("printf '%s' '{}'", LLVMPIPE.replace('\'', ""))) else {
        return;
    };
    let so = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "{so}");
    assert!(so.contains("llvmpipe") && so.contains("software"), "{so}");
    assert!(so.contains("Vulkan: usable"), "{so}");
}

#[test]
fn a_hanging_tool_is_killed_and_is_unknown() {
    let Some((out, took)) = info("sleep 30") else { return };
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(took < Duration::from_secs(15), "took {took:?}");
    assert_eq!(out.status.code(), Some(0));
    assert!(so.contains("unknown"), "{so}");
}

#[test]
fn a_flood_of_output_is_capped_and_is_unknown() {
    let Some((out, took)) = info("head -c 1048576 /dev/zero | tr '\\0' x") else {
        return;
    };
    let so = String::from_utf8_lossy(&out.stdout);
    assert!(took < Duration::from_secs(15), "took {took:?}");
    assert!(so.contains("unknown"), "{so}");
    assert!(so.len() < 4096, "{}", so.len());
}
