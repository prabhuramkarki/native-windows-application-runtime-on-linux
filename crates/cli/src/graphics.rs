//! `runtime graphics info`: what the host's Vulkan stack offers, from `vulkaninfo --summary`.
//!
//! `vulkaninfo` is host software we do not control, so it runs bounded: a cleared environment with a short
//! allowlist, no stdin, [`TIMEOUT`] and [`MAX_OUTPUT`] enforced by killing the child (and its process group).
//! Anything but a clean, in-budget run is `None`, which the verdict turns into "unknown": it never blocks.
use crate::CmdError;
use crate::safe::safe;
use rt_core::doctor::{FsProbe, HostFs, VULKAN_DIRS};
use rt_core::{HostVulkan, VulkanVerdict, host_verdict, probe_host};
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_OUTPUT: usize = 64 * 1024;
const PASS_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "XDG_RUNTIME_DIR",
    "DISPLAY",
    "WAYLAND_DISPLAY",
    "VK_ICD_FILENAMES",
    "VK_DRIVER_FILES",
];

/// Runs `vulkaninfo --summary`; its stdout, or `None` if it is missing, failed, timed out or wrote too much.
pub(crate) fn run_vulkaninfo() -> Option<String> {
    run_tool(OsStr::new("vulkaninfo"), TIMEOUT)
}

/// How long the reader may take to see EOF once the child has exited (it is normally instant).
const DRAIN: Duration = Duration::from_millis(500);

/// Runs `<program> --summary` bounded. The reader thread is never joined: a descendant that left the process
/// group (setsid) can hold the pipe open forever, so every wait here is bounded and a stuck reader is detached
/// (it ends when the pipe closes).
fn run_tool(program: &OsStr, timeout: Duration) -> Option<String> {
    let mut cmd = Command::new(program);
    cmd.arg("--summary")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own process group, so a kill also reaches what it started (unless that moved away itself).
        .process_group(0);
    for k in PASS_ENV {
        if let Some(v) = std::env::var_os(k) {
            cmd.env(k, v);
        }
    }
    let mut child = cmd.spawn().ok()?;
    let pgid = child.id() as libc::pid_t;
    let kill = |child: &mut std::process::Child| {
        // SAFETY: plain signal to the group we created; ESRCH (already gone) is harmless.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
        let _ = child.kill();
        let _ = child.wait();
    };
    let Some(mut stdout) = child.stdout.take() else {
        kill(&mut child);
        return None;
    };
    let buf = Arc::new(Mutex::new(Vec::new()));
    let too_big = Arc::new(AtomicBool::new(false));
    let (done_tx, done_rx) = mpsc::channel::<()>();
    {
        let (buf, flag) = (buf.clone(), too_big.clone());
        thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            while let Ok(n) = stdout.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let mut b = buf.lock().unwrap();
                let take = n.min(MAX_OUTPUT + 1 - b.len());
                b.extend_from_slice(&chunk[..take]);
                if b.len() > MAX_OUTPUT {
                    flag.store(true, Ordering::SeqCst);
                    break;
                }
            }
            let _ = done_tx.send(());
        });
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        if too_big.load(Ordering::SeqCst) || Instant::now() >= deadline {
            kill(&mut child);
            return None;
        }
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                kill(&mut child);
                return None;
            }
        }
    };
    // Reaped; end what is left of the group, then give the reader a bounded moment to reach EOF.
    // SAFETY: as above.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    if done_rx.recv_timeout(DRAIN).is_err() {
        return None; // something still holds the pipe: the output may be incomplete
    }
    let buf = std::mem::take(&mut *buf.lock().unwrap());
    if !status.success() || buf.len() > MAX_OUTPUT {
        return None;
    }
    String::from_utf8(buf).ok()
}

pub(crate) fn probe() -> HostVulkan {
    let loader = VULKAN_DIRS
        .iter()
        .any(|d| HostFs.exists(&Path::new(d).join("libvulkan.so.1")));
    probe_host(&run_vulkaninfo, loader)
}

pub fn info() -> Result<u8, CmdError> {
    let h = probe();
    let mut out = String::new();
    match host_verdict(&h, None) {
        VulkanVerdict::Usable => {
            out.push_str("Vulkan: usable\n");
            for (i, d) in h.devices.iter().enumerate() {
                let kind = d
                    .device_type
                    .strip_prefix("PHYSICAL_DEVICE_TYPE_")
                    .unwrap_or(&d.device_type);
                let soft = if kind == "CPU" {
                    "software rendering (CPU)".to_string()
                } else {
                    safe(&kind.to_lowercase())
                };
                out.push_str(&format!(
                    "  GPU{i}  {}   Vulkan {}.{}   {soft}\n",
                    safe(&d.name),
                    d.api.0,
                    d.api.1
                ));
            }
        }
        VulkanVerdict::Unusable(why) => out.push_str(&format!("Vulkan: unusable  ({})\n", safe(&why))),
        VulkanVerdict::Unknown => {
            out.push_str("Vulkan: unknown  (vulkaninfo not available; the loader is present)\n");
        }
    }
    crate::emit(&out)?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    /// Runs a fake tool whose body is `script`; `None` when the tool is bounded out.
    fn run(script: &str, timeout: Duration) -> Option<String> {
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("vulkaninfo");
        fs::write(&tool, format!("#!/bin/sh\n{script}\n")).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        run_tool(tool.as_os_str(), timeout)
    }
    const T: Duration = Duration::from_secs(10);

    #[test]
    fn normal_output_is_returned() {
        assert_eq!(run("printf hello", T).as_deref(), Some("hello"));
    }
    #[test]
    fn a_hang_is_killed_at_the_timeout() {
        let t = Instant::now();
        assert_eq!(run("sleep 30", Duration::from_millis(300)), None);
        assert!(t.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn a_flood_is_cut_off() {
        let t = Instant::now();
        assert_eq!(run("head -c 1048576 /dev/zero | tr '\\0' x", T), None);
        assert!(t.elapsed() < Duration::from_secs(5));
    }
    #[test]
    fn a_failing_tool_is_none() {
        assert_eq!(run("echo hi; exit 3", T), None);
    }
    #[test]
    fn non_utf8_output_is_none() {
        assert_eq!(run("printf '\\377\\376'", T), None);
    }
    #[test]
    fn a_missing_or_non_executable_tool_is_none() {
        assert_eq!(run_tool(OsStr::new("/nonexistent/vulkaninfo"), T), None);
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("vulkaninfo");
        fs::write(&f, "#!/bin/sh\necho hi\n").unwrap(); // mode 0644
        assert_eq!(run_tool(f.as_os_str(), T), None);
    }
    #[test]
    fn a_descendant_in_its_own_session_cannot_hang_us() {
        let t = Instant::now();
        // Holds stdout open from another session, so the group kill cannot reach it; the tool itself exits.
        assert_eq!(run("setsid sleep 30 &\nprintf partial", T), None);
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
        let t = Instant::now();
        assert_eq!(run("setsid sleep 30 &\nsleep 30", Duration::from_millis(300)), None);
        assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    }
}
