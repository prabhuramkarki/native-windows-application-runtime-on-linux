//! `runtime graphics info`: what the host's Vulkan stack offers, from `vulkaninfo --summary`.
//!
//! `vulkaninfo` is host software we do not control, so it runs bounded: a cleared environment with a short
//! allowlist, no stdin, [`TIMEOUT`] and [`MAX_OUTPUT`] enforced by killing the child (and its process group).
//! Anything but a clean, in-budget run is `None`, which the verdict turns into "unknown": it never blocks.
use crate::CmdError;
use crate::safe::safe;
use rt_core::doctor::{FsProbe, HostFs, VULKAN_DIRS};
use rt_core::{HostVulkan, VulkanVerdict, host_verdict, probe_host};
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    let mut cmd = Command::new("vulkaninfo");
    cmd.arg("--summary")
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own process group, so a kill also reaches anything it started that holds the pipe.
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
    let mut stdout = child.stdout.take()?;
    let too_big = Arc::new(AtomicBool::new(false));
    let flag = too_big.clone();
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(n) = stdout.read(&mut chunk) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n.min(MAX_OUTPUT + 1 - buf.len())]);
            if buf.len() > MAX_OUTPUT {
                flag.store(true, Ordering::SeqCst);
                break;
            }
        }
        buf
    });
    let deadline = Instant::now() + TIMEOUT;
    let status = loop {
        if too_big.load(Ordering::SeqCst) || Instant::now() >= deadline {
            kill(&mut child);
            let _ = reader.join(); // the group is dead, so the pipe is closed
            return None;
        }
        match child.try_wait() {
            Ok(Some(st)) => break st,
            Ok(None) => thread::sleep(Duration::from_millis(10)),
            Err(_) => {
                kill(&mut child);
                let _ = reader.join();
                return None;
            }
        }
    };
    // Reaped; anything left in the group could keep the pipe open, so end it before joining the reader.
    // SAFETY: as above.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let buf = reader.join().ok()?;
    if !status.success() || buf.len() > MAX_OUTPUT {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// Probes the host once: the loader by file, the devices by `vulkaninfo`.
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
                let soft = if d.device_type.ends_with("CPU") {
                    "software rendering (CPU)"
                } else {
                    "hardware"
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
