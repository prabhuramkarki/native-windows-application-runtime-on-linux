//! The host's Vulkan stack, from `vulkaninfo --summary` (what `runtime graphics info`, `doctor` and the dependency
//! plan ask about).
//!
//! `vulkaninfo` is host software we do not control, so it runs bounded: a cleared environment with a short
//! allowlist, no stdin, [`TIMEOUT`] and [`MAX_OUTPUT`] enforced by killing the child (and its process group).
//! Anything but a clean, in-budget run is `None`, which the verdict turns into "unknown": it never blocks.
//!
//! **Caching.** [`host`] probes once per process: right for one CLI invocation. A long-lived process (the daemon)
//! uses [`rt_core::Cached`] with [`probe`] instead, which probes again once its result is older than a bound, so a
//! GPU or driver change is seen without a restart.
use rt_core::doctor::{FsProbe, HostFs, VULKAN_DIRS};
use rt_core::{HostVulkan, VulkanVerdict, host_verdict, probe_host};
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, mpsc};
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
pub fn run_vulkaninfo() -> Option<String> {
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
    loop {
        if too_big.load(Ordering::SeqCst) || Instant::now() >= deadline {
            kill(&mut child);
            return None;
        }
        // Exit is noticed without reaping (WNOWAIT), so the group id stays ours until after the kill below.
        // SAFETY: waitid on our own child with a zeroed siginfo it fills in.
        let mut si: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let r = unsafe {
            libc::waitid(
                libc::P_PID,
                pgid as libc::id_t,
                &mut si,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if r != 0 {
            kill(&mut child);
            return None;
        }
        // SAFETY: si_pid reads the field waitid filled in (0 while the child still runs).
        if unsafe { si.si_pid() } != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(10));
    }
    // Exited but not yet reaped, so its pgid cannot be recycled: end what is left of the group, then reap.
    // SAFETY: as above.
    unsafe { libc::kill(-pgid, libc::SIGKILL) };
    let Ok(status) = child.wait() else { return None };
    if done_rx.recv_timeout(DRAIN).is_err() {
        return None; // something still holds the pipe: the output may be incomplete
    }
    let buf = std::mem::take(&mut *buf.lock().unwrap());
    if !status.success() || buf.len() > MAX_OUTPUT {
        return None;
    }
    String::from_utf8(buf).ok()
}

/// The host's Vulkan, probed on first use and then shared for the life of the process, so one CLI invocation runs
/// `vulkaninfo` at most once. A long-lived process uses [`rt_core::Cached`].
pub fn host() -> &'static HostVulkan {
    static HOST: OnceLock<HostVulkan> = OnceLock::new();
    HOST.get_or_init(probe)
}

/// The verdict `plan_for_app` asks for, lazily: the probe only runs if some package needs Vulkan (through [`host`]).
pub fn verdict_for(min: Option<(u32, u32)>) -> VulkanVerdict {
    host_verdict(host(), min)
}

/// `RUNTIME_VULKAN_LOADER=present|absent` overrides the loader lookup (for tests); anything else is no override.
fn loader_override(v: Option<&OsStr>) -> Option<bool> {
    match v?.to_str()? {
        "present" => Some(true),
        "absent" => Some(false),
        _ => None,
    }
}

/// Probes the host now: the loader (or the override) and a bounded `vulkaninfo` run.
pub fn probe() -> HostVulkan {
    let loader = loader_override(std::env::var_os("RUNTIME_VULKAN_LOADER").as_deref()).unwrap_or_else(|| {
        VULKAN_DIRS
            .iter()
            .any(|d| HostFs.exists(&Path::new(d).join("libvulkan.so.1")))
    });
    probe_host(&run_vulkaninfo, loader)
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
        fs::write(&tool, format!("#!/bin/sh\n[ \"$1\" = --probe ] && exit 0\n{script}\n")).unwrap();
        fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
        // Another test thread may have forked while the file was open for writing; that child holds the write fd
        // until its exec, and executing the script meanwhile fails with ETXTBSY. Wait until it can be executed.
        for _ in 0..500 {
            match std::process::Command::new(&tool).arg("--probe").status() {
                Err(e) if e.raw_os_error() == Some(libc::ETXTBSY) => thread::sleep(Duration::from_millis(4)),
                _ => break,
            }
        }
        run_tool(tool.as_os_str(), timeout)
    }
    const T: Duration = Duration::from_secs(10);

    #[test]
    fn the_loader_override_takes_only_present_or_absent() {
        let o = |s: &str| loader_override(Some(OsStr::new(s)));
        assert_eq!(o("present"), Some(true));
        assert_eq!(o("absent"), Some(false));
        for v in ["", "Present", "1", "yes", "present "] {
            assert_eq!(o(v), None, "{v:?}");
        }
        assert_eq!(loader_override(None), None);
    }

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
        // The child must have left the tool's group before the tool goes on (else the group kill reaches it):
        // it touches "$0.ready" from inside its new session; the wait is bounded (about 5 s).
        let detach = "setsid sh -c ': > \"$0.ready\"; exec sleep 30' \"$0\" &\n\
                      n=0; while [ ! -e \"$0.ready\" ] && [ $n -lt 500 ]; do n=$((n+1)); sleep 0.01; done";
        let t = Instant::now();
        // Holds stdout open from another session, so the group kill cannot reach it; the tool itself exits.
        assert_eq!(run(&format!("{detach}\nprintf partial"), T), None);
        // Joining the reader would take the full 30 s of the stray `sleep`; the bound is far under that and
        // over the runner's own DRAIN, with generous slack for a loaded machine.
        assert!(t.elapsed() < Duration::from_secs(20), "{:?}", t.elapsed());
        let t = Instant::now();
        assert_eq!(run(&format!("{detach}\nsleep 30"), Duration::from_millis(300)), None);
        // 300 ms timeout + DRAIN, plus slack, still well under 30 s.
        assert!(t.elapsed() < Duration::from_secs(20), "{:?}", t.elapsed());
    }
}
