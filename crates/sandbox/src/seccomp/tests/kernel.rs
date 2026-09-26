//! Real-kernel tests: a forked child installs the filter and makes real calls, reporting each call's errno through a
//! pipe. The same probes also run in a child WITHOUT the filter: where the kernel's own answer is deterministic
//! (a bad pointer, an unknown command) it must differ from the filtered one, which proves the filter answered.
//! Everything the child does is async-signal-safe: the filter, the probe table and the result buffer exist before
//! `fork`, and the child only makes syscalls and `_exit`s. Skipped visibly when seccomp is unavailable, required
//! under `RUNTIME_REQUIRE_BWRAP=1`.
use super::super::*;
use super::filter;
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::sync::atomic::{AtomicI32, Ordering};

/// A call made in the child: 0 on success, else its errno.
type Probe = fn() -> i32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Want {
    Ok,
    Errno(i32),
    NotEperm,
    /// Host policy decides (yama, sysctls, loaded modules): not asserted.
    Any,
}

struct P {
    name: &'static str,
    probe: Probe,
    filtered: Want,
    unfiltered: Want,
}

const MAX_PROBES: usize = 63;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

fn check(r: libc::c_long) -> i32 {
    if r < 0 { errno() } else { 0 }
}

/// A result that is a new fd: closed again.
fn check_fd(r: libc::c_long) -> i32 {
    if r >= 0 {
        // SAFETY: `r` is a descriptor the probe just created and nothing else uses.
        unsafe { libc::close(r as i32) };
    }
    check(r)
}

/// The pty master the ioctl probes use, opened before `fork`.
static PTY: AtomicI32 = AtomicI32::new(-1);

// Hand-typed where libc lacks them: <linux/userfaultfd.h>, <asm/prctl.h>.
const UFFD_USER_MODE_ONLY: libc::c_long = 1;
#[cfg(target_arch = "x86_64")]
const ARCH_GET_FS: libc::c_long = 0x1003;

const THREAD_FLAGS: libc::c_long = (libc::CLONE_VM
    | libc::CLONE_FS
    | libc::CLONE_FILES
    | libc::CLONE_SIGHAND
    | libc::CLONE_THREAD
    | libc::CLONE_SYSVSEM
    | libc::CLONE_SETTLS
    | libc::CLONE_PARENT_SETTID
    | libc::CLONE_CHILD_CLEARTID) as libc::c_long;

// SAFETY (all probes): each is one raw syscall with integer arguments, NULL, or pointers to live locals/statics of
// the size the kernel reads or writes; none of them touches the Rust heap, so they are safe after `fork`.

fn getpid() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_getpid) })
}
fn ptrace_peek_pid0() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_PEEKDATA, 0, 0, 0) })
}
fn ptrace_traceme() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_ptrace, libc::PTRACE_TRACEME, 0, 0, 0) })
}
fn keyctl_unknown() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_keyctl, 9999, 0, 0, 0, 0) })
}
fn add_key_null() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_add_key, 0, 0, 0, 0, 0) })
}
fn bpf_unknown() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_bpf, 9999, 0, 0) })
}
fn perf_event_open_null() -> i32 {
    check_fd(unsafe { libc::syscall(libc::SYS_perf_event_open, 0, 0, -1, -1, 0) })
}
fn userfaultfd_user_mode() -> i32 {
    check_fd(unsafe {
        libc::syscall(
            libc::SYS_userfaultfd,
            UFFD_USER_MODE_ONLY | libc::O_CLOEXEC as libc::c_long,
        )
    })
}
fn mount_tmpfs() -> i32 {
    check(unsafe { libc::mount(c"none".as_ptr(), c"/".as_ptr(), c"tmpfs".as_ptr(), 0, std::ptr::null()) } as _)
}
fn umount_root() -> i32 {
    check(unsafe { libc::umount2(c"/".as_ptr(), libc::MNT_DETACH) } as _)
}
fn open_by_handle_null() -> i32 {
    check_fd(unsafe { libc::syscall(libc::SYS_open_by_handle_at, libc::AT_FDCWD, 0, libc::O_RDONLY) })
}
fn unshare_user() -> i32 {
    check(unsafe { libc::unshare(libc::CLONE_NEWUSER) } as _)
}
fn tiocsti() -> i32 {
    let c: u8 = b'x';
    check(unsafe { libc::syscall(libc::SYS_ioctl, PTY.load(Ordering::Relaxed), libc::TIOCSTI, &c) })
}
fn tiocsti_high_garbage() -> i32 {
    let c: u8 = b'x';
    let cmd = 0xdead_beef_0000_0000u64 | libc::TIOCSTI;
    check(unsafe { libc::syscall(libc::SYS_ioctl, PTY.load(Ordering::Relaxed), cmd, &c) })
}
fn tioclinux() -> i32 {
    let sub: u8 = 0;
    check(unsafe { libc::syscall(libc::SYS_ioctl, PTY.load(Ordering::Relaxed), libc::TIOCLINUX, &sub) })
}
fn tcgets() -> i32 {
    // SAFETY: an all-zero termios is a valid value.
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    check(unsafe { libc::syscall(libc::SYS_ioctl, PTY.load(Ordering::Relaxed), libc::TCGETS, &mut t) })
}
fn fionread() -> i32 {
    let mut n: libc::c_int = 0;
    check(unsafe { libc::syscall(libc::SYS_ioctl, PTY.load(Ordering::Relaxed), libc::FIONREAD, &mut n) })
}
fn clone3_null() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_clone3, 0, 0) })
}
/// glibc's thread flags plus `CLONE_PIDFD`: the kernel refuses the pair (pidfd and parent_tid share a pointer)
/// with `EINVAL` before creating anything, so the filter's verdict shows without a thread on a shared stack.
fn clone_thread_flags() -> i32 {
    check(unsafe {
        libc::syscall(
            libc::SYS_clone,
            THREAD_FLAGS | libc::CLONE_PIDFD as libc::c_long,
            0,
            0,
            0,
            0,
        )
    })
}
fn clone_thread_flags_newuser() -> i32 {
    let flags = THREAD_FLAGS | (libc::CLONE_PIDFD | libc::CLONE_NEWUSER) as libc::c_long;
    check(unsafe { libc::syscall(libc::SYS_clone, flags, 0, 0, 0, 0) })
}
/// A real fork through `clone(SIGCHLD)`; the new process `_exit`s at once and is reaped.
fn clone_fork() -> i32 {
    let r = unsafe { libc::syscall(libc::SYS_clone, libc::SIGCHLD, 0, 0, 0, 0) };
    if r == 0 {
        unsafe { libc::_exit(0) };
    }
    if r > 0 {
        let mut status = 0;
        unsafe { libc::waitpid(r as libc::pid_t, &mut status, 0) };
    }
    check(r)
}
fn personality_query() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_personality, 0xffff_ffffu64) })
}
fn personality_uname26() -> i32 {
    check(unsafe { libc::syscall(libc::SYS_personality, libc::UNAME26) })
}
fn socket(domain: libc::c_int) -> i32 {
    check_fd(unsafe { libc::syscall(libc::SYS_socket, domain, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) })
}
fn socket_unix() -> i32 {
    socket(libc::AF_UNIX)
}
fn socket_inet() -> i32 {
    socket(libc::AF_INET)
}
fn socket_inet6() -> i32 {
    socket(libc::AF_INET6)
}
fn socket_vsock() -> i32 {
    socket(libc::AF_VSOCK)
}
fn socket_alg() -> i32 {
    check_fd(unsafe { libc::syscall(libc::SYS_socket, libc::AF_ALG, libc::SOCK_SEQPACKET, 0) })
}
fn socket_key() -> i32 {
    check_fd(unsafe { libc::syscall(libc::SYS_socket, libc::AF_KEY, libc::SOCK_RAW, 2) })
}
fn memfd() -> i32 {
    check_fd(unsafe { libc::syscall(libc::SYS_memfd_create, c"probe".as_ptr(), libc::MFD_CLOEXEC) })
}
/// An anonymous page made executable, as Wine and DXVK do.
fn mprotect_exec() -> i32 {
    let (rw, len) = (libc::PROT_READ | libc::PROT_WRITE, 4096);
    let p = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            len,
            rw,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    if p == libc::MAP_FAILED {
        return errno();
    }
    let r = check(unsafe { libc::mprotect(p, len, libc::PROT_READ | libc::PROT_EXEC) } as _);
    unsafe { libc::munmap(p, len) };
    r
}
fn execve_missing() -> i32 {
    let argv = [std::ptr::null::<libc::c_char>()];
    check(unsafe {
        libc::syscall(
            libc::SYS_execve,
            c"/nonexistent/probe".as_ptr(),
            argv.as_ptr(),
            argv.as_ptr(),
        )
    })
}
#[cfg(target_arch = "x86_64")]
fn x32_getpid() -> i32 {
    check(unsafe { libc::syscall(X32_SYSCALL_BIT as libc::c_long | libc::SYS_getpid) })
}
#[cfg(target_arch = "x86_64")]
fn arch_prctl_get_fs() -> i32 {
    let mut fs: u64 = 0;
    check(unsafe { libc::syscall(libc::SYS_arch_prctl, ARCH_GET_FS, &mut fs) })
}
#[cfg(target_arch = "x86_64")]
fn modify_ldt_read() -> i32 {
    let mut buf = [0u8; 64];
    check(unsafe { libc::syscall(libc::SYS_modify_ldt, 0, buf.as_mut_ptr(), buf.len()) })
}

const EPERM: Want = Want::Errno(libc::EPERM);

/// In order; `unshare` and `ptrace(PTRACE_TRACEME)` come last because without the filter they change the child
/// (a new user namespace; the test process as its tracer, which would stop it at the next signal).
const PROBES: &[P] = &[
    P {
        name: "getpid",
        probe: getpid,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "ptrace(PEEKDATA, 0)",
        probe: ptrace_peek_pid0,
        filtered: EPERM,
        unfiltered: Want::Errno(libc::ESRCH),
    },
    P {
        name: "keyctl(9999)",
        probe: keyctl_unknown,
        filtered: EPERM,
        unfiltered: Want::Errno(libc::EOPNOTSUPP),
    },
    P {
        name: "add_key(NULL)",
        probe: add_key_null,
        filtered: EPERM,
        unfiltered: Want::Errno(libc::EFAULT),
    },
    P {
        name: "bpf(9999)",
        probe: bpf_unknown,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "perf_event_open(NULL)",
        probe: perf_event_open_null,
        filtered: EPERM,
        // EFAULT, or EACCES first where `kernel.perf_event_paranoid` forbids unprivileged use (Ubuntu's 4)
        unfiltered: Want::NotEperm,
    },
    P {
        name: "userfaultfd(USER_MODE_ONLY)",
        probe: userfaultfd_user_mode,
        filtered: EPERM,
        unfiltered: Want::NotEperm,
    },
    P {
        name: "mount(tmpfs)",
        probe: mount_tmpfs,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "umount2(/)",
        probe: umount_root,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "open_by_handle_at",
        probe: open_by_handle_null,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "ioctl(TIOCSTI)",
        probe: tiocsti,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "ioctl(TIOCSTI|high garbage)",
        probe: tiocsti_high_garbage,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "ioctl(TIOCLINUX)",
        probe: tioclinux,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "ioctl(TCGETS)",
        probe: tcgets,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "ioctl(FIONREAD)",
        probe: fionread,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "clone3(NULL, 0)",
        probe: clone3_null,
        filtered: Want::Errno(libc::ENOSYS),
        unfiltered: Want::NotEperm,
    },
    P {
        name: "clone(thread flags|PIDFD)",
        probe: clone_thread_flags,
        filtered: Want::Errno(libc::EINVAL),
        unfiltered: Want::Errno(libc::EINVAL),
    },
    P {
        name: "clone(thread flags|PIDFD|NEWUSER)",
        probe: clone_thread_flags_newuser,
        filtered: EPERM,
        unfiltered: Want::Errno(libc::EINVAL),
    },
    P {
        name: "clone(SIGCHLD)",
        probe: clone_fork,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "personality(query)",
        probe: personality_query,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "personality(UNAME26)",
        probe: personality_uname26,
        filtered: EPERM,
        unfiltered: Want::Ok,
    },
    P {
        name: "socket(AF_UNIX)",
        probe: socket_unix,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "socket(AF_INET)",
        probe: socket_inet,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "socket(AF_INET6)",
        probe: socket_inet6,
        filtered: Want::NotEperm,
        unfiltered: Want::NotEperm,
    },
    P {
        name: "socket(AF_VSOCK)",
        probe: socket_vsock,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "socket(AF_ALG)",
        probe: socket_alg,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "socket(AF_KEY)",
        probe: socket_key,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "memfd_create",
        probe: memfd,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "mprotect(PROT_EXEC)",
        probe: mprotect_exec,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "execve(missing)",
        probe: execve_missing,
        filtered: Want::Errno(libc::ENOENT),
        unfiltered: Want::Errno(libc::ENOENT),
    },
    #[cfg(target_arch = "x86_64")]
    P {
        name: "x32 getpid",
        probe: x32_getpid,
        filtered: EPERM,
        unfiltered: Want::NotEperm,
    },
    #[cfg(target_arch = "x86_64")]
    P {
        name: "arch_prctl(ARCH_GET_FS)",
        probe: arch_prctl_get_fs,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    #[cfg(target_arch = "x86_64")]
    P {
        name: "modify_ldt(read)",
        probe: modify_ldt_read,
        filtered: Want::Ok,
        unfiltered: Want::Ok,
    },
    P {
        name: "unshare(CLONE_NEWUSER)",
        probe: unshare_user,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
    P {
        name: "ptrace(TRACEME)",
        probe: ptrace_traceme,
        filtered: EPERM,
        unfiltered: Want::Any,
    },
];

/// Why a child produced no results.
#[derive(Debug)]
enum ChildEnd {
    /// `install` failed with this errno.
    InstallFailed(i32),
    Signalled(i32),
}

/// Forks a child that installs `filter` (if any), runs `probes` and reports each result.
fn in_child(filter: Option<&[SockFilter]>, probes: &[P]) -> Result<Vec<i32>, ChildEnd> {
    assert!(probes.len() <= MAX_PROBES);
    let mut out = [0i32; MAX_PROBES + 1];
    let mut fds = [-1; 2];
    // SAFETY: `fds` is a two-int array, as pipe2 requires.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: the child below only makes async-signal-safe calls (raw syscalls, `install`, `write`, `_exit`) on
    // data that exists before the fork; it never returns into the test harness.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        out[0] = match filter.map(install) {
            None | Some(Ok(())) => 0,
            Some(Err(SeccompError::Install { source, .. })) => source.raw_os_error().unwrap_or(-1),
            Some(Err(_)) => -1,
        };
        if out[0] == 0 {
            for (slot, p) in out[1..].iter_mut().zip(probes) {
                *slot = (p.probe)();
            }
        }
        // SAFETY: `out` is a live array of that many bytes; `_exit` skips every atexit handler and destructor.
        unsafe {
            libc::write(fds[1], out.as_ptr().cast(), size_of_val(&out));
            libc::_exit(0);
        }
    }
    assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());
    // SAFETY: the write end is ours to close; the read end is owned by `File` from here on.
    unsafe { libc::close(fds[1]) };
    let mut pipe = unsafe { File::from_raw_fd(fds[0]) };
    let mut bytes = [0u8; size_of::<[i32; MAX_PROBES + 1]>()];
    let read = pipe.read_exact(&mut bytes);
    let mut status = 0;
    // SAFETY: `pid` is our child; `status` is a live int.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    if libc::WIFSIGNALED(status) {
        return Err(ChildEnd::Signalled(libc::WTERMSIG(status)));
    }
    if let Err(e) = read {
        panic!("the child reported no results ({e}), status {status:#x}");
    }
    let res: Vec<i32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| i32::from_ne_bytes(*c))
        .collect();
    if res[0] != 0 {
        return Err(ChildEnd::InstallFailed(res[0]));
    }
    Ok(res[1..=probes.len()].to_vec())
}

fn required() -> bool {
    std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty())
}

/// The filter, or `None` after saying why the real-kernel tests are skipped (a failure under
/// `RUNTIME_REQUIRE_BWRAP`).
fn real_filter(test: &str) -> Option<Vec<SockFilter>> {
    // SAFETY: PR_GET_SECCOMP takes no pointer; EINVAL means the kernel has no seccomp.
    let why = if unsafe { libc::prctl(libc::PR_GET_SECCOMP) } < 0 {
        format!("seccomp is not available ({})", std::io::Error::last_os_error())
    } else {
        let prog = filter();
        match in_child(Some(&prog), &[]) {
            Ok(_) => return Some(prog),
            Err(ChildEnd::InstallFailed(e)) => {
                format!(
                    "the filter cannot be installed here ({})",
                    std::io::Error::from_raw_os_error(e)
                )
            }
            Err(e) => panic!("{test}: the install probe child failed: {e:?}"),
        }
    };
    assert!(!required(), "RUNTIME_REQUIRE_BWRAP=1 but {why}");
    eprintln!("SKIPPED {test}: {why}");
    None
}

fn meets(want: Want, got: i32) -> bool {
    match want {
        Want::Ok => got == 0,
        Want::Errno(e) => got == e,
        Want::NotEperm => got != libc::EPERM,
        Want::Any => true,
    }
}

fn open_pty() -> File {
    // SAFETY: posix_openpt takes flags only; the fd is owned by the returned File.
    let fd = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    assert!(fd >= 0, "posix_openpt: {}", std::io::Error::last_os_error());
    unsafe { File::from_raw_fd(fd) }
}

#[test]
fn denied_calls_fail_in_a_real_filtered_process_and_allowed_ones_work() {
    use std::os::fd::AsRawFd;
    let Some(prog) = real_filter("denied_calls_fail_in_a_real_filtered_process_and_allowed_ones_work") else {
        return;
    };
    let pty = open_pty();
    PTY.store(pty.as_raw_fd(), Ordering::Relaxed);
    let filtered = in_child(Some(&prog), PROBES).expect("filtered child");
    let unfiltered = in_child(None, PROBES).expect("unfiltered child");
    let mut bad = Vec::new();
    for ((p, &f), &u) in PROBES.iter().zip(&filtered).zip(&unfiltered) {
        if !meets(p.filtered, f) {
            bad.push(format!("{}: filtered {f} wanted {:?}", p.name, p.filtered));
        }
        if !meets(p.unfiltered, u) {
            bad.push(format!("{}: unfiltered {u} wanted {:?}", p.name, p.unfiltered));
        }
    }
    // With TIOCSTI disabled for unprivileged callers (Linux 6.2+, `dev.tty.legacy_tiocsti = 0`) the kernel's own
    // answer is EIO, so the filtered EPERM is the filter's.
    if std::fs::read_to_string("/proc/sys/dev/tty/legacy_tiocsti").is_ok_and(|s| s.trim() == "0") {
        let i = PROBES.iter().position(|p| p.name == "ioctl(TIOCSTI)").unwrap();
        if unfiltered[i] != libc::EIO {
            bad.push(format!("ioctl(TIOCSTI): unfiltered {} wanted EIO", unfiltered[i]));
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    // the test process itself is not filtered
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    assert!(
        status.lines().any(|l| l.split_whitespace().eq(["Seccomp:", "0"])),
        "{status}"
    );
    assert_eq!(keyctl_unknown(), libc::EOPNOTSUPP);
}

#[cfg(target_arch = "x86_64")]
fn int80_getpid() -> i32 {
    let mut rax: i64 = 20; // __NR_getpid in the i386 table
    // SAFETY: `int 0x80` enters the i386 syscall ABI; getpid takes no arguments and touches no memory. The 32-bit
    // entry path does not preserve r8-r11, so they are declared clobbered; no stack is used.
    unsafe {
        std::arch::asm!("int 0x80", inout("rax") rax, out("r8") _, out("r9") _, out("r10") _, out("r11") _,
            options(nostack));
    }
    let r = rax as i32;
    if (-4095..0).contains(&r) { -r } else { 0 }
}

#[cfg(target_arch = "x86_64")]
#[test]
fn the_i386_abi_is_refused_in_a_real_filtered_process() {
    let test = "the_i386_abi_is_refused_in_a_real_filtered_process";
    let Some(prog) = real_filter(test) else { return };
    const INT80: &[P] = &[P {
        name: "int 0x80 getpid",
        probe: int80_getpid,
        filtered: EPERM,
        unfiltered: Want::Ok,
    }];
    match in_child(None, INT80) {
        Ok(r) => assert_eq!(r, [0], "the i386 getpid without the filter"),
        // IA32 emulation disabled (`ia32_emulation=false`): `int 0x80` faults before seccomp sees it
        Err(ChildEnd::Signalled(sig)) => {
            assert!(
                !required(),
                "RUNTIME_REQUIRE_BWRAP=1 but int 0x80 kills the process (signal {sig})"
            );
            eprintln!("SKIPPED {test}: the kernel has no IA32 emulation (int 0x80 raised signal {sig})");
            return;
        }
        Err(e) => panic!("unfiltered child: {e:?}"),
    }
    assert_eq!(in_child(Some(&prog), INT80).expect("filtered child"), [libc::EPERM]);
}
