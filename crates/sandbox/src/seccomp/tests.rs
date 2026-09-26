use super::*;
use crate::bpf_interp::{Data, run, validate};

fn filter() -> Vec<SockFilter> {
    build_filter(host_arch().unwrap()).unwrap()
}

fn call(prog: &[SockFilter], nr: libc::c_long, args: [u64; 6]) -> u32 {
    let arch = host_arch().unwrap().audit();
    run(
        prog,
        &Data {
            nr: nr as i32,
            arch,
            ip: 0x7fff_1234_5678,
            args,
        },
    )
}

/// `x` in the low 32 bits with garbage above: what a caller passing an `unsigned long` could hand the kernel.
fn garbage_high(x: u32) -> u64 {
    0xdead_beef_0000_0000 | u64::from(x)
}

const G: u64 = 0xffff_ffff_ffff_ffff;

#[test]
fn every_denied_syscall_is_refused_with_its_errno() {
    let prog = filter();
    for d in DENIED {
        match d.when {
            When::Always => {
                assert_eq!(call(&prog, d.nr, [0; 6]), RET_EPERM, "{}", d.name);
                assert_eq!(call(&prog, d.nr, [G; 6]), RET_EPERM, "{}", d.name);
            }
            When::NoSys => {
                assert_eq!(call(&prog, d.nr, [0; 6]), RET_ENOSYS, "{}", d.name);
                assert_eq!(call(&prog, d.nr, [G; 6]), RET_ENOSYS, "{}", d.name);
            }
            When::ArgHasBit { arg, mask } => {
                for bit in (0..32).map(|b| 1u32 << b).filter(|b| mask & b != 0) {
                    let mut args = [0; 6];
                    args[usize::from(arg)] = garbage_high(bit);
                    assert_eq!(call(&prog, d.nr, args), RET_EPERM, "{} {bit:#x}", d.name);
                }
            }
            When::ArgIn { arg, values } => {
                for &v in values {
                    let mut args = [0; 6];
                    args[usize::from(arg)] = u64::from(v);
                    assert_eq!(call(&prog, d.nr, args), RET_EPERM, "{} {v:#x}", d.name);
                    args[usize::from(arg)] = garbage_high(v);
                    assert_eq!(call(&prog, d.nr, args), RET_EPERM, "{} {v:#x} (high garbage)", d.name);
                }
            }
            When::ArgNotIn { arg, .. } => {
                let mut args = [0; 6];
                args[usize::from(arg)] = 0x0002_0000;
                assert_eq!(call(&prog, d.nr, args), RET_EPERM, "{}", d.name);
            }
        }
    }
}

#[test]
fn the_named_argument_rules_refuse_what_the_review_asked_for() {
    let prog = filter();
    let clone = |flags: u64| call(&prog, libc::SYS_clone, [flags, 0, 0, 0, 0, 0]);
    for flag in [
        libc::CLONE_NEWUSER,
        libc::CLONE_NEWNS,
        libc::CLONE_NEWNET,
        libc::CLONE_NEWPID,
        libc::CLONE_NEWIPC,
        libc::CLONE_NEWUTS,
        libc::CLONE_NEWCGROUP,
    ] {
        assert_eq!(clone(flag as u64 | libc::SIGCHLD as u64), RET_EPERM, "{flag:#x}");
    }
    assert_eq!(call(&prog, libc::SYS_clone3, [0, 88, 0, 0, 0, 0]), RET_ENOSYS);
    let ioctl = |cmd: u64| call(&prog, libc::SYS_ioctl, [0, cmd, 0, 0, 0, 0]);
    assert_eq!(ioctl(libc::TIOCSTI), RET_EPERM);
    assert_eq!(ioctl(garbage_high(libc::TIOCSTI as u32)), RET_EPERM);
    assert_eq!(ioctl(0xffff_ffff_0000_0000 | libc::TIOCLINUX), RET_EPERM);
    let personality = |p: u64| call(&prog, libc::SYS_personality, [p, 0, 0, 0, 0, 0]);
    assert_eq!(personality(libc::UNAME26 as u64), RET_EPERM);
    assert_eq!(personality(libc::ADDR_NO_RANDOMIZE as u64), RET_EPERM);
    assert_eq!(personality(0x0040_0000), RET_EPERM); // READ_IMPLIES_EXEC
    let socket = |domain: libc::c_int| call(&prog, libc::SYS_socket, [domain as u64, 1, 0, 0, 0, 0]);
    for domain in [libc::AF_VSOCK, libc::AF_ALG, libc::AF_KEY] {
        assert_eq!(socket(domain), RET_EPERM, "{domain}");
    }
}

#[test]
fn what_programs_and_wine_need_stays_allowed() {
    let prog = filter();
    let ok = |nr: libc::c_long, args: [u64; 6]| assert_eq!(call(&prog, nr, args), RET_ALLOW, "nr {nr} {args:x?}");
    for nr in [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_openat,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_futex,
        libc::SYS_execve,
        libc::SYS_prctl,
        libc::SYS_memfd_create,
        libc::SYS_set_tid_address,
        libc::SYS_rt_sigaction,
        libc::SYS_getpid,
        libc::SYS_exit_group,
    ] {
        ok(nr, [0; 6]);
        ok(nr, [G; 6]);
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [libc::SYS_arch_prctl, libc::SYS_modify_ldt] {
        ok(nr, [G; 6]);
    }
    // glibc's pthread_create (and its clone fallback), fork, and vfork
    let thread = libc::CLONE_VM
        | libc::CLONE_FS
        | libc::CLONE_FILES
        | libc::CLONE_SIGHAND
        | libc::CLONE_THREAD
        | libc::CLONE_SYSVSEM
        | libc::CLONE_SETTLS
        | libc::CLONE_PARENT_SETTID
        | libc::CLONE_CHILD_CLEARTID;
    ok(libc::SYS_clone, [thread as u64, 0x7f00_0000_0000, 0, 0, 0, 0]);
    ok(
        libc::SYS_clone,
        [
            (libc::CLONE_CHILD_SETTID | libc::CLONE_CHILD_CLEARTID | libc::SIGCHLD) as u64,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    ok(
        libc::SYS_clone,
        [
            (libc::CLONE_VM | libc::CLONE_VFORK | libc::SIGCHLD) as u64,
            0,
            0,
            0,
            0,
            0,
        ],
    );
    // high garbage in clone's flags cannot fake a CLONE_NEW* flag the kernel would see
    ok(libc::SYS_clone, [0xffff_ffff_0000_0000 | thread as u64, 0, 0, 0, 0, 0]);
    for cmd in [libc::TCGETS, libc::FIONREAD, libc::TIOCGWINSZ] {
        ok(libc::SYS_ioctl, [0, cmd, 0, 0, 0, 0]);
    }
    // the ioctl rule looks at `cmd`, not at the fd
    ok(libc::SYS_ioctl, [libc::TIOCSTI, libc::TCGETS, 0, 0, 0, 0]);
    for p in [0, 0x0008, 0xffff_ffff, G] {
        ok(libc::SYS_personality, [p, 0, 0, 0, 0, 0]);
    }
    for domain in [libc::AF_UNIX, libc::AF_INET, libc::AF_INET6, libc::AF_NETLINK] {
        ok(libc::SYS_socket, [domain as u64, libc::SOCK_STREAM as u64, 0, 0, 0, 0]);
    }
    // the socket rule looks at the domain, not at the type or protocol
    ok(
        libc::SYS_socket,
        [
            libc::AF_INET as u64,
            libc::AF_VSOCK as u64,
            libc::AF_ALG as u64,
            0,
            0,
            0,
        ],
    );
}

#[test]
fn another_architecture_or_the_x32_abi_is_refused_whatever_the_call() {
    let prog = filter();
    let own = host_arch().unwrap().audit();
    // i386 (`int 0x80` from x86-64), 32-bit ARM, and the other supported 64-bit architecture
    let i386 = libc::EM_386 as u32 | AUDIT_ARCH_LE;
    let arm = libc::EM_ARM as u32 | AUDIT_ARCH_LE;
    for arch in [i386, arm, AUDIT_ARCH_X86_64, AUDIT_ARCH_AARCH64, 0, u32::MAX]
        .into_iter()
        .filter(|a| *a != own)
    {
        for nr in [libc::SYS_read, libc::SYS_getpid, 20, 0] {
            let d = Data {
                nr: nr as i32,
                arch,
                ip: 0,
                args: [0; 6],
            };
            assert_eq!(run(&prog, &d), RET_EPERM, "arch {arch:#x} nr {nr}");
        }
    }
    #[cfg(target_arch = "x86_64")]
    for nr in [libc::SYS_read, libc::SYS_getpid, libc::SYS_execve, 512, 547] {
        assert_eq!(
            call(&prog, X32_SYSCALL_BIT as libc::c_long | nr, [0; 6]),
            RET_EPERM,
            "x32 {nr}"
        );
    }
}

#[test]
fn the_program_passes_the_kernel_checks_and_fits_its_limit() {
    let prog = filter();
    validate(&prog).unwrap();
    assert!(prog.len() < libc::BPF_MAXINSNS as usize, "{} instructions", prog.len());
    // the validator itself catches what it claims to
    let ret = SockFilter {
        code: RET,
        jt: 0,
        jf: 0,
        k: RET_ALLOW,
    };
    assert!(validate(&[]).is_err());
    assert!(
        validate(&[
            SockFilter {
                code: JEQ,
                jt: 1,
                jf: 0,
                k: 0
            },
            ret
        ])
        .is_err()
    );
    assert!(
        validate(&[
            SockFilter {
                code: LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 64
            },
            ret
        ])
        .is_err()
    );
    assert!(
        validate(&[
            SockFilter {
                code: LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 2
            },
            ret
        ])
        .is_err()
    );
    assert!(
        validate(&[
            SockFilter {
                code: 0x07,
                jt: 0,
                jf: 0,
                k: 0
            },
            ret
        ])
        .is_err()
    );
    assert!(
        validate(&[
            ret,
            SockFilter {
                code: LD_W_ABS,
                jt: 0,
                jf: 0,
                k: 0
            }
        ])
        .is_err()
    );
    assert!(
        validate(&[
            SockFilter {
                code: JEQ,
                jt: 0,
                jf: 0,
                k: 0
            },
            ret
        ])
        .is_ok()
    );
}

#[test]
fn only_this_builds_architecture_can_be_built_and_i386_is_never_allowed() {
    let own = host_arch().unwrap();
    let other = if own == Arch::X86_64 {
        Arch::Aarch64
    } else {
        Arch::X86_64
    };
    assert!(matches!(build_filter(other), Err(SeccompError::UnsupportedArch(n)) if n == other.name()));
    assert!(matches!(
        build_filter_with(own, FilterOptions { allow_i386: true }),
        Err(SeccompError::I386NotSupported)
    ));
    assert_eq!(build_filter_with(own, FilterOptions::default()).unwrap(), filter());
    // the hand-typed audit values are the kernel's (<linux/audit.h>)
    assert_eq!(AUDIT_ARCH_X86_64, 0xc000_003e);
    assert_eq!(AUDIT_ARCH_AARCH64, 0xc000_00b7);
    assert_eq!(CLONE_NEW_ANY, 0x7e02_0080);
}

#[test]
fn the_deny_list_is_consistent_and_its_reasons_are_one_line() {
    let mut names: Vec<_> = DENIED.iter().map(|d| d.name).collect();
    let mut nrs: Vec<_> = DENIED.iter().map(|d| d.nr).collect();
    names.sort_unstable();
    nrs.sort_unstable();
    names.dedup();
    nrs.dedup();
    assert_eq!(names.len(), DENIED.len(), "duplicate name");
    assert_eq!(nrs.len(), DENIED.len(), "duplicate number");
    for d in DENIED {
        assert!(
            !d.reason.is_empty() && !d.reason.contains('\n') && d.reason.len() <= 120,
            "{}",
            d.name
        );
        assert!(!d.name.starts_with("SYS_") && !d.name.is_empty(), "{}", d.name);
    }
    let names: Vec<_> = DENIED.iter().map(|d| d.name).collect();
    for name in [
        "ptrace",
        "keyctl",
        "unshare",
        "mount",
        "clone3",
        "clone",
        "ioctl",
        "personality",
        "socket",
    ] {
        assert!(names.contains(&name), "{name}");
    }
    #[cfg(target_arch = "x86_64")]
    assert!(names.contains(&"iopl") && names.contains(&"ioperm"));
}

/// The module documentation's table row for `d`.
fn doc_row(d: &Denied) -> String {
    let hex = |v: &[u32]| v.iter().map(|x| format!("{x:#x}")).collect::<Vec<_>>().join(", ");
    let when = match d.when {
        When::Always => "always".to_owned(),
        When::NoSys => "always (`ENOSYS`)".to_owned(),
        When::ArgHasBit { arg, mask } => format!("arg{arg} has any bit of {mask:#x}"),
        When::ArgIn { arg, values } => format!("arg{arg} is one of {}", hex(values)),
        When::ArgNotIn { arg, values } => format!("arg{arg} is none of {}", hex(values)),
    };
    format!("//! | `{}` | {when} | {} |", d.name, d.reason)
}

#[test]
fn the_module_documentation_table_is_the_deny_list() {
    let src = include_str!("../seccomp.rs");
    let table: Vec<&str> = src.lines().filter(|l| l.starts_with("//! | `")).collect();
    let want: Vec<String> = DENIED.iter().map(doc_row).collect();
    let missing: Vec<&String> = want.iter().filter(|r| !table.contains(&r.as_str())).collect();
    assert!(
        missing.is_empty(),
        "update the table in seccomp.rs; expected rows:\n{}",
        want.join("\n")
    );
    // iopl/ioperm are x86-64 only; on x86-64 the table has no stale row
    #[cfg(target_arch = "x86_64")]
    assert_eq!(
        table.len(),
        want.len(),
        "stale rows in the table; expected:\n{}",
        want.join("\n")
    );
}

mod kernel;
