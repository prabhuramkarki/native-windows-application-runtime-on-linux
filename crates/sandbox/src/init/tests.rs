use super::*;
use crate::landlock::{Access, Rule};
use std::process::{Command, Output};

fn os(s: &str) -> OsString {
    OsString::from(s)
}

fn block(parts: &[&str]) -> Vec<OsString> {
    parts.iter().map(|p| os(p)).collect()
}

fn awkward() -> Vec<OsString> {
    vec![
        os("a b"),
        os(""),
        os("--"),
        os("--rule"),
        os("--v1"),
        os("ro:/etc"),
        os("line\nbreak"),
        OsString::from_vec(b"\xff\xfe not utf-8".to_vec()),
        os("$HOME `x` 'q' \"d\""),
    ]
}

#[test]
fn encode_and_parse_round_trip_every_byte() {
    let args = InitArgs {
        landlock: vec![
            Rule {
                path: "/usr".into(),
                access: Access::ReadExec,
            },
            Rule {
                path: PathBuf::from(OsStr::from_bytes(b"/data/\xff odd:dir")),
                access: Access::ReadWrite,
            },
        ],
        program: "/usr/bin/wine".into(),
        argv: awkward(),
    };
    let enc = encode(&args);
    let mut want = block(&["--v1", "--rule", "ro:/usr", "--rule"]);
    want.push(OsString::from_vec(b"rw:/data/\xff odd:dir".to_vec()));
    want.extend(block(&["--", "/usr/bin/wine"]));
    want.extend(awkward());
    assert_eq!(enc, want);
    assert_eq!(parse(&enc).unwrap(), args);
    // no rules, no arguments
    let bare = InitArgs {
        landlock: vec![],
        program: "/bin/true".into(),
        argv: vec![],
    };
    assert_eq!(encode(&bare), block(&["--v1", "--", "/bin/true"]));
    assert_eq!(parse(&encode(&bare)).unwrap(), bare);
    // exactly MAX_RULES is accepted
    let many = InitArgs {
        landlock: (0..MAX_RULES)
            .map(|i| Rule {
                path: format!("/r{i}").into(),
                access: Access::ReadExec,
            })
            .collect(),
        ..bare
    };
    assert_eq!(parse(&encode(&many)).unwrap(), many);
}

#[test]
fn every_malformed_block_is_refused() {
    use InitError::*;
    let nul = |b: &[u8]| OsString::from_vec(b.to_vec());
    let cases: Vec<(Vec<OsString>, InitError)> = vec![
        (block(&[]), Version),
        (block(&["--", "/bin/true"]), Version),
        (block(&["--v2", "--", "/bin/true"]), Version),
        (block(&["--V1", "--", "/bin/true"]), Version),
        (block(&["v1", "--", "/bin/true"]), Version),
        (block(&[" --v1", "--", "/bin/true"]), Version),
        (block(&["--v1"]), NoSeparator),
        (block(&["--v1", "--rule", "ro:/usr"]), NoSeparator),
        (block(&["--v1", "/bin/true"]), Unexpected(1)),
        (
            block(&["--v1", "--rule", "ro:/usr", "--rules", "ro:/x", "--"]),
            Unexpected(3),
        ),
        (block(&["--v1", "--rule"]), MissingRule),
        (
            block(&["--v1", "--rule", "/usr", "--", "/bin/true"]),
            RuleAccess("/usr".into()),
        ),
        (
            block(&["--v1", "--rule", "rx:/usr", "--", "/bin/true"]),
            RuleAccess("rx:/usr".into()),
        ),
        (
            block(&["--v1", "--rule", "RO:/usr", "--", "/bin/true"]),
            RuleAccess("RO:/usr".into()),
        ),
        (
            block(&["--v1", "--rule", "ro", "--", "/bin/true"]),
            RuleAccess("ro".into()),
        ),
        (
            block(&["--v1", "--rule", "ro:usr", "--", "/bin/true"]),
            NotAbsolute("usr".into()),
        ),
        (
            block(&["--v1", "--rule", "ro:", "--", "/bin/true"]),
            NotAbsolute("".into()),
        ),
        (
            block(&["--v1", "--rule", "rw:/a/../b", "--", "/bin/true"]),
            NotAbsolute("/a/../b".into()),
        ),
        (
            block(&["--v1", "--rule", "rw:/a/./b", "--", "/bin/true"]),
            NotAbsolute("/a/./b".into()),
        ),
        (block(&["--v1", "--"]), NoProgram),
        (block(&["--v1", "--", ""]), NoProgram),
        (block(&["--v1", "--", "wine"]), NotAbsolute("wine".into())),
        (block(&["--v1", "--", "./wine"]), NotAbsolute("./wine".into())),
        (
            block(&["--v1", "--", "/usr/../bin/sh"]),
            NotAbsolute("/usr/../bin/sh".into()),
        ),
        (
            vec![os("--v1"), os("--rule"), nul(b"ro:/a\0b"), os("--"), os("/bin/true")],
            Nul,
        ),
        (vec![os("--v1"), os("--"), nul(b"/bin/tr\0ue")], Nul),
        (vec![os("--v1"), os("--"), os("/bin/true"), nul(b"a\0")], Nul),
        (vec![nul(b"--v1\0")], Nul),
    ];
    for (args, want) in cases {
        assert_eq!(parse(&args), Err(want.clone()), "{args:?}");
    }
    let mut too_many = vec![os("--v1")];
    for i in 0..=MAX_RULES {
        too_many.extend([os("--rule"), os(&format!("ro:/r{i}"))]);
    }
    too_many.extend(block(&["--", "/bin/true"]));
    assert_eq!(parse(&too_many), Err(TooManyRules));
}

/// This test binary as the shim (see `TEST_SHIM`): `<self> sandbox-init <args>`, environment `env` only.
fn shim(args: &[OsString], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.arg("sandbox-init").args(args).env_clear().envs(env.iter().copied());
    c.output().unwrap()
}

fn text(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

#[test]
fn a_program_that_cannot_be_executed_is_a_126_refusal() {
    let out = shim(&block(&["--v1", "--", "/nonexistent/program", "x"]), &[]);
    assert_eq!(out.status.code(), Some(REFUSED), "{out:?}");
    let err = text(&out.stderr);
    assert!(
        err.starts_with("runtime: sandbox-init: cannot run \"/nonexistent/program\": No such file"),
        "{err}"
    );
    assert!(out.stdout.is_empty());
    // a directory is not a program either
    let out = shim(&block(&["--v1", "--", "/usr"]), &[]);
    assert_eq!(out.status.code(), Some(REFUSED), "{out:?}");
    // and a malformed block runs nothing
    let out = shim(&block(&["--v2", "--", "/bin/true"]), &[]);
    assert_eq!(out.status.code(), Some(REFUSED), "{out:?}");
    assert!(text(&out.stderr).contains("refused its arguments"), "{out:?}");
}

/// Outside bwrap, on the host's own paths (canonical ones: `/lib` may be a symlink here): the program runs with the
/// filter, no new privileges, no core dumps, its environment and arguments as given, and (with Landlock) only
/// the rule paths.
#[test]
fn the_shim_hardens_itself_and_runs_the_program_with_its_arguments_unchanged() {
    let td = crate::grant_tempdir();
    let secret = td.path().join("secret");
    std::fs::write(&secret, "s").unwrap();
    let mut rules = Vec::new();
    for p in ["/usr", "/etc", "/proc"] {
        rules.extend([os("--rule"), os(&format!("ro:{p}"))]);
    }
    let script = r#"
        grep -E '^(Seccomp|NoNewPrivs):' /proc/self/status | tr -d '\t '
        echo "core:$(ulimit -c)"
        echo "env:$ONLY"
        cat "$1" >/dev/null 2>&1 && echo SECRET-READ || echo secret-denied
        shift
        echo "--args--"
        printf '%s\0' "$@"
    "#;
    let mut args = vec![os("--v1")];
    args.extend(rules);
    args.extend(block(&["--", "/usr/bin/sh", "-c", script, "sh"]));
    args.push(secret.clone().into_os_string());
    args.extend(awkward());
    let out = shim(&args, &[("ONLY", "this"), ("PATH", "/usr/bin")]);
    assert!(out.status.success(), "{out:?}");
    let stdout = out.stdout;
    let marker = b"--args--\n";
    let head_end = stdout.windows(marker.len()).position(|w| w == marker).unwrap() + marker.len();
    let head = text(&stdout[..head_end]);
    let lines: Vec<&str> = head.lines().collect();
    assert_eq!(
        lines[..4],
        ["NoNewPrivs:1", "Seccomp:2", "core:0", "env:this"],
        "{head}"
    );
    let mut want = Vec::new();
    for a in awkward() {
        want.extend_from_slice(a.as_bytes());
        want.push(0);
    }
    assert_eq!(&stdout[head_end..], &want[..], "the arguments arrive byte for byte");
    match landlock::abi_version() {
        Ok(_) => assert_eq!(lines[4], "secret-denied", "Landlock allows only the rule paths: {head}"),
        Err(e) => eprintln!("SKIPPED the Landlock part: {e}"),
    }
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "s");
}

#[test]
fn the_filter_follows_what_landlock_did() {
    use crate::bpf_interp::{Data, run as bpf};
    let arch = seccomp::host_arch().unwrap();
    let enforced = filter_for(
        &landlock::Applied::Enforced {
            abi: 8,
            skipped: vec![],
        },
        arch,
    )
    .unwrap();
    let unavailable = filter_for(&landlock::Applied::Unavailable("no".into()), arch).unwrap();
    assert_eq!(enforced, seccomp::build_filter_confined_ptrace(arch).unwrap());
    assert_eq!(unavailable, seccomp::build_filter(arch).unwrap());
    let own = bpf_arch(arch);
    let call = |prog: &[seccomp::SockFilter], arch: u32, nr: i64, a0: u64| {
        bpf(
            prog,
            &Data {
                nr: nr as i32,
                arch,
                ip: 0,
                args: [a0, 1, 0, 0, 0, 0],
            },
        )
    };
    let allow = libc::SECCOMP_RET_ALLOW;
    let eperm = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
    for req in [
        libc::PTRACE_PEEKDATA,
        libc::PTRACE_POKEDATA,
        libc::PTRACE_CONT,
        libc::PTRACE_ATTACH,
        libc::PTRACE_DETACH,
    ] {
        assert_eq!(
            call(&enforced, own, libc::SYS_ptrace, u64::from(req)),
            allow,
            "enforced {req}"
        );
        assert_eq!(
            call(&unavailable, own, libc::SYS_ptrace, u64::from(req)),
            eperm,
            "unavailable {req}"
        );
    }
    for req in [
        libc::PTRACE_SEIZE,
        libc::PTRACE_SYSCALL,
        libc::PTRACE_SETOPTIONS,
        libc::PTRACE_INTERRUPT,
        libc::PTRACE_TRACEME,
        libc::PTRACE_KILL,
    ] {
        assert_eq!(
            call(&enforced, own, libc::SYS_ptrace, u64::from(req)),
            eperm,
            "enforced {req}"
        );
        assert_eq!(
            call(&unavailable, own, libc::SYS_ptrace, u64::from(req)),
            eperm,
            "unavailable {req}"
        );
    }
    // i386 set_thread_area (Wine's WoW64 %fs selector) is allowed by BOTH filters; other i386 calls by neither
    #[cfg(target_arch = "x86_64")]
    {
        let i386 = libc::EM_386 as u32 | 0x4000_0000;
        let sta = i64::from(seccomp::I386_SET_THREAD_AREA);
        for prog in [&enforced, &unavailable] {
            assert_eq!(call(prog, i386, sta, 0), allow);
            assert_eq!(call(prog, i386, 20, 0), eperm);
        }
    }
}

/// The audit architecture value of `arch` (the filter's own check).
fn bpf_arch(arch: seccomp::Arch) -> u32 {
    let em = match arch {
        seccomp::Arch::X86_64 => libc::EM_X86_64,
        seccomp::Arch::Aarch64 => libc::EM_AARCH64,
    };
    em as u32 | 0x8000_0000 | 0x4000_0000
}

/// A Landlock error refuses the run (126) before any filter is chosen or the program started: here a rule on a
/// symlink (`ELOOP`), skipped when this host has no such link or no Landlock.
#[test]
fn a_landlock_error_is_a_126_refusal() {
    let link = crate::grant_tempdir();
    let l = link.path().join("link");
    std::os::unix::fs::symlink("/usr", &l).unwrap();
    if landlock::abi_version().is_err() {
        eprintln!("SKIPPED a_landlock_error_is_a_126_refusal: no Landlock");
        return;
    }
    let args = vec![
        os("--v1"),
        os("--rule"),
        os(&format!("ro:{}", l.display())),
        os("--"),
        os("/usr/bin/true"),
    ];
    let out = shim(&args, &[]);
    assert_eq!(out.status.code(), Some(REFUSED), "{out:?}");
    assert!(
        text(&out.stderr).starts_with("runtime: sandbox-init: landlock:"),
        "{out:?}"
    );
}

#[test]
fn a_denied_syscall_fails_with_eperm_in_the_program() {
    // `unshare -U` needs unshare(2), which the filter refuses.
    let mut args = block(&["--v1"]);
    for p in ["/usr", "/etc"] {
        args.extend([os("--rule"), os(&format!("ro:{p}"))]);
    }
    args.extend(block(&["--", "/usr/bin/unshare", "-U", "/usr/bin/true"]));
    let out = shim(&args, &[]);
    assert!(!out.status.success(), "{out:?}");
    assert!(text(&out.stderr).contains("Operation not permitted"), "{out:?}");
    // the control: without the shim it works (or the host forbids user namespaces: then this proves nothing)
    let control = Command::new("/usr/bin/unshare")
        .args(["-U", "/usr/bin/true"])
        .output()
        .unwrap();
    if !control.status.success() {
        eprintln!("SKIPPED the control: unshare -U fails on this host too: {control:?}");
    }
}
