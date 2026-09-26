//! Pure tests of the access sets, plus real-kernel tests. Landlock is irreversible and inherited, so every
//! real-kernel test restricts a forked CHILD: the rules (C paths), the probe paths and the exec argument arrays
//! exist before `fork`, and the child only makes raw syscalls, runs [`enforce`] (allocation-free) and `_exit`s,
//! reporting through a pipe. After each child the test process proves it is still unrestricted. Skipped visibly
//! when Landlock is unavailable, required under `RUNTIME_REQUIRE_BWRAP=1`.
use super::*;
use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::os::fd::FromRawFd;
use std::path::Path;

#[test]
fn the_handled_set_per_abi_is_frozen_and_only_grows() {
    // <linux/landlock.h>: the hand-typed bits are the kernel's
    assert_eq!(
        [EXECUTE, WRITE_FILE, READ_FILE, READ_DIR, REFER, TRUNCATE, IOCTL_DEV],
        [1, 2, 4, 8, 1 << 13, 1 << 14, 1 << 15]
    );
    assert_eq!(MAKE_SYM, 1 << 12);
    let want = [
        (0, 0),
        (1, 0x1fff),
        (2, 0x3fff),
        (3, 0x7fff),
        (4, 0x7fff), // network rights only: not handled here
        (5, 0xffff),
        (6, 0xffff), // scoping only: not used
        (7, 0xffff),
        (8, 0xffff),
        (u32::MAX, 0xffff), // an ABI newer than this code: only the rights it knows
    ];
    for (abi, mask) in want {
        assert_eq!(handled_mask(abi), mask, "abi {abi}");
    }
    for abi in 1..=8 {
        let (lo, hi) = (handled_mask(abi), handled_mask(abi + 1));
        assert_eq!(lo & hi, lo, "abi {abi} -> {}: a right disappeared", abi + 1);
    }
}

#[test]
fn rule_rights_follow_the_access_and_files_get_only_file_rights() {
    let rx = EXECUTE | READ_FILE | READ_DIR;
    for abi in 1..=8 {
        let h = handled_mask(abi);
        assert_eq!(rule_access(Access::ReadExec, h, true), rx, "abi {abi}");
        assert_eq!(
            rule_access(Access::ReadExec, h, false),
            EXECUTE | READ_FILE,
            "abi {abi}"
        );
        assert_eq!(rule_access(Access::ReadWrite, h, true), h, "abi {abi}");
        assert_eq!(rule_access(Access::ReadWrite, h, false), h & ACCESS_FILE, "abi {abi}");
        assert_eq!(rule_access(Access::ReadWrite, h, false) & !ACCESS_FILE, 0);
    }
    // the kernel's file rights: execute, write, read, truncate, device ioctls
    assert_eq!(ACCESS_FILE, EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV);
    assert_eq!(rule_access(Access::ReadWrite, handled_mask(5), false), ACCESS_FILE);
    assert_eq!(
        rule_access(Access::ReadWrite, handled_mask(1), false),
        EXECUTE | WRITE_FILE | READ_FILE
    );
}

#[test]
fn rule_paths_must_be_absolute_and_nul_free() {
    use std::os::unix::ffi::OsStrExt;
    let rule = |p: &Path| Rule {
        path: p.to_owned(),
        access: Access::ReadExec,
    };
    for bad in [
        Path::new("usr/lib"),
        Path::new(""),
        Path::new(std::ffi::OsStr::from_bytes(b"/a\0b")),
    ] {
        assert!(
            matches!(prepare(&[rule(bad)]), Err(LandlockError::BadPath(p)) if p == bad),
            "{bad:?}"
        );
    }
    let ok = prepare(&[rule(Path::new("/usr"))]).unwrap();
    assert_eq!(ok[0].0.as_c_str(), c"/usr");
}

#[test]
fn outcomes_map_to_applied_and_errors_name_the_rule() {
    let rules = [
        Rule {
            path: "/one".into(),
            access: Access::ReadExec,
        },
        Rule {
            path: "/two".into(),
            access: Access::ReadWrite,
        },
    ];
    match finish(&rules, &[false, true], Ok(Outcome::Enforced(6))).unwrap() {
        Applied::Enforced { abi: 6, skipped } => assert_eq!(skipped, [PathBuf::from("/two")]),
        other => panic!("{other:?}"),
    }
    for e in [libc::ENOSYS, libc::EOPNOTSUPP] {
        match finish(&rules, &[false; 2], Ok(Outcome::Unavailable(e))).unwrap() {
            Applied::Unavailable(why) => assert!(why.contains("Landlock"), "{why}"),
            other => panic!("{other:?}"),
        }
    }
    let e = finish(&rules, &[false; 2], Err(Fail::Rule(1, libc::EACCES))).unwrap_err();
    assert!(
        matches!(&e, LandlockError::Rule { path, source } if path == Path::new("/two")
        && source.raw_os_error() == Some(libc::EACCES))
    );
    let e = finish(
        &rules,
        &[false; 2],
        Err(Fail::Step("landlock_restrict_self", libc::EPERM)),
    )
    .unwrap_err();
    assert!(e.to_string().contains("landlock_restrict_self"), "{e}");
    // a rule without a skipped slot is refused before anything happens, never silently left out
    let one = [(CString::from(c"/x"), Access::ReadExec)];
    let r = enforce(&one, &mut [], kernel_abi, set_no_new_privs);
    assert!(matches!(r, Err(Fail::Step(_, libc::EINVAL))), "{r:?}");
}

// ---- real kernel ----

const SLOTS: usize = 16;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(-1)
}

/// `open(path, flags)`: 0 on success (the fd is closed again), else the errno.
fn open_errno(path: &CStr, flags: i32) -> i32 {
    // SAFETY: `path` is NUL-terminated and live; the mode is read only with O_CREAT.
    let fd = unsafe { libc::open(path.as_ptr(), flags | libc::O_CLOEXEC, 0o600) };
    if fd < 0 {
        return errno();
    }
    // SAFETY: `fd` was just opened here and nothing else uses it.
    unsafe { libc::close(fd) };
    0
}

fn read_errno(path: &CStr) -> i32 {
    open_errno(path, libc::O_RDONLY)
}

fn rc(r: libc::c_int) -> i32 {
    if r < 0 { errno() } else { 0 }
}

/// Runs `path` (no arguments, empty environment) in a grandchild: its exit status, or the `execve` errno.
fn exec_status(path: &CStr) -> i32 {
    let argv = [path.as_ptr(), std::ptr::null()];
    let envp = [std::ptr::null::<libc::c_char>()];
    // SAFETY: the grandchild only calls `execve` with live NUL-terminated arrays and `_exit`s if it fails.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        unsafe {
            libc::execve(path.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(errno());
        }
    }
    if pid < 0 {
        return -errno();
    }
    let mut status = 0;
    // SAFETY: `pid` is our child; `status` is a live int.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if libc::WIFEXITED(status) {
        libc::WEXITSTATUS(status)
    } else {
        -1
    }
}

/// [`enforce`]'s result as two slots: (0 enforced | 1 unavailable | 2 step failed | 3 rule failed, abi or errno).
fn outcome(r: Result<Outcome, Fail>) -> [i32; 2] {
    match r {
        Ok(Outcome::Enforced(abi)) => [0, abi as i32],
        Ok(Outcome::Unavailable(e)) => [1, e],
        Err(Fail::Step(_, e)) => [2, e],
        Err(Fail::Rule(_, e)) => [3, e],
    }
}

fn enforce_real(rules: &[(CString, Access)], skipped: &mut [bool]) -> [i32; 2] {
    outcome(enforce(rules, skipped, kernel_abi, set_no_new_privs))
}

/// Forks a child that runs `body` and reports its slots; the child never returns into the test harness.
fn in_child(body: impl FnOnce() -> [i32; SLOTS]) -> [i32; SLOTS] {
    let mut fds = [-1; 2];
    // SAFETY: `fds` is a two-int array, as pipe2 requires.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    // SAFETY: the child only runs `body` (raw syscalls on data built before the fork), `write` and `_exit`.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        // SAFETY: `out` is a live array of that many bytes; `_exit` skips every atexit handler and destructor.
        unsafe {
            if let Ok(out) = out {
                libc::write(fds[1], out.as_ptr().cast(), size_of_val(&out));
            }
            libc::_exit(0);
        }
    }
    assert!(pid > 0, "fork failed: {}", std::io::Error::last_os_error());
    // SAFETY: the write end is ours to close; the read end is owned by `File` from here on.
    unsafe { libc::close(fds[1]) };
    let mut pipe = unsafe { File::from_raw_fd(fds[0]) };
    let mut bytes = [0u8; SLOTS * 4];
    let read = pipe.read_exact(&mut bytes);
    let mut status = 0;
    // SAFETY: `pid` is our child; `status` is a live int.
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    read.unwrap_or_else(|e| panic!("the child reported nothing ({e}), status {status:#x}"));
    let mut out = [0; SLOTS];
    for (o, c) in out.iter_mut().zip(bytes.as_chunks::<4>().0) {
        *o = i32::from_ne_bytes(*c);
    }
    out
}

fn required() -> bool {
    std::env::var_os("RUNTIME_REQUIRE_BWRAP").is_some_and(|v| !v.is_empty())
}

/// The host's Landlock ABI, or `None` after saying why the test is skipped (a failure under
/// `RUNTIME_REQUIRE_BWRAP`).
fn host_abi(test: &str) -> Option<u32> {
    let e = match abi_version() {
        Ok(abi) => return Some(abi),
        Err(e) => e,
    };
    let LandlockError::Syscall { source, .. } = &e else {
        panic!("{e}")
    };
    assert!(
        matches!(source.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)),
        "{test}: {e}"
    );
    assert!(!required(), "RUNTIME_REQUIRE_BWRAP=1 but Landlock is unavailable: {e}");
    eprintln!("SKIPPED {test}: Landlock is unavailable ({e})");
    None
}

/// `td/a/{ok,other,mv}.txt`, `td/b/no.txt`, `td/link -> a`.
struct Tree {
    td: tempfile::TempDir,
}

impl Tree {
    fn new() -> Tree {
        let td = crate::grant_tempdir();
        for (f, text) in [
            ("a/ok.txt", "ok"),
            ("a/other.txt", "other"),
            ("a/mv.txt", "mv"),
            ("b/no.txt", "no"),
        ] {
            let p = td.path().join(f);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        std::os::unix::fs::symlink(td.path().join("a"), td.path().join("link")).unwrap();
        Tree { td }
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.td.path().join(rel)
    }

    fn c(&self, rel: &str) -> CString {
        use std::os::unix::ffi::OsStrExt;
        CString::new(self.path(rel).as_os_str().as_bytes()).unwrap()
    }

    fn rules(&self, rules: &[(&str, Access)]) -> Vec<(CString, Access)> {
        let rules: Vec<Rule> = rules
            .iter()
            .map(|&(rel, access)| Rule {
                path: if rel.starts_with('/') {
                    rel.into()
                } else {
                    self.path(rel)
                },
                access,
            })
            .collect();
        prepare(&rules).unwrap()
    }

    /// The test process itself is not restricted by anything a child did.
    fn assert_parent_unrestricted(&self) {
        assert_eq!(read_errno(&self.c("b/no.txt")), 0);
        assert_eq!(
            open_errno(&self.c("b/parent-can-write"), libc::O_WRONLY | libc::O_CREAT),
            0
        );
    }
}

const EACCES: i32 = libc::EACCES;

#[test]
fn a_read_write_rule_confines_the_process_to_its_tree() {
    let Some(abi) = host_abi("a_read_write_rule_confines_the_process_to_its_tree") else {
        return;
    };
    let t = Tree::new();
    let rules = t.rules(&[("a", Access::ReadWrite)]);
    let (ok, no, new, b_new, mv, moved) = (
        t.c("a/ok.txt"),
        t.c("b/no.txt"),
        t.c("a/new"),
        t.c("b/new"),
        t.c("a/mv.txt"),
        t.c("b/moved"),
    );
    let got = in_child(|| {
        let mut skipped = [false; 1];
        let [kind, v] = enforce_real(&rules, &mut skipped);
        let wr = libc::O_WRONLY;
        let (from, to) = (mv.as_ptr(), moved.as_ptr());
        [
            kind,
            v,
            skipped[0] as i32,
            read_errno(&ok),
            open_errno(&ok, wr),
            open_errno(&ok, wr | libc::O_TRUNC),
            open_errno(&new, wr | libc::O_CREAT),
            read_errno(&no),
            open_errno(&b_new, wr | libc::O_CREAT),
            // SAFETY: both paths are live NUL-terminated strings.
            rc(unsafe { libc::rename(from, to) }),
            rc(unsafe { libc::unlink(new.as_ptr()) }),
            0,
            0,
            0,
            0,
            0,
        ]
    });
    assert_eq!(
        &got[..3],
        [0, abi as i32, 0],
        "enforced at the host ABI, nothing skipped"
    );
    assert_eq!(&got[3..7], [0; 4], "read, write, truncate and create inside the rule");
    assert_eq!(&got[7..9], [EACCES; 2], "read and create outside the rule");
    // EXDEV (ABI 1, or a rename Landlock cannot prove safe) or EACCES: the exact errno depends on the ABI
    assert_ne!(got[9], 0, "rename out of the rule's tree");
    assert_eq!(got[10], 0, "unlink inside the rule");
    assert!(t.path("a/mv.txt").exists() && !t.path("b/moved").exists());
    t.assert_parent_unrestricted();
}

#[test]
fn a_read_exec_rule_allows_reading_and_running_but_not_writing() {
    let Some(_) = host_abi("a_read_exec_rule_allows_reading_and_running_but_not_writing") else {
        return;
    };
    let t = Tree::new();
    for dir in ["x", "y"] {
        std::fs::create_dir(t.path(dir)).unwrap();
        // a copy of /bin/true under each directory: allowed under x, outside every rule under y
        std::fs::copy("/bin/true", t.path(dir).join("true")).unwrap();
    }
    // the dynamic loader and libc: canonical paths (on merged-/usr hosts /lib and /lib64 are symlinks, which a
    // rule refuses)
    let mut sys: Vec<PathBuf> = ["/usr", "/lib", "/lib64", "/etc"]
        .iter()
        .filter_map(|p| std::fs::canonicalize(p).ok())
        .collect();
    sys.sort();
    sys.dedup();
    let mut rules = t.rules(&[("x", Access::ReadExec)]);
    rules.extend(
        prepare(
            &sys.iter()
                .map(|p| Rule {
                    path: p.clone(),
                    access: Access::ReadExec,
                })
                .collect::<Vec<_>>(),
        )
        .unwrap(),
    );
    assert_eq!(exec_status(&t.c("y/true")), 0, "the copy runs unrestricted");
    let (x_true, y_true, x_new) = (t.c("x/true"), t.c("y/true"), t.c("x/new"));
    let n = rules.len();
    let got = in_child(|| {
        let mut skipped = [false; 8];
        let [kind, _] = enforce_real(&rules, &mut skipped[..n]);
        [
            kind,
            exec_status(&x_true),
            exec_status(&y_true),
            read_errno(&x_true),
            open_errno(&x_true, libc::O_WRONLY),
            open_errno(&x_new, libc::O_WRONLY | libc::O_CREAT),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    });
    assert_eq!(
        &got[..6],
        [0, 0, EACCES, 0, EACCES, EACCES],
        "enforce, exec in/out, read, write, create"
    );
    t.assert_parent_unrestricted();
}

#[test]
fn a_file_rule_grants_the_file_only_with_its_directory_rights_masked() {
    let Some(_) = host_abi("a_file_rule_grants_the_file_only_with_its_directory_rights_masked") else {
        return;
    };
    let t = Tree::new();
    // ReadWrite includes directory-only rights (make, remove, refer): unmasked, add_rule fails with EINVAL
    let rules = t.rules(&[("a/ok.txt", Access::ReadWrite)]);
    let (ok, other, new) = (t.c("a/ok.txt"), t.c("a/other.txt"), t.c("a/new"));
    let got = in_child(|| {
        let mut skipped = [false; 1];
        let [kind, v] = enforce_real(&rules, &mut skipped);
        [
            kind,
            v,
            read_errno(&ok),
            open_errno(&ok, libc::O_WRONLY),
            read_errno(&other),
            open_errno(&new, libc::O_WRONLY | libc::O_CREAT),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    });
    assert_eq!(
        got[0],
        0,
        "not enforced: {:?}",
        std::io::Error::from_raw_os_error(got[1])
    );
    assert_eq!(&got[2..6], [0, 0, EACCES, EACCES], "the file itself, not its directory");
    t.assert_parent_unrestricted();
}

#[test]
fn a_missing_rule_path_is_skipped_and_reported() {
    let Some(_) = host_abi("a_missing_rule_path_is_skipped_and_reported") else {
        return;
    };
    let t = Tree::new();
    let rules = t.rules(&[
        ("gone", Access::ReadWrite),
        ("a", Access::ReadWrite),
        ("a/ok.txt/under-a-file", Access::ReadExec),
    ]);
    let ok = t.c("a/ok.txt");
    let got = in_child(|| {
        let mut skipped = [false; 3];
        let [kind, _] = enforce_real(&rules, &mut skipped);
        let s = skipped.map(i32::from);
        [kind, s[0], s[1], s[2], read_errno(&ok), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    });
    assert_eq!(
        &got[..5],
        [0, 1, 0, 1, 0],
        "enforced; skipped gone and under-a-file; a still granted"
    );
    t.assert_parent_unrestricted();
}

#[test]
fn an_empty_rule_list_denies_every_handled_right() {
    let Some(_) = host_abi("an_empty_rule_list_denies_every_handled_right") else {
        return;
    };
    let t = Tree::new();
    let (ok, no, new) = (t.c("a/ok.txt"), t.c("b/no.txt"), t.c("a/new"));
    let got = in_child(|| {
        let [kind, _] = enforce_real(&[], &mut []);
        [
            kind,
            read_errno(&ok),
            read_errno(&no),
            read_errno(c"/etc/passwd"),
            open_errno(&new, libc::O_WRONLY | libc::O_CREAT),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    });
    assert_eq!(&got[..5], [0, EACCES, EACCES, EACCES, EACCES]);
    t.assert_parent_unrestricted();
}

#[test]
fn a_symlink_rule_path_is_an_error_and_restricts_nothing() {
    let Some(_) = host_abi("a_symlink_rule_path_is_an_error_and_restricts_nothing") else {
        return;
    };
    let t = Tree::new();
    let rules = t.rules(&[("b", Access::ReadExec), ("link", Access::ReadWrite)]);
    let ok = t.c("a/ok.txt");
    let got = in_child(|| {
        let mut skipped = [false; 2];
        let [kind, v] = enforce_real(&rules, &mut skipped);
        [kind, v, read_errno(&ok), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    });
    assert_eq!(
        &got[..3],
        [3, libc::ELOOP, 0],
        "a rule error, and the child is not restricted"
    );
    t.assert_parent_unrestricted();
}

fn enosys() -> Result<u32, i32> {
    Err(libc::ENOSYS)
}
fn eopnotsupp() -> Result<u32, i32> {
    Err(libc::EOPNOTSUPP)
}
fn einval() -> Result<u32, i32> {
    Err(libc::EINVAL)
}
fn no_nnp() -> Result<(), i32> {
    Err(libc::EPERM)
}

#[test]
fn unavailable_landlock_applies_nothing_and_is_not_an_error() {
    let t = Tree::new();
    let rules = t.rules(&[("a", Access::ReadWrite)]);
    let no = t.c("b/no.txt");
    for (probe, want) in [
        (enosys as Probe, [1, libc::ENOSYS]),
        (eopnotsupp, [1, libc::EOPNOTSUPP]),
        (einval, [2, libc::EINVAL]),
    ] {
        let got = in_child(|| {
            let mut skipped = [false; 1];
            let [kind, v] = outcome(enforce(&rules, &mut skipped, probe, set_no_new_privs));
            [kind, v, read_errno(&no), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        });
        assert_eq!(&got[..3], [want[0], want[1], 0], "nothing applied");
    }
    // through the public mapping: the probe fails before anything is created, so the test process is safe
    for probe in [enosys as Probe, eopnotsupp] {
        assert!(matches!(
            apply_with(&[], probe, set_no_new_privs),
            Ok(Applied::Unavailable(_))
        ));
    }
    assert!(matches!(
        apply_with(&[], einval, set_no_new_privs),
        Err(LandlockError::Syscall { .. })
    ));
    t.assert_parent_unrestricted();
}

#[test]
fn without_no_new_privs_nothing_is_restricted_and_it_is_an_error() {
    let Some(_) = host_abi("without_no_new_privs_nothing_is_restricted_and_it_is_an_error") else {
        return;
    };
    let t = Tree::new();
    let rules = t.rules(&[("a", Access::ReadWrite)]);
    let no = t.c("b/no.txt");
    let got = in_child(|| {
        let mut skipped = [false; 1];
        let [kind, v] = outcome(enforce(&rules, &mut skipped, kernel_abi, no_nnp));
        [kind, v, read_errno(&no), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    });
    assert_eq!(
        &got[..3],
        [2, libc::EPERM, 0],
        "a step error; the ruleset was never enforced"
    );
    t.assert_parent_unrestricted();
}

#[test]
fn a_second_ruleset_only_narrows() {
    let Some(_) = host_abi("a_second_ruleset_only_narrows") else {
        return;
    };
    let t = Tree::new();
    let first = t.rules(&[("a", Access::ReadWrite)]);
    let broader = t.rules(&[("", Access::ReadWrite)]);
    let (ok, no, b_new) = (t.c("a/ok.txt"), t.c("b/no.txt"), t.c("b/new"));
    let got = in_child(|| {
        let mut skipped = [false; 1];
        let [k1, _] = enforce_real(&first, &mut skipped);
        let [k2, _] = enforce_real(&broader, &mut skipped);
        [
            k1,
            k2,
            read_errno(&ok),
            read_errno(&no),
            open_errno(&b_new, libc::O_WRONLY | libc::O_CREAT),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        ]
    });
    assert_eq!(
        &got[..5],
        [0, 0, 0, EACCES, EACCES],
        "the broader second layer regains nothing"
    );
    t.assert_parent_unrestricted();
}

#[test]
fn device_ioctls_need_a_read_write_rule_from_abi_5() {
    let test = "device_ioctls_need_a_read_write_rule_from_abi_5";
    let Some(abi) = host_abi(test) else { return };
    if abi < 5 {
        assert!(
            !required(),
            "RUNTIME_REQUIRE_BWRAP=1 but the host Landlock ABI {abi} has no IOCTL_DEV"
        );
        eprintln!("SKIPPED {test}: the host Landlock ABI {abi} has no IOCTL_DEV");
        return;
    }
    fn fionread() -> i32 {
        // SAFETY: a NUL-terminated literal path; FIONREAD writes one int to a live local.
        let fd = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return 1000 + errno();
        }
        let mut n: libc::c_int = 0;
        let r = rc(unsafe { libc::ioctl(fd, libc::FIONREAD, &mut n) });
        unsafe { libc::close(fd) };
        r
    }
    let unrestricted = fionread();
    assert_ne!(unrestricted, EACCES);
    let t = Tree::new();
    for (access, want) in [(Access::ReadExec, EACCES), (Access::ReadWrite, unrestricted)] {
        let rules = t.rules(&[("/dev", access)]);
        let got = in_child(|| {
            let mut skipped = [false; 1];
            let [kind, _] = enforce_real(&rules, &mut skipped);
            [kind, fionread(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        });
        assert_eq!(&got[..2], [0, want], "{access:?} /dev");
    }
    t.assert_parent_unrestricted();
}
