//! The Landlock filesystem ruleset the `sandbox-init` shim applies inside bwrap: defence in depth under the mount
//! layout, never the only boundary. Raw syscalls (`landlock_create_ruleset`, `landlock_add_rule`,
//! `landlock_restrict_self`), no library. A ruleset is inherited by every child and can never be widened: a later
//! ruleset only narrows (each is another layer that must also allow an access).
//!
//! **Best effort, fail closed.** When the kernel has no Landlock (`ENOSYS`) or it is not in the boot-time LSM list
//! (`EOPNOTSUPP`), [`apply`] returns [`Applied::Unavailable`], never an error, and restricts nothing. Every other
//! failure, including any after the ruleset was created, is an error: a half-built ruleset must never pass for
//! "unavailable". An empty rule list is not a no-op: it denies every handled right everywhere.
//!
//! **ABI negotiation.** The kernel reports its ABI; the ruleset handles every filesystem right of that ABI this
//! code knows, and never an unknown bit (a newer kernel gets the ABI 5 set):
//!
//! | ABI | handled filesystem rights |
//! |---|---|
//! | 1 | execute, write/read file, read dir, remove dir/file, make char/dir/reg/sock/fifo/block/sym (`0x1fff`) |
//! | 2 | + `REFER` (rename and link across directories) (`0x3fff`) |
//! | 3, 4 | + `TRUNCATE` (`0x7fff`); ABI 4's network rights are not handled (bwrap's `--unshare-net` covers deny) |
//! | 5 and later | + `IOCTL_DEV` (ioctls on device files) (`0xffff`); ABI 6's scoping is not used |
//!
//! A [`Access::ReadExec`] rule grants execute, read file and read dir; [`Access::ReadWrite`] grants every handled
//! right, so on ABI 5+ it is what lets a program `ioctl` a device (`/dev/dri`: GPU drivers): device paths need a
//! `ReadWrite` rule. A rule on a non-directory gets only the rights that apply to files (execute, write, read,
//! truncate, ioctl), because the kernel refuses directory rights on a file with `EINVAL`.
//!
//! **Rule paths** must be absolute; one that does not exist (`ENOENT`, `ENOTDIR`) is skipped and reported. The
//! last component is opened with `O_NOFOLLOW` and a symlink there is an error: callers pass canonical paths (the
//! renderer's resolved mount sources), and a rule silently landing on a symlink's target, or on the link itself
//! where it grants nothing, would hide a mistake either way.
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

// <linux/landlock.h>, which libc does not carry.
const CREATE_RULESET_VERSION: libc::c_uint = 1;
const RULE_PATH_BENEATH: libc::c_int = 1;

const EXECUTE: u64 = 1 << 0;
const WRITE_FILE: u64 = 1 << 1;
const READ_FILE: u64 = 1 << 2;
const READ_DIR: u64 = 1 << 3;
// REMOVE_DIR (1 << 4) up to MAKE_SYM: the rest of ABI 1, all directory rights.
const MAKE_SYM: u64 = 1 << 12;
const REFER: u64 = 1 << 13;
const TRUNCATE: u64 = 1 << 14;
const IOCTL_DEV: u64 = 1 << 15;
const ABI1: u64 = (MAKE_SYM << 1) - 1;
/// The rights that apply to a non-directory (the kernel's `ACCESS_FILE`).
const ACCESS_FILE: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE | IOCTL_DEV;

/// `struct landlock_ruleset_attr` up to `handled_access_fs`: the ABI 1 size, which every kernel accepts; the later
/// fields (network rights, scoping) are not used.
#[repr(C)]
struct RulesetAttr {
    handled_access_fs: u64,
}

/// `struct landlock_path_beneath_attr`, which the kernel declares packed.
#[repr(C, packed)]
struct PathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

const _: () = assert!(size_of::<RulesetAttr>() == 8 && size_of::<PathBeneathAttr>() == 12);

/// What a rule grants beneath its path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    ReadExec,
    ReadWrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub path: PathBuf,
    pub access: Access,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Applied {
    /// The process is restricted at this ABI; `skipped` rule paths did not exist.
    Enforced { abi: u32, skipped: Vec<PathBuf> },
    /// Landlock is not available here (the reason); nothing was restricted. Never an error.
    Unavailable(String),
}

#[derive(Debug, thiserror::Error)]
pub enum LandlockError {
    #[error("landlock: rule path {0:?} is not absolute or contains a NUL byte")]
    BadPath(PathBuf),
    #[error("landlock: {step} failed: {source}")]
    Syscall { step: &'static str, source: std::io::Error },
    #[error("landlock: the rule for {path:?} failed: {source}")]
    Rule { path: PathBuf, source: std::io::Error },
}

/// The kernel's Landlock ABI version (`landlock_create_ruleset(NULL, 0, VERSION)`); `ENOSYS`/`EOPNOTSUPP` mean
/// unavailable.
pub fn abi_version() -> Result<u32, LandlockError> {
    kernel_abi().map_err(|e| syscall_error("landlock_create_ruleset(VERSION)", e))
}

/// Restricts the calling thread (and everything it later runs) to `rules`; see the module documentation. Call it
/// single-threaded: only the calling thread is restricted.
pub fn apply(rules: &[Rule]) -> Result<Applied, LandlockError> {
    apply_with(rules, kernel_abi, set_no_new_privs)
}

/// The ABI probe: the version, or the errno.
type Probe = fn() -> Result<u32, i32>;

fn apply_with(rules: &[Rule], abi: Probe, no_new_privs: fn() -> Result<(), i32>) -> Result<Applied, LandlockError> {
    let prepared = prepare(rules)?;
    let mut skipped = vec![false; rules.len()];
    let outcome = enforce(&prepared, &mut skipped, abi, no_new_privs);
    finish(rules, &skipped, outcome)
}

/// The rules as C paths, validated (everything that allocates happens here, before [`enforce`]).
fn prepare(rules: &[Rule]) -> Result<Vec<(CString, Access)>, LandlockError> {
    rules
        .iter()
        .map(|r| match CString::new(r.path.as_os_str().as_bytes()) {
            Ok(c) if r.path.is_absolute() => Ok((c, r.access)),
            _ => Err(LandlockError::BadPath(r.path.clone())),
        })
        .collect()
}

/// What [`enforce`] did.
#[derive(Debug)]
enum Outcome {
    Enforced(u32),
    /// The probe's errno.
    Unavailable(i32),
}

/// Why [`enforce`] failed: a step and its errno, or the index of a rule and its errno.
#[derive(Debug)]
enum Fail {
    Step(&'static str, i32),
    Rule(usize, i32),
}

/// Builds and enforces the ruleset. Allocation-free, so a forked child may call it; `skipped[i]` is set for each
/// rule path that does not exist.
fn enforce(
    rules: &[(CString, Access)],
    skipped: &mut [bool],
    abi: Probe,
    no_new_privs: fn() -> Result<(), i32>,
) -> Result<Outcome, Fail> {
    if skipped.len() != rules.len() {
        // a rule without a slot would be silently left out: fail closed
        return Err(Fail::Step("landlock rule bookkeeping", libc::EINVAL));
    }
    let abi = match abi() {
        Ok(v) => v,
        Err(e @ (libc::ENOSYS | libc::EOPNOTSUPP)) => return Ok(Outcome::Unavailable(e)),
        Err(e) => return Err(Fail::Step("landlock_create_ruleset(VERSION)", e)),
    };
    let handled = handled_mask(abi);
    let attr = RulesetAttr {
        handled_access_fs: handled,
    };
    // SAFETY: `attr` is a live `landlock_ruleset_attr` prefix of the size passed; the kernel only reads it.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr as *const RulesetAttr,
            size_of::<RulesetAttr>(),
            0,
        )
    };
    let ruleset = owned(fd).map_err(|e| Fail::Step("landlock_create_ruleset", e))?;
    for (i, ((path, access), skip)) in rules.iter().zip(skipped.iter_mut()).enumerate() {
        // SAFETY: `path` is NUL-terminated and live for the call.
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) };
        let target = match owned(fd as libc::c_long) {
            Ok(fd) => fd,
            Err(libc::ENOENT | libc::ENOTDIR) => {
                *skip = true;
                continue;
            }
            Err(e) => return Err(Fail::Rule(i, e)),
        };
        // SAFETY: an all-zero `stat` is a valid value; fstat fills it from a live descriptor (O_PATH suffices).
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        // SAFETY: `target` is a live descriptor and `st` a live, writable `stat` the kernel fills.
        if unsafe { libc::fstat(target.as_raw_fd(), &mut st) } != 0 {
            return Err(Fail::Rule(i, errno()));
        }
        let kind = st.st_mode & libc::S_IFMT;
        if kind == libc::S_IFLNK {
            return Err(Fail::Rule(i, libc::ELOOP));
        }
        let beneath = PathBeneathAttr {
            allowed_access: rule_access(*access, handled, kind == libc::S_IFDIR),
            parent_fd: target.as_raw_fd(),
        };
        // SAFETY: `beneath` is a live `landlock_path_beneath_attr`, read by the kernel during the call only.
        let r = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset.as_raw_fd(),
                RULE_PATH_BENEATH,
                &beneath as *const PathBeneathAttr,
                0,
            )
        };
        if r != 0 {
            return Err(Fail::Rule(i, errno()));
        }
    }
    no_new_privs().map_err(|e| Fail::Step("prctl(PR_SET_NO_NEW_PRIVS)", e))?;
    // SAFETY: integer arguments only; `ruleset` is a live Landlock ruleset descriptor.
    if unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset.as_raw_fd(), 0) } != 0 {
        return Err(Fail::Step("landlock_restrict_self", errno()));
    }
    Ok(Outcome::Enforced(abi))
}

/// [`enforce`]'s result for the public API: skipped flags back to paths, errnos to errors.
fn finish(rules: &[Rule], skipped: &[bool], outcome: Result<Outcome, Fail>) -> Result<Applied, LandlockError> {
    match outcome {
        Ok(Outcome::Enforced(abi)) => Ok(Applied::Enforced {
            abi,
            skipped: rules
                .iter()
                .zip(skipped)
                .filter(|&(_, &s)| s)
                .map(|(r, _)| r.path.clone())
                .collect(),
        }),
        Ok(Outcome::Unavailable(e)) => Ok(Applied::Unavailable(unavailable_why(e))),
        Err(Fail::Step(step, e)) => Err(syscall_error(step, e)),
        Err(Fail::Rule(i, e)) => Err(LandlockError::Rule {
            path: rules[i].path.clone(),
            source: std::io::Error::from_raw_os_error(e),
        }),
    }
}

/// Why Landlock is unavailable, for the probe's `ENOSYS` or `EOPNOTSUPP`.
fn unavailable_why(e: i32) -> String {
    if e == libc::ENOSYS {
        "the kernel has no Landlock (Linux 5.13+ built with CONFIG_SECURITY_LANDLOCK is needed)".to_owned()
    } else {
        "Landlock is disabled on this host (not in the boot-time LSM list, /sys/kernel/security/lsm)".to_owned()
    }
}

/// What [`apply`] would find on this host, probed from outside the sandbox (for `runtime sandbox` and `doctor`).
#[derive(Debug)]
pub enum HostState {
    /// Enforced at this ABI.
    Abi(u32),
    /// [`Applied::Unavailable`], and why.
    Unavailable(String),
    /// The probe failed otherwise: [`apply`] would fail with this, so every sandboxed run is refused.
    Error(LandlockError),
}

pub fn host_state() -> HostState {
    match kernel_abi() {
        Ok(v) => HostState::Abi(v),
        Err(e @ (libc::ENOSYS | libc::EOPNOTSUPP)) => HostState::Unavailable(unavailable_why(e)),
        Err(e) => HostState::Error(syscall_error("landlock_create_ruleset(VERSION)", e)),
    }
}

/// Every filesystem right ABI `abi` has that this code knows (see the module documentation's table).
fn handled_mask(abi: u32) -> u64 {
    match abi {
        0 => 0,
        1 => ABI1,
        2 => ABI1 | REFER,
        3 | 4 => ABI1 | REFER | TRUNCATE,
        _ => ABI1 | REFER | TRUNCATE | IOCTL_DEV,
    }
}

/// The rights a rule grants: within `handled`, and only file rights on a non-directory.
fn rule_access(access: Access, handled: u64, is_dir: bool) -> u64 {
    let wanted = match access {
        Access::ReadExec => EXECUTE | READ_FILE | READ_DIR,
        Access::ReadWrite => handled,
    };
    wanted & handled & if is_dir { u64::MAX } else { ACCESS_FILE }
}

fn kernel_abi() -> Result<u32, i32> {
    // SAFETY: the VERSION query takes a NULL attribute and size 0.
    let r = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<RulesetAttr>(),
            0,
            CREATE_RULESET_VERSION,
        )
    };
    if r < 0 { Err(errno()) } else { Ok(r as u32) }
}

fn set_no_new_privs() -> Result<(), i32> {
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(errno());
    }
    Ok(())
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EIO)
}

fn syscall_error(step: &'static str, e: i32) -> LandlockError {
    LandlockError::Syscall {
        step,
        source: std::io::Error::from_raw_os_error(e),
    }
}

/// A syscall's new descriptor, owned (closed on drop), or the errno.
fn owned(r: libc::c_long) -> Result<OwnedFd, i32> {
    if r < 0 {
        return Err(errno());
    }
    // SAFETY: `r` is a descriptor the kernel just returned, owned by nothing else.
    Ok(unsafe { OwnedFd::from_raw_fd(r as RawFd) })
}

#[cfg(test)]
mod tests;
