//! The seccomp deny-list every sandboxed program runs under: a hand-assembled classic-BPF filter (no libseccomp)
//! that the `sandbox-init` shim installs after `PR_SET_NO_NEW_PRIVS`, inherited by every Wine process. It is a
//! DENY list: the syscalls below fail, everything else is allowed. A denied call returns `EPERM` (never a kill),
//! so a program that probes for a feature gets an ordinary error.
//!
//! **Program shape.** First the architecture: `seccomp_data.arch` must be this build's audit architecture, or the
//! call fails with `EPERM`. On x86-64 that refuses the whole i386 ABI (`int 0x80`, a 32-bit ELF), whose syscall
//! numbers differ and would slip past the table; Wine runs 32-bit Windows programs in 64-bit processes (new
//! WoW64), so it never enters it. Then, on x86-64, any number with the x32 bit (`0x40000000`) set fails with
//! `EPERM` (the x32 ABI shares the x86-64 audit architecture but numbers its calls differently). Then each entry
//! of [`DENIED`] is compared by number; an entry with an argument condition jumps to its own check. Everything
//! else is allowed. Arguments are compared on their low 32 bits: the kernel truncates `clone`'s flags, `ioctl`'s
//! `cmd`, `personality`'s persona and `socket`'s domain to 32 bits, so garbage in the upper half changes nothing.
//! Jump offsets are computed by a small label builder, never counted by hand.
//!
//! The syscall numbers are this build's `libc::SYS_*` constants, so the filter is built only for the architecture
//! the runtime was compiled for (x86-64 or aarch64). `clone3` fails with `ENOSYS`: its flags live behind a pointer
//! seccomp cannot read, and glibc answers `ENOSYS` by falling back to `clone`, whose flags are checked. The
//! `socket` rule is deliberately narrow: Wine uses `AF_UNIX`, `AF_INET`/`AF_INET6` and `AF_NETLINK` (routing, for
//! adapter enumeration), which stay allowed, and neither architecture has the `socketcall` multiplexer.
//! `io_uring_setup` is denied because io_uring requests never pass through seccomp.
//!
//! | syscall | refused when | why |
//! |---|---|---|
//! | `ptrace` | always | inspects and rewrites the memory and registers of other processes of the same user |
//! | `process_vm_readv` | always | reads another process's memory directly |
//! | `process_vm_writev` | always | writes another process's memory directly |
//! | `kcmp` | always | compares kernel objects (files, memory maps) of other processes, leaking how they are shared |
//! | `keyctl` | always | manages kernel keyrings, which hold credentials and are shared with the session outside the sandbox |
//! | `add_key` | always | adds keys to the kernel keyrings (see keyctl) |
//! | `request_key` | always | looks up keyring keys and can make the kernel run the host's request-key helper |
//! | `bpf` | always | loads eBPF programs and maps, a large kernel attack surface |
//! | `perf_event_open` | always | performance counters: a large kernel attack surface and a side channel |
//! | `userfaultfd` | always | lets a program stall page faults (even the kernel's) at will, a standard kernel-exploit primitive |
//! | `mount` | always | mounts filesystems; the sandbox's mount layout is fixed by bubblewrap |
//! | `umount2` | always | unmounts filesystems, which could uncover what the sandbox's mounts hide |
//! | `pivot_root` | always | changes the root mount |
//! | `chroot` | always | changes the root directory |
//! | `unshare` | always | creates namespaces; a new user namespace grants capabilities inside it |
//! | `setns` | always | joins other namespaces |
//! | `open_by_handle_at` | always | opens files by handle, bypassing path-based confinement (the 'shocker' container escape) |
//! | `name_to_handle_at` | always | produces the file handles open_by_handle_at consumes |
//! | `kexec_load` | always | loads a new kernel to boot into |
//! | `kexec_file_load` | always | loads a new kernel to boot into |
//! | `init_module` | always | loads a kernel module |
//! | `finit_module` | always | loads a kernel module |
//! | `delete_module` | always | unloads a kernel module |
//! | `syslog` | always | reads or clears the kernel log, which leaks kernel addresses and host activity |
//! | `acct` | always | switches process accounting on or off |
//! | `quotactl` | always | manages filesystem quotas |
//! | `swapon` | always | enables a swap area |
//! | `swapoff` | always | disables a swap area |
//! | `reboot` | always | reboots or halts the machine |
//! | `settimeofday` | always | sets the system clock |
//! | `clock_settime` | always | sets a system clock |
//! | `clock_adjtime` | always | adjusts a system clock |
//! | `adjtimex` | always | adjusts the system clock |
//! | `sethostname` | always | renames the host |
//! | `setdomainname` | always | renames the host's NIS domain |
//! | `iopl` | always | grants direct access to hardware I/O ports |
//! | `ioperm` | always | grants direct access to hardware I/O ports |
//! | `lookup_dcookie` | always | obsolete profiling interface that turns kernel directory cookies into paths |
//! | `nfsservctl` | always | obsolete NFS server control (removed from Linux in 3.1) |
//! | `move_pages` | always | moves the memory pages of other processes between NUMA nodes |
//! | `mbind` | always | NUMA memory policy: unused by desktop programs, historically buggy kernel code |
//! | `set_mempolicy` | always | NUMA memory policy: unused by desktop programs, historically buggy kernel code |
//! | `get_mempolicy` | always | NUMA memory policy: unused by desktop programs, historically buggy kernel code |
//! | `migrate_pages` | always | moves the memory pages of other processes between NUMA nodes |
//! | `fanotify_init` | always | watches file access across whole mounts or filesystems |
//! | `mount_setattr` | always | new mount API: changes mount attributes |
//! | `move_mount` | always | new mount API: attaches or moves mounts |
//! | `open_tree` | always | new mount API: clones mount trees |
//! | `fsopen` | always | new mount API: creates a filesystem context |
//! | `fsconfig` | always | new mount API: configures a filesystem context |
//! | `fsmount` | always | new mount API: creates a mount from a filesystem context |
//! | `fspick` | always | new mount API: reconfigures a mounted filesystem |
//! | `pidfd_getfd` | always | copies a file descriptor out of another process |
//! | `io_uring_setup` | always | io_uring runs operations without seccomp seeing them (it could open the sockets denied below) |
//! | `clone3` | always (`ENOSYS`) | its flags live behind a pointer seccomp cannot read; ENOSYS makes glibc fall back to clone |
//! | `clone` | arg0 has any bit of 0x7e020080 | creates namespaces (CLONE_NEW* flags); threads and plain forks are allowed |
//! | `ioctl` | arg1 is one of 0x5412, 0x541c | TIOCSTI and TIOCLINUX push input into a terminal, e.g. keystrokes into the user's shell |
//! | `personality` | arg0 is none of 0x0, 0x8, 0xffffffff | only PER_LINUX, PER_LINUX32 and the query are allowed; other flags weaken exploit mitigations |
//! | `socket` | arg0 is one of 0x28, 0x26, 0xf | AF_VSOCK (hypervisor), AF_ALG (kernel crypto, a recurring exploit vector), AF_KEY (IPsec keys): no Windows API uses them |

use std::mem::offset_of;

/// One classic-BPF instruction, laid out as the kernel's `struct sock_filter`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const _: () = assert!(
    size_of::<SockFilter>() == size_of::<libc::sock_filter>()
        && align_of::<SockFilter>() == align_of::<libc::sock_filter>()
);
// The argument loads read the low 32 bits of each 64-bit argument at its own offset.
const _: () = assert!(cfg!(target_endian = "little"));

/// The instructions the filter uses (and the only ones the test interpreter implements).
pub(crate) const LD_W_ABS: u16 = (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16;
pub(crate) const JEQ: u16 = (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16;
pub(crate) const JSET: u16 = (libc::BPF_JMP | libc::BPF_JSET | libc::BPF_K) as u16;
pub(crate) const RET: u16 = (libc::BPF_RET | libc::BPF_K) as u16;

const RET_ALLOW: u32 = libc::SECCOMP_RET_ALLOW;
const RET_EPERM: u32 = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
const RET_ENOSYS: u32 = libc::SECCOMP_RET_ERRNO | libc::ENOSYS as u32;

const NR: u32 = offset_of!(libc::seccomp_data, nr) as u32;
const ARCH: u32 = offset_of!(libc::seccomp_data, arch) as u32;
const ARGS: u32 = offset_of!(libc::seccomp_data, args) as u32;

// <linux/audit.h>, which libc does not carry: the ELF machine plus the 64-bit and little-endian flags.
const AUDIT_ARCH_64BIT: u32 = 0x8000_0000;
const AUDIT_ARCH_LE: u32 = 0x4000_0000;
const AUDIT_ARCH_X86_64: u32 = libc::EM_X86_64 as u32 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
const AUDIT_ARCH_AARCH64: u32 = libc::EM_AARCH64 as u32 | AUDIT_ARCH_64BIT | AUDIT_ARCH_LE;
/// x86-64's `__X32_SYSCALL_BIT` (libc defines it only for the x32 target itself).
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

/// Every `CLONE_NEW*` flag. `CLONE_NEWTIME` (0x80) sits in `clone`'s exit-signal byte, where only an invalid
/// signal number (above 64) sets it, so including it refuses no valid `clone`.
const CLONE_NEW_ANY: u32 = (libc::CLONE_NEWNS
    | libc::CLONE_NEWCGROUP
    | libc::CLONE_NEWUTS
    | libc::CLONE_NEWIPC
    | libc::CLONE_NEWUSER
    | libc::CLONE_NEWPID
    | libc::CLONE_NEWNET
    | libc::CLONE_NEWTIME) as u32;
/// `<linux/personality.h>` values libc lacks: `PER_LINUX` (0), `PER_LINUX32` and the query value.
const PERSONALITY_ALLOWED: &[u32] = &[0, 0x0008, 0xffff_ffff];

/// When a [`DENIED`] syscall is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum When {
    /// Every call fails with `EPERM`.
    Always,
    /// Every call fails with `ENOSYS`, so libc falls back to an older syscall the filter can inspect.
    NoSys,
    /// `EPERM` when the low 32 bits of argument `arg` have any bit of `mask`.
    ArgHasBit { arg: u8, mask: u32 },
    /// `EPERM` when the low 32 bits of argument `arg` are one of `values`.
    ArgIn { arg: u8, values: &'static [u32] },
    /// `EPERM` unless the low 32 bits of argument `arg` are one of `values`.
    ArgNotIn { arg: u8, values: &'static [u32] },
}

/// One entry of the deny-list: the syscall, this build's number for it, when it is refused and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Denied {
    pub name: &'static str,
    pub nr: libc::c_long,
    pub when: When,
    pub reason: &'static str,
}

/// `deny!(SYS_x, when, reason)`: the name is the `libc::SYS_*` constant's without `SYS_`, so they cannot disagree.
macro_rules! deny {
    ($sys:ident, $when:expr, $reason:literal) => {
        Denied {
            name: stringify!($sys).split_at(4).1,
            nr: libc::$sys,
            when: $when,
            reason: $reason,
        }
    };
}

use When::Always;

/// The deny-list, in filter order (see the module documentation, whose table must match it).
pub const DENIED: &[Denied] = &[
    deny!(
        SYS_ptrace,
        Always,
        "inspects and rewrites the memory and registers of other processes of the same user"
    ),
    deny!(SYS_process_vm_readv, Always, "reads another process's memory directly"),
    deny!(
        SYS_process_vm_writev,
        Always,
        "writes another process's memory directly"
    ),
    deny!(
        SYS_kcmp,
        Always,
        "compares kernel objects (files, memory maps) of other processes, leaking how they are shared"
    ),
    deny!(
        SYS_keyctl,
        Always,
        "manages kernel keyrings, which hold credentials and are shared with the session outside the sandbox"
    ),
    deny!(SYS_add_key, Always, "adds keys to the kernel keyrings (see keyctl)"),
    deny!(
        SYS_request_key,
        Always,
        "looks up keyring keys and can make the kernel run the host's request-key helper"
    ),
    deny!(
        SYS_bpf,
        Always,
        "loads eBPF programs and maps, a large kernel attack surface"
    ),
    deny!(
        SYS_perf_event_open,
        Always,
        "performance counters: a large kernel attack surface and a side channel"
    ),
    deny!(
        SYS_userfaultfd,
        Always,
        "lets a program stall page faults (even the kernel's) at will, a standard kernel-exploit primitive"
    ),
    deny!(
        SYS_mount,
        Always,
        "mounts filesystems; the sandbox's mount layout is fixed by bubblewrap"
    ),
    deny!(
        SYS_umount2,
        Always,
        "unmounts filesystems, which could uncover what the sandbox's mounts hide"
    ),
    deny!(SYS_pivot_root, Always, "changes the root mount"),
    deny!(SYS_chroot, Always, "changes the root directory"),
    deny!(
        SYS_unshare,
        Always,
        "creates namespaces; a new user namespace grants capabilities inside it"
    ),
    deny!(SYS_setns, Always, "joins other namespaces"),
    deny!(
        SYS_open_by_handle_at,
        Always,
        "opens files by handle, bypassing path-based confinement (the 'shocker' container escape)"
    ),
    deny!(
        SYS_name_to_handle_at,
        Always,
        "produces the file handles open_by_handle_at consumes"
    ),
    deny!(SYS_kexec_load, Always, "loads a new kernel to boot into"),
    deny!(SYS_kexec_file_load, Always, "loads a new kernel to boot into"),
    deny!(SYS_init_module, Always, "loads a kernel module"),
    deny!(SYS_finit_module, Always, "loads a kernel module"),
    deny!(SYS_delete_module, Always, "unloads a kernel module"),
    deny!(
        SYS_syslog,
        Always,
        "reads or clears the kernel log, which leaks kernel addresses and host activity"
    ),
    deny!(SYS_acct, Always, "switches process accounting on or off"),
    deny!(SYS_quotactl, Always, "manages filesystem quotas"),
    deny!(SYS_swapon, Always, "enables a swap area"),
    deny!(SYS_swapoff, Always, "disables a swap area"),
    deny!(SYS_reboot, Always, "reboots or halts the machine"),
    deny!(SYS_settimeofday, Always, "sets the system clock"),
    deny!(SYS_clock_settime, Always, "sets a system clock"),
    deny!(SYS_clock_adjtime, Always, "adjusts a system clock"),
    deny!(SYS_adjtimex, Always, "adjusts the system clock"),
    deny!(SYS_sethostname, Always, "renames the host"),
    deny!(SYS_setdomainname, Always, "renames the host's NIS domain"),
    #[cfg(target_arch = "x86_64")]
    deny!(SYS_iopl, Always, "grants direct access to hardware I/O ports"),
    #[cfg(target_arch = "x86_64")]
    deny!(SYS_ioperm, Always, "grants direct access to hardware I/O ports"),
    deny!(
        SYS_lookup_dcookie,
        Always,
        "obsolete profiling interface that turns kernel directory cookies into paths"
    ),
    deny!(
        SYS_nfsservctl,
        Always,
        "obsolete NFS server control (removed from Linux in 3.1)"
    ),
    deny!(
        SYS_move_pages,
        Always,
        "moves the memory pages of other processes between NUMA nodes"
    ),
    deny!(
        SYS_mbind,
        Always,
        "NUMA memory policy: unused by desktop programs, historically buggy kernel code"
    ),
    deny!(
        SYS_set_mempolicy,
        Always,
        "NUMA memory policy: unused by desktop programs, historically buggy kernel code"
    ),
    deny!(
        SYS_get_mempolicy,
        Always,
        "NUMA memory policy: unused by desktop programs, historically buggy kernel code"
    ),
    deny!(
        SYS_migrate_pages,
        Always,
        "moves the memory pages of other processes between NUMA nodes"
    ),
    deny!(
        SYS_fanotify_init,
        Always,
        "watches file access across whole mounts or filesystems"
    ),
    deny!(SYS_mount_setattr, Always, "new mount API: changes mount attributes"),
    deny!(SYS_move_mount, Always, "new mount API: attaches or moves mounts"),
    deny!(SYS_open_tree, Always, "new mount API: clones mount trees"),
    deny!(SYS_fsopen, Always, "new mount API: creates a filesystem context"),
    deny!(SYS_fsconfig, Always, "new mount API: configures a filesystem context"),
    deny!(
        SYS_fsmount,
        Always,
        "new mount API: creates a mount from a filesystem context"
    ),
    deny!(SYS_fspick, Always, "new mount API: reconfigures a mounted filesystem"),
    deny!(
        SYS_pidfd_getfd,
        Always,
        "copies a file descriptor out of another process"
    ),
    deny!(
        SYS_io_uring_setup,
        Always,
        "io_uring runs operations without seccomp seeing them (it could open the sockets denied below)"
    ),
    deny!(
        SYS_clone3,
        When::NoSys,
        "its flags live behind a pointer seccomp cannot read; ENOSYS makes glibc fall back to clone"
    ),
    deny!(
        SYS_clone,
        When::ArgHasBit {
            arg: 0,
            mask: CLONE_NEW_ANY
        },
        "creates namespaces (CLONE_NEW* flags); threads and plain forks are allowed"
    ),
    deny!(
        SYS_ioctl,
        When::ArgIn {
            arg: 1,
            values: &[libc::TIOCSTI as u32, libc::TIOCLINUX as u32]
        },
        "TIOCSTI and TIOCLINUX push input into a terminal, e.g. keystrokes into the user's shell"
    ),
    deny!(
        SYS_personality,
        When::ArgNotIn {
            arg: 0,
            values: PERSONALITY_ALLOWED
        },
        "only PER_LINUX, PER_LINUX32 and the query are allowed; other flags weaken exploit mitigations"
    ),
    deny!(
        SYS_socket,
        When::ArgIn {
            arg: 0,
            values: &[libc::AF_VSOCK as u32, libc::AF_ALG as u32, libc::AF_KEY as u32]
        },
        "AF_VSOCK (hypervisor), AF_ALG (kernel crypto, a recurring exploit vector), AF_KEY (IPsec keys): no Windows API uses them"
    ),
];

/// The architectures the filter has a syscall table for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arch {
    X86_64,
    Aarch64,
}

impl Arch {
    pub fn name(self) -> &'static str {
        match self {
            Arch::X86_64 => "x86_64",
            Arch::Aarch64 => "aarch64",
        }
    }

    fn audit(self) -> u32 {
        match self {
            Arch::X86_64 => AUDIT_ARCH_X86_64,
            Arch::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }
}

/// The architecture this build's `libc::SYS_*` numbers belong to.
const BUILT_FOR: Option<Arch> = if cfg!(target_arch = "x86_64") {
    Some(Arch::X86_64)
} else if cfg!(target_arch = "aarch64") {
    Some(Arch::Aarch64)
} else {
    None
};

#[derive(Debug, thiserror::Error)]
pub enum SeccompError {
    #[error("seccomp: no syscall table for the {0} architecture in this build")]
    UnsupportedArch(&'static str),
    #[error("seccomp: the i386 syscall ABI cannot be allowed: the filter has no i386 deny-list")]
    I386NotSupported,
    #[error("seccomp: invalid filter program: {0}")]
    Program(&'static str),
    #[error("seccomp: {step} failed: {source}")]
    Install { step: &'static str, source: std::io::Error },
}

/// Knobs for [`build_filter_with`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FilterOptions {
    /// Let i386-ABI calls through on x86-64. Refused ([`SeccompError::I386NotSupported`]): Wine's 32-bit programs
    /// do not need it, and allowing it needs an i386 copy of the deny-list, which does not exist.
    pub allow_i386: bool,
}

/// The architecture the runtime was built for, if the filter supports it.
pub fn host_arch() -> Result<Arch, SeccompError> {
    BUILT_FOR.ok_or(SeccompError::UnsupportedArch(std::env::consts::ARCH))
}

/// The filter for `arch` with the default options.
pub fn build_filter(arch: Arch) -> Result<Vec<SockFilter>, SeccompError> {
    build_filter_with(arch, FilterOptions::default())
}

/// The filter program for `arch`, which must be the architecture this build's syscall numbers belong to.
pub fn build_filter_with(arch: Arch, opts: FilterOptions) -> Result<Vec<SockFilter>, SeccompError> {
    if opts.allow_i386 {
        return Err(SeccompError::I386NotSupported);
    }
    if BUILT_FOR != Some(arch) {
        return Err(SeccompError::UnsupportedArch(arch.name()));
    }
    let mut b = Builder::default();
    let (deny, nosys, allow) = (b.label(), b.label(), b.label());
    b.stmt(LD_W_ABS, ARCH);
    b.jump(JEQ, arch.audit(), None, Some(deny));
    b.stmt(LD_W_ABS, NR);
    if arch == Arch::X86_64 {
        b.jump(JSET, X32_SYSCALL_BIT, Some(deny), None);
    }
    let mut checks = Vec::new();
    for d in DENIED {
        let target = match d.when {
            When::Always => deny,
            When::NoSys => nosys,
            when => {
                let l = b.label();
                checks.push((l, when));
                l
            }
        };
        b.jump(JEQ, d.nr as u32, Some(target), None);
    }
    b.stmt(RET, RET_ALLOW);
    for (l, when) in checks {
        b.bind(l);
        match when {
            When::ArgHasBit { arg, mask } => {
                b.stmt(LD_W_ABS, arg_low(arg));
                b.jump(JSET, mask, Some(deny), None);
                b.stmt(RET, RET_ALLOW);
            }
            When::ArgIn { arg, values } => {
                b.stmt(LD_W_ABS, arg_low(arg));
                for &v in values {
                    b.jump(JEQ, v, Some(deny), None);
                }
                b.stmt(RET, RET_ALLOW);
            }
            When::ArgNotIn { arg, values } => {
                b.stmt(LD_W_ABS, arg_low(arg));
                for &v in values {
                    b.jump(JEQ, v, Some(allow), None);
                }
                b.stmt(RET, RET_EPERM);
            }
            When::Always | When::NoSys => unreachable!("numbers only"),
        }
    }
    b.bind(deny);
    b.stmt(RET, RET_EPERM);
    b.bind(nosys);
    b.stmt(RET, RET_ENOSYS);
    b.bind(allow);
    b.stmt(RET, RET_ALLOW);
    b.finish()
}

/// The offset of the low 32 bits of argument `arg` in `seccomp_data`.
fn arg_low(arg: u8) -> u32 {
    ARGS + 8 * u32::from(arg)
}

/// A jump target, bound to an instruction index by [`Builder::bind`].
#[derive(Clone, Copy, Debug)]
struct Label(usize);

/// Emits instructions with symbolic jump targets and resolves them into forward offsets in [`Builder::finish`].
#[derive(Default)]
struct Builder {
    prog: Vec<(SockFilter, Option<Label>, Option<Label>)>,
    at: Vec<Option<usize>>,
}

impl Builder {
    fn label(&mut self) -> Label {
        self.at.push(None);
        Label(self.at.len() - 1)
    }

    /// The next instruction emitted is `l`'s target.
    fn bind(&mut self, l: Label) {
        assert!(self.at[l.0].replace(self.prog.len()).is_none(), "label bound twice");
    }

    fn stmt(&mut self, code: u16, k: u32) {
        self.prog.push((SockFilter { code, jt: 0, jf: 0, k }, None, None));
    }

    /// A conditional jump; `None` falls through to the next instruction.
    fn jump(&mut self, code: u16, k: u32, jt: Option<Label>, jf: Option<Label>) {
        self.prog.push((SockFilter { code, jt: 0, jf: 0, k }, jt, jf));
    }

    fn finish(self) -> Result<Vec<SockFilter>, SeccompError> {
        if self.prog.len() > libc::BPF_MAXINSNS as usize {
            return Err(SeccompError::Program("more instructions than the kernel accepts"));
        }
        let offset = |pc: usize, l: Option<Label>| -> Result<u8, SeccompError> {
            let Some(l) = l else { return Ok(0) };
            let to = self.at[l.0].ok_or(SeccompError::Program("jump to an unbound label"))?;
            match to.checked_sub(pc + 1) {
                None => Err(SeccompError::Program("backward jump")),
                Some(off) => u8::try_from(off).map_err(|_| SeccompError::Program("jump farther than 255")),
            }
        };
        let mut out = Vec::with_capacity(self.prog.len());
        for (pc, &(mut insn, jt, jf)) in self.prog.iter().enumerate() {
            insn.jt = offset(pc, jt)?;
            insn.jf = offset(pc, jf)?;
            out.push(insn);
        }
        Ok(out)
    }
}

/// Installs `filter` on the calling thread: `PR_SET_NO_NEW_PRIVS`, then `seccomp(SECCOMP_SET_MODE_FILTER)`. Only
/// the calling thread is filtered (no TSYNC: the shim is single-threaded and `execve`s next); every child and the
/// `execve`d program inherit it. Allocation-free, so a forked child may call it.
pub fn install(filter: &[SockFilter]) -> Result<(), SeccompError> {
    let Ok(len) = u16::try_from(filter.len()) else {
        return Err(SeccompError::Program("more instructions than the kernel accepts"));
    };
    if len == 0 || usize::from(len) > libc::BPF_MAXINSNS as usize {
        return Err(SeccompError::Program(
            "an empty program or more instructions than the kernel accepts",
        ));
    }
    // SAFETY: PR_SET_NO_NEW_PRIVS takes integer arguments only.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        let source = std::io::Error::last_os_error();
        return Err(SeccompError::Install {
            step: "prctl(PR_SET_NO_NEW_PRIVS)",
            source,
        });
    }
    // The kernel only reads (copies) the program; `*mut` is the C struct's type, not a licence to write.
    let prog = libc::sock_fprog {
        len,
        filter: filter.as_ptr().cast_mut().cast(),
    };
    // SAFETY: `prog` points at `len` live instructions laid out as `struct sock_filter` (asserted above), valid for
    // the whole call; the kernel copies them before returning.
    if unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, 0, &prog) } != 0 {
        let source = std::io::Error::last_os_error();
        return Err(SeccompError::Install {
            step: "seccomp(SECCOMP_SET_MODE_FILTER)",
            source,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
