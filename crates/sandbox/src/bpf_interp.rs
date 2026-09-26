//! A minimal classic-BPF interpreter for the seccomp tests: exactly the instructions [`crate::seccomp`] emits
//! (`LD W ABS`, `JEQ K`, `JSET K`, `RET K`), and a panic on anything else so a new instruction in the generator
//! forces this interpreter (and its review) to follow. [`validate`] applies the kernel's structural checks.
use crate::seccomp::{JEQ, JSET, LD_W_ABS, RET, SockFilter};

/// The `struct seccomp_data` a filter sees: the syscall number, the audit architecture and six arguments.
#[derive(Debug, Clone, Copy)]
pub struct Data {
    pub nr: i32,
    pub arch: u32,
    pub ip: u64,
    pub args: [u64; 6],
}

/// Runs `prog` over `d` and returns the `RET` value.
pub fn run(prog: &[SockFilter], d: &Data) -> u32 {
    let mut a: u32 = 0;
    let mut pc = 0;
    loop {
        let i = prog[pc];
        pc += 1;
        match i.code {
            LD_W_ABS => a = word(d, i.k),
            JEQ => pc += usize::from(if a == i.k { i.jt } else { i.jf }),
            JSET => pc += usize::from(if a & i.k != 0 { i.jt } else { i.jf }),
            RET => return i.k,
            other => panic!("the interpreter does not implement BPF code {other:#x} at {}", pc - 1),
        }
    }
}

/// The 32-bit word at byte offset `k` of `seccomp_data` (little-endian, as on x86-64 and aarch64).
fn word(d: &Data, k: u32) -> u32 {
    match k {
        0 => d.nr as u32,
        4 => d.arch,
        8 => d.ip as u32,
        12 => (d.ip >> 32) as u32,
        16..=60 if k.is_multiple_of(4) => {
            let arg = d.args[(k as usize - 16) / 8];
            if k.is_multiple_of(8) {
                arg as u32
            } else {
                (arg >> 32) as u32
            }
        }
        _ => panic!("load outside seccomp_data or unaligned: offset {k}"),
    }
}

/// The kernel's structural checks (`bpf_check_classic` + `seccomp_check_filter`) for the instructions the generator
/// emits: 1..=4096 instructions, only known codes, aligned loads inside `seccomp_data`, every jump target inside
/// the program, and a `RET` last. Jumps are forward only, so every path ends in a `RET`.
pub fn validate(prog: &[SockFilter]) -> Result<(), String> {
    if prog.is_empty() || prog.len() > libc::BPF_MAXINSNS as usize {
        return Err(format!("{} instructions", prog.len()));
    }
    for (pc, i) in prog.iter().enumerate() {
        match i.code {
            LD_W_ABS if i.k % 4 != 0 || i.k >= 64 => return Err(format!("{pc}: bad load offset {}", i.k)),
            JEQ | JSET => {
                let far = pc + 1 + usize::from(i.jt.max(i.jf));
                if far >= prog.len() {
                    return Err(format!("{pc}: jump to {far} past the end ({})", prog.len()));
                }
            }
            LD_W_ABS | RET => {}
            other => return Err(format!("{pc}: unknown code {other:#x}")),
        }
    }
    match prog.last() {
        Some(i) if i.code == RET => Ok(()),
        _ => Err("the last instruction is not a RET".to_owned()),
    }
}
