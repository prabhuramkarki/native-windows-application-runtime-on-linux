//! `runtime sandbox-init <block>`: the hidden shim bubblewrap starts inside an app's sandbox
//! ([`rt_sandbox::init`]: Landlock, the seccomp deny-list, then `execve` of the real program; 126 on any refusal).
//! Hidden, not secret: it only takes rights away from itself and then runs the program its caller named, which the
//! caller could have run directly, so it is safe for anyone to run. Its only input is its own argument block; it
//! reads no config file and no environment variable for its rules.
use std::ffi::OsString;

pub fn run(args: &[OsString]) -> ! {
    rt_sandbox::init::main(args)
}
