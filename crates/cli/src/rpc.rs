//! `runtime rpc <method> [params] [--socket PATH]` and `runtime daemon-status [--socket PATH]`: the only commands
//! that talk to `runtimed` (through `rt_daemon::client`, which checks the socket before it sends anything). Every
//! other command works on its own, daemon or not.
//!
//! The daemon's answer is shown, never trusted: the result is re-serialised from the parsed value and passed
//! through `json_safe` (a JSON string cannot carry a raw control, C1 or bidi character to the terminal), and an
//! error's message goes through `safe` on its way to stderr.
use crate::CmdError;
use crate::safe::{json_safe, safe};
use rt_daemon::client::{self, Client};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

/// How long `daemon-status` waits for an answer (`rpc.version` needs no probe).
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);

fn socket_path(socket: Option<PathBuf>) -> Result<PathBuf, CmdError> {
    match socket {
        Some(p) => Ok(p),
        None => Ok(client::default_socket_path()?),
    }
}

pub fn rpc(method: &str, params: Option<&str>, socket: Option<PathBuf>) -> Result<u8, CmdError> {
    let params = match params.map(serde_json::from_str::<Value>) {
        None => Value::Null,
        Some(Ok(v @ Value::Object(_))) => v,
        Some(_) => return Err(r#"params must be one JSON object, e.g. '{"id": "notepad"}'"#.into()),
    };
    let result = Client::connect(&socket_path(socket)?)?.call(method, params)?;
    crate::emit(&format!("{}\n", json_safe(&serde_json::to_string_pretty(&result)?)))?;
    Ok(0)
}

pub fn status(socket: Option<PathBuf>) -> Result<u8, CmdError> {
    let path = socket_path(socket)?;
    let head = format!("socket: {}\n", safe(&path.to_string_lossy()));
    match Client::connect_with(&path, STATUS_TIMEOUT).and_then(|mut c| c.version()) {
        Ok(v) => {
            crate::emit(&format!(
                "{head}reachable: yes\napi: {}\nruntime: {}\nprotocol: {}\n",
                safe(&v.api),
                safe(&v.runtime),
                safe(&v.protocol)
            ))?;
            Ok(0)
        }
        Err(e) => {
            crate::emit(&format!(
                "{head}reachable: no ({})\nstart `runtimed`, or `systemctl --user start runtimed.socket` (see docs/API.md)\n",
                safe(&e.to_string())
            ))?;
            Ok(1)
        }
    }
}
