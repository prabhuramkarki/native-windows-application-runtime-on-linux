//! `runtime rpc <method> [params] [--socket PATH]` and `runtime daemon-status [--socket PATH]`: the only commands
//! that talk to `runtimed` (through `rt_daemon::client`, which checks the socket before it sends anything). Every
//! other command works on its own, daemon or not.
//!
//! The daemon's answer is shown, never trusted: the result is re-serialised from the parsed value and passed
//! through `json_safe` (a JSON string cannot carry a raw control, C1 or bidi character to the terminal), and an
//! error's message goes through `safe` on its way to stderr.
use crate::CmdError;
use crate::safe::{json_safe, safe, shorten};
use rt_api::VersionInfo;
use rt_daemon::client::{self, Client};
use serde_json::Value;
use std::io::ErrorKind;
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

/// What `daemon-status` found (spec Decision E9). The strings are already terminal-safe and bounded.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Answered {
        api: String,
        runtime: String,
        protocol: String,
        mode: String,
    },
    /// The daemon refused the connection: its connection cap is reached (`-32001`).
    Busy,
    /// Connected, but no reply in time (the client's deadline, or the daemon's own `-32002`).
    NotAnswering,
    /// Nothing to connect to: the only case where starting `runtimed` helps.
    Unreachable(String),
    /// Refused before anything was sent (an unsafe socket or directory).
    NotChecked(String),
    /// Connected, but the exchange failed otherwise (a bad or cut reply, an error reply).
    Failed(String),
}

fn shown(e: &client::ClientError) -> String {
    safe(&shorten(&e.to_string(), 300))
}

fn outcome(r: Result<(VersionInfo, Option<bool>), client::ClientError>) -> Outcome {
    use client::ClientError as E;
    use rt_daemon::protocol::{BUSY, TIMEOUT};
    let timed_out = |e: &std::io::Error| matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock);
    match r {
        Ok((v, write)) => Outcome::Answered {
            // A 0.1 daemon has no `write` field: it has no write methods either.
            mode: match write {
                Some(true) => "write".to_owned(),
                Some(false) => "read-only".to_owned(),
                None => format!("read-only (API {})", safe(&v.api)),
            },
            api: safe(&v.api),
            runtime: safe(&v.runtime),
            protocol: safe(&v.protocol),
        },
        Err(E::Rpc { code, .. }) if code == i64::from(BUSY) => Outcome::Busy,
        Err(E::Rpc { code, .. }) if code == i64::from(TIMEOUT) => Outcome::NotAnswering,
        Err(E::Io(ref e)) if timed_out(e) => Outcome::NotAnswering,
        // A socket whose backlog stays full: something listens there but never accepts.
        Err(E::Unreachable { ref err, .. }) if timed_out(err) => Outcome::NotAnswering,
        Err(e @ (E::NoRuntimeDir | E::Unreachable { .. })) => Outcome::Unreachable(shown(&e)),
        Err(e @ E::Unsafe { .. }) => Outcome::NotChecked(shown(&e)),
        Err(e) => Outcome::Failed(shown(&e)),
    }
}

pub fn status(socket: Option<PathBuf>) -> Result<u8, CmdError> {
    let path = socket_path(socket)?;
    let head = format!("socket: {}\n", safe(&path.to_string_lossy()));
    let answer = Client::connect_with(&path, STATUS_TIMEOUT).and_then(|mut c| c.call("rpc.version", Value::Null));
    let parsed = answer.and_then(|raw| {
        let v: VersionInfo = serde_json::from_value(raw.clone())
            .map_err(|_| client::ClientError::Protocol("the result does not have the expected shape"))?;
        Ok((v, raw.get("write").and_then(Value::as_bool)))
    });
    let body = match outcome(parsed) {
        Outcome::Answered {
            api,
            runtime,
            protocol,
            mode,
        } => {
            crate::emit(&format!(
                "{head}reachable: yes\napi: {api}\nruntime: {runtime}\nprotocol: {protocol}\nmode: {mode}\n"
            ))?;
            return Ok(0);
        }
        Outcome::Busy => "reachable: yes, busy (connection limit reached): try again\n".to_owned(),
        Outcome::NotAnswering => format!("reachable: yes, not answering within {} s\n", STATUS_TIMEOUT.as_secs()),
        Outcome::Unreachable(e) => format!(
            "reachable: no ({e})\nstart `runtimed`, or `systemctl --user start runtimed.socket` (see docs/API.md)\n"
        ),
        Outcome::NotChecked(e) => format!("reachable: not checked ({e})\n"),
        Outcome::Failed(e) => format!("reachable: yes, but the exchange failed ({e})\n"),
    };
    crate::emit(&format!("{head}{body}"))?;
    Ok(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use client::ClientError as E;
    use std::io;

    fn rpc(code: i64) -> E {
        E::Rpc {
            code,
            message: "m\u{1b}[2J".into(),
            kind: None,
        }
    }

    fn unreachable(kind: ErrorKind) -> E {
        E::Unreachable {
            path: "/s".into(),
            err: kind.into(),
        }
    }

    #[test]
    fn each_client_result_has_its_outcome() {
        let v = VersionInfo {
            api: "0.1.0".into(),
            runtime: "r\u{1b}".into(),
            protocol: "p".into(),
            write: false,
        };
        assert_eq!(
            outcome(Ok((v.clone(), None))),
            Outcome::Answered {
                api: "0.1.0".into(),
                runtime: "r\\u{1b}".into(),
                protocol: "p".into(),
                mode: "read-only (API 0.1.0)".into()
            }
        );
        assert!(matches!(outcome(Ok((v, Some(true)))), Outcome::Answered { mode, .. } if mode == "write"));
        assert_eq!(outcome(Err(rpc(-32001))), Outcome::Busy);
        assert_eq!(outcome(Err(rpc(-32002))), Outcome::NotAnswering);
        // Pinned by the spike: the client's read deadline surfaces as `Io(TimedOut)`.
        assert_eq!(outcome(Err(E::Io(ErrorKind::TimedOut.into()))), Outcome::NotAnswering);
        assert_eq!(outcome(Err(E::Io(ErrorKind::WouldBlock.into()))), Outcome::NotAnswering);
        assert_eq!(outcome(Err(unreachable(ErrorKind::TimedOut))), Outcome::NotAnswering);
        assert!(
            matches!(outcome(Err(unreachable(ErrorKind::NotFound))), Outcome::Unreachable(e) if e.starts_with("no daemon at /s"))
        );
        assert!(matches!(outcome(Err(E::NoRuntimeDir)), Outcome::Unreachable(e) if e.contains("XDG_RUNTIME_DIR")));
        let unsafe_ = E::Unsafe {
            path: "/s".into(),
            why: "open to others",
        };
        assert_eq!(
            outcome(Err(unsafe_)),
            Outcome::NotChecked("refusing /s: open to others".into())
        );
        // Connected, then something else went wrong: the daemon is there, so no start hint.
        let failed = |e: E| matches!(outcome(Err(e)), Outcome::Failed(_));
        assert!(matches!(outcome(Err(rpc(-32000))), Outcome::Failed(e) if e == "m\\u{1b}[2J (code -32000)"));
        assert!(failed(E::Io(io::Error::from(ErrorKind::ConnectionReset))));
        assert!(failed(E::Protocol("not a JSON object")));
        assert!(failed(E::TooLarge));
        assert!(failed(E::Unsupported("x")));
        assert!(failed(rpc(-32603)));
        // Bounded.
        let long = E::Rpc {
            code: -32000,
            message: "x".repeat(10_000),
            kind: None,
        };
        assert!(matches!(outcome(Err(long)), Outcome::Failed(e) if e.len() < 400));
    }
}
