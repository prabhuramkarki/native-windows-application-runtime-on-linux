//! The wire protocol: JSON-RPC 2.0, one UTF-8 JSON object per line (NDJSON), both ways.
//!
//! **Framing.** [`read_frame`] returns the bytes up to (not including) the next `\n`. A line longer than
//! [`MAX_FRAME`] is refused as soon as the cap is passed: nothing beyond the cap plus one read buffer is ever held.
//! A last line without its `\n` (the client half-closed or went away) is still a frame: whatever it holds is
//! parsed like any other line, so a truncated request earns a parse error, never a guess.
//!
//! **Requests.** [`parse_request`] accepts exactly one JSON object with `"jsonrpc": "2.0"`, a string `method`,
//! an optional `params` and an optional `id`, and nothing else (an unknown member is an invalid request). Rules
//! where JSON-RPC 2.0 leaves a choice, all the strict one:
//! - a batch (a JSON array) is refused with -32600: batches are not supported;
//! - an `id` is an integer that fits `i64`, a string of at most [`MAX_ID`] bytes without control or format
//!   characters, or `null`; anything else (a fraction, a huge number, an object) is an invalid request answered
//!   with id `null`. A valid id is echoed exactly;
//! - a request without `id` is a notification and never gets a reply (not even an error); every method is
//!   read-only, so a notification is not executed at all;
//! - `params`, when present, must be an object (by-name); its shape is checked by the method (-32602).
//!
//! **Errors.** Standard codes for protocol faults; [`DOMAIN`] for an `rt_api::ApiError` with `data.kind`, the
//! error's stable snake_case kind; [`BUSY`] and [`TIMEOUT`] for the server's own limits. Every `message` is
//! either fixed text or already cleaned (`rt_api` cleans its errors; serde's messages are cleaned here).
use serde::Serialize;
use serde_json::{Map, Value, json};

/// The longest request line, excluding its `\n`.
pub const MAX_FRAME: usize = 1 << 20;
/// The longest string `id`.
pub const MAX_ID: usize = 128;

pub const PARSE_ERROR: i32 = -32700;
pub const INVALID_REQUEST: i32 = -32600;
pub const METHOD_NOT_FOUND: i32 = -32601;
pub const INVALID_PARAMS: i32 = -32602;
pub const INTERNAL: i32 = -32603;
/// An `rt_api::ApiError`: `data.kind` says which.
pub const DOMAIN: i32 = -32000;
/// The connection cap is reached; the connection is closed after this reply.
pub const BUSY: i32 = -32001;
/// The request did not finish within the per-request deadline; the connection is closed after this reply.
pub const TIMEOUT: i32 = -32002;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Id {
    Num(i64),
    Str(String),
    Null,
}

/// A request that passed [`parse_request`]. `id: None` is a notification.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub method: String,
    pub params: Option<Value>,
    pub id: Option<Id>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Ok {
        id: Id,
        result: Value,
    },
    Err {
        id: Id,
        code: i32,
        message: String,
        data: Option<Value>,
    },
}

impl Reply {
    pub fn error(id: Id, code: i32, message: impl Into<String>) -> Reply {
        Reply::Err {
            id,
            code,
            message: message.into(),
            data: None,
        }
    }

    /// The JSON-RPC response object as one line, `\n` included.
    pub fn to_line(&self) -> Vec<u8> {
        let v = match self {
            Reply::Ok { id, result } => json!({"jsonrpc": "2.0", "id": id, "result": result}),
            Reply::Err {
                id,
                code,
                message,
                data,
            } => {
                let mut e = json!({"code": code, "message": message});
                if let Some(d) = data {
                    e["data"] = d.clone();
                }
                json!({"jsonrpc": "2.0", "id": id, "error": e})
            }
        };
        let mut line = v.to_string().into_bytes();
        line.push(b'\n');
        line
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("line longer than the cap")]
    TooLarge,
    #[error("read failed: {0}")]
    Io(#[from] std::io::Error),
}

/// The next line without its `\n`; `None` at a clean end of stream. Holds at most `MAX_FRAME` bytes of the line
/// (plus `r`'s own buffer): one byte more and it is [`FrameError::TooLarge`].
pub fn read_frame<R: std::io::BufRead>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    read_frame_max(r, MAX_FRAME)
}

/// [`read_frame`] with the cap `max` instead of [`MAX_FRAME`] (the client reads replies, which may be longer).
pub fn read_frame_max<R: std::io::BufRead>(r: &mut R, max: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut line = Vec::new();
    loop {
        let buf = r.fill_buf()?;
        if buf.is_empty() {
            return Ok((!line.is_empty()).then_some(line));
        }
        let (take, done) = match buf.iter().position(|&b| b == b'\n') {
            Some(i) => (i, true),
            None => (buf.len(), false),
        };
        if line.len() + take > max {
            return Err(FrameError::TooLarge);
        }
        line.extend_from_slice(&buf[..take]);
        r.consume(take + usize::from(done));
        if done {
            return Ok(Some(line));
        }
    }
}

fn clean(s: &str) -> bool {
    !s.chars().any(|c| c.is_control() || rt_core::is_format(c))
}

/// The `id` member: `Ok(None)` when absent, `Err` when present but not an id we echo.
fn id_of(obj: &Map<String, Value>) -> Result<Option<Id>, ()> {
    match obj.get("id") {
        None => Ok(None),
        Some(Value::Null) => Ok(Some(Id::Null)),
        Some(Value::Number(n)) => n.as_i64().map(|n| Some(Id::Num(n))).ok_or(()),
        Some(Value::String(s)) if s.len() <= MAX_ID && clean(s) => Ok(Some(Id::Str(s.clone()))),
        Some(_) => Err(()),
    }
}

/// One frame as a request, or the error reply it earns (always with id `null` unless a valid id was read).
pub fn parse_request(frame: &[u8]) -> Result<Request, Reply> {
    let parse = || Reply::error(Id::Null, PARSE_ERROR, "parse error: not a JSON value");
    let text = std::str::from_utf8(frame).map_err(|_| parse())?;
    let v: Value = serde_json::from_str(text).map_err(|_| parse())?;
    let invalid = |id: Id, why: &str| Reply::error(id, INVALID_REQUEST, format!("invalid request: {why}"));
    let obj = match v {
        Value::Object(o) => o,
        Value::Array(_) => return Err(invalid(Id::Null, "batch requests are not supported")),
        _ => return Err(invalid(Id::Null, "not an object")),
    };
    let id = id_of(&obj).map_err(|()| invalid(Id::Null, "`id` must be an i64, a short plain string or null"))?;
    let reply_id = || id.clone().unwrap_or(Id::Null);
    if let Some(k) = obj
        .keys()
        .find(|k| !matches!(k.as_str(), "jsonrpc" | "method" | "params" | "id"))
    {
        // The member name is the client's: say which only when it is printable and short.
        let k = if k.len() <= 64 && clean(k) {
            k.as_str()
        } else {
            "(unprintable)"
        };
        return Err(invalid(reply_id(), &format!("unknown member `{k}`")));
    }
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid(reply_id(), "`jsonrpc` must be \"2.0\""));
    }
    let Some(Value::String(method)) = obj.get("method") else {
        return Err(invalid(reply_id(), "`method` must be a string"));
    };
    Ok(Request {
        method: method.clone(),
        params: obj.get("params").cloned(),
        id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufReader, Read};

    /// Hands out at most `n` bytes per read, like a socket with a slow peer.
    struct Trickle<'a>(&'a [u8], usize);
    impl Read for Trickle<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.1.min(buf.len()).min(self.0.len());
            buf[..n].copy_from_slice(&self.0[..n]);
            self.0 = &self.0[n..];
            Ok(n)
        }
    }

    fn frames(input: &[u8], chunk: usize) -> Vec<Result<Vec<u8>, String>> {
        let mut r = BufReader::new(Trickle(input, chunk));
        let mut out = vec![];
        loop {
            match read_frame(&mut r) {
                Ok(Some(f)) => out.push(Ok(f)),
                Ok(None) => return out,
                Err(e) => {
                    out.push(Err(e.to_string()));
                    return out;
                }
            }
        }
    }

    #[test]
    fn frames_split_on_newlines_whatever_the_read_sizes() {
        let input = b"{\"a\":1}\n\n{\"b\":2}\n";
        for chunk in [1, 2, 3, 7, 1000] {
            assert_eq!(
                frames(input, chunk),
                vec![Ok(b"{\"a\":1}".to_vec()), Ok(vec![]), Ok(b"{\"b\":2}".to_vec())],
                "chunk {chunk}"
            );
        }
    }

    #[test]
    fn a_partial_last_line_is_a_frame_and_then_eof() {
        assert_eq!(
            frames(b"x\n{\"trunc", 3),
            vec![Ok(b"x".to_vec()), Ok(b"{\"trunc".to_vec())]
        );
        assert!(frames(b"", 1).is_empty());
        assert!(parse_request(b"{\"trunc").is_err());
    }

    #[test]
    fn the_frame_cap_is_exact() {
        let mut at = vec![b'x'; MAX_FRAME];
        at.push(b'\n');
        let f = frames(&at, 64 * 1024);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].as_ref().unwrap().len(), MAX_FRAME);
        let mut over = vec![b'x'; MAX_FRAME + 1];
        over.push(b'\n');
        assert!(
            frames(&over, 64 * 1024)[0]
                .as_ref()
                .unwrap_err()
                .contains("longer than")
        );
        // Without any newline, it stops at the cap instead of reading on.
        let endless = vec![b'x'; 4 * MAX_FRAME];
        let mut r = BufReader::with_capacity(8192, Trickle(&endless, 8192));
        assert!(matches!(read_frame(&mut r), Err(FrameError::TooLarge)));
        let consumed = 4 * MAX_FRAME - r.get_ref().0.len();
        assert!(consumed <= MAX_FRAME + 8192, "read {consumed} bytes");
    }

    fn err(frame: &[u8]) -> (Id, i32) {
        match parse_request(frame).unwrap_err() {
            Reply::Err { id, code, .. } => (id, code),
            r => panic!("{r:?}"),
        }
    }

    #[test]
    fn malformed_input_earns_a_parse_error() {
        for f in [
            &b"{\"jsonrpc\":\"2.0\",\"method\":\"\xff\",\"id\":1}"[..],
            b"{\"jsonrpc\":\"2.0\",\"method\":\"a\0\",\"id\":1}",
            b"\0",
            b"",
            b"{",
            b"nul",
        ] {
            assert_eq!(err(f), (Id::Null, PARSE_ERROR), "{f:?}");
        }
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));
        assert_eq!(err(deep.as_bytes()), (Id::Null, PARSE_ERROR));
    }

    #[test]
    fn ids_of_every_json_type() {
        let req = |id: &str| format!(r#"{{"jsonrpc":"2.0","method":"m","id":{id}}}"#);
        let ok = |id: &str| parse_request(req(id).as_bytes()).unwrap().id;
        assert_eq!(ok("7"), Some(Id::Num(7)));
        assert_eq!(ok("-9223372036854775808"), Some(Id::Num(i64::MIN)));
        assert_eq!(ok(r#""abc""#), Some(Id::Str("abc".into())));
        assert_eq!(ok("null"), Some(Id::Null));
        assert_eq!(parse_request(br#"{"jsonrpc":"2.0","method":"m"}"#).unwrap().id, None);
        let long = format!("\"{}\"", "a".repeat(MAX_ID + 1));
        for bad in [
            "1.5",
            "1e3",
            "123456789012345678901234567890",
            "9223372036854775808",
            "true",
            "[]",
            "{}",
            &long,
            r#""a\u001bb""#,
            r#""a\u202eb""#,
        ] {
            assert_eq!(err(req(bad).as_bytes()), (Id::Null, INVALID_REQUEST), "{bad}");
        }
        // Echoed exactly.
        let line = Reply::Ok {
            id: Id::Str("x\"y".into()),
            result: json!(1),
        }
        .to_line();
        assert_eq!(line, b"{\"id\":\"x\\\"y\",\"jsonrpc\":\"2.0\",\"result\":1}\n");
    }

    #[test]
    fn requests_must_be_single_strict_objects() {
        assert_eq!(
            err(br#"[{"jsonrpc":"2.0","method":"m","id":1}]"#),
            (Id::Null, INVALID_REQUEST)
        );
        assert_eq!(err(b"[]"), (Id::Null, INVALID_REQUEST));
        assert_eq!(err(b"42"), (Id::Null, INVALID_REQUEST));
        assert_eq!(
            err(br#"{"jsonrpc":"1.0","method":"m","id":3}"#),
            (Id::Num(3), INVALID_REQUEST)
        );
        assert_eq!(err(br#"{"method":"m","id":3}"#), (Id::Num(3), INVALID_REQUEST));
        assert_eq!(
            err(br#"{"jsonrpc":2.0,"method":"m","id":3}"#),
            (Id::Num(3), INVALID_REQUEST)
        );
        assert_eq!(
            err(br#"{"jsonrpc":"2.0","method":1,"id":"s"}"#),
            (Id::Str("s".into()), INVALID_REQUEST)
        );
        assert_eq!(
            err(br#"{"jsonrpc":"2.0","id":"s"}"#),
            (Id::Str("s".into()), INVALID_REQUEST)
        );
        let Reply::Err { message, .. } =
            parse_request(br#"{"jsonrpc":"2.0","method":"m","id":1,"extra\u202e":1}"#).unwrap_err()
        else {
            unreachable!()
        };
        assert_eq!(message, "invalid request: unknown member `(unprintable)`");
        assert_eq!(
            err(br#"{"jsonrpc":"2.0","method":"m","id":1,"extra":1}"#),
            (Id::Num(1), INVALID_REQUEST)
        );
        // Params are not checked here: that is the method's job (-32602).
        let r = parse_request(br#"{"jsonrpc":"2.0","method":"m","params":[1],"id":1}"#).unwrap();
        assert_eq!(r.params, Some(json!([1])));
    }

    #[test]
    fn replies_are_one_json_rpc_line() {
        let r = Reply::Err {
            id: Id::Num(1),
            code: DOMAIN,
            message: "m".into(),
            data: Some(json!({"kind": "not_found"})),
        };
        let line = r.to_line();
        assert_eq!(line.iter().filter(|&&b| b == b'\n').count(), 1);
        let v: Value = serde_json::from_slice(&line).unwrap();
        assert_eq!(
            v,
            json!({"jsonrpc":"2.0","id":1,"error":{"code":-32000,"message":"m","data":{"kind":"not_found"}}})
        );
        let v: Value = serde_json::from_slice(&Reply::error(Id::Null, BUSY, "busy").to_line()).unwrap();
        assert!(v["error"].get("data").is_none() && v["id"].is_null());
    }

    #[test]
    fn mutated_frames_never_panic() {
        let base = br#"{"jsonrpc":"2.0","method":"apps.get","params":{"id":"game"},"id":17}"#;
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for _ in 0..5000 {
            let mut f = base.to_vec();
            for _ in 0..1 + next() % 4 {
                let at = (next() as usize) % (f.len() + 1);
                match next() % 3 {
                    0 if at < f.len() => f[at] = next() as u8,
                    1 if at < f.len() => {
                        f.truncate(at);
                    }
                    _ => f.insert(at.min(f.len()), next() as u8),
                }
            }
            let _ = parse_request(&f);
        }
    }
}
