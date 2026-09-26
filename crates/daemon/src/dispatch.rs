//! The method table: a JSON-RPC method name, its by-name params, the `rt_api::Runtime` call. Results and errors
//! are built only from `rt_api` wire types, which are sanitised at their own boundary; the few messages made here
//! are fixed text or cleaned.
//!
//! | method            | params          | `Runtime` call                  |
//! |-------------------|-----------------|---------------------------------|
//! | `rpc.version`     | none            | `version()`                     |
//! | `apps.list`       | none            | `apps()`                        |
//! | `apps.get`        | `{"id": str}`   | `app(id)`                       |
//! | `permissions.get` | `{"id": str}`   | `permissions(id)`               |
//! | `compat.list`     | none            | `compat()`                      |
//! | `doctor.system`   | none            | `doctor(DoctorTarget::System)`  |
//! | `doctor.app`      | `{"id": str}`   | `doctor(DoctorTarget::App(id))` |
//! | `graphics.info`   | none            | `graphics_info()`               |
//! | `sandbox.info`    | `{"id": str}`   | `sandbox_info(id)`              |
//! | `deps.plan`       | `{"id": str}`   | `deps_plan(id)`                 |
//!
//! "none" accepts a missing `params` or `{}`; any unknown member, a missing `id`, or `params` that is not an
//! object is -32602. Every other name (including anything that would change state: there is no such method in
//! this version) is -32601. The id's validity and existence are `rt_api`'s to judge (`invalid_argument`,
//! `not_found`).
use crate::protocol::{DOMAIN, INTERNAL, INVALID_PARAMS, Id, METHOD_NOT_FOUND, Reply, Request};
use rt_api::{ApiError, DoctorTarget, Runtime};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};

/// Every method this daemon serves.
pub const METHODS: &[&str] = &[
    "rpc.version",
    "apps.list",
    "apps.get",
    "permissions.get",
    "compat.list",
    "doctor.system",
    "doctor.app",
    "graphics.info",
    "sandbox.info",
    "deps.plan",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdParams {
    id: String,
}

/// A failed call: the error part of a reply.
struct Fail(i32, String, Option<Value>);

fn params<T: DeserializeOwned>(p: Option<Value>) -> Result<T, Fail> {
    let p = p.unwrap_or_else(|| json!({}));
    if !p.is_object() {
        return Err(Fail(INVALID_PARAMS, "invalid params: must be an object".into(), None));
    }
    // serde's message can quote a member name of the client's: cleaned and bounded.
    serde_json::from_value(p).map_err(|e| {
        Fail(
            INVALID_PARAMS,
            rt_core::clean_text(&format!("invalid params: {e}"), 256),
            None,
        )
    })
}

fn id(p: Option<Value>) -> Result<String, Fail> {
    params::<IdParams>(p).map(|p| p.id)
}

fn none(p: Option<Value>) -> Result<(), Fail> {
    params::<NoParams>(p).map(|_| ())
}

fn api(e: ApiError) -> Fail {
    let kind = serde_json::to_value(e.kind).unwrap_or(Value::Null);
    Fail(DOMAIN, e.message, Some(json!({ "kind": kind })))
}

fn ok<T: serde::Serialize>(r: Result<T, ApiError>) -> Result<Value, Fail> {
    serde_json::to_value(r.map_err(api)?).map_err(|_| Fail(INTERNAL, "internal error".into(), None))
}

fn call(rt: &Runtime, method: &str, p: Option<Value>) -> Result<Value, Fail> {
    match method {
        "rpc.version" => none(p).and_then(|()| ok(Ok(rt.version()))),
        "apps.list" => none(p).and_then(|()| ok(Ok(rt.apps()))),
        "apps.get" => ok(rt.app(&id(p)?)),
        "permissions.get" => ok(rt.permissions(&id(p)?)),
        "compat.list" => none(p).and_then(|()| ok(Ok(rt.compat()))),
        "doctor.system" => none(p).and_then(|()| ok(rt.doctor(DoctorTarget::System))),
        "doctor.app" => ok(rt.doctor(DoctorTarget::App(id(p)?))),
        "graphics.info" => none(p).and_then(|()| ok(Ok(rt.graphics_info()))),
        "sandbox.info" => ok(rt.sandbox_info(&id(p)?)),
        "deps.plan" => ok(rt.deps_plan(&id(p)?)),
        #[cfg(test)]
        "test.panic" => panic!("injected panic with a secret /home/someone/path"),
        #[cfg(test)]
        "test.sleep" => {
            std::thread::sleep(std::time::Duration::from_millis(600));
            ok(Ok("slept"))
        }
        _ => Err(Fail(METHOD_NOT_FOUND, "method not found".into(), None)),
    }
}

/// The reply to `req`; `None` for a notification, which is not executed (every method only reads).
pub fn dispatch(rt: &Runtime, req: Request) -> Option<Reply> {
    let id = req.id?;
    Some(match call(rt, &req.method, req.params) {
        Ok(result) => Reply::Ok { id, result },
        Err(Fail(code, message, data)) => Reply::Err {
            id,
            code,
            message,
            data,
        },
    })
}

/// [`dispatch`], except that a panicking method is a generic -32603: its message never reaches the wire, and
/// the daemon keeps serving (`Runtime` holds no lock a panic could leave poisoned for good).
pub fn handle(rt: &Runtime, req: Request) -> Option<Reply> {
    let id = req.id.clone();
    catch_unwind(AssertUnwindSafe(|| dispatch(rt, req)))
        .unwrap_or_else(|_| id.map(|id: Id| Reply::error(id, INTERNAL, "internal error")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{plant, rt};

    fn reply(rt: &Runtime, line: &str) -> Option<Reply> {
        match crate::protocol::parse_request(line.as_bytes()) {
            Ok(req) => handle(rt, req),
            Err(r) => Some(r),
        }
    }

    fn call_line(rt: &Runtime, line: &str) -> Value {
        let r = reply(rt, line).expect("a reply");
        serde_json::from_slice(&r.to_line()).unwrap()
    }

    fn req(method: &str, params: Option<Value>) -> String {
        let mut v = json!({"jsonrpc": "2.0", "method": method, "id": 1});
        if let Some(p) = params {
            v["params"] = p;
        }
        v.to_string()
    }

    fn code(v: &Value) -> i64 {
        v["error"]["code"]
            .as_i64()
            .unwrap_or_else(|| panic!("not an error: {v}"))
    }

    #[test]
    fn each_simple_method_is_the_runtime_value() {
        let (d, rt) = rt();
        plant(d.path(), "game", "Game");
        let cases: Vec<(&str, Option<Value>, Value)> = vec![
            ("rpc.version", None, serde_json::to_value(rt.version()).unwrap()),
            ("apps.list", Some(json!({})), serde_json::to_value(rt.apps()).unwrap()),
            (
                "apps.get",
                Some(json!({"id": "game"})),
                serde_json::to_value(rt.app("game").unwrap()).unwrap(),
            ),
            (
                "permissions.get",
                Some(json!({"id": "game"})),
                serde_json::to_value(rt.permissions("game").unwrap()).unwrap(),
            ),
            ("compat.list", None, serde_json::to_value(rt.compat()).unwrap()),
        ];
        for (m, p, want) in cases {
            let v = call_line(&rt, &req(m, p));
            assert_eq!(v["result"], want, "{m}");
            assert_eq!((v["jsonrpc"].as_str(), v["id"].as_i64()), (Some("2.0"), Some(1)));
        }
    }

    #[test]
    fn api_errors_carry_their_kind() {
        let (_d, rt) = rt();
        for (m, id, kind) in [
            ("apps.get", "nope", "not_found"),
            ("apps.get", "../x", "invalid_argument"),
            ("permissions.get", "a b", "invalid_argument"),
            ("sandbox.info", "nope", "not_found"),
            ("deps.plan", "nope", "not_found"),
            ("doctor.app", "..", "invalid_argument"),
        ] {
            let v = call_line(&rt, &req(m, Some(json!({ "id": id }))));
            assert_eq!(code(&v), -32000, "{m} {v}");
            assert_eq!(v["error"]["data"]["kind"], kind, "{m} {v}");
            let want = match m {
                "apps.get" => rt.app(id),
                "permissions.get" => rt.permissions(id).map(|_| unreachable!()),
                "sandbox.info" => rt.sandbox_info(id).map(|_| unreachable!()),
                "deps.plan" => rt.deps_plan(id).map(|_| unreachable!()),
                _ => rt.doctor(DoctorTarget::App(id.into())).map(|_| unreachable!()),
            };
            assert_eq!(v["error"]["message"], want.unwrap_err().message);
        }
    }

    #[test]
    fn params_of_the_wrong_shape_are_invalid_params() {
        let (_d, rt) = rt();
        for (m, p) in [
            ("apps.get", json!([1])),
            ("apps.get", json!({})),
            ("apps.get", json!({"id": 1})),
            ("apps.get", json!({"id": "x", "extra": true})),
            ("apps.get", json!("x")),
            ("apps.get", Value::Null),
            ("rpc.version", json!({"x": 1})),
            ("apps.list", json!([])),
            ("doctor.system", json!({"id": "x"})),
            ("graphics.info", json!(3)),
        ] {
            let v = call_line(&rt, &req(m, Some(p.clone())));
            assert_eq!(code(&v), -32602, "{m} {p}");
        }
        let v = call_line(&rt, &req("apps.get", Some(json!({"id": "x", "\u{202e}\u{1b}": 1}))));
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(!msg.chars().any(|c| c.is_control() || rt_core::is_format(c)), "{msg:?}");
    }

    #[test]
    fn unknown_and_mutating_names_are_not_found() {
        let (_d, rt) = rt();
        for m in [
            "apps.install",
            "apps.remove",
            "apps.run",
            "run",
            "install",
            "remove",
            "deps.install",
            "permissions.set",
            "runtime.version",
            "rpc.discover",
            "RPC.VERSION",
            "",
            "test.panic.not",
        ] {
            let v = call_line(&rt, &req(m, None));
            assert_eq!(code(&v), -32601, "{m}");
            assert_eq!(v["id"], 1);
        }
    }

    #[test]
    fn notifications_get_nothing_and_run_nothing() {
        let (_d, rt) = rt();
        for m in ["rpc.version", "no.such", "test.panic", "apps.get"] {
            let line = json!({"jsonrpc": "2.0", "method": m, "params": [1]}).to_string();
            assert!(reply(&rt, &line).is_none(), "{m}");
        }
        // A frame that is not a valid request is answered even without an id (the id cannot be known).
        let v = call_line(&rt, r#"{"jsonrpc":"1.0","method":"rpc.version"}"#);
        assert_eq!((code(&v), v["id"].is_null()), (-32600, true));
    }

    #[test]
    fn a_panicking_method_is_a_generic_internal_error() {
        let (_d, rt) = rt();
        let v = call_line(&rt, &req("test.panic", None));
        assert_eq!(code(&v), -32603);
        assert_eq!(v["error"]["message"], "internal error");
        assert!(!v.to_string().contains("secret"));
        // And the next call is served.
        let v = call_line(&rt, &req("rpc.version", None));
        assert_eq!(v["result"]["api"], rt_api::API_VERSION);
    }

    #[test]
    fn every_listed_method_is_dispatched() {
        let (_d, rt) = rt();
        for m in METHODS {
            let v = call_line(&rt, &req(m, Some(json!({"id": "nope"}))));
            // Either the id is refused by the api (id methods) or `id` is an unknown member (the others).
            assert!(matches!(code(&v), -32000 | -32602), "{m}: {v}");
        }
    }
}
