//! The method table: a JSON-RPC method name, its by-name params, the `rt_api::Runtime` call or the job it starts.
//! Results and errors are built only from `rt_api` wire types, which are sanitised at their own boundary; the few
//! messages made here are fixed text or cleaned.
//!
//! | method              | params                                     | call                             |
//! |---------------------|--------------------------------------------|----------------------------------|
//! | `rpc.version`       | none                                       | `version()` + `write`            |
//! | `apps.list`         | none                                       | `apps()`                         |
//! | `apps.get`          | `{"id": str}`                              | `app(id)`                        |
//! | `permissions.get`   | `{"id": str}`                              | `permissions(id)`                |
//! | `compat.list`       | none                                       | `compat()`                       |
//! | `doctor.system`     | none                                       | `doctor(DoctorTarget::System)`   |
//! | `doctor.app`        | `{"id": str}`                              | `doctor(DoctorTarget::App(id))`  |
//! | `graphics.info`     | none                                       | `graphics_info()`                |
//! | `sandbox.info`      | `{"id": str}`                              | `sandbox_info(id)`               |
//! | `deps.plan`         | `{"id": str}`                              | `deps_plan(id)`                  |
//! | `apps.run` ... `display.set` | see `rt_api::jobs`                | `Jobs::start(JobSpec)`           |
//! | `deps.install`      | `{"id", "planDigest", "consent"}`          | `deps_install_spec` + `start`    |
//! | `jobs.poll`         | `{"jobId", "afterSeq", "waitMs"?}`         | `Jobs::poll` (long-poll)         |
//! | `jobs.status`/`jobs.cancel` | `{"jobId"}`                        | `Jobs::status`/`Jobs::cancel`    |
//! | `jobs.list`         | none                                       | `Jobs::list`                     |
//!
//! "none" accepts a missing `params` or `{}`; any unknown member, a missing field, or `params` that is not an
//! object is -32602. On a read-only daemon (no `--write`) every [`WRITE_METHODS`] name is `-32000 read_only` before
//! its params are even read; every name in neither list is -32601. Notifications are never executed. At most
//! [`MAX_WAITING_POLLS`] `jobs.poll`s wait at once daemon-wide; another answers at once, as if `waitMs` were 0, so
//! waiting polls never hold more than 8 of the server's connection slots.
use crate::jobs::Jobs;
use crate::protocol::{DOMAIN, INTERNAL, INVALID_PARAMS, Id, METHOD_NOT_FOUND, Reply, Request};
use rt_api::jobs::{DepsInstallParams, JobList, JobParamsError, JobSpec};
use rt_api::{ApiError, DoctorTarget, ErrorKind, Runtime};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// The methods of a write-mode daemon (`runtimed --write`); a read-only one answers them `read_only`.
pub const WRITE_METHODS: &[&str] = &[
    "apps.run",
    "apps.install",
    "apps.import",
    "apps.remove",
    "deps.install",
    "permissions.set",
    "permissions.reset",
    "display.set",
    "jobs.poll",
    "jobs.status",
    "jobs.cancel",
    "jobs.list",
];

/// Every method this daemon knows (the read methods, then [`WRITE_METHODS`]).
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
    "apps.run",
    "apps.install",
    "apps.import",
    "apps.remove",
    "deps.install",
    "permissions.set",
    "permissions.reset",
    "display.set",
    "jobs.poll",
    "jobs.status",
    "jobs.cancel",
    "jobs.list",
];

/// Most `jobs.poll`s waiting at once, daemon-wide.
pub const MAX_WAITING_POLLS: usize = 8;
/// Longest `waitMs` (under the server's 30 s request deadline).
pub const MAX_WAIT_MS: u32 = 25_000;

/// What a request is served with: the runtime, the job table (`None`: read-only), the daemon's stop flag.
pub struct Ctx {
    pub rt: Arc<Runtime>,
    pub jobs: Option<Jobs>,
    pub stop: &'static AtomicBool,
    pub waiting_polls: AtomicUsize,
}

impl Ctx {
    pub fn new(rt: Arc<Runtime>, jobs: Option<Jobs>, stop: &'static AtomicBool) -> Ctx {
        Ctx {
            rt,
            jobs,
            stop,
            waiting_polls: AtomicUsize::new(0),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NoParams {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdParams {
    id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JobIdParams {
    job_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PollParams {
    job_id: String,
    after_seq: u64,
    #[serde(default)]
    wait_ms: u32,
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

fn job_params(e: JobParamsError) -> Fail {
    match e {
        JobParamsError::Shape(m) => Fail(INVALID_PARAMS, m, None),
        JobParamsError::Api(e) => api(e),
    }
}

fn ok<T: serde::Serialize>(r: Result<T, ApiError>) -> Result<Value, Fail> {
    serde_json::to_value(r.map_err(api)?).map_err(|_| Fail(INTERNAL, "internal error".into(), None))
}

/// Frees a waiting-poll slot however the poll ends.
struct Waiting<'a>(&'a AtomicUsize);
impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn poll(ctx: &Ctx, jobs: &Jobs, p: Option<Value>) -> Result<Value, Fail> {
    let q: PollParams = params(p)?;
    if q.wait_ms > MAX_WAIT_MS {
        return Err(Fail(
            INVALID_PARAMS,
            format!("invalid params: waitMs is at most {MAX_WAIT_MS}"),
            None,
        ));
    }
    let mut wait = Duration::ZERO;
    let mut _slot = None;
    if q.wait_ms > 0 {
        let before = ctx.waiting_polls.fetch_add(1, Ordering::SeqCst);
        _slot = Some(Waiting(&ctx.waiting_polls));
        if before < MAX_WAITING_POLLS {
            wait = Duration::from_millis(q.wait_ms.into());
        }
    }
    ok(jobs.poll(&q.job_id, q.after_seq, wait, ctx.stop))
}

fn write(ctx: &Ctx, jobs: &Jobs, method: &str, p: Option<Value>) -> Result<Value, Fail> {
    match method {
        "jobs.poll" => poll(ctx, jobs, p),
        "jobs.status" => ok(jobs.status(&params::<JobIdParams>(p)?.job_id)),
        "jobs.cancel" => ok(jobs.cancel(&params::<JobIdParams>(p)?.job_id)),
        "jobs.list" => none(p).and_then(|()| ok(Ok(JobList { jobs: jobs.list() }))),
        "deps.install" => {
            let q = DepsInstallParams::from_value(p.unwrap_or_else(|| json!({}))).map_err(job_params)?;
            let spec = ctx
                .rt
                .deps_install_spec(&q.id, &q.plan_digest, &q.consent)
                .map_err(api)?;
            ok(jobs.start(spec))
        }
        _ => {
            let spec = JobSpec::from_request(method, p.unwrap_or_else(|| json!({}))).map_err(job_params)?;
            ok(jobs.start(spec))
        }
    }
}

fn call(ctx: &Ctx, method: &str, p: Option<Value>) -> Result<Value, Fail> {
    if WRITE_METHODS.contains(&method) {
        return match &ctx.jobs {
            Some(jobs) => write(ctx, jobs, method, p),
            None => Err(api(ApiError::new(
                ErrorKind::ReadOnly,
                "this runtimed is read-only (start it with --write)",
            ))),
        };
    }
    let rt = &ctx.rt;
    match method {
        "rpc.version" => none(p).and_then(|()| {
            let mut v = rt.version();
            v.write = ctx.jobs.is_some();
            ok(Ok(v))
        }),
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

/// The reply to `req`; `None` for a notification, which is never executed (a client that cannot learn a job's id
/// must not start one).
pub fn dispatch(ctx: &Ctx, req: Request) -> Option<Reply> {
    let id = req.id?;
    Some(match call(ctx, &req.method, req.params) {
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
/// the daemon keeps serving (no lock a panic could leave poisoned for good: the job table recovers poisoned locks).
pub fn handle(ctx: &Ctx, req: Request) -> Option<Reply> {
    let id = req.id.clone();
    catch_unwind(AssertUnwindSafe(|| dispatch(ctx, req)))
        .unwrap_or_else(|_| id.map(|id: Id| Reply::error(id, INTERNAL, "internal error")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jobs::tests::{Fx, fx};
    use crate::testutil::{plant, rt};
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    fn flag() -> &'static AtomicBool {
        Box::leak(Box::new(AtomicBool::new(false)))
    }

    /// A read-only context over a scratch store.
    fn ro() -> (tempfile::TempDir, Arc<Runtime>, Ctx) {
        let (d, rt) = rt();
        let rt = Arc::new(rt);
        let c = Ctx::new(rt.clone(), None, flag());
        (d, rt, c)
    }

    /// A write context whose jobs run the fake `runtime` (`crate::jobs::tests`).
    fn rw() -> (tempfile::TempDir, Arc<Runtime>, Fx, Ctx) {
        let (d, rt) = rt();
        let rt = Arc::new(rt);
        let f = fx();
        let c = Ctx::new(rt.clone(), Some(f.jobs.clone()), flag());
        (d, rt, f, c)
    }

    fn reply(c: &Ctx, line: &str) -> Option<Reply> {
        match crate::protocol::parse_request(line.as_bytes()) {
            Ok(req) => handle(c, req),
            Err(r) => Some(r),
        }
    }

    fn call_line(c: &Ctx, line: &str) -> Value {
        let r = reply(c, line).expect("a reply");
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
        let (d, rt, c) = ro();
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
            let v = call_line(&c, &req(m, p));
            assert_eq!(v["result"], want, "{m}");
            assert_eq!((v["jsonrpc"].as_str(), v["id"].as_i64()), (Some("2.0"), Some(1)));
        }
    }

    #[test]
    fn api_errors_carry_their_kind() {
        let (_d, rt, c) = ro();
        for (m, id, kind) in [
            ("apps.get", "nope", "not_found"),
            ("apps.get", "../x", "invalid_argument"),
            ("permissions.get", "a b", "invalid_argument"),
            ("sandbox.info", "nope", "not_found"),
            ("deps.plan", "nope", "not_found"),
            ("doctor.app", "..", "invalid_argument"),
        ] {
            let v = call_line(&c, &req(m, Some(json!({ "id": id }))));
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
        let (_d, _rt, c) = ro();
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
            let v = call_line(&c, &req(m, Some(p.clone())));
            assert_eq!(code(&v), -32602, "{m} {p}");
        }
        let v = call_line(&c, &req("apps.get", Some(json!({"id": "x", "\u{202e}\u{1b}": 1}))));
        let msg = v["error"]["message"].as_str().unwrap();
        assert!(!msg.chars().any(|c| c.is_control() || rt_core::is_format(c)), "{msg:?}");
    }

    #[test]
    fn unknown_names_are_not_found() {
        let (_d, _rt, c) = ro();
        for m in [
            "apps.install2",
            "apps.uninstall",
            "jobs.start",
            "run",
            "install",
            "remove",
            "runtime.version",
            "rpc.discover",
            "RPC.VERSION",
            "",
            "test.panic.not",
        ] {
            let v = call_line(&c, &req(m, None));
            assert_eq!(code(&v), -32601, "{m}");
            assert_eq!(v["id"], 1);
        }
    }

    #[test]
    fn notifications_get_nothing_and_run_nothing() {
        let (_d, _rt, c) = ro();
        for m in ["rpc.version", "no.such", "test.panic", "apps.get"] {
            let line = json!({"jsonrpc": "2.0", "method": m, "params": [1]}).to_string();
            assert!(reply(&c, &line).is_none(), "{m}");
        }
        // A frame that is not a valid request is answered even without an id (the id cannot be known).
        let v = call_line(&c, r#"{"jsonrpc":"1.0","method":"rpc.version"}"#);
        assert_eq!((code(&v), v["id"].is_null()), (-32600, true));
    }

    #[test]
    fn a_panicking_method_is_a_generic_internal_error() {
        let (_d, _rt, c) = ro();
        let v = call_line(&c, &req("test.panic", None));
        assert_eq!(code(&v), -32603);
        assert_eq!(v["error"]["message"], "internal error");
        assert!(!v.to_string().contains("secret"));
        // And the next call is served.
        let v = call_line(&c, &req("rpc.version", None));
        assert_eq!(v["result"]["api"], rt_api::API_VERSION);
    }

    #[test]
    fn the_documented_methods_are_the_dispatch_table() {
        let doc = include_str!("../../../docs/API.md");
        // The method table's rows (`| \`name\` | ...`) and the `### \`name\`` sections, both in METHODS' order.
        let rows: Vec<&str> = doc
            .lines()
            .filter_map(|l| l.strip_prefix("| `")?.split('`').next())
            .collect();
        let sections: Vec<&str> = doc
            .lines()
            .filter_map(|l| l.strip_prefix("### `")?.strip_suffix('`'))
            .collect();
        assert_eq!(rows, METHODS, "docs/API.md's method table");
        assert_eq!(sections, METHODS, "docs/API.md's method sections");
    }

    #[test]
    fn every_error_kind_is_documented() {
        let doc = include_str!("../../../docs/API.md");
        for &k in ErrorKind::ALL {
            let name = serde_json::to_value(k).unwrap();
            let name = name.as_str().unwrap();
            assert!(
                doc.contains(&format!("- `{name}`:")),
                "docs/API.md does not document data.kind {name}"
            );
        }
    }

    #[test]
    fn every_listed_method_is_dispatched() {
        let (_d, _rt, c) = ro();
        for m in METHODS {
            let v = call_line(&c, &req(m, Some(json!({"id": "nope"}))));
            // Either the id is refused by the api (id methods) or `id` is an unknown member (the others).
            assert!(matches!(code(&v), -32000 | -32602), "{m}: {v}");
        }
    }

    const RO_KIND: &str = "read_only";

    #[test]
    fn a_read_only_daemon_refuses_every_write_method_without_reading_its_params() {
        let (_d, _rt, c) = ro();
        for m in WRITE_METHODS {
            for p in [
                Some(json!({"id": "notepad"})),
                Some(json!([1, 2])),
                Some(json!("x")),
                None,
            ] {
                let v = call_line(&c, &req(m, p.clone()));
                assert_eq!(code(&v), -32000, "{m} {p:?}");
                assert_eq!(v["error"]["data"]["kind"], RO_KIND, "{m}");
            }
        }
        assert_eq!(call_line(&c, &req("rpc.version", None))["result"]["write"], false);
        // A write method name is listed, not unknown.
        assert!(WRITE_METHODS.iter().all(|m| METHODS.contains(m)));
        assert_eq!(METHODS.len(), 10 + WRITE_METHODS.len());
    }

    #[test]
    fn a_write_daemon_starts_jobs_and_answers_for_them() {
        let (_d, _rt, f, c) = rw();
        assert_eq!(call_line(&c, &req("rpc.version", None))["result"]["write"], true);
        let v = call_line(&c, &req("apps.remove", Some(json!({"id": "notepad"}))));
        let id = v["result"]["jobId"]
            .as_str()
            .unwrap_or_else(|| panic!("{v}"))
            .to_owned();
        f.wait_end(&id);
        let st = call_line(&c, &req("jobs.status", Some(json!({"jobId": id}))));
        assert_eq!(
            (st["result"]["state"].as_str(), st["result"]["kind"].as_str()),
            (Some("succeeded"), Some("remove"))
        );
        let ev = call_line(&c, &req("jobs.poll", Some(json!({"jobId": id, "afterSeq": 0}))));
        assert_eq!(ev["result"]["events"][0]["text"], "queued");
        let l = call_line(&c, &req("jobs.list", None));
        assert_eq!(l["result"]["jobs"][0]["jobId"], id.as_str());
        let x = call_line(&c, &req("jobs.cancel", Some(json!({"jobId": id}))));
        assert_eq!(x["result"]["state"], "succeeded");
        for m in ["jobs.status", "jobs.cancel"] {
            let v = call_line(&c, &req(m, Some(json!({"jobId": "0".repeat(32)}))));
            assert_eq!(v["error"]["data"]["kind"], "not_found", "{m}");
        }
        let v = call_line(&c, &req("jobs.poll", Some(json!({"jobId": "x", "afterSeq": 0}))));
        assert_eq!(v["error"]["data"]["kind"], "not_found");
    }

    #[test]
    fn write_params_are_checked_shape_then_content() {
        let (_d, _rt, f, c) = rw();
        for (m, p) in [
            ("apps.remove", json!({"id": "a", "force": true})),
            ("apps.run", json!({"id": "a", "unsandboxed": true})),
            ("apps.install", json!([1])),
            ("apps.import", json!({"path": "/p.wrun", "name": "x"})),
            ("display.set", json!({"id": "a", "driver": "vnc"})),
            ("deps.install", json!({"id": "a", "planDigest": "x"})),
            (
                "deps.install",
                json!({"id": "a", "planDigest": "x", "consent": [], "all": true}),
            ),
            ("jobs.poll", json!({"jobId": "x"})),
            ("jobs.poll", json!({"jobId": "x", "afterSeq": 0, "waitMs": 25001})),
            ("jobs.poll", json!({"jobId": "x", "afterSeq": -1})),
            ("jobs.status", json!({})),
            ("jobs.list", json!({"all": true})),
        ] {
            let v = call_line(&c, &req(m, Some(p.clone())));
            assert_eq!(code(&v), -32602, "{m} {p}: {v}");
        }
        for (m, p) in [
            ("apps.remove", json!({"id": "-rf"})),
            ("apps.run", json!({"id": "x.exe"})),
            ("apps.install", json!({"path": "setup.exe"})),
            ("apps.import", json!({"path": "-x.wrun"})),
            ("apps.import", json!({"path": "/a/../p.wrun"})),
            ("permissions.set", json!({"id": "a", "set": ["a\nb"]})),
            ("deps.install", json!({"id": "a", "planDigest": "x", "consent": []})),
        ] {
            let v = call_line(&c, &req(m, Some(p.clone())));
            assert_eq!(
                (code(&v), v["error"]["data"]["kind"].as_str()),
                (-32000, Some("invalid_argument")),
                "{m} {p}"
            );
        }
        assert!(f.jobs.list().is_empty(), "a refused request started a job");
        // At the bound: fine.
        let v = call_line(
            &c,
            &req("jobs.poll", Some(json!({"jobId": "x", "afterSeq": 0, "waitMs": 25000}))),
        );
        assert_eq!(v["error"]["data"]["kind"], "not_found");
    }

    #[test]
    fn apps_import_is_a_write_method_with_its_exact_argv() {
        let (_d, _rt, c) = ro();
        let v = call_line(&c, &req("apps.import", Some(json!({"path": "/p.wrun"}))));
        assert_eq!((code(&v), v["error"]["data"]["kind"].as_str()), (-32000, Some(RO_KIND)));
        let (_d, _rt, f, c) = rw();
        let v = call_line(
            &c,
            &req("apps.import", Some(json!({"path": "/in/-x.wrun", "silent": true}))),
        );
        let id = v["result"]["jobId"]
            .as_str()
            .unwrap_or_else(|| panic!("{v}"))
            .to_owned();
        let info = f.wait_end(&id);
        assert_eq!((info.kind, info.app), (rt_api::jobs::JobKind::Import, None));
        let argv = std::fs::read(f.fake.join("argv._in_-x.wrun")).unwrap();
        assert_eq!(argv, b"import\0--silent\0--\0/in/-x.wrun\0");
    }

    #[test]
    fn deps_install_needs_the_digest_of_the_recomputed_plan() {
        let (d, rt, f, c) = rw();
        plant(d.path(), "game", "Game");
        let digest = rt.deps_plan("game").unwrap().digest;
        let stale = "0".repeat(64);
        let v = call_line(
            &c,
            &req(
                "deps.install",
                Some(json!({"id": "game", "planDigest": stale, "consent": []})),
            ),
        );
        assert_eq!(v["error"]["data"]["kind"], "consent_mismatch");
        let item = json!({"package": "vcrun2022", "version": "1", "sha256": "0"});
        let v = call_line(
            &c,
            &req(
                "deps.install",
                Some(json!({"id": "game", "planDigest": digest, "consent": [item]})),
            ),
        );
        assert_eq!(v["error"]["data"]["kind"], "consent_mismatch");
        assert!(f.jobs.list().is_empty());
        let v = call_line(
            &c,
            &req(
                "deps.install",
                Some(json!({"id": "game", "planDigest": digest, "consent": []})),
            ),
        );
        let id = v["result"]["jobId"]
            .as_str()
            .unwrap_or_else(|| panic!("{v}"))
            .to_owned();
        f.wait_end(&id);
        let argv = std::fs::read(f.fake.join("argv.game")).unwrap();
        assert_eq!(
            argv,
            format!("deps\0--install\0--plan-digest={digest}\0--\0game\0").into_bytes()
        );
    }

    #[test]
    fn a_write_request_without_an_id_is_never_executed() {
        let (_d, _rt, f, c) = rw();
        for m in ["apps.remove", "apps.run", "permissions.reset"] {
            let line = json!({"jsonrpc": "2.0", "method": m, "params": {"id": "notepad"}}).to_string();
            assert!(reply(&c, &line).is_none());
        }
        assert!(f.jobs.list().is_empty());
    }

    #[test]
    fn at_most_eight_polls_wait_at_once() {
        let (_d, _rt, f, c) = rw();
        f.mode(None, "wait");
        let id = f.start_job("a");
        f.wait_for(&id, "ready");
        let after = f.events(&id).last().unwrap().seq;
        let c = Arc::new(c);
        fn poll(c: &Ctx, id: &str, after: u64) -> Duration {
            let t = Instant::now();
            let v = call_line(
                c,
                &req(
                    "jobs.poll",
                    Some(json!({"jobId": id, "afterSeq": after, "waitMs": 1500})),
                ),
            );
            assert!(v["result"]["events"].as_array().unwrap().is_empty(), "{v}");
            t.elapsed()
        }
        let waiting: Vec<_> = (0..MAX_WAITING_POLLS)
            .map(|_| {
                let (c, id) = (c.clone(), id.clone());
                std::thread::spawn(move || poll(&c, &id, after))
            })
            .collect();
        let until = Instant::now() + Duration::from_secs(5);
        while c.waiting_polls.load(Ordering::SeqCst) < MAX_WAITING_POLLS {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(5));
        }
        // The ninth answers at once, as if waitMs were 0.
        assert!(poll(&c, &id, after) < Duration::from_millis(200));
        for w in waiting {
            assert!(w.join().unwrap() >= Duration::from_millis(1400));
        }
        assert_eq!(c.waiting_polls.load(Ordering::SeqCst), 0, "every waiter left its slot");
        f.jobs.shutdown(Duration::from_secs(2));
    }
}
