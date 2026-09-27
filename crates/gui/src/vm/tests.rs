use super::*;
use rt_api::jobs::JobEvent;
use rt_api::{AppSummary, ConsentView, PlanAction, PlanEntryView};
use serde_json::json;
use std::io;
use std::path::Path;

const HIDDEN: [char; 4] = ['\u{1b}', '\u{202e}', '\u{200b}', '\0'];

fn version(write: bool, api: &str) -> VersionInfo {
    VersionInfo {
        api: api.into(),
        runtime: "0.0.1".into(),
        protocol: rt_api::PROTOCOL.into(),
        write,
    }
}

fn app(id: &str, name: &str) -> AppSummary {
    AppSummary {
        id: id.into(),
        name: name.into(),
        version: Some("1.0".into()),
        architecture: "x86_64".into(),
        executable: "C:\\a.exe".into(),
        created: 0,
    }
}

fn job(id: &str, kind: JobKind, app: &str, state: JobState) -> JobInfo {
    JobInfo {
        job_id: id.into(),
        kind,
        app: Some(app.into()),
        state,
        exit_code: None,
        signal: None,
        created_at: 0,
        started_at: None,
        ended_at: None,
        dropped: 0,
    }
}

fn detail(id: &str) -> AppDetail {
    serde_json::from_value(json!({
        "id": id, "name": "Game", "version": null, "architecture": "x86_64", "executable": "C:\\g.exe",
        "environment": "e", "backend": {"id": "wine", "version": "10"}, "subsystem": "gui", "created": 0,
        "installer": null, "dependencies": [], "prefix": {"exists": true, "hasDriveC": true}
    }))
    .unwrap()
}

fn perms(grants: &[&str]) -> PermissionsView {
    serde_json::from_value(json!({
        "source": "file", "network": "deny", "display": true, "audio": false, "gpu": false,
        "filesystem": grants.iter().map(|g| json!({"path": g, "access": "ro"})).collect::<Vec<_>>(),
        "limits": {"memoryMb": null, "cpuPercent": null, "tasks": 512, "tasksDefault": true, "explicit": false}
    }))
    .unwrap()
}

fn rpc(kind: &str) -> ClientError {
    ClientError::Rpc {
        code: -32000,
        message: format!("{kind} happened"),
        kind: Some(kind.into()),
    }
}

/// A model connected to a daemon (`write` or not), with apps `game` and `other` and `game` open and loaded.
fn ready(write: bool) -> Model {
    let mut m = Model::new();
    m.update(Msg::Connected(version(write, "0.2.0")));
    m.update(Msg::Apps(AppList {
        apps: vec![app("game", "Game"), app("other", "Other")],
        skipped: 0,
    }));
    m.update(Msg::Open("game".into()));
    load(&mut m, &["/data/music"]);
    m
}

fn load(m: &mut Model, grants: &[&str]) {
    m.update(Msg::AppLoaded(Box::new(AppData {
        detail: detail("game"),
        permissions: Ok(perms(grants)),
        doctor: Err(rpc("unavailable")),
        graphics: Err(rpc("unavailable")),
        sandbox: Err(rpc("unavailable")),
    })));
}

fn entry(package: &str, consent: ConsentView, text: Option<&[&str]>) -> PlanEntryView {
    PlanEntryView {
        package: package.into(),
        version: Some(format!("{package}-1.0")),
        action: PlanAction::Install,
        consent,
        blocked_reason: None,
        sha256: Some(format!("{:0>64}", package.len())),
        consent_text: text.map(|t| t.iter().map(|l| l.to_string()).collect()),
    }
}

const DIGEST: &str = "ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12";

/// Two needed entries (`a`, with an ESC and U+202E in its text; `b`) and one `notNeeded`.
fn plan() -> DepsPlanView {
    DepsPlanView {
        entries: vec![
            entry(
                "a",
                ConsentView::Needed,
                Some(&["Licence of a", "evil \u{1b}[2J \u{202e}txet"]),
            ),
            entry("b", ConsentView::Needed, Some(&["Licence of b"])),
            entry("dxvk", ConsentView::NotNeeded, None),
        ],
        unsatisfied: vec![],
        warnings: vec![],
        digest: DIGEST.into(),
    }
}

/// [`planned`] with the consent dialog open.
fn opened_plan(write: bool, p: DepsPlanView) -> Model {
    let mut m = planned(write, p);
    m.update(Msg::ConsentOpened);
    m
}

fn planned(write: bool, p: DepsPlanView) -> Model {
    let mut m = ready(write);
    assert_eq!(m.update(Msg::Plan), vec![Cmd::Plan("game".into())]);
    m.update(Msg::PlanLoaded {
        id: "game".into(),
        plan: p,
    });
    m
}

// ------------------------------------------------------------------------------------------------ connection

#[test]
fn every_client_error_is_a_connection_state() {
    let sock = PathBuf::from("/run/user/1/runtime/runtimed.sock");
    let failed = |error: ClientError| {
        let mut m = Model::new();
        assert!(
            m.update(Msg::ConnectFailed(ConnError {
                socket: sock.clone(),
                error,
            }))
            .is_empty()
        );
        m
    };
    let unreachable = Conn::Unreachable {
        socket: sock.display().to_string(),
    };
    assert_eq!(*failed(ClientError::NoRuntimeDir).conn(), unreachable);
    let m = failed(ClientError::Unreachable {
        path: "x".into(),
        err: io::ErrorKind::NotFound.into(),
    });
    assert_eq!(*m.conn(), unreachable);
    let m = failed(ClientError::Unsafe {
        path: sock.display().to_string(),
        why: "the socket is open to group or others",
    });
    match m.conn() {
        Conn::Refused(why) => assert!(why.contains("open to group or others"), "{why}"),
        c => panic!("{c:?}"),
    }
    // Anything else: the connection is gone (Retry reconnects); the reason is the notice.
    for e in [
        ClientError::Io(io::ErrorKind::BrokenPipe.into()),
        ClientError::Protocol("not a JSON object"),
        ClientError::TooLarge,
        ClientError::Unsupported("old"),
        rpc("busy"),
    ] {
        let m = failed(e);
        assert_eq!(*m.conn(), unreachable);
        assert!(m.notice().is_some());
    }
    // Retry reconnects.
    let mut m = failed(ClientError::NoRuntimeDir);
    assert_eq!(m.update(Msg::Retry), vec![Cmd::Connect]);
    assert_eq!(*m.conn(), Conn::Connecting);
}

#[test]
fn a_hostile_socket_path_or_reason_is_cleaned() {
    let mut m = Model::new();
    m.update(Msg::ConnectFailed(ConnError {
        socket: PathBuf::from("/run/\u{1b}[2J\u{202e}.sock"),
        error: ClientError::NoRuntimeDir,
    }));
    match m.conn() {
        Conn::Unreachable { socket } => assert!(!socket.contains(HIDDEN), "{socket:?}"),
        c => panic!("{c:?}"),
    }
}

#[test]
fn connecting_loads_the_apps_and_on_a_write_daemon_the_jobs() {
    let mut m = Model::new();
    assert_eq!(
        m.update(Msg::Connected(version(true, "0.2.0"))),
        vec![Cmd::ListApps, Cmd::ListJobs]
    );
    assert_eq!(
        *m.conn(),
        Conn::Ready {
            write: true,
            api: "0.2.0".into(),
            runtime: "0.0.1".into()
        }
    );
    // jobs.list is a write method: a read-only daemon is not asked.
    let mut m = Model::new();
    assert_eq!(m.update(Msg::Connected(version(false, "0.2.0"))), vec![Cmd::ListApps]);
    // A reconnect reloads the open page.
    let mut m = ready(true);
    m.update(Msg::ConnectFailed(ConnError {
        socket: "/s".into(),
        error: ClientError::Io(io::ErrorKind::BrokenPipe.into()),
    }));
    assert_eq!(
        m.update(Msg::Connected(version(true, "0.2.0"))),
        vec![Cmd::ListApps, Cmd::ListJobs, Cmd::LoadApp("game".into())]
    );
}

const WRITES: [Action; 7] = [
    Action::Install,
    Action::Run,
    Action::Stop,
    Action::Remove,
    Action::InstallDeps,
    Action::EditPermissions,
    Action::Cancel,
];

fn write_intents() -> Vec<Msg> {
    vec![
        Msg::Run,
        Msg::Stop,
        Msg::Remove,
        Msg::InstallDeps,
        Msg::Install(InstallForm {
            path: "/in/setup.exe".into(),
            ..Default::default()
        }),
        Msg::Permission(PermChange::Network(true)),
        Msg::ResetPermissions,
        Msg::Cancel("j1".into()),
    ]
}

#[test]
fn a_read_only_daemon_disables_every_write_with_the_reason() {
    for api in ["0.2.0", "0.1.0"] {
        // A 0.1 daemon is read-only whatever it says.
        let mut m = ready(true);
        m.update(Msg::Connected(version(api == "0.1.0", api)));
        if api == "0.2.0" {
            m = ready(false);
        }
        m.update(Msg::Plan);
        m.update(Msg::PlanLoaded {
            id: "game".into(),
            plan: plan(),
        });
        m.update(Msg::JobList(vec![job("j1", JobKind::Run, "game", JobState::Running)]));
        for a in WRITES {
            assert_eq!(m.can(a), Err(READ_ONLY), "{api} {a:?}");
        }
        assert_eq!(m.can(Action::Plan), Ok(()), "reading still works");
        for msg in write_intents() {
            m.update(Msg::Dismiss);
            let what = format!("{msg:?}");
            assert!(m.update(msg).is_empty(), "{api}: {what} sent something");
            assert_eq!(m.notice(), Some(READ_ONLY));
        }
    }
}

#[test]
fn nothing_is_sent_before_the_daemon_answers() {
    let mut m = Model::new();
    for msg in write_intents().into_iter().chain([Msg::Plan, Msg::Open("game".into())]) {
        let what = format!("{msg:?}");
        assert!(m.update(msg).is_empty(), "{what}");
    }
    assert!(m.can(Action::Plan).is_err());
}

#[test]
fn a_write_daemon_enables_the_writes() {
    let m = ready(true);
    for a in [
        Action::Install,
        Action::Run,
        Action::Remove,
        Action::EditPermissions,
        Action::Plan,
    ] {
        assert_eq!(m.can(a), Ok(()), "{a:?}");
    }
    // No plan yet, no live job.
    assert!(m.can(Action::InstallDeps).is_err());
    assert!(m.can(Action::Stop).is_err());
}

// ------------------------------------------------------------------------------------------------ apps

#[test]
fn search_is_case_insensitive_over_name_and_id() {
    let mut m = ready(false);
    m.update(Msg::Apps(AppList {
        apps: vec![
            app("notepad-plus", "Notepad++"),
            app("game", "Big GAME"),
            app("x", "Zed"),
        ],
        skipped: 0,
    }));
    let ids = |m: &Model| m.visible_apps().into_iter().map(|r| r.id).collect::<Vec<_>>();
    assert_eq!(ids(&m).len(), 3);
    m.update(Msg::Search("gAmE".into()));
    assert_eq!(ids(&m), ["game"]);
    m.update(Msg::Search("NOTEPAD-".into()));
    assert_eq!(ids(&m), ["notepad-plus"], "the id matches too");
    m.update(Msg::Search("  ".into()));
    assert_eq!(ids(&m).len(), 3);
    assert_eq!(m.apps_note(), None);
}

#[test]
fn hostile_app_lists_are_shown_clean_and_bounded() {
    let mut m = ready(false);
    let list: AppList = serde_json::from_value(json!({
        "apps": [{"id": "evil", "name": format!("\u{1b}[31m<b>x</b>\u{202e}{}", "n".repeat(1 << 20)),
                  "version": "1\u{200b}.0\0", "architecture": "x", "executable": "e", "created": 0}],
        "skipped": 3
    }))
    .unwrap();
    m.update(Msg::Apps(list));
    let rows = m.visible_apps();
    assert_eq!(rows[0].id, "evil");
    assert!(
        rows[0].title.starts_with("[31m<b>x</b>"),
        "markup is kept as text: {:?}",
        &rows[0].title[..20]
    );
    assert!(rows[0].title.len() <= TEXT_MAX);
    for s in [&rows[0].title, &rows[0].subtitle] {
        assert!(!s.contains(HIDDEN), "{s:?}");
    }
    assert!(rows[0].subtitle.contains("1.0"));
    assert_eq!(m.apps_note().as_deref(), Some("3 app entries could not be read"));
}

#[test]
fn opening_an_app_loads_it_and_a_stale_answer_is_ignored() {
    let mut m = ready(true);
    assert_eq!(
        m.update(Msg::Open("other".into())),
        vec![Cmd::LoadApp("other".into()), Cmd::ListJobs]
    );
    assert!(m.page().unwrap().data().is_none());
    // The answer for the app open before arrives late.
    load(&mut m, &[]);
    assert!(m.page().unwrap().data().is_none());
    assert_eq!(m.page().unwrap().title(), "other");
}

#[test]
fn a_removed_app_closes_its_page() {
    let mut m = ready(true);
    m.update(Msg::Plan);
    m.update(Msg::PlanLoaded {
        id: "game".into(),
        plan: plan(),
    });
    // Another app's answer leaves the page alone.
    m.update(Msg::Failed {
        what: Cmd::LoadApp("other".into()),
        error: rpc("not_found"),
    });
    assert!(m.page().is_some());
    m.update(Msg::Failed {
        what: Cmd::LoadApp("game".into()),
        error: rpc("not_found"),
    });
    assert!(m.page().is_none() && m.consent().is_none());
    assert!(m.can(Action::Run).is_err());
}

#[test]
fn stop_needs_a_live_run_job_of_this_app() {
    let mut m = ready(true);
    let stop = |m: &mut Model| (m.can(Action::Stop).is_ok(), m.update(Msg::Stop));
    for jobs in [
        vec![],
        vec![job("j1", JobKind::Run, "other", JobState::Running)],
        vec![job("j1", JobKind::Run, "game", JobState::Succeeded)],
        vec![job("j1", JobKind::Remove, "game", JobState::Running)],
    ] {
        m.update(Msg::JobList(jobs.clone()));
        assert_eq!(stop(&mut m), (false, vec![]), "{jobs:?}");
    }
    m.update(Msg::JobList(vec![
        job("j0", JobKind::Run, "other", JobState::Running),
        job("j2", JobKind::Run, "game", JobState::Queued),
    ]));
    assert_eq!(stop(&mut m), (true, vec![Cmd::Cancel("j2".into())]));
    // A live job for the app holds the other app writes back.
    assert!(m.can(Action::Run).is_err());
    assert!(m.can(Action::Remove).is_err());
}

/// The last write's job started and ended: the app is free again.
fn free(m: &mut Model) {
    m.update(Msg::JobStarted {
        what: Cmd::Run("game".into()),
        job_id: "done".into(),
    });
    m.update(Msg::JobList(vec![]));
}

#[test]
fn write_intents_send_their_command() {
    let mut m = ready(true);
    assert_eq!(m.update(Msg::Run), vec![Cmd::Run("game".into())]);
    free(&mut m);
    assert_eq!(m.update(Msg::Remove), vec![Cmd::Remove("game".into())]);
    free(&mut m);
    assert_eq!(m.update(Msg::ResetPermissions), vec![Cmd::PermReset("game".into())]);
    assert_eq!(m.update(Msg::Cancel("j9".into())), vec![Cmd::Cancel("j9".into())]);
    assert_eq!(
        m.update(Msg::Refresh),
        vec![Cmd::ListApps, Cmd::ListJobs, Cmd::LoadApp("game".into())]
    );
}

// ------------------------------------------------------------------------------------------------ jobs

fn events(id: &str, state: JobState, from: u64, lines: &[&str], dropped: u64) -> JobEvents {
    JobEvents {
        events: lines
            .iter()
            .enumerate()
            .map(|(i, l)| JobEvent {
                seq: from + i as u64,
                ts: 0,
                kind: EventKind::Stdout,
                text: l.to_string(),
            })
            .collect(),
        next_seq: from + lines.len() as u64,
        dropped,
        job: job(id, JobKind::Remove, "game", state),
    }
}

#[test]
fn a_started_job_is_followed_and_its_end_reloads() {
    let mut m = ready(true);
    assert_eq!(
        m.update(Msg::JobStarted {
            what: Cmd::Remove("game".into()),
            job_id: "j1".into(),
        }),
        vec![Cmd::Follow("j1".into()), Cmd::ListJobs]
    );
    assert!(
        m.update(Msg::JobEvents(events(
            "j1",
            JobState::Running,
            1,
            &["a\u{1b}[2J", "b"],
            0
        )))
        .is_empty()
    );
    let lines: Vec<&str> = m.log("j1").unwrap().lines().collect();
    assert_eq!(lines, ["a[2J", "b"]);
    assert_eq!(m.jobs()[0].state, JobState::Running, "the job list follows the events");
    assert_eq!(
        m.update(Msg::JobEvents(events("j1", JobState::Succeeded, 3, &["c"], 0))),
        vec![Cmd::ListApps, Cmd::ListJobs, Cmd::LoadApp("game".into())]
    );
    // A second final answer does not reload again; events of a job not followed are not kept.
    assert!(
        m.update(Msg::JobEvents(events("j1", JobState::Succeeded, 4, &[], 0)))
            .is_empty()
    );
    m.update(Msg::JobEvents(events("zz", JobState::Running, 1, &["x"], 0)));
    assert!(m.log("zz").is_none());
}

#[test]
fn a_log_keeps_the_newest_lines_and_says_what_was_dropped() {
    let mut m = ready(true);
    m.update(Msg::JobStarted {
        what: Cmd::Run("game".into()),
        job_id: "j1".into(),
    });
    let many: Vec<String> = (0..=LOG_MAX).map(|i| format!("line {i}")).collect();
    let refs: Vec<&str> = many.iter().map(String::as_str).collect();
    m.update(Msg::JobEvents(events("j1", JobState::Running, 1, &refs, 0)));
    let lines: Vec<&str> = m.log("j1").unwrap().lines().collect();
    assert_eq!(lines.len(), LOG_MAX + 1);
    assert_eq!(lines[0], EARLIER_DROPPED);
    assert_eq!(lines[1], "line 1");
    assert_eq!(lines[LOG_MAX], format!("line {LOG_MAX}"));
    m.update(Msg::JobEvents(events("j1", JobState::Running, 9000, &["after"], 7)));
    let lines: Vec<&str> = m.log("j1").unwrap().lines().collect();
    assert_eq!(lines.len(), LOG_MAX + 1);
    assert_eq!(lines[0], EARLIER_DROPPED);
    assert_eq!(&lines[LOG_MAX - 1..], ["[7 lines were dropped by the daemon]", "after"]);
}

#[test]
fn errors_are_fixed_sentences_or_the_cleaned_message() {
    let mut m = ready(true);
    let fail = |m: &mut Model, e: ClientError| {
        assert!(
            m.update(Msg::Failed {
                what: Cmd::Run("game".into()),
                error: e,
            })
            .is_empty()
        );
        m.notice().unwrap().to_owned()
    };
    assert!(fail(&mut m, rpc("busy")).contains("4 jobs are already running; try again when one ends"));
    assert!(fail(&mut m, rpc("read_only")).contains(READ_ONLY));
    assert!(fail(&mut m, rpc("app_busy")).contains("still running"));
    let n = fail(
        &mut m,
        ClientError::Rpc {
            code: -32000,
            message: format!("bad \u{1b}[2J\u{202e}{}", "x".repeat(5000)),
            kind: Some("invalid_argument".into()),
        },
    );
    assert!(n.contains("bad [2J"), "{n}");
    assert!(!n.contains(HIDDEN) && n.chars().count() <= MAX_SHOWN, "{n}");
    let n = fail(&mut m, ClientError::Unsupported("this daemon cannot"));
    assert!(n.contains("this daemon cannot"), "{n}");
}

// ------------------------------------------------------------------------------------------------ consent

#[test]
fn nothing_is_accepted_until_each_entry_is() {
    let mut m = opened_plan(true, plan());
    let c = m.consent().unwrap();
    assert_eq!(c.choices().len(), 2, "one choice per needed entry");
    assert!(c.choices().iter().all(|c| !c.accepted() && c.unacceptable().is_none()));
    assert_eq!(c.install_label(), "Install (0 of 2 accepted)");
    assert_eq!(c.entries().len(), 3, "every entry is listed");
    let a = &c.choices()[0];
    assert_eq!(a.text[0], "Licence of a");
    assert!(!a.text[1].contains(HIDDEN), "{:?}", a.text[1]);
    m.update(Msg::Accept("a".into(), true));
    let c = m.consent().unwrap();
    assert_eq!(
        c.choices().iter().map(ConsentChoice::accepted).collect::<Vec<_>>(),
        [true, false]
    );
    assert_eq!(c.install_label(), "Install (1 of 2 accepted)");
    // Unknown and not-needed packages accept nothing.
    m.update(Msg::Accept("dxvk".into(), true));
    m.update(Msg::Accept("zzz".into(), true));
    assert_eq!(m.consent().unwrap().accepted_count(), 1);
    // Accepting then un-accepting.
    m.update(Msg::Accept("b".into(), true));
    m.update(Msg::Accept("b".into(), false));
    assert_eq!(m.consent().unwrap().accepted_count(), 1);
}

#[test]
fn install_deps_sends_the_digest_verbatim_and_exactly_the_accepted_entries_once() {
    let mut m = opened_plan(true, plan());
    m.update(Msg::Accept("a".into(), true));
    let a = &plan().entries[0];
    assert_eq!(
        m.update(Msg::InstallDeps),
        vec![Cmd::DepsInstall {
            id: "game".into(),
            digest: DIGEST.into(),
            consent: vec![ConsentItem {
                package: a.package.clone(),
                version: a.version.clone().unwrap(),
                sha256: a.sha256.clone().unwrap(),
            }],
        }]
    );
    assert!(m.consent().is_none(), "the plan is dropped once sent");
    assert!(
        m.update(Msg::InstallDeps).is_empty(),
        "a second install needs a new plan"
    );
    assert!(m.can(Action::InstallDeps).is_err());
    // Nothing accepted: the digest alone (the daemon installs only what needs no consent).
    let mut m = opened_plan(true, plan());
    assert_eq!(
        m.update(Msg::InstallDeps),
        vec![Cmd::DepsInstall {
            id: "game".into(),
            digest: DIGEST.into(),
            consent: vec![],
        }]
    );
}

#[test]
fn entries_that_cannot_be_shown_whole_can_never_be_accepted() {
    let mut p = plan();
    p.entries[0].sha256 = None;
    p.entries[1].consent_text = None;
    let mut bad = entry("c", ConsentView::Needed, Some(&["t"]));
    bad.version = Some("1.0\u{202e}".into());
    let mut twin1 = entry("d", ConsentView::Needed, Some(&["t"]));
    let twin2 = twin1.clone();
    twin1.consent_text = Some(vec!["other terms".into()]);
    let empty_text = entry("e", ConsentView::Needed, Some(&[]));
    let mut bad_name = entry("f\u{7}", ConsentView::Needed, Some(&["t"]));
    bad_name.version = Some("1.0".into());
    let mut bad_sum = entry("g", ConsentView::Needed, Some(&["t"]));
    bad_sum.sha256 = Some(format!("{:0>63}\u{200b}", 1));
    p.entries.extend([bad, twin1, twin2, empty_text, bad_name, bad_sum]);
    let mut m = opened_plan(true, p);
    for pkg in ["a", "b", "c", "d", "e", "f\u{7}", "g"] {
        m.update(Msg::Accept(pkg.into(), true));
    }
    let c = m.consent().unwrap();
    assert!(
        c.choices().iter().all(|c| c.unacceptable().is_some() && !c.accepted()),
        "{:?}",
        c.choices()
    );
    match &m.update(Msg::InstallDeps)[..] {
        [Cmd::DepsInstall { consent, .. }] => assert!(consent.is_empty()),
        c => panic!("{c:?}"),
    }
}

#[test]
fn a_plan_without_a_digest_cannot_be_installed() {
    let mut p = plan();
    p.digest.clear();
    let mut m = opened_plan(true, p);
    assert!(m.can(Action::InstallDeps).unwrap_err().contains("API 0.1"));
    assert!(m.update(Msg::InstallDeps).is_empty());
}

#[test]
fn a_changed_plan_is_planned_again_and_nothing_is_resent() {
    let mut m = opened_plan(true, plan());
    m.update(Msg::Accept("a".into(), true));
    let sent = m.update(Msg::InstallDeps).remove(0);
    let again = m.update(Msg::Failed {
        what: sent,
        error: rpc("consent_mismatch"),
    });
    assert_eq!(again, vec![Cmd::Plan("game".into())]);
    assert_eq!(m.notice(), Some(PLAN_CHANGED));
    // The new plan starts unaccepted.
    m.update(Msg::PlanLoaded {
        id: "game".into(),
        plan: plan(),
    });
    assert_eq!(m.consent().unwrap().accepted_count(), 0);
}

#[test]
fn a_plan_for_another_app_is_not_kept() {
    let mut m = ready(true);
    m.update(Msg::PlanLoaded {
        id: "other".into(),
        plan: plan(),
    });
    assert!(m.consent().is_none());
    // Opening another app drops the plan.
    let mut m = opened_plan(true, plan());
    m.update(Msg::Open("other".into()));
    assert!(m.consent().is_none());
}

#[test]
fn a_hostile_plan_is_cleaned_for_display() {
    let p: DepsPlanView = serde_json::from_value(json!({
        "entries": [{"package": "p\u{1b}]0;x\u{7}", "version": "1", "action": "blocked", "consent": "denied",
                     "blockedReason": format!("why\u{202e}{}", "y".repeat(1 << 20)), "sha256": null, "consentText": null}],
        "unsatisfied": ["cap\u{200b}"], "warnings": ["w\0"], "digest": DIGEST
    }))
    .unwrap();
    let m = opened_plan(true, p);
    let c = m.consent().unwrap();
    assert!(c.choices().is_empty());
    let e = &c.entries()[0];
    for s in [&e.package, e.note.as_ref().unwrap(), &c.unsatisfied[0], &c.warnings[0]] {
        assert!(!s.contains(HIDDEN) && s.chars().count() <= MAX_SHOWN, "{s:?}");
    }
    assert_eq!(e.action, "blocked");
}

// ------------------------------------------------------------------------------------------------ permissions

fn perm(m: &mut Model, c: PermChange) -> Vec<Cmd> {
    let cmds = m.update(Msg::Permission(c));
    free(m);
    cmds
}

fn set(e: &str) -> Vec<Cmd> {
    vec![Cmd::PermSet {
        id: "game".into(),
        set: vec![e.into()],
    }]
}

#[test]
fn permission_changes_are_typed_expressions() {
    let mut m = ready(true);
    assert_eq!(perm(&mut m, PermChange::Network(true)), set("network=allow"));
    assert_eq!(perm(&mut m, PermChange::Network(false)), set("network=deny"));
    assert_eq!(perm(&mut m, PermChange::Display(false)), set("display=off"));
    assert_eq!(perm(&mut m, PermChange::Audio(true)), set("audio=on"));
    assert_eq!(perm(&mut m, PermChange::Gpu(true)), set("gpu=on"));
    let grant = |p: &str, rw| PermChange::Grant { path: p.into(), rw };
    assert_eq!(perm(&mut m, grant("/a/b", true)), set("fs+=/a/b:rw"));
    assert_eq!(perm(&mut m, grant("/a b/ü", false)), set("fs+=/a b/ü:ro"));
    assert_eq!(
        perm(&mut m, PermChange::Revoke("/data/music".into())),
        set("fs-=/data/music")
    );
}

#[test]
fn unsafe_folders_are_refused_with_a_message() {
    use std::os::unix::ffi::OsStrExt;
    let mut m = ready(true);
    let non_utf8 = PathBuf::from(std::ffi::OsStr::from_bytes(b"/a/\xff"));
    for p in [
        PathBuf::from("/a:b"),
        PathBuf::from("a/b"),
        PathBuf::from(""),
        PathBuf::from("/a\nb"),
        PathBuf::from("/a\u{202e}b"),
        PathBuf::from("/a\u{200b}b"),
        non_utf8,
        PathBuf::from(format!("/{}", "a".repeat(5000))),
    ] {
        m.update(Msg::Dismiss);
        let what = format!("{p:?}");
        assert!(
            perm(&mut m, PermChange::Grant { path: p, rw: false }).is_empty(),
            "{what}"
        );
        assert!(m.notice().is_some(), "{what}");
    }
    // Only a grant the app has can be revoked.
    for p in ["/etc", "/data/music\n"] {
        m.update(Msg::Dismiss);
        assert!(perm(&mut m, PermChange::Revoke(p.into())).is_empty());
        assert_eq!(m.notice(), Some("that folder is not granted"));
    }
}

// ------------------------------------------------------------------------------------------------ install form

#[test]
fn the_install_form_is_checked_before_sending() {
    use std::os::unix::ffi::OsStrExt;
    let form = InstallForm::default();
    assert!(!form.network && !form.silent, "network access is off unless asked for");
    let mut m = ready(true);
    let send = |m: &mut Model, path: PathBuf, name: &str| {
        m.update(Msg::Install(InstallForm {
            path,
            name: name.into(),
            silent: true,
            network: false,
        }))
    };
    assert_eq!(
        send(&mut m, "/in/setup.exe".into(), "  My App  "),
        vec![Cmd::Install(InstallParams {
            path: "/in/setup.exe".into(),
            name: Some("My App".into()),
            exe: None,
            silent: true,
            network: false,
        })]
    );
    match &send(&mut m, "/in/s.msi".into(), "   ")[..] {
        [Cmd::Install(p)] => assert_eq!(p.name, None),
        c => panic!("{c:?}"),
    }
    for (path, name) in [
        (PathBuf::from("in/setup.exe"), ""),
        (PathBuf::from(std::ffi::OsStr::from_bytes(b"/in/\xff.exe")), ""),
        (PathBuf::from("/in/setup.exe"), &*"n".repeat(257)),
        (PathBuf::from("/in/setup.exe"), "a\u{7}b"),
        (PathBuf::from("/in/setup.exe"), "a\u{202e}b"),
    ] {
        let what = format!("{path:?} {name:?}");
        m.update(Msg::Dismiss);
        assert!(send(&mut m, path, name).is_empty(), "{what}");
        assert!(m.notice().is_some(), "{what}");
    }
    assert_eq!(send(&mut m, "/in/setup.exe".into(), &"n".repeat(256)).len(), 1);
}

// ------------------------------------------------------------------------------------------------ shown

#[test]
fn shown_removes_invisible_characters_and_bounds() {
    assert_eq!(shown("a\u{1b}b\u{202e}c\u{200b}d\0e", 100), "abcde");
    let big = "x".repeat(1 << 20);
    assert_eq!(shown(&big, 1024).chars().count(), 1024);
    assert_eq!(
        shown("<b>&amp;</b>", 100),
        "<b>&amp;</b>",
        "markup is text, escaping is the widget's"
    );
    assert!(Path::new(START_HINT).is_relative());
}

// ------------------------------------------------------------------------------------------------ Tasks 4-5: display

#[test]
fn at_most_max_logs_followed_logs_are_kept_oldest_ended_first() {
    let mut m = ready(true);
    for i in 0..MAX_LOGS + 4 {
        m.update(Msg::JobStarted {
            what: Cmd::Run("game".into()),
            job_id: format!("j{i}"),
        });
        // j1 stays live; the others end.
        if i != 1 {
            m.update(Msg::JobEvents(events(
                &format!("j{i}"),
                JobState::Succeeded,
                1,
                &["x"],
                0,
            )));
        }
    }
    assert_eq!(m.logs().count(), MAX_LOGS);
    assert!(m.log("j1").is_some(), "a live job's log is not dropped");
    assert!(m.log("j0").is_none() && m.log("j2").is_none());
    assert!(m.log(&format!("j{}", MAX_LOGS + 3)).is_some());
}

fn doctor_json() -> DoctorView {
    serde_json::from_value(json!({
        "subject": {"kind": "app", "id": "game", "name": null, "version": null},
        "verdict": "may_fail",
        "checks": [{"area": "imports", "status": "warn", "text": "needs <b>x</b> & \u{1b}[2J\u{202e}y"}],
        "missingDependencies": 1, "notes": []
    }))
    .unwrap()
}

#[test]
fn the_page_is_shown_as_cleaned_lines() {
    let mut m = ready(true);
    m.update(Msg::AppLoaded(Box::new(AppData {
        detail: detail("game"),
        permissions: Ok(perms(&["/data/mu\u{200b}sic"])),
        doctor: Ok(doctor_json()),
        graphics: Err(rpc("unavailable")),
        sandbox: Err(ClientError::Rpc {
            code: -32000,
            message: "no \u{1b}bwrap".into(),
            kind: Some("unavailable".into()),
        }),
    })));
    let sections = m.page_sections();
    let names: Vec<&str> = sections.iter().map(|s| s.0).collect();
    assert_eq!(names, ["Checks", "Graphics", "Sandbox"]);
    let all: Vec<&Line> = sections.iter().flat_map(|s| &s.1).collect();
    assert!(
        all.iter()
            .any(|l| l.title == "imports" && l.detail == "warn: needs <b>x</b> & [2Jy"),
        "{all:?}"
    );
    for l in &all {
        assert!(!l.title.contains(HIDDEN) && !l.detail.contains(HIDDEN), "{l:?}");
    }
    assert!(sections[2].1[0].detail.contains("no bwrap"), "{:?}", sections[2].1);
    let p = m.page_permissions().unwrap().unwrap();
    assert!(p.display && !p.network);
    assert_eq!(p.grants[0].path, "/data/mu\u{200b}sic", "raw: what a revoke sends back");
    assert_eq!(p.grants[0].shown, "/data/music");
    assert_eq!(p.grants[0].access, "read-only");
    assert!(p.limits.contains("512 tasks"), "{}", p.limits);
    assert_eq!(m.page_status().as_deref(), Some("Not running"));
    m.update(Msg::JobList(vec![job("j1", JobKind::Run, "game", JobState::Running)]));
    assert_eq!(m.page_status().as_deref(), Some("Running (job j1)"));
}

// ------------------------------------------------------------------------------------------------ review fixes

#[test]
fn consent_is_reset_whenever_the_dialog_opens_or_closes_without_install() {
    let mut m = planned(true, plan());
    // No dialog open: nothing can be accepted or installed.
    m.update(Msg::Accept("a".into(), true));
    assert_eq!(m.consent().unwrap().accepted_count(), 0);
    assert!(m.update(Msg::InstallDeps).is_empty());
    // Tick, cancel, reopen: nothing accepted, nothing sent.
    m.update(Msg::ConsentOpened);
    m.update(Msg::Accept("a".into(), true));
    assert_eq!(m.consent().unwrap().accepted_count(), 1);
    m.update(Msg::ConsentClosed);
    assert_eq!(m.consent().unwrap().accepted_count(), 0);
    m.update(Msg::ConsentOpened);
    assert_eq!(m.consent().unwrap().install_label(), "Install (0 of 2 accepted)");
    match &m.update(Msg::InstallDeps)[..] {
        [Cmd::DepsInstall { consent, .. }] => assert!(consent.is_empty()),
        c => panic!("{c:?}"),
    }
    // A tick then a reopen (without a close in between) also starts over.
    let mut m = planned(true, plan());
    m.update(Msg::ConsentOpened);
    m.update(Msg::Accept("a".into(), true));
    m.update(Msg::ConsentOpened);
    assert_eq!(m.consent().unwrap().accepted_count(), 0);
}

#[test]
fn a_plan_answer_while_the_dialog_is_open_closes_it() {
    for digest in [
        DIGEST,
        "cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34cd34",
    ] {
        let mut m = planned(true, plan());
        m.update(Msg::ConsentOpened);
        m.update(Msg::Accept("a".into(), true));
        assert!(m.consent_open());
        let mut p = plan();
        p.digest = digest.into();
        m.update(Msg::PlanLoaded {
            id: "game".into(),
            plan: p,
        });
        assert!(!m.consent_open(), "{digest}");
        assert_eq!(m.notice(), Some(PLAN_REPLACED));
        assert_eq!(m.consent().unwrap().accepted_count(), 0);
        assert!(
            m.update(Msg::InstallDeps).is_empty(),
            "the replaced dialog cannot install"
        );
    }
}

#[test]
fn a_second_click_before_the_job_is_known_sends_nothing() {
    let mut m = ready(true);
    assert_eq!(m.update(Msg::Run), vec![Cmd::Run("game".into())]);
    assert!(m.update(Msg::Run).is_empty());
    assert!(m.update(Msg::Remove).is_empty());
    assert!(m.update(Msg::Permission(PermChange::Gpu(true))).is_empty());
    assert!(m.can(Action::Run).is_err());
    // Started, and the job list shows it: still busy (now through the list).
    m.update(Msg::JobStarted {
        what: Cmd::Run("game".into()),
        job_id: "j1".into(),
    });
    m.update(Msg::JobList(vec![job("j1", JobKind::Run, "game", JobState::Running)]));
    assert!(m.can(Action::Run).is_err());
    m.update(Msg::JobList(vec![job("j1", JobKind::Run, "game", JobState::Succeeded)]));
    assert_eq!(m.can(Action::Run), Ok(()));
    // A refused command frees the app at once.
    m.update(Msg::Remove);
    m.update(Msg::Failed {
        what: Cmd::Remove("game".into()),
        error: rpc("busy"),
    });
    assert_eq!(m.can(Action::Remove), Ok(()));
}

#[test]
fn a_log_is_bounded_in_bytes_and_reads_what_is_new() {
    let mut m = ready(true);
    m.update(Msg::JobStarted {
        what: Cmd::Run("game".into()),
        job_id: "j1".into(),
    });
    let line = "x".repeat(4000);
    let lines: Vec<&str> = (0..400).map(|_| line.as_str()).collect();
    m.update(Msg::JobEvents(events("j1", JobState::Running, 1, &lines, 0)));
    let log = m.log("j1").unwrap();
    assert!(log.bytes() <= LOG_BYTES, "{}", log.bytes());
    assert!(log.lines().next() == Some(EARLIER_DROPPED));
    assert_eq!(log.len(), log.lines().count());
    // Incremental reads: what came after a version, or None once it was dropped.
    let v = log.version();
    m.update(Msg::JobEvents(events("j1", JobState::Running, 401, &["a", "b"], 0)));
    let log = m.log("j1").unwrap();
    assert_eq!(log.since(v).unwrap().collect::<Vec<_>>(), ["a", "b"]);
    assert!(log.since(0).is_none(), "the first lines are gone");
    assert_eq!(log.since(log.version()).unwrap().count(), 0);
}

#[test]
fn a_local_refusal_is_a_notice() {
    let mut m = ready(true);
    assert!(m.update(Msg::Refused("that file is not a local file")).is_empty());
    assert_eq!(m.notice(), Some("that file is not a local file"));
}

#[test]
fn a_refused_install_closes_the_models_dialog_and_forgets_its_choices() {
    let mut m = planned(true, plan());
    m.update(Msg::ConsentOpened);
    m.update(Msg::Accept("a".into(), true));
    // The app became busy while the dialog was open: Install is refused.
    m.update(Msg::JobList(vec![job("j1", JobKind::Run, "game", JobState::Running)]));
    assert!(m.update(Msg::InstallDeps).is_empty());
    assert!(!m.consent_open());
    assert_eq!(m.consent().unwrap().accepted_count(), 0);
}

#[test]
fn another_jobs_start_does_not_free_a_pending_app() {
    let mut m = ready(true);
    assert_eq!(m.update(Msg::Run), vec![Cmd::Run("game".into())]);
    // An install (no app) starts and the job list arrives before game's own start.
    m.update(Msg::JobStarted {
        what: Cmd::Install(InstallParams::default()),
        job_id: "other".into(),
    });
    m.update(Msg::JobList(vec![]));
    assert!(m.update(Msg::Run).is_empty(), "game is still pending");
}
