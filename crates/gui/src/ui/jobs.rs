//! The jobs panel (spec D11): `jobs.list` plus the jobs this GUI follows, Cancel on live ones, and the selected
//! followed job's output in a plain, read-only text view (never markup).
use super::{Ui, text};
use crate::vm::{Action, EARLIER_DROPPED, Model, Msg, TEXT_MAX, is_live, shown};
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita::prelude::*;
use std::rc::Rc;

/// Most jobs listed.
const SHOWN_JOBS: usize = 30;

fn kind(k: rt_api::jobs::JobKind) -> &'static str {
    use rt_api::jobs::JobKind as K;
    match k {
        K::Run => "run",
        K::Install => "install",
        K::Remove => "remove",
        K::DepsInstall => "dependencies",
        K::PermissionsSet | K::PermissionsReset => "permissions",
        K::DisplaySet => "display",
        _ => "job",
    }
}

fn state(s: rt_api::jobs::JobState) -> &'static str {
    use rt_api::jobs::JobState as S;
    match s {
        S::Queued => "queued",
        S::Running => "running",
        S::Succeeded => "succeeded",
        S::Failed => "failed",
        S::Cancelled => "cancelled",
        _ => "unknown",
    }
}

pub fn render(ui: &Rc<Ui>, m: &Model) {
    // A newly followed job is selected and the panel opens.
    let newest = m.logs().last().map(|(id, _)| id.to_owned());
    if newest.is_some() && *ui.last_followed.borrow() != newest {
        *ui.last_followed.borrow_mut() = newest.clone();
        *ui.selected_job.borrow_mut() = newest;
        ui.w.btn_jobs.set_active(true);
    }
    let can_cancel = m.can(Action::Cancel);
    let jobs: Vec<_> = m.jobs().iter().take(SHOWN_JOBS).collect();
    let key: String = jobs
        .iter()
        .map(|j| format!("{}:{}:{};", j.job_id, state(j.state), can_cancel.is_ok()))
        .collect();
    if *ui.jobs_key.borrow() != key {
        *ui.jobs_key.borrow_mut() = key;
        let list = &ui.w.jobs_list;
        list.remove_all();
        for j in &jobs {
            let app = j.app.as_deref().map(|a| shown(a, TEXT_MAX)).unwrap_or_default();
            let followed = m.log(&j.job_id).is_some();
            let row = text::row(
                &format!("{} {app}", kind(j.kind)),
                &format!("{}{}", state(j.state), if followed { " · output below" } else { "" }),
            );
            row.set_activatable(followed);
            if is_live(j.state) {
                let cancel = gtk::Button::builder()
                    .label("Cancel")
                    .valign(gtk::Align::Center)
                    .build();
                cancel.set_sensitive(can_cancel.is_ok());
                cancel.set_tooltip_text(can_cancel.err());
                let (weak, id) = (Rc::downgrade(ui), j.job_id.clone());
                cancel.connect_clicked(move |_| {
                    if let Some(ui) = weak.upgrade() {
                        ui.dispatch(Msg::Cancel(id.clone()));
                    }
                });
                row.add_suffix(&cancel);
            }
            let (weak, id) = (Rc::downgrade(ui), j.job_id.clone());
            row.connect_activated(move |_| {
                if let Some(ui) = weak.upgrade() {
                    *ui.selected_job.borrow_mut() = Some(id.clone());
                    ui.redraw_log();
                }
            });
            list.append(&row);
        }
    }
    ui.redraw_log_from(m);
}

/// What the log view shows: which job, up to which version, how many kept lines, and whether the note is first.
#[derive(Default)]
pub struct LogView {
    job: Option<String>,
    version: u64,
    lines: usize,
    note: bool,
}

impl Ui {
    fn redraw_log(&self) {
        let m = self.model();
        self.redraw_log_from(&m);
    }

    /// The selected job's log: only the new lines are appended, and lines the model dropped are deleted from the
    /// top, so a chatty job costs what it adds, not the whole log per update.
    fn redraw_log_from(&self, m: &Model) {
        let sel = self.selected_job.borrow().clone();
        let log = sel.as_deref().and_then(|id| m.log(id));
        let mut v = self.log_view.borrow_mut();
        let buf = self.w.job_log.buffer();
        let Some(log) = log else {
            if v.job.is_some() || sel.is_none() {
                buf.set_text("");
            }
            *v = LogView {
                job: sel,
                ..LogView::default()
            };
            return;
        };
        if v.job == sel && v.version == log.version() {
            return;
        }
        match log.since(v.version).filter(|_| v.job == sel) {
            Some(new) => {
                let mut end = buf.end_iter();
                for l in new {
                    buf.insert(&mut end, l);
                    buf.insert(&mut end, "\n");
                    v.lines += 1;
                }
                let excess = v.lines.saturating_sub(log.kept());
                if excess > 0 {
                    let top = i32::from(v.note);
                    let line = |n: usize| i32::try_from(n).unwrap_or(i32::MAX);
                    let mut from = buf.iter_at_line(top).unwrap_or_else(|| buf.end_iter());
                    let mut to = buf.iter_at_line(top + line(excess)).unwrap_or_else(|| buf.end_iter());
                    buf.delete(&mut from, &mut to);
                    v.lines -= excess;
                }
                if log.cut() && !v.note {
                    buf.insert(&mut buf.start_iter(), &format!("{EARLIER_DROPPED}\n"));
                    v.note = true;
                }
            }
            None => {
                let text: String = log.lines().flat_map(|l| [l, "\n"]).collect();
                buf.set_text(&text);
                *v = LogView {
                    job: sel,
                    version: 0,
                    lines: log.kept(),
                    note: log.cut(),
                };
            }
        }
        v.version = log.version();
        buf.place_cursor(&buf.end_iter());
        self.w.job_log.scroll_mark_onscreen(&buf.get_insert());
    }
}
