//! The GTK layer: widgets built from the view model, which decides everything. The only way in is [`Ui::dispatch`]
//! on the GTK thread: the model's `update`, each `Cmd` to the backend (which never blocks), then a render. Backend
//! messages cross from its threads through a channel read by a future on the GTK main loop ([`start`]), which handles
//! everything waiting in one go and renders once. Job output is credit-limited: a follower waits while
//! [`MAX_PENDING_EVENTS`] of its messages are unhandled, so a chatty job cannot flood the channel or the UI.
mod about;
mod app;
mod apps;
mod consent;
mod install;
mod jobs;
mod permissions;
pub mod text;
mod window;

use crate::backend::{Backend, Credits};
use crate::vm::{Action, Cmd, Conn, Model, Msg};
use gtk4 as gtk;
use gtk4::prelude::*;
use gtk4::{gio, glib};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::{Cell, Ref, RefCell};
use std::path::{Path, PathBuf};
use std::rc::{Rc, Weak};
use std::sync::Arc;

pub use window::Widgets;

pub struct Ui {
    model: RefCell<Model>,
    send: Box<dyn Fn(Cmd)>,
    pub w: Widgets,
    /// The daemon's socket, for About.
    socket: String,
    /// The raw app ids of the sidebar rows, in order.
    app_ids: RefCell<Vec<String>>,
    /// Write controls and the action each needs: their sensitivity and tooltip follow `Model::can`.
    controls: RefCell<Vec<(gtk::Widget, Action)>>,
    /// The same for the app page's controls (replaced with the page).
    page_controls: RefCell<Vec<(gtk::Widget, Action)>>,
    /// The app page's status line.
    status: RefCell<Option<gtk::Label>>,
    /// The jobs panel: what its list shows, the selected job, the newest followed one, and the log drawn.
    jobs_key: RefCell<String>,
    selected_job: RefCell<Option<String>>,
    last_followed: RefCell<Option<String>>,
    log_view: RefCell<jobs::LogView>,
    /// The open consent dialog (closed when the model no longer considers it open).
    consent_dialog: RefCell<Option<adw::AlertDialog>>,
    /// Set while widgets are updated from the model: the signals that fires are not user intents.
    rendering: Cell<bool>,
}

/// Most job-output messages handed to the UI and not handled yet.
pub const MAX_PENDING_EVENTS: usize = 8;
/// Most messages handled per main-loop turn (then one render).
const BATCH: usize = 64;

/// The GUI on a real backend for `socket`: backend messages reach [`Ui::dispatch_all`] on the GTK main loop.
pub fn start(socket: PathBuf) -> Rc<Ui> {
    let (tx, mut rx) = futures_channel::mpsc::unbounded::<Msg>();
    let credits = Arc::new(Credits::new(MAX_PENDING_EVENTS));
    let c = credits.clone();
    let backend = Backend::spawn(
        socket.clone(),
        Arc::new(move |m| {
            if matches!(m, Msg::JobEvents(_)) {
                c.acquire(|| tx.is_closed());
            }
            let _ = tx.unbounded_send(m);
        }),
    );
    let ui = Ui::new(Box::new(move |c| backend.send(c)), &socket);
    let weak = Rc::downgrade(&ui);
    glib::spawn_future_local(async move {
        while let Ok(first) = rx.recv().await {
            let Some(ui) = weak.upgrade() else { break };
            let mut batch = vec![first];
            while batch.len() < BATCH
                && let Ok(m) = rx.try_recv()
            {
                batch.push(m);
            }
            let events = batch.iter().filter(|m| matches!(m, Msg::JobEvents(_))).count();
            ui.dispatch_all(batch);
            for _ in 0..events {
                credits.release();
            }
        }
    });
    ui
}

/// A handler that dispatches `msg()` to the UI while it lives.
fn on(ui: &Weak<Ui>, msg: impl Fn() -> Msg + 'static) -> impl Fn() + 'static {
    let ui = ui.clone();
    move || {
        if let Some(ui) = ui.upgrade() {
            ui.dispatch(msg());
        }
    }
}

impl Ui {
    /// The window over a model, sending commands to `send` (the backend, or a recorder in tests).
    pub fn new(send: Box<dyn Fn(Cmd)>, socket: &Path) -> Rc<Ui> {
        let ui = Rc::new(Ui {
            model: RefCell::new(Model::new()),
            send,
            w: window::build(),
            socket: crate::vm::shown(&socket.to_string_lossy(), rt_api::PATH_MAX),
            app_ids: RefCell::default(),
            controls: RefCell::default(),
            page_controls: RefCell::default(),
            status: RefCell::default(),
            jobs_key: RefCell::default(),
            selected_job: RefCell::default(),
            last_followed: RefCell::default(),
            log_view: RefCell::default(),
            consent_dialog: RefCell::default(),
            rendering: Cell::new(false),
        });
        let weak = Rc::downgrade(&ui);
        let w = &ui.w;
        for r in &w.retry {
            let f = on(&weak, || Msg::Retry);
            r.connect_clicked(move |_| f());
        }
        let f = on(&weak, || Msg::Dismiss);
        w.banner_notice.connect_button_clicked(move |_| f());
        let ui2 = weak.clone();
        w.search.connect_search_changed(move |s| {
            if let Some(ui) = ui2.upgrade() {
                ui.dispatch(Msg::Search(s.text().to_string()));
            }
        });
        let ui2 = weak.clone();
        w.apps_list.connect_row_activated(move |_, row| {
            let Some(ui) = ui2.upgrade() else { return };
            let id = usize::try_from(row.index())
                .ok()
                .and_then(|i| ui.app_ids.borrow().get(i).cloned());
            if let Some(id) = id {
                ui.w.split.set_show_content(true);
                ui.dispatch(Msg::Open(id));
            }
        });
        let panel = w.jobs_panel.clone();
        w.btn_jobs
            .connect_toggled(move |b| panel.set_reveal_child(b.is_active()));
        let refresh = gio::SimpleAction::new("refresh", None);
        let f = on(&weak, || Msg::Refresh);
        refresh.connect_activate(move |_, _| f());
        let about = gio::SimpleAction::new("about", None);
        let ui2 = weak.clone();
        about.connect_activate(move |_, _| {
            if let Some(ui) = ui2.upgrade() {
                about::dialog(&ui.model(), &ui.socket).present(Some(&ui.w.window));
            }
        });
        w.window.add_action(&refresh);
        w.window.add_action(&about);
        for b in [&w.btn_install, &w.btn_install_empty] {
            let ui2 = weak.clone();
            b.connect_clicked(move |_| {
                if let Some(ui) = ui2.upgrade() {
                    install::open(&ui);
                }
            });
        }
        ui.control(&w.btn_install, Action::Install);
        ui.control(&w.btn_install_empty, Action::Install);
        ui.render(true);
        ui
    }

    pub fn window(&self) -> &adw::ApplicationWindow {
        &self.w.window
    }

    pub fn model(&self) -> Ref<'_, Model> {
        self.model.borrow()
    }

    /// Registers a write control: sensitive only when `action` is possible, else insensitive with the reason.
    fn control(&self, w: &impl IsA<gtk::Widget>, action: Action) {
        self.controls.borrow_mut().push((w.clone().upcast(), action));
    }

    fn page_control(&self, w: &impl IsA<gtk::Widget>, action: Action) {
        self.page_controls.borrow_mut().push((w.clone().upcast(), action));
    }

    /// The only way the model changes: update, send its commands, render.
    pub fn dispatch(self: &Rc<Self>, msg: Msg) {
        self.dispatch_all(vec![msg]);
    }

    /// Several messages, then one render.
    pub fn dispatch_all(self: &Rc<Self>, msgs: Vec<Msg>) {
        if self.rendering.get() {
            return;
        }
        let mut rebuild = false;
        for msg in msgs {
            // Job progress, selections, the dialog and the notice leave the lists and the page as they are (focus
            // stays put).
            rebuild |= !matches!(
                msg,
                Msg::JobEvents(_)
                    | Msg::JobList(_)
                    | Msg::Accept(..)
                    | Msg::ConsentOpened
                    | Msg::ConsentClosed
                    | Msg::Refused(_)
                    | Msg::Dismiss
            );
            let cmds = self.model.borrow_mut().update(msg);
            for c in cmds {
                (self.send)(c);
            }
        }
        self.render(rebuild);
    }

    fn render(self: &Rc<Self>, rebuild: bool) {
        // A consent dialog the model closed (a new plan replaced the one it shows) goes away.
        if !self.model().consent_open() {
            let open = self.consent_dialog.borrow_mut().take();
            if let Some(d) = open {
                d.force_close();
            }
        }
        self.rendering.set(true);
        let m = self.model.borrow();
        let w = &self.w;
        let child = match m.conn() {
            Conn::Connecting => "connecting",
            Conn::Unreachable { socket } => {
                w.unreachable_socket.set_label(&format!("Socket: {socket}"));
                "unreachable"
            }
            Conn::Refused(why) => {
                w.refused_reason.set_label(why);
                "refused"
            }
            Conn::Ready { .. } => "main",
        };
        w.stack.set_visible_child_name(child);
        w.banner_read_only
            .set_revealed(matches!(m.conn(), Conn::Ready { write: false, .. }));
        w.banner_notice.set_title(m.notice().unwrap_or_default());
        w.banner_notice.set_revealed(m.notice().is_some());
        if rebuild {
            apps::render(self, &m);
            self.page_controls.borrow_mut().clear();
            *self.status.borrow_mut() = None;
            app::render(self, &m);
        }
        if let Some(s) = self.status.borrow().as_ref() {
            s.set_label(&m.page_status().unwrap_or_default());
        }
        jobs::render(self, &m);
        for (widget, action) in self.controls.borrow().iter().chain(self.page_controls.borrow().iter()) {
            let can = m.can(*action);
            widget.set_sensitive(can.is_ok());
            widget.set_tooltip_text(can.err());
        }
        drop(m);
        self.rendering.set(false);
    }
}
