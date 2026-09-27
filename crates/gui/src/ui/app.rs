//! The app page (spec 3): Run / Stop / Remove, the doctor, graphics and sandbox views, permissions, dependencies.
use super::{Ui, consent, permissions, text};
use crate::vm::{Action, Model, Msg};
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::rc::Rc;

fn button(ui: &Rc<Ui>, name: &str, label: &str, action: Action, msg: impl Fn(&Rc<Ui>) + 'static) -> gtk::Button {
    let b = gtk::Button::with_label(label);
    b.set_widget_name(name);
    let weak = Rc::downgrade(ui);
    b.connect_clicked(move |_| {
        if let Some(ui) = weak.upgrade() {
            msg(&ui);
        }
    });
    ui.page_control(&b, action);
    b
}

pub fn render(ui: &Rc<Ui>, m: &Model) {
    let page = &ui.w.page;
    while let Some(c) = page.first_child() {
        page.remove(&c);
    }
    let Some(p) = m.page() else {
        ui.w.page_nav.set_title("App");
        page.append(
            &adw::StatusPage::builder()
                .icon_name("application-x-executable-symbolic")
                .title("Choose an app")
                .vexpand(true)
                .build(),
        );
        return;
    };
    let title = p.title();
    ui.w.page_nav.set_title(&title);
    let heading = text::label(&title);
    heading.add_css_class("title-1");
    page.append(&heading);
    let status = text::label("");
    status.add_css_class("dim-label");
    page.append(&status);
    *ui.status.borrow_mut() = Some(status);

    let actions = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    let run = button(ui, "btn-run", "Run", Action::Run, |ui| ui.dispatch(Msg::Run));
    run.add_css_class("suggested-action");
    actions.append(&run);
    actions.append(&button(ui, "btn-stop", "Stop", Action::Stop, |ui| {
        ui.dispatch(Msg::Stop)
    }));
    let remove = button(ui, "btn-remove", "Remove…", Action::Remove, confirm_remove);
    remove.add_css_class("destructive-action");
    actions.append(&remove);
    page.append(&actions);
    if p.data().is_none() {
        page.append(&text::label("Loading…"));
        return;
    }

    for (name, lines) in m.page_sections() {
        let g = adw::PreferencesGroup::builder().title(name).build();
        for l in lines {
            g.add(&text::row(&l.title, &l.detail));
        }
        page.append(&g);
    }
    if let Some(g) = permissions::group(ui, m) {
        page.append(&g);
    }

    let deps = adw::PreferencesGroup::builder().title("Dependencies").build();
    match m.consent() {
        None => deps.add(&text::row("Not planned yet", "Plan to see what this app needs")),
        Some(c) if c.nothing_to_install() => deps.add(&text::row("Nothing to install", "")),
        Some(c) => {
            for e in c.entries() {
                let note = e.note.as_deref().map(|n| format!(": {n}")).unwrap_or_default();
                deps.add(&text::row(
                    &format!("{} {}", e.package, e.version),
                    &format!("{}{note}", e.action),
                ));
            }
        }
    }
    let row = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    row.set_margin_top(6);
    row.append(&button(ui, "btn-plan", "Plan", Action::Plan, |ui| {
        ui.dispatch(Msg::Plan)
    }));
    row.append(&button(
        ui,
        "btn-deps",
        "Install dependencies…",
        Action::InstallDeps,
        open_consent,
    ));
    deps.add(&row);
    page.append(&deps);
}

fn confirm_remove(ui: &Rc<Ui>) {
    let (title, id) = {
        let m = ui.model();
        let Some(p) = m.page() else { return };
        (p.title(), crate::vm::shown(p.id(), crate::vm::TEXT_MAX))
    };
    let d = adw::AlertDialog::builder()
        .heading("Remove this app?")
        .body(format!(
            "This deletes {title} (app id {id}), its Wine prefix and everything installed into it. It cannot be undone."
        ))
        .build();
    d.set_heading_use_markup(false);
    d.set_body_use_markup(false);
    d.set_widget_name("remove-dialog");
    d.add_responses(&[("cancel", "Cancel"), ("remove", "Remove")]);
    d.set_response_appearance("remove", adw::ResponseAppearance::Destructive);
    d.set_default_response(Some("cancel"));
    d.set_close_response("cancel");
    let weak = Rc::downgrade(ui);
    d.connect_response(None, move |_, r| {
        if let (Some(ui), "remove") = (weak.upgrade(), r) {
            ui.dispatch(Msg::Remove);
        }
    });
    d.present(Some(&ui.w.window));
}

fn open_consent(ui: &Rc<Ui>) {
    // Every choice starts unaccepted, whatever happened in an earlier dialog.
    ui.dispatch(Msg::ConsentOpened);
    let (d, checks) = {
        let m = ui.model();
        let Some(c) = m.consent().filter(|_| m.consent_open()) else {
            return;
        };
        consent::dialog(c)
    };
    for (package, check) in checks {
        let (weak, d2) = (Rc::downgrade(ui), d.clone());
        check.connect_toggled(move |c| {
            let Some(ui) = weak.upgrade() else { return };
            ui.dispatch(Msg::Accept(package.clone(), c.is_active()));
            if let Some(label) = ui.model().consent().map(|c| c.install_label()) {
                d2.set_response_label("install", &label);
            }
        });
    }
    let weak = Rc::downgrade(ui);
    d.connect_response(None, move |_, r| {
        let Some(ui) = weak.upgrade() else { return };
        ui.consent_dialog.borrow_mut().take();
        // Anything but Install (Cancel, Escape, closing) resets every choice.
        ui.dispatch(if r == "install" {
            Msg::InstallDeps
        } else {
            Msg::ConsentClosed
        });
    });
    *ui.consent_dialog.borrow_mut() = Some(d.clone());
    d.present(Some(&ui.w.window));
}
