//! The permissions editor (spec D9): typed choices only. Switches for network, display, audio and GPU, a folder
//! from the folder chooser, a remove button per grant, Reset. No free text; limits are shown, not edited.
use super::{Ui, text};
use crate::vm::{Action, Model, Msg, PermChange};
use gtk4 as gtk;
use gtk4::glib;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;
use std::rc::Rc;

pub fn group(ui: &Rc<Ui>, m: &Model) -> Option<adw::PreferencesGroup> {
    let perms = m.page_permissions()?;
    let g = adw::PreferencesGroup::builder().title("Permissions").build();
    let p = match perms {
        Ok(p) => p,
        Err(why) => {
            g.add(&text::row("Unavailable", &why));
            return Some(g);
        }
    };
    let weak = Rc::downgrade(ui);
    let switch = |name: &str, title: &str, on: bool, change: fn(bool) -> PermChange| {
        let row = adw::SwitchRow::builder().title(title).active(on).build();
        row.set_widget_name(name);
        let weak = weak.clone();
        row.connect_active_notify(move |r| {
            if let Some(ui) = weak.upgrade() {
                ui.dispatch(Msg::Permission(change(r.is_active())));
            }
        });
        ui.page_control(&row, Action::EditPermissions);
        g.add(&row);
    };
    switch("perm-network", "Network access", p.network, PermChange::Network);
    switch("perm-display", "Display", p.display, PermChange::Display);
    switch("perm-audio", "Audio", p.audio, PermChange::Audio);
    switch("perm-gpu", "GPU", p.gpu, PermChange::Gpu);
    for grant in p.grants {
        let row = text::row(&grant.shown, grant.access);
        let remove = gtk::Button::builder()
            .icon_name("list-remove-symbolic")
            .valign(gtk::Align::Center)
            .build();
        remove.add_css_class("flat");
        let (weak, path) = (weak.clone(), grant.path);
        remove.connect_clicked(move |_| {
            if let Some(ui) = weak.upgrade() {
                ui.dispatch(Msg::Permission(PermChange::Revoke(path.clone())));
            }
        });
        ui.page_control(&remove, Action::EditPermissions);
        row.add_suffix(&remove);
        g.add(&row);
    }
    let buttons = gtk::Box::new(gtk::Orientation::Horizontal, 6);
    buttons.set_margin_top(6);
    for (name, label, rw) in [
        ("perm-grant-ro", "Grant a folder (read-only)…", false),
        ("perm-grant-rw", "Grant a folder (read-write)…", true),
    ] {
        let b = gtk::Button::with_label(label);
        b.set_widget_name(name);
        let weak = weak.clone();
        b.connect_clicked(move |_| {
            let Some(ui) = weak.upgrade() else { return };
            let win = ui.w.window.clone();
            let weak = weak.clone();
            glib::spawn_future_local(async move {
                let d = gtk::FileDialog::builder().title("Choose a folder").modal(true).build();
                if let Ok(f) = d.select_folder_future(Some(&win)).await
                    && let Some(ui) = weak.upgrade()
                {
                    // The view model refuses a path it cannot grant safely (with a message).
                    ui.dispatch(match f.path() {
                        Some(path) => Msg::Permission(PermChange::Grant { path, rw }),
                        None => Msg::Refused(super::install::NOT_LOCAL),
                    });
                }
            });
        });
        ui.page_control(&b, Action::EditPermissions);
        buttons.append(&b);
    }
    let reset = gtk::Button::with_label("Reset to defaults");
    reset.set_widget_name("perm-reset");
    reset.add_css_class("destructive-action");
    let w = weak.clone();
    reset.connect_clicked(move |_| {
        if let Some(ui) = w.upgrade() {
            ui.dispatch(Msg::ResetPermissions);
        }
    });
    ui.page_control(&reset, Action::EditPermissions);
    buttons.append(&reset);
    g.add(&text::row("Limits", &p.limits));
    if let Some(r) = &p.requested {
        let l = text::label(r);
        l.set_widget_name("perm-requested");
        l.add_css_class("dim-label");
        g.add(&l);
    }
    let outer = gtk::Box::new(gtk::Orientation::Vertical, 0);
    outer.append(&buttons);
    // A group takes rows; the buttons go under it.
    g.add(&outer);
    Some(g)
}
