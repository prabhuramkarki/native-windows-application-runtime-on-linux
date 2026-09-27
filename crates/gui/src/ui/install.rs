//! The install dialog (spec D10): a file from the file chooser, an optional name, silent and network both off. The
//! result goes to the view model as `Msg::Install`, which validates it before anything is sent.
use super::{Ui, text};
use crate::vm::{InstallForm, MAX_SHOWN, Msg, shown};
use gtk4 as gtk;
use gtk4::prelude::*;
use gtk4::{gio, glib};
use libadwaita as adw;
use libadwaita::prelude::*;
use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

fn file_dialog() -> gtk::FileDialog {
    let programs = gtk::FileFilter::new();
    programs.set_name(Some("Windows programs and installers (.exe, .msi, .zip)"));
    for s in ["exe", "msi", "zip"] {
        programs.add_suffix(s);
    }
    let all = gtk::FileFilter::new();
    all.set_name(Some("All files"));
    all.add_pattern("*");
    let filters = gio::ListStore::new::<gtk::FileFilter>();
    filters.append(&programs);
    filters.append(&all);
    gtk::FileDialog::builder()
        .title("Choose a program or installer")
        .modal(true)
        .filters(&filters)
        .default_filter(&programs)
        .build()
}

/// A chosen file or folder with no local path (a remote gvfs location).
pub const NOT_LOCAL: &str = "That is not a local file or folder (copy it to this computer first).";

pub fn open(ui: &Rc<Ui>) {
    let d = adw::AlertDialog::builder().heading("Install a program").build();
    d.set_heading_use_markup(false);
    d.set_widget_name("install-dialog");
    let path: Rc<RefCell<Option<PathBuf>>> = Rc::default();
    let chosen = text::label("No file chosen");
    let choose = gtk::Button::with_label("Choose a file…");
    let name = gtk::Entry::builder().placeholder_text("Name (optional)").build();
    let group = adw::PreferencesGroup::new();
    let silent = adw::SwitchRow::builder().title("Silent install").build();
    silent.set_widget_name("install-silent");
    let network = adw::SwitchRow::builder()
        .title("Network access")
        .subtitle("gives the installer network access")
        .build();
    network.set_widget_name("install-network");
    group.add(&silent);
    group.add(&network);
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 12);
    bx.append(&choose);
    bx.append(&chosen);
    bx.append(&name);
    bx.append(&group);
    d.set_extra_child(Some(&bx));
    d.add_responses(&[("cancel", "Cancel"), ("install", "Install")]);
    d.set_response_appearance("install", adw::ResponseAppearance::Suggested);
    d.set_response_enabled("install", false);
    d.set_default_response(Some("cancel"));
    d.set_close_response("cancel");
    let win = ui.w.window.clone();
    let (p, dd, weak) = (path.clone(), d.clone(), Rc::downgrade(ui));
    choose.connect_clicked(move |_| {
        let (p, dd, chosen, win) = (p.clone(), dd.clone(), chosen.clone(), win.clone());
        let weak = weak.clone();
        glib::spawn_future_local(async move {
            let Ok(file) = file_dialog().open_future(Some(&win)).await else {
                return;
            };
            match file.path() {
                Some(f) => {
                    chosen.set_label(&shown(&f.to_string_lossy(), MAX_SHOWN));
                    *p.borrow_mut() = Some(f);
                    dd.set_response_enabled("install", true);
                }
                None => {
                    if let Some(ui) = weak.upgrade() {
                        ui.dispatch(Msg::Refused(NOT_LOCAL));
                    }
                }
            }
        });
    });
    let weak = Rc::downgrade(ui);
    d.connect_response(None, move |_, r| {
        let (Some(ui), "install") = (weak.upgrade(), r) else {
            return;
        };
        let Some(path) = path.borrow().clone() else { return };
        ui.dispatch(Msg::Install(InstallForm {
            path,
            name: name.text().to_string(),
            silent: silent.is_active(),
            network: network.is_active(),
        }));
    });
    d.present(Some(&ui.w.window));
}
