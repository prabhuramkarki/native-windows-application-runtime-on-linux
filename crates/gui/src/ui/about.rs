//! About: this GUI's version and the daemon it talks to.
use crate::vm::{Conn, Model};
use gtk4::glib;
use libadwaita as adw;

pub fn dialog(m: &Model, socket: &str) -> adw::AboutDialog {
    let daemon = match m.conn() {
        Conn::Ready { write, api, runtime } => format!(
            "runtimed: API {api}, runtime {runtime}, {}",
            if *write { "write mode" } else { "read-only" }
        ),
        _ => "runtimed: not connected".to_owned(),
    };
    // `comments` is Pango markup: every part is already cleaned, and escaped here.
    let comments = glib::markup_escape_text(&format!("A desktop client of runtimed.\n{daemon}\nSocket: {socket}"));
    adw::AboutDialog::builder()
        .application_name("runtime-gui")
        .application_icon("application-x-executable")
        .version(env!("CARGO_PKG_VERSION"))
        .comments(comments.as_str())
        .build()
}
