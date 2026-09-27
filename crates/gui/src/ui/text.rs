//! Markup-safe text (spec 5.4): daemon strings are shown as plain text, never parsed as Pango markup. Labels and rows
//! get `use-markup` off (`AdwPreferencesRow` defaults it ON); a property that is always markup gets [`escaped`].
use crate::vm::{MAX_SHOWN, shown};
use gtk4 as gtk;
use gtk4::glib;
use libadwaita as adw;
use libadwaita::prelude::*;

/// A plain, wrapping, left-aligned label.
pub fn label(s: &str) -> gtk::Label {
    gtk::Label::builder()
        .label(s)
        .use_markup(false)
        .wrap(true)
        .wrap_mode(gtk::pango::WrapMode::WordChar)
        .xalign(0.0)
        .build()
}

/// A plain label the user can select and copy.
pub fn selectable(s: &str) -> gtk::Label {
    let l = label(s);
    l.set_selectable(true);
    l
}

/// An action row whose title and subtitle are plain text.
pub fn row(title: &str, subtitle: &str) -> adw::ActionRow {
    let r = adw::ActionRow::new();
    r.set_use_markup(false);
    r.set_title(title);
    r.set_subtitle(subtitle);
    r
}

/// `s` cleaned, bounded and markup-escaped: for properties that are always parsed as markup.
pub fn escaped(s: &str) -> String {
    glib::markup_escape_text(&shown(s, MAX_SHOWN)).to_string()
}
