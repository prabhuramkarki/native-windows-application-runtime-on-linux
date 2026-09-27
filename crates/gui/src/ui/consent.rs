//! The consent dialog (spec 3, 5.3): each consent-gated package with its version, sha256 and full terms, and its own
//! unchecked box; no "accept all". Everything shown is the model's cleaned text, as plain labels.
use super::text;
use crate::vm::ConsentState;
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

/// The dialog and, per acceptable package, its checkbox.
pub fn dialog(c: &ConsentState) -> (adw::AlertDialog, Vec<(String, gtk::CheckButton)>) {
    let d = adw::AlertDialog::builder()
        .heading("Install dependencies")
        .body(if c.nothing_to_install() {
            "Nothing to install."
        } else {
            "Packages that need your consent are listed with their terms. Nothing is accepted until you tick its \
             own box; a package you do not accept is not installed."
        })
        .build();
    d.set_heading_use_markup(false);
    d.set_body_use_markup(false);
    d.set_widget_name("consent-dialog");
    let bx = gtk::Box::new(gtk::Orientation::Vertical, 12);
    let mut checks = vec![];
    for ch in c.choices() {
        let head = text::label(&format!("{} {}", ch.package, ch.version));
        head.add_css_class("heading");
        bx.append(&head);
        let sha = text::selectable(&format!("sha256 {}", ch.sha256));
        sha.add_css_class("monospace");
        bx.append(&sha);
        let terms = text::selectable(&ch.text.join("\n"));
        terms.set_widget_name(&format!("consent-text-{}", ch.package));
        bx.append(
            &gtk::ScrolledWindow::builder()
                .child(&terms)
                .max_content_height(240)
                .propagate_natural_height(true)
                .hscrollbar_policy(gtk::PolicyType::Never)
                .build(),
        );
        match ch.unacceptable() {
            Some(why) => {
                let l = text::label(&format!("This package cannot be accepted: {why}."));
                l.add_css_class("error");
                bx.append(&l);
            }
            None => {
                // Plain text (a check button's label is never markup), unchecked.
                let check = gtk::CheckButton::with_label(&format!(
                    "I accept the terms above for {} {}",
                    ch.package, ch.version
                ));
                check.set_active(false);
                check.set_widget_name(&format!("consent-check-{}", ch.package));
                bx.append(&check);
                checks.push((ch.package.clone(), check));
            }
        }
        bx.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    }
    if !c.nothing_to_install() {
        let plan = text::label("The whole plan:");
        plan.add_css_class("heading");
        bx.append(&plan);
        for e in c.entries() {
            let note = e.note.as_ref().map(|n| format!(" ({n})")).unwrap_or_default();
            bx.append(&text::label(&format!(
                "{} {}: {}{note}",
                e.package, e.version, e.action
            )));
        }
    }
    if !c.unsatisfied.is_empty() {
        bx.append(&text::label(&format!(
            "Not provided by any bundled package: {}",
            c.unsatisfied.join(", ")
        )));
    }
    for w in &c.warnings {
        bx.append(&text::label(&format!("Warning: {w}")));
    }
    d.set_extra_child(Some(
        &gtk::ScrolledWindow::builder()
            .child(&bx)
            .max_content_height(480)
            .propagate_natural_height(true)
            .hscrollbar_policy(gtk::PolicyType::Never)
            .build(),
    ));
    d.add_responses(&[("cancel", "Cancel"), ("install", &c.install_label())]);
    d.set_response_appearance("install", adw::ResponseAppearance::Suggested);
    d.set_default_response(Some("cancel"));
    d.set_close_response("cancel");
    (d, checks)
}
