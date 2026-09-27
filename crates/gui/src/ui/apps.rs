//! The sidebar: the apps, filtered by the search, and the empty state.
use super::Ui;
use super::text;
use crate::vm::Model;
use gtk4::prelude::*;
use std::rc::Rc;

pub fn render(ui: &Rc<Ui>, m: &Model) {
    let w = &ui.w;
    w.apps_list.remove_all();
    let rows = m.visible_apps();
    for r in &rows {
        let row = text::row(&r.title, &r.subtitle);
        row.set_activatable(true);
        w.apps_list.append(&row);
        if m.page().is_some_and(|p| p.id() == r.id) {
            w.apps_list.select_row(Some(&row));
        }
    }
    *ui.app_ids.borrow_mut() = rows.into_iter().map(|r| r.id).collect();
    let none = ui.app_ids.borrow().is_empty();
    w.apps_empty.set_visible(none);
    w.apps_scroll.set_visible(!none);
    w.apps_empty.set_title(if w.search.text().is_empty() {
        "No apps installed"
    } else {
        "No app matches"
    });
    match m.apps_note() {
        Some(n) => {
            w.apps_note.set_label(&n);
            w.apps_note.set_visible(true);
        }
        None => w.apps_note.set_visible(false),
    }
}
