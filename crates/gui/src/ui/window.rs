//! The main window's widgets (spec 3). Widget names (`set_widget_name`) are stable test handles.
use super::text;
use crate::vm::{READ_ONLY, START_HINT};
use gtk4 as gtk;
use gtk4::prelude::*;
use libadwaita as adw;
use libadwaita::prelude::*;

pub struct Widgets {
    pub window: adw::ApplicationWindow,
    /// `connecting`, `unreachable`, `refused` or `main`.
    pub stack: gtk::Stack,
    pub unreachable_socket: gtk::Label,
    pub refused_reason: gtk::Label,
    pub retry: [gtk::Button; 2],
    pub banner_read_only: adw::Banner,
    pub banner_notice: adw::Banner,
    pub btn_install: gtk::Button,
    pub btn_install_empty: gtk::Button,
    pub btn_jobs: gtk::ToggleButton,
    pub split: adw::NavigationSplitView,
    pub search: gtk::SearchEntry,
    pub apps_list: gtk::ListBox,
    pub apps_scroll: gtk::ScrolledWindow,
    pub apps_empty: adw::StatusPage,
    pub apps_note: gtk::Label,
    /// The content page's box, rebuilt from the model.
    pub page: gtk::Box,
    pub page_nav: adw::NavigationPage,
    pub jobs_panel: gtk::Revealer,
    pub jobs_box: gtk::Box,
}

fn named<W: IsA<gtk::Widget>>(w: W, name: &str) -> W {
    w.set_widget_name(name);
    w
}

fn status(name: &str, icon: &str, title: &str, description: &str, child: &gtk::Box) -> adw::StatusPage {
    named(
        adw::StatusPage::builder()
            .icon_name(icon)
            .title(title)
            // Always markup: fixed text, escaped anyway.
            .description(text::escaped(description))
            .child(child)
            .build(),
        name,
    )
}

fn vbox() -> gtk::Box {
    gtk::Box::builder()
        .orientation(gtk::Orientation::Vertical)
        .spacing(12)
        .build()
}

pub fn build() -> Widgets {
    let window = adw::ApplicationWindow::builder()
        .title("Windows apps")
        .default_width(960)
        .default_height(680)
        .build();
    // The status pages.
    let retry = [gtk::Button::with_label("Retry"), gtk::Button::with_label("Retry")];
    for r in &retry {
        r.add_css_class("pill");
        r.set_halign(gtk::Align::Center);
    }
    let hint = text::selectable(START_HINT);
    hint.add_css_class("monospace");
    hint.set_xalign(0.5);
    let unreachable_socket = text::selectable("");
    unreachable_socket.set_xalign(0.5);
    let b = vbox();
    b.append(&hint);
    b.append(&unreachable_socket);
    b.append(&retry[0]);
    let unreachable = status(
        "status-unreachable",
        "network-offline-symbolic",
        "runtimed is not running",
        "Start it with the command below (or enable runtimed.socket), then Retry. This app never starts it for you.",
        &b,
    );
    let refused_reason = text::selectable("");
    refused_reason.set_xalign(0.5);
    let b = vbox();
    b.append(&refused_reason);
    b.append(&retry[1]);
    let refused = status(
        "status-refused",
        "dialog-warning-symbolic",
        "The runtimed socket was refused",
        "The socket is not one this user's runtimed would create (wrong owner or permissions). Nothing was sent to it.",
        &b,
    );
    let connecting = adw::StatusPage::builder().title("Connecting to runtimed…").build();

    // The sidebar.
    let search = gtk::SearchEntry::builder().placeholder_text("Search apps").build();
    let apps_list = named(gtk::ListBox::new(), "apps-list");
    apps_list.add_css_class("navigation-sidebar");
    let apps_scroll = gtk::ScrolledWindow::builder()
        .child(&apps_list)
        .vexpand(true)
        .hscrollbar_policy(gtk::PolicyType::Never)
        .build();
    let btn_install_empty = named(gtk::Button::with_label("Install a program…"), "btn-install-empty");
    btn_install_empty.add_css_class("pill");
    btn_install_empty.set_halign(gtk::Align::Center);
    let apps_empty = adw::StatusPage::builder()
        .icon_name("application-x-executable-symbolic")
        .title("No apps installed")
        .child(&btn_install_empty)
        .vexpand(true)
        .build();
    let apps_note = text::label("");
    apps_note.add_css_class("dim-label");
    apps_note.set_visible(false);
    let side = vbox();
    side.set_margin_top(6);
    side.set_margin_start(6);
    side.set_margin_end(6);
    side.append(&search);
    side.append(&apps_scroll);
    side.append(&apps_empty);
    side.append(&apps_note);
    let sidebar = adw::NavigationPage::builder().title("Apps").child(&side).build();

    // The content.
    let page = vbox();
    page.set_margin_top(18);
    page.set_margin_bottom(18);
    page.set_margin_start(18);
    page.set_margin_end(18);
    let clamp = adw::Clamp::builder().maximum_size(760).child(&page).build();
    let page_nav = adw::NavigationPage::builder()
        .title("App")
        .child(&gtk::ScrolledWindow::builder().child(&clamp).build())
        .build();
    let split = adw::NavigationSplitView::builder()
        .sidebar(&sidebar)
        .content(&page_nav)
        .vexpand(true)
        .build();

    // The jobs panel.
    let jobs_box = vbox();
    jobs_box.set_margin_start(12);
    jobs_box.set_margin_end(12);
    jobs_box.set_margin_bottom(12);
    let jobs_panel = named(
        gtk::Revealer::builder()
            .child(&jobs_box)
            .transition_type(gtk::RevealerTransitionType::SlideUp)
            .build(),
        "jobs-panel",
    );
    let main = gtk::Box::new(gtk::Orientation::Vertical, 0);
    main.append(&split);
    main.append(&gtk::Separator::new(gtk::Orientation::Horizontal));
    main.append(&jobs_panel);

    let stack = gtk::Stack::new();
    stack.add_named(&connecting, Some("connecting"));
    stack.add_named(&unreachable, Some("unreachable"));
    stack.add_named(&refused, Some("refused"));
    stack.add_named(&main, Some("main"));

    // Header and banners.
    let btn_install = named(gtk::Button::with_label("Install…"), "btn-install");
    btn_install.add_css_class("suggested-action");
    let btn_jobs = named(gtk::ToggleButton::with_label("Jobs"), "btn-jobs");
    let menu = gtk4::gio::Menu::new();
    menu.append(Some("Refresh"), Some("win.refresh"));
    menu.append(Some("About"), Some("win.about"));
    let menu_btn = gtk::MenuButton::builder()
        .icon_name("open-menu-symbolic")
        .menu_model(&menu)
        .tooltip_text("Menu")
        .build();
    let header = adw::HeaderBar::new();
    header.pack_start(&btn_install);
    header.pack_end(&menu_btn);
    header.pack_end(&btn_jobs);
    let banner_read_only = named(adw::Banner::new(READ_ONLY), "banner-read-only");
    banner_read_only.set_use_markup(false);
    let banner_notice = named(adw::Banner::new(""), "banner-notice");
    banner_notice.set_use_markup(false);
    banner_notice.set_button_label(Some("Dismiss"));
    let view = adw::ToolbarView::new();
    view.add_top_bar(&header);
    view.add_top_bar(&banner_read_only);
    view.add_top_bar(&banner_notice);
    view.set_content(Some(&stack));
    window.set_content(Some(&view));
    // A narrow window shows one pane at a time.
    let bp = adw::Breakpoint::new(adw::BreakpointCondition::parse("max-width: 600sp").expect("a valid condition"));
    bp.add_setter(&split, "collapsed", Some(&true.to_value()));
    window.add_breakpoint(bp);

    Widgets {
        window,
        stack,
        unreachable_socket,
        refused_reason,
        retry,
        banner_read_only,
        banner_notice,
        btn_install,
        btn_install_empty,
        btn_jobs,
        split,
        search,
        apps_list,
        apps_scroll,
        apps_empty,
        apps_note,
        page,
        page_nav,
        jobs_panel,
        jobs_box,
    }
}
