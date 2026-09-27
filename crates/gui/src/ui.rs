//! The GTK widgets.
use libadwaita as adw;

/// The main window (empty for now); the caller attaches it to the application.
pub fn window() -> adw::ApplicationWindow {
    adw::ApplicationWindow::builder()
        .title("Windows apps")
        .default_width(960)
        .default_height(640)
        .build()
}
