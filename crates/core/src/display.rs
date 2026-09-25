//! The Wine graphics driver setting (`HKCU\Software\Wine\Drivers`, value `Graphics`): the pure types. Reading
//! it out of `user.reg` is `rt_deps::wine_config::read_graphics_driver`, which goes through the one registry
//! parser (`rt_installer::reg::WineReg`) so it cannot disagree with it. `rt_core` cannot depend on the installer.
use crate::text::clean;

/// The key as `reg.exe` takes it.
pub const DRIVERS_KEY: &str = r"HKCU\Software\Wine\Drivers";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GraphicsDriver {
    Auto,
    X11,
    Wayland,
    /// Anything else Wine holds (`x11,wayland`, an empty string, a driver we do not know); `clean(value, 60)`.
    Custom(String),
}

impl GraphicsDriver {
    /// Only the three words we offer, exactly as written (lowercase, no surrounding space).
    pub fn parse_choice(s: &str) -> Option<GraphicsDriver> {
        match s {
            "auto" => Some(GraphicsDriver::Auto),
            "x11" => Some(GraphicsDriver::X11),
            "wayland" => Some(GraphicsDriver::Wayland),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            GraphicsDriver::Auto => "auto",
            GraphicsDriver::X11 => "x11",
            GraphicsDriver::Wayland => "wayland",
            GraphicsDriver::Custom(s) => s,
        }
    }
}

/// The driver a `Graphics` value names: none is `Auto` (Wine picks itself), `x11`/`wayland` exactly, anything
/// else (`x11,wayland`, empty, an unknown driver) is `Custom(clean(v, 60))`. The value is untrusted.
pub fn driver_from_value(v: Option<&str>) -> GraphicsDriver {
    match v {
        None => GraphicsDriver::Auto,
        Some("x11") => GraphicsDriver::X11,
        Some("wayland") => GraphicsDriver::Wayland,
        Some(v) => GraphicsDriver::Custom(clean(v, 60)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_map_to_drivers() {
        assert_eq!(driver_from_value(None), GraphicsDriver::Auto);
        assert_eq!(driver_from_value(Some("x11")), GraphicsDriver::X11);
        assert_eq!(driver_from_value(Some("wayland")), GraphicsDriver::Wayland);
        let c = |s: &str| GraphicsDriver::Custom(s.into());
        assert_eq!(driver_from_value(Some("x11,wayland")), c("x11,wayland"));
        assert_eq!(driver_from_value(Some("")), c(""));
        assert_eq!(driver_from_value(Some("X11")), c("X11"));
        assert_eq!(driver_from_value(Some("x\n\x1b[31m\u{202e}y")), c("x[31my"));
        match driver_from_value(Some(&"a".repeat(10_000))) {
            GraphicsDriver::Custom(s) => assert!(!s.is_empty() && s.len() <= 60),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn parse_choice_is_exact() {
        assert_eq!(GraphicsDriver::parse_choice("auto"), Some(GraphicsDriver::Auto));
        assert_eq!(GraphicsDriver::parse_choice("x11"), Some(GraphicsDriver::X11));
        assert_eq!(GraphicsDriver::parse_choice("wayland"), Some(GraphicsDriver::Wayland));
        for s in ["X11", " x11", "auto\n", "", "x11,wayland"] {
            assert_eq!(GraphicsDriver::parse_choice(s), None, "{s:?}");
        }
        assert_eq!(GraphicsDriver::X11.as_str(), "x11");
        assert_eq!(GraphicsDriver::Custom("q".into()).as_str(), "q");
        assert_eq!(DRIVERS_KEY, r"HKCU\Software\Wine\Drivers");
    }
}
