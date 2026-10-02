//! The backend registry: a recorded `backend.id` mapped to a backend compiled into this workspace. There are no
//! plugins (see `rt_core::backend`): a backend is a Rust type added here by a reviewed change. Test doubles
//! (`FakeBackend`, the conformance suite's null backend) are never listed, so none reaches a release build.
use rt_core::{BackendError, Capabilities, CompatBackend, Detail, Launcher, clean_text};

/// The ids [`select`] knows.
pub const KNOWN: &[&str] = &["wine"];
/// The backend of new installs. There is no user-facing choice while [`KNOWN`] has one entry.
pub const DEFAULT: &str = "wine";

/// The backend with `id`, its helpers run with `launcher`. An unknown id is `Unavailable` naming it (cleaned) and
/// the known ones: an app recorded for another backend is refused, never run with Wine.
pub fn select(id: &str, launcher: &Launcher) -> Result<Box<dyn CompatBackend>, BackendError> {
    match id {
        "wine" => Ok(Box::new(backend_wine::WineBackend::discover_with(launcher.clone())?)),
        other => Err(unknown(other)),
    }
}

/// The refusal of an id that is not in [`KNOWN`]: `Unavailable` naming it (cleaned, bounded) and the known ones.
pub fn unknown(id: &str) -> BackendError {
    BackendError::Unavailable(Detail::from_bytes(
        format!(
            "unknown compatibility backend \"{}\" (known: {})",
            clean_text(id, 64),
            KNOWN.join(", ")
        )
        .as_bytes(),
    ))
}

/// The capabilities of a known backend id, without discovering or starting it; `None` for an unknown id. For a
/// check that must work when the backend is not installed (`runtime display`'s read path).
pub fn capabilities(id: &str) -> Option<Capabilities> {
    match id {
        "wine" => Some(backend_wine::CAPABILITIES),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unknown_id_is_unavailable_with_a_cleaned_message_listing_the_known_ones() {
        let l = Launcher::with_host_env([("PATH", "/nonexistent")]);
        for (id, shown) in [
            ("nope", "\"nope\""),
            ("null", "\"null\""),
            ("fake", "\"fake\""),
            ("\u{1b}[31m", "\"[31m\""),
            ("Wine", "\"Wine\""),
            ("", "\"\""),
        ] {
            let e = select(id, &l).err().unwrap_or_else(|| panic!("{id:?} was selected"));
            let text = e.to_string();
            assert!(matches!(e, BackendError::Unavailable(_)), "{e:?}");
            assert!(text.contains(shown) && text.ends_with("(known: wine)"), "{text}");
            assert!(!text.chars().any(char::is_control), "{text:?}");
        }
        let long = "x".repeat(10_000);
        assert!(select(&long, &l).err().unwrap().to_string().len() < 200);
    }

    #[test]
    fn capabilities_map_a_known_id_without_discovering_it() {
        assert_eq!(capabilities("wine"), Some(backend_wine::CAPABILITIES));
        for id in ["null", "fake", "Wine", ""] {
            assert_eq!(capabilities(id), None, "{id:?}");
        }
        for id in KNOWN {
            assert!(capabilities(id).is_some(), "{id}");
        }
    }

    #[test]
    fn the_default_is_known() {
        assert!(KNOWN.contains(&DEFAULT));
    }
}
