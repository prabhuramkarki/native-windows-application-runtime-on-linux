//! Per-package consent (spec 5.3): one choice per `install` + `needed` entry of a `deps.plan`, never accepted until
//! the user accepts that entry, and a `deps.install` built only from the plan's own digest and accepted entries.
use super::{TEXT_MAX, shown};
use rt_api::jobs::ConsentItem;
use rt_api::{ConsentView, DepsPlanView, PlanAction};

/// The longest consent text line shown (the daemon's own bound).
const LINE_MAX: usize = 4096;

/// One consent-gated package of the plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentChoice {
    /// Exactly what `deps.plan` said: what is sent back when accepted.
    raw: ConsentItem,
    /// Cleaned, for display.
    pub package: String,
    pub version: String,
    pub sha256: String,
    /// The full consent text, one cleaned line each.
    pub text: Vec<String>,
    accepted: bool,
    unacceptable: Option<&'static str>,
}

impl ConsentChoice {
    pub fn accepted(&self) -> bool {
        self.accepted
    }
    /// Why this entry can never be accepted (`None`: it can).
    pub fn unacceptable(&self) -> Option<&'static str> {
        self.unacceptable
    }
}

/// Any entry of the plan, for the list (cleaned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRow {
    pub package: String,
    pub version: String,
    /// `install`, `already installed`, `blocked`.
    pub action: &'static str,
    /// The blocked reason, or that consent was denied.
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentState {
    app: String,
    /// `deps.plan`'s digest, untouched.
    digest: String,
    choices: Vec<ConsentChoice>,
    entries: Vec<EntryRow>,
    pub unsatisfied: Vec<String>,
    pub warnings: Vec<String>,
}

impl ConsentState {
    pub(crate) fn new(app: String, plan: DepsPlanView) -> ConsentState {
        let mut choices: Vec<ConsentChoice> = vec![];
        for e in plan
            .entries
            .iter()
            .filter(|e| e.action == PlanAction::Install && e.consent == ConsentView::Needed)
        {
            let (version, sha256) = (
                e.version.clone().unwrap_or_default(),
                e.sha256.clone().unwrap_or_default(),
            );
            let text = e.consent_text.clone().unwrap_or_default();
            let mut c = ConsentChoice {
                package: shown(&e.package, TEXT_MAX),
                version: shown(&version, TEXT_MAX),
                sha256: shown(&sha256, TEXT_MAX),
                text: text.iter().map(|l| shown(l, LINE_MAX)).collect(),
                raw: ConsentItem {
                    package: e.package.clone(),
                    version,
                    sha256,
                },
                accepted: false,
                unacceptable: None,
            };
            c.unacceptable = if e.version.is_none() || e.sha256.is_none() || text.is_empty() {
                Some("the plan does not give this package's version, checksum or terms")
            } else if c.package != c.raw.package || c.version != c.raw.version || c.sha256 != c.raw.sha256 {
                // What would be sent is not what is shown.
                Some("this entry has characters that cannot be shown")
            } else {
                None
            };
            if let Some(twin) = choices.iter_mut().find(|o| o.raw.package == c.raw.package) {
                twin.unacceptable = Some("the plan lists this package more than once");
                c.unacceptable = twin.unacceptable;
            }
            choices.push(c);
        }
        let entries = plan
            .entries
            .iter()
            .map(|e| EntryRow {
                package: shown(&e.package, TEXT_MAX),
                version: shown(e.version.as_deref().unwrap_or("-"), TEXT_MAX),
                action: match e.action {
                    PlanAction::Install => "install",
                    PlanAction::AlreadyInstalled => "already installed",
                    _ => "blocked",
                },
                note: match (&e.blocked_reason, e.consent) {
                    (Some(r), _) => Some(shown(r, super::MAX_SHOWN)),
                    (None, ConsentView::Denied) => Some("consent denied".to_owned()),
                    _ => None,
                },
            })
            .collect();
        ConsentState {
            app,
            digest: plan.digest,
            choices,
            entries,
            unsatisfied: plan.unsatisfied.iter().map(|u| shown(u, TEXT_MAX)).collect(),
            warnings: plan.warnings.iter().map(|w| shown(w, super::MAX_SHOWN)).collect(),
        }
    }

    /// The plan's digest as `deps.plan` gave it (a dialog checks it still shows this plan).
    pub fn digest(&self) -> &str {
        &self.digest
    }
    /// The app the plan is for (raw id).
    pub fn app(&self) -> &str {
        &self.app
    }
    pub fn choices(&self) -> &[ConsentChoice] {
        &self.choices
    }
    pub fn entries(&self) -> &[EntryRow] {
        &self.entries
    }
    /// The plan has no entry at all.
    pub fn nothing_to_install(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn accepted_count(&self) -> usize {
        self.choices.iter().filter(|c| c.accepted).count()
    }
    /// "Install (1 of 2 accepted)", or "Install" when nothing needs consent.
    pub fn install_label(&self) -> String {
        match self.choices.len() {
            0 => "Install".to_owned(),
            n => format!("Install ({} of {n} accepted)", self.accepted_count()),
        }
    }
    /// A 0.1 daemon's plan: it has no digest and cannot be installed.
    pub(crate) fn digest_missing(&self) -> bool {
        self.digest.is_empty()
    }

    /// Flips only the entry named `package`, if it can be accepted.
    pub(crate) fn accept(&mut self, package: &str, yes: bool) {
        if let Some(c) = self
            .choices
            .iter_mut()
            .find(|c| c.raw.package == package && c.unacceptable.is_none())
        {
            c.accepted = yes;
        }
    }

    /// Every choice back to not accepted.
    pub(crate) fn reset(&mut self) {
        for c in &mut self.choices {
            c.accepted = false;
        }
    }

    /// The digest and the accepted entries, exactly as the plan gave them.
    pub(crate) fn into_install(self) -> (String, String, Vec<ConsentItem>) {
        let consent = self
            .choices
            .into_iter()
            .filter(|c| c.accepted && c.unacceptable.is_none())
            .map(|c| c.raw)
            .collect();
        (self.app, self.digest, consent)
    }
}
