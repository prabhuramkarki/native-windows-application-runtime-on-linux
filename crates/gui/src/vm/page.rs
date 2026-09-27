//! The open app, display-ready: every daemon string cleaned, every failed probe a sentence.
use super::{AppData, MAX_SHOWN, Model, TEXT_MAX, error_text, shown};
use rt_api::{AccessView, Availability, NetworkView, PermissionsView, VulkanState};
use rt_daemon::client::ClientError;

/// One row: a short title and its detail (both cleaned).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    pub title: String,
    pub detail: String,
}

fn line(title: &str, detail: &str) -> Line {
    Line {
        title: shown(title, TEXT_MAX),
        detail: shown(detail, MAX_SHOWN),
    }
}

/// A folder grant: `path` exactly as `permissions.get` gave it (what a revoke sends), `shown` for display.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRow {
    pub path: String,
    pub shown: String,
    pub access: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermRows {
    pub network: bool,
    pub display: bool,
    pub audio: bool,
    pub gpu: bool,
    pub grants: Vec<GrantRow>,
    /// The resource limits, one line (shown, not edited).
    pub limits: String,
}

fn section<T>(r: &Result<T, ClientError>, lines: impl FnOnce(&T) -> Vec<Line>) -> Vec<Line> {
    match r {
        Ok(v) => lines(v),
        Err(e) => vec![line("Unavailable", &error_text(e))],
    }
}

fn availability(a: &Availability) -> String {
    match a {
        Availability::Available => "available".to_owned(),
        Availability::Unavailable { reason } => format!("unavailable: {reason}"),
        _ => "unknown".to_owned(),
    }
}

fn perm_rows(p: &PermissionsView) -> PermRows {
    let l = &p.limits;
    let mut limits = vec![];
    limits.extend(l.memory_mb.map(|m| format!("{m} MiB memory")));
    limits.extend(l.cpu_percent.map(|c| format!("{c}% CPU")));
    limits.push(match l.tasks {
        Some(t) => format!("{t} tasks{}", if l.tasks_default { " (default)" } else { "" }),
        None => "unlimited tasks".to_owned(),
    });
    PermRows {
        network: p.network == NetworkView::Allow,
        display: p.display,
        audio: p.audio,
        gpu: p.gpu,
        grants: p
            .filesystem
            .iter()
            .map(|g| GrantRow {
                path: g.path.clone(),
                shown: shown(&g.path, rt_api::PATH_MAX),
                access: if g.access == AccessView::Rw {
                    "read-write"
                } else {
                    "read-only"
                },
            })
            .collect(),
        limits: limits.join(", "),
    }
}

impl Model {
    fn data(&self) -> Option<&AppData> {
        self.page.as_ref()?.data.as_ref()
    }

    /// "Running (job ...)" or "Not running" for the open app.
    pub fn page_status(&self) -> Option<String> {
        self.page.as_ref()?;
        Some(match self.live_run() {
            Some(j) => format!("Running (job {})", shown(&j.job_id, TEXT_MAX)),
            None => "Not running".to_owned(),
        })
    }

    /// The doctor, graphics and sandbox views of the open app, once loaded.
    pub fn page_sections(&self) -> Vec<(&'static str, Vec<Line>)> {
        let Some(d) = self.data() else { return vec![] };
        let checks = section(&d.doctor, |v| {
            let mut out = vec![line("Verdict", &v.verdict)];
            out.extend(
                v.checks
                    .iter()
                    .map(|c| line(&c.area, &format!("{}: {}", c.status, c.text))),
            );
            if v.missing_dependencies > 0 {
                out.push(line(
                    "Dependencies",
                    &format!("{} missing (plan them below)", v.missing_dependencies),
                ));
            }
            out.extend(v.notes.iter().map(|n| line("Note", n)));
            out
        });
        let graphics = section(&d.graphics, |g| {
            let verdict = match g.verdict {
                VulkanState::Usable => "usable",
                VulkanState::Unusable => "unusable",
                _ => "unknown",
            };
            let mut out = vec![line("Vulkan", verdict)];
            out.extend(g.reason.iter().map(|r| line("Reason", r)));
            out.extend(
                g.devices
                    .iter()
                    .map(|dev| line(&dev.name, &format!("{}, Vulkan {}", dev.device_type, dev.api))),
            );
            out
        });
        let sandbox = section(&d.sandbox, |s| {
            let mut out = vec![
                line("bubblewrap", &availability(&s.bwrap)),
                line("seccomp", &s.seccomp),
                line("Landlock", &s.landlock),
                line("Hardening complete", if s.hardening_complete { "yes" } else { "no" }),
            ];
            out.extend(s.refused.iter().map(|r| line("Refused", r)));
            out.extend(s.caveats.iter().map(|c| line("Caveat", c)));
            out
        });
        vec![("Checks", checks), ("Graphics", graphics), ("Sandbox", sandbox)]
    }

    /// The open app's permissions (`Err`: why they could not be read), once loaded.
    pub fn page_permissions(&self) -> Option<Result<PermRows, String>> {
        Some(match &self.data()?.permissions {
            Ok(p) => Ok(perm_rows(p)),
            Err(e) => Err(error_text(e)),
        })
    }
}
