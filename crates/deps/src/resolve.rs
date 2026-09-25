//! The pure resolver: what an app needs (facts), what the runtime recorded as installed, and which consents were
//! denied, turned into an ordered install plan. No I/O, no globals, no clock.
//!
//! The plan is architecture-agnostic: it names packages, not per-architecture files. Known limitation: DXVK
//! extraction is currently x64-only (the manifest's `extract` lists), so a 32-bit app gets a 64-bit DXVK.

use crate::capabilities::capability_for;
use crate::manifest::{Manifest, Package, clip};
use rt_core::VulkanVerdict;
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};

/// What the runtime knows about an app.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Facts {
    /// Imported DLL names as found in the PE (any case, with or without `.dll`). The caller includes delay-load
    /// imports too: missing a real need is worse than a harmless extra plan entry (e.g. an unused DXVK).
    pub imports: Vec<String>,
    /// Capabilities known from elsewhere (installer family, MSI facts), as manifest `provides` names.
    pub extra_capabilities: Vec<String>,
}

/// Packages the runtime itself recorded as installed for this app (never inferred from prefix files).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InstalledSet(pub Vec<InstalledRef>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledRef {
    pub id: String,
    pub version: String,
    pub sha256: String,
}

/// Consent to download a package. Meaningless on a `Blocked` entry: callers (Task 7) must not prompt for those.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentState {
    NotNeeded,
    Needed,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Install,
    AlreadyInstalled,
    Blocked { reason: String },
}

/// One package in the plan. `consent` only matters when `action` is `Install`; see [`ConsentState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanEntry {
    pub package: String,
    pub action: Action,
    pub consent: ConsentState,
}

/// Dependencies first; packages with no ordering constraint between them are sorted by id.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Plan {
    pub entries: Vec<PlanEntry>,
    /// Required capabilities that no manifest package provides (sorted, deduplicated, clipped), so callers can
    /// say something is missing instead of reporting an empty plan as "nothing needed".
    pub unsatisfied: Vec<String>,
}

/// Capabilities the app needs: its imports mapped through the capability table, plus `extra_capabilities`. Sorted
/// and deduplicated; unknown imports contribute nothing.
pub fn required_capabilities(facts: &Facts) -> Vec<String> {
    let caps: BTreeSet<&str> = facts
        .imports
        .iter()
        .filter_map(|i| capability_for(i))
        .chain(facts.extra_capabilities.iter().map(String::as_str))
        .collect();
    caps.into_iter().map(str::to_owned).collect()
}

/// Plan the packages that provide the app's required capabilities, plus everything they transitively require.
///
/// Each package appears once, after all of its requirements; ties are broken by id, so the plan does not depend on
/// input or manifest order. A package counts as installed only if `installed` has its exact id, version and
/// sha256; an installed package is `AlreadyInstalled` (consent `NotNeeded`) even if denied or if something below
/// it is blocked, since consent only gates downloads. A package that would otherwise be installed is blocked if it
/// is denied or requires a blocked package. Robust against a hand-built (unvalidated) manifest: unknown
/// requirements and cycles block the packages involved, ahead of the installed check.
pub fn resolve(facts: &Facts, installed: &InstalledSet, denied: &[String], manifest: &Manifest) -> Plan {
    // id -> package (first wins on a duplicate id, as in `Manifest::get`); capability -> smallest providing id.
    let mut index: HashMap<&str, &Package> = HashMap::with_capacity(manifest.packages.len());
    let mut provider: HashMap<&str, &str> = HashMap::new();
    for p in &manifest.packages {
        index.entry(&p.id).or_insert(p);
        for cap in &p.provides {
            provider
                .entry(cap)
                .and_modify(|id| *id = (*id).min(&p.id))
                .or_insert(&p.id);
        }
    }

    // Transitive closure of the providers, iteratively.
    let required = required_capabilities(facts);
    let mut stack: Vec<&str> = required
        .iter()
        .filter_map(|c| provider.get(c.as_str()).copied())
        .collect();
    // `required` is sorted; clipping can only merge neighbours, so dedup after it keeps the result sorted-unique.
    let mut unsatisfied: Vec<String> = required
        .iter()
        .filter(|c| !provider.contains_key(c.as_str()))
        .map(|c| clip(c))
        .collect();
    unsatisfied.dedup();
    let mut wanted: HashSet<&str> = HashSet::new();
    while let Some(id) = stack.pop() {
        if let Some(p) = index.get(id)
            && wanted.insert(id)
        {
            stack.extend(p.requires.iter().map(String::as_str));
        }
    }

    // Kahn's algorithm over the closure, always taking the smallest ready id.
    let mut pending: HashMap<&str, usize> = HashMap::with_capacity(wanted.len());
    let mut dependents: HashMap<&str, Vec<&str>> = HashMap::new();
    for &id in &wanted {
        // A repeated requirement adds one edge per occurrence and is released once per occurrence, so it balances.
        let mut n = 0;
        for r in index[id]
            .requires
            .iter()
            .map(String::as_str)
            .filter(|r| wanted.contains(r))
        {
            dependents.entry(r).or_default().push(id);
            n += 1;
        }
        pending.insert(id, n);
    }
    let mut ready: BinaryHeap<Reverse<&str>> = pending
        .iter()
        .filter(|&(_, &n)| n == 0)
        .map(|(&id, _)| Reverse(id))
        .collect();
    let mut order: Vec<&str> = Vec::with_capacity(wanted.len());
    while let Some(Reverse(id)) = ready.pop() {
        order.push(id);
        for &d in dependents.get(id).into_iter().flatten() {
            let n = pending.get_mut(d).expect("dependent is in the closure");
            *n -= 1;
            if *n == 0 {
                ready.push(Reverse(d));
            }
        }
    }
    // Anything left is on or behind a cycle (only possible in a hand-built manifest): block it, in id order.
    let mut cyclic: Vec<&str> = pending.iter().filter(|&(_, &n)| n > 0).map(|(&id, _)| id).collect();
    cyclic.sort_unstable();
    let acyclic = order.len();
    order.extend(cyclic);

    let installed: HashSet<(&str, &str, &str)> = installed
        .0
        .iter()
        .map(|r| (r.id.as_str(), r.version.as_str(), r.sha256.as_str()))
        .collect();
    let denied: HashSet<&str> = denied.iter().map(String::as_str).collect();
    let mut blocked: HashSet<&str> = HashSet::new();
    let entries = order
        .into_iter()
        .enumerate()
        .map(|(i, id)| {
            let p = index[id];
            let blocked_by = |why: &str, other: &str| Action::Blocked {
                reason: format!("{why} {:?}", clip(other)),
            };
            // A broken graph stays blocked; otherwise an exact installed match wins, since consent and blocking
            // only gate downloads.
            let action = if i >= acyclic {
                blocked_by("dependency cycle through", id)
            } else if let Some(r) = p.requires.iter().find(|r| !index.contains_key(r.as_str())) {
                blocked_by("requires unknown package", r)
            } else if installed.contains(&(id, p.version.as_str(), p.sha256.as_str())) {
                Action::AlreadyInstalled
            } else if denied.contains(id) {
                blocked_by("consent denied for", id)
            } else if let Some(r) = p.requires.iter().find(|r| blocked.contains(r.as_str())) {
                blocked_by("requires blocked package", r)
            } else {
                Action::Install
            };
            if matches!(action, Action::Blocked { .. }) {
                blocked.insert(id);
            }
            let consent = if action == Action::AlreadyInstalled {
                ConsentState::NotNeeded
            } else if denied.contains(id) {
                ConsentState::Denied
            } else if p.requires_consent {
                ConsentState::Needed
            } else {
                ConsentState::NotNeeded
            };
            PlanEntry {
                package: id.to_owned(),
                action,
                consent,
            }
        })
        .collect();
    Plan { entries, unsatisfied }
}

/// Blocks the `Install` entries that need a Vulkan the host cannot give (and, since entries are dependency-first,
/// whatever requires them), so `deps` says so instead of installing DLLs that would not work. Kept out of
/// [`resolve`] because the verdict is a fact about the host: the caller supplies it, and it is asked for once per
/// distinct `min_vulkan` (never, if no entry needs Vulkan). Only `Unusable` blocks; an installed package stays.
pub fn block_for_vulkan(
    plan: &mut Plan,
    manifest: &Manifest,
    verdict_for: &dyn Fn(Option<(u32, u32)>) -> VulkanVerdict,
) {
    let mut cache: HashMap<(u32, u32), VulkanVerdict> = HashMap::new();
    let mut blocked: HashSet<String> = HashSet::new();
    for e in &mut plan.entries {
        if e.action != Action::Install {
            continue;
        }
        let Some(p) = manifest.get(&e.package) else { continue };
        if let Some(min) = p.min_vulkan
            && let VulkanVerdict::Unusable(why) = cache.entry(min).or_insert_with(|| verdict_for(Some(min)))
        {
            e.action = Action::Blocked {
                // Only the host's text is clipped; the fixed part must survive.
                reason: format!(
                    "Vulkan is unusable: {}; Wine's built-in Direct3D will be used",
                    clip(why)
                ),
            };
            blocked.insert(e.package.clone());
        } else if let Some(blocker) = p.requires.iter().find(|r| blocked.contains(*r)) {
            e.action = Action::Blocked {
                reason: format!("needs {}, which is blocked (Vulkan is unusable)", clip(blocker)),
            };
            blocked.insert(e.package.clone());
        }
    }
}

#[cfg(test)]
mod tests;
