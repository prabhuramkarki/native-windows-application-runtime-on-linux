//! The pure resolver: what an app needs (facts), what the runtime recorded as installed, and which consents were
//! denied, turned into an ordered install plan. No I/O, no globals, no clock.

use crate::capabilities::capability_for;
use crate::manifest::{Manifest, Package, clip};
use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap, HashMap, HashSet};

/// What the runtime knows about an app.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Facts {
    /// Imported DLL names as found in the PE (any case, with or without `.dll`).
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
/// sha256. A `denied` package is blocked, and so is everything that requires a blocked package. Robust against a
/// hand-built (unvalidated) manifest: unknown requirements and cycles block the packages involved.
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
    let mut stack: Vec<&str> = required_capabilities(facts)
        .iter()
        .filter_map(|c| provider.get(c.as_str()).copied())
        .collect();
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
            let action = if denied.contains(id) {
                blocked_by("consent denied for", id)
            } else if i >= acyclic {
                blocked_by("dependency cycle through", id)
            } else if let Some(r) = p.requires.iter().find(|r| !index.contains_key(r.as_str())) {
                blocked_by("requires unknown package", r)
            } else if let Some(r) = p.requires.iter().find(|r| blocked.contains(r.as_str())) {
                blocked_by("requires blocked package", r)
            } else if installed.contains(&(id, p.version.as_str(), p.sha256.as_str())) {
                Action::AlreadyInstalled
            } else {
                Action::Install
            };
            if matches!(action, Action::Blocked { .. }) {
                blocked.insert(id);
            }
            let consent = if denied.contains(id) {
                ConsentState::Denied
            } else if p.requires_consent && action != Action::AlreadyInstalled {
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
    Plan { entries }
}

#[cfg(test)]
mod tests;
