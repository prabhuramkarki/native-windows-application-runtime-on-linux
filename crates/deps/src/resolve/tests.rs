use super::*;
use crate::manifest::{Install, Kind, Marker, Package};
use std::collections::HashSet;
use std::time::{Duration, Instant};

const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// A hand-built package (bypasses validation, so tests can also build manifests `parse` would reject).
fn pkg(id: &str, requires: &[&str], provides: &[&str], consent: bool) -> Package {
    Package {
        id: id.into(),
        version: "1.0".into(),
        sha256: HASH.into(),
        size: 1,
        licence: "Zlib".into(),
        url: format!("https://example.org/{id}.zip"),
        kind: Kind::Installer,
        requires_consent: consent,
        requires: requires.iter().map(|s| s.to_string()).collect(),
        provides: provides.iter().map(|s| s.to_string()).collect(),
        min_vulkan: None,
        install: Install::Installer {
            silent_args: vec![],
            marker: Marker::File(format!("{id}.marker")),
            dll_overrides: vec![],
        },
    }
}

fn manifest(packages: Vec<Package>) -> Manifest {
    Manifest { packages }
}

fn imports(names: &[&str]) -> Facts {
    Facts {
        imports: names.iter().map(|s| s.to_string()).collect(),
        extra_capabilities: vec![],
    }
}

fn caps(names: &[&str]) -> Facts {
    Facts {
        imports: vec![],
        extra_capabilities: names.iter().map(|s| s.to_string()).collect(),
    }
}

fn installed_ref(p: &Package) -> InstalledRef {
    InstalledRef {
        id: p.id.clone(),
        version: p.version.clone(),
        sha256: p.sha256.clone(),
    }
}

fn entry(package: &str, action: Action, consent: ConsentState) -> PlanEntry {
    PlanEntry {
        package: package.into(),
        action,
        consent,
    }
}

fn ids(plan: &Plan) -> Vec<&str> {
    plan.entries.iter().map(|e| e.package.as_str()).collect()
}

/// The dependency shapes these tests need (a consent-gated package, and one package requiring another), which the
/// real bundled manifest does not have: it has one `requires` edge (vkd3d-proton -> dxvk) but no consent-gated
/// package next to it.
fn graph() -> Manifest {
    manifest(vec![
        pkg("dxvk", &[], &["d3d9", "d3d10core", "d3d11", "dxgi"], false),
        pkg("vkd3d-proton", &["dxvk"], &["d3d12"], false),
        pkg("vcrun2022", &[], &["vcruntime140", "msvcp140"], true),
    ])
}

fn none() -> InstalledSet {
    InstalledSet::default()
}

#[test]
fn d3d11_import_plans_dxvk() {
    let m = Manifest::bundled();
    let facts = imports(&["d3d11.dll"]);
    assert_eq!(required_capabilities(&facts), ["d3d11"]);
    let plan = resolve(&facts, &none(), &[], m);
    assert_eq!(plan.entries, [entry("dxvk", Action::Install, ConsentState::NotNeeded)]);
}

#[test]
fn import_names_are_normalised_and_deduped() {
    let facts = imports(&["D3D11.DLL", "d3d11", "d3d11.dll", "DXGI.dll", "dxgi"]);
    assert_eq!(required_capabilities(&facts), ["d3d11", "dxgi"]);
    let plan = resolve(&facts, &none(), &[], Manifest::bundled());
    assert_eq!(
        ids(&plan),
        ["dxvk"],
        "one entry even though two capabilities and five imports hit it"
    );
}

#[test]
fn consent_needed_for_proprietary_package() {
    let plan = resolve(&imports(&["VCRUNTIME140.dll", "msvcp140.dll"]), &none(), &[], &graph());
    assert_eq!(
        plan.entries,
        [entry("vcrun2022", Action::Install, ConsentState::Needed)]
    );
}

#[test]
fn already_installed_exact_match() {
    let m = &graph();
    let dxvk = m.get("dxvk").unwrap();
    let installed = InstalledSet(vec![installed_ref(dxvk)]);
    let plan = resolve(&imports(&["d3d11.dll"]), &installed, &[], m);
    assert_eq!(
        plan.entries,
        [entry("dxvk", Action::AlreadyInstalled, ConsentState::NotNeeded)]
    );

    // A consent-gated package that is installed needs no new consent.
    let vc = m.get("vcrun2022").unwrap();
    let plan = resolve(
        &imports(&["vcruntime140.dll"]),
        &InstalledSet(vec![installed_ref(vc)]),
        &[],
        m,
    );
    assert_eq!(
        plan.entries,
        [entry("vcrun2022", Action::AlreadyInstalled, ConsentState::NotNeeded)]
    );
}

#[test]
fn installed_mismatch_replans_install() {
    let m = Manifest::bundled();
    let dxvk = m.get("dxvk").unwrap();
    let stale = [
        InstalledRef {
            sha256: "f".repeat(64),
            ..installed_ref(dxvk)
        },
        InstalledRef {
            version: "0.0.1".into(),
            ..installed_ref(dxvk)
        },
        InstalledRef {
            id: "vkd3d-proton".into(),
            ..installed_ref(dxvk)
        },
    ];
    for r in stale {
        let plan = resolve(&imports(&["d3d11.dll"]), &InstalledSet(vec![r.clone()]), &[], m);
        assert_eq!(
            plan.entries,
            [entry("dxvk", Action::Install, ConsentState::NotNeeded)],
            "{r:?}"
        );
    }
}

#[test]
fn dependencies_come_first() {
    let plan = resolve(&imports(&["d3d12.dll"]), &none(), &[], &graph());
    assert_eq!(ids(&plan), ["dxvk", "vkd3d-proton"]);
    assert!(plan.entries.iter().all(|e| e.action == Action::Install));

    // Ordering beats id order: "a" requires "z".
    let m = manifest(vec![pkg("a", &["z"], &["cap-a"], false), pkg("z", &[], &[], false)]);
    assert_eq!(ids(&resolve(&caps(&["cap-a"]), &none(), &[], &m)), ["z", "a"]);
}

#[test]
fn diamond_dependency_appears_once() {
    let m = manifest(vec![
        pkg("top", &["left", "right"], &["top"], false),
        pkg("left", &["base"], &["left"], false),
        pkg("right", &["base"], &["right"], false),
        pkg("base", &[], &["base"], false),
    ]);
    let plan = resolve(&caps(&["top", "left", "base"]), &none(), &[], &m);
    assert_eq!(ids(&plan), ["base", "left", "right", "top"]);
    assert!(plan.entries.iter().all(|e| e.action == Action::Install));

    // A repeated requirement (hand-built manifest) counts once, not as an unmet edge.
    let m = manifest(vec![pkg("a", &["b", "b"], &["a"], false), pkg("b", &[], &[], false)]);
    let plan = resolve(&caps(&["a"]), &none(), &[], &m);
    assert_eq!(ids(&plan), ["b", "a"]);
    assert!(plan.entries.iter().all(|e| e.action == Action::Install), "{plan:?}");
}

#[test]
fn denied_blocks_it_and_its_dependents_only() {
    let m = manifest(vec![
        pkg("base", &[], &["base"], true),
        pkg("mid", &["base"], &["mid"], false),
        pkg("top", &["mid"], &["top"], true),
        pkg("other", &[], &["other"], false),
        pkg("side", &["other"], &["side"], false),
    ]);
    let plan = resolve(&caps(&["top", "side"]), &none(), &["base".into()], &m);
    assert_eq!(ids(&plan), ["base", "mid", "other", "side", "top"]);
    let by_id = |id: &str| plan.entries.iter().find(|e| e.package == id).unwrap();
    assert!(matches!(by_id("base").action, Action::Blocked { .. }));
    assert_eq!(by_id("base").consent, ConsentState::Denied);
    assert!(matches!(by_id("mid").action, Action::Blocked { .. }));
    assert_eq!(by_id("mid").consent, ConsentState::NotNeeded);
    assert!(matches!(by_id("top").action, Action::Blocked { .. }));
    assert_eq!(by_id("top").consent, ConsentState::Needed);
    assert_eq!(by_id("other").action, Action::Install);
    assert_eq!(by_id("side").action, Action::Install);

    // Denying on the dxvk/vkd3d graph: dxvk denied blocks vkd3d-proton too.
    let plan = resolve(&imports(&["d3d12.dll"]), &none(), &["dxvk".into()], &graph());
    assert_eq!(ids(&plan), ["dxvk", "vkd3d-proton"]);
    assert!(plan.entries.iter().all(|e| matches!(e.action, Action::Blocked { .. })));
    assert_eq!(plan.entries[0].consent, ConsentState::Denied);
    assert_eq!(plan.entries[1].consent, ConsentState::NotNeeded);
}

#[test]
fn installed_dependent_of_denied_package_stays_installed() {
    // dxvk denied and not installed: blocked. vkd3d-proton installed exactly: nothing to download, so it stays
    // AlreadyInstalled rather than being blocked by something below it.
    let m = &graph();
    let vk = m.get("vkd3d-proton").unwrap();
    let plan = resolve(
        &imports(&["d3d12"]),
        &InstalledSet(vec![installed_ref(vk)]),
        &["dxvk".into()],
        m,
    );
    assert_eq!(ids(&plan), ["dxvk", "vkd3d-proton"]);
    assert!(matches!(plan.entries[0].action, Action::Blocked { .. }));
    assert_eq!(plan.entries[0].consent, ConsentState::Denied);
    assert_eq!(
        plan.entries[1],
        entry("vkd3d-proton", Action::AlreadyInstalled, ConsentState::NotNeeded)
    );

    // Same denial, dependent not installed: its would-be Install is blocked.
    let plan = resolve(&imports(&["d3d12"]), &none(), &["dxvk".into()], m);
    assert!(matches!(plan.entries[1].action, Action::Blocked { .. }));
}

#[test]
fn denied_but_installed_is_already_installed() {
    let m = &graph();
    let vc = m.get("vcrun2022").unwrap();
    let plan = resolve(
        &imports(&["vcruntime140.dll"]),
        &InstalledSet(vec![installed_ref(vc)]),
        &["vcrun2022".into()],
        m,
    );
    assert_eq!(
        plan.entries,
        [entry("vcrun2022", Action::AlreadyInstalled, ConsentState::NotNeeded)]
    );

    // A broken graph stays blocked even when installed.
    let hand = manifest(vec![pkg("c", &["ghost"], &["c"], false)]);
    let plan = resolve(
        &caps(&["c"]),
        &InstalledSet(vec![installed_ref(&hand.packages[0])]),
        &[],
        &hand,
    );
    assert!(matches!(plan.entries[0].action, Action::Blocked { .. }), "{plan:?}");
    let hand = manifest(vec![pkg("a", &["b"], &["a"], false), pkg("b", &["a"], &[], false)]);
    let all = InstalledSet(hand.packages.iter().map(installed_ref).collect());
    let plan = resolve(&caps(&["a"]), &all, &[], &hand);
    assert!(
        plan.entries.iter().all(|e| matches!(e.action, Action::Blocked { .. })),
        "{plan:?}"
    );
}

#[test]
fn unsatisfied_capabilities_are_reported() {
    let m = Manifest::bundled();
    let plan = resolve(&imports(&["MSCOREE.dll", "d3d11.dll"]), &none(), &[], m);
    assert!(plan.unsatisfied.is_empty(), "{plan:?}");
    assert_eq!(ids(&plan), ["dxvk", "wine-mono"]);
    assert!(
        resolve(&imports(&["d3d11.dll"]), &none(), &[], m)
            .unsatisfied
            .is_empty()
    );
    assert!(
        resolve(&imports(&["kernel32.dll"]), &none(), &[], m)
            .unsatisfied
            .is_empty()
    );

    // Extras count too; sorted, deduped, clipped, deterministic.
    let long = "z".repeat(10_000);
    let facts = Facts {
        imports: vec!["mscoree".into()],
        extra_capabilities: vec!["zzz".into(), "aaa".into(), "zzz".into(), long.clone(), "d3d9".into()],
    };
    let plan = resolve(&facts, &none(), &[], m);
    assert_eq!(plan.unsatisfied[..2], ["aaa", "zzz"]);
    assert_eq!(plan.unsatisfied.len(), 3);
    assert!(plan.unsatisfied[2].len() < 100);
    assert_eq!(plan, resolve(&facts, &none(), &[], m));

    // Two long names that differ only past the clip point collapse to one entry.
    let facts = caps(&[&format!("{long}a"), &format!("{long}b")]);
    assert_eq!(resolve(&facts, &none(), &[], m).unsatisfied.len(), 1);
}

#[test]
fn unknown_imports_yield_nothing() {
    let long = "x".repeat(1_000_000);
    let facts = imports(&["kernel32.dll", "", "\0", "d3d11\0.dll", "\u{fffd}.dll", "user32", &long]);
    assert!(required_capabilities(&facts).is_empty());
    assert!(resolve(&facts, &none(), &[], Manifest::bundled()).entries.is_empty());
    // A capability nothing provides is not an error either.
    assert!(
        resolve(&caps(&["", "nope"]), &none(), &[], Manifest::bundled())
            .entries
            .is_empty()
    );
}

#[test]
fn extra_capabilities_are_honoured() {
    let facts = caps(&["d3d12"]);
    assert_eq!(required_capabilities(&facts), ["d3d12"]);
    assert_eq!(ids(&resolve(&facts, &none(), &[], &graph())), ["dxvk", "vkd3d-proton"]);
    let both = Facts {
        imports: vec!["msvcp140.dll".into()],
        extra_capabilities: vec!["d3d9".into(), "d3d9".into()],
    };
    assert_eq!(required_capabilities(&both), ["d3d9", "msvcp140"]);
}

#[test]
fn smallest_provider_id_wins() {
    let m = manifest(vec![pkg("zeta", &[], &["x"], false), pkg("alpha", &[], &["x"], false)]);
    assert_eq!(ids(&resolve(&caps(&["x"]), &none(), &[], &m)), ["alpha"]);
}

#[test]
fn output_is_deterministic() {
    let names = ["d3d12.dll", "VCRUNTIME140.dll", "d3d9.dll", "kernel32.dll", "dxgi"];
    let m = &graph();
    let first = resolve(&imports(&names), &none(), &[], m);
    assert_eq!(first, resolve(&imports(&names), &none(), &[], m));
    assert_eq!(ids(&first), ["dxvk", "vcrun2022", "vkd3d-proton"]);

    let mut reversed = names;
    reversed.reverse();
    assert_eq!(first, resolve(&imports(&reversed), &none(), &[], m));

    let mut shuffled = m.clone();
    shuffled.packages.reverse();
    assert_eq!(first, resolve(&imports(&names), &none(), &[], &shuffled));
}

#[test]
fn hand_built_cycles_and_unknown_refs_are_blocked_not_hangs() {
    let m = manifest(vec![
        pkg("a", &["b"], &["a"], false),
        pkg("b", &["a"], &[], false),
        pkg("c", &["ghost"], &["c"], false),
        pkg("d", &["d"], &["d"], false),
        pkg("e", &["c"], &["e"], false),
    ]);
    let plan = resolve(&caps(&["a", "c", "d", "e"]), &none(), &[], &m);
    let mut seen = ids(&plan);
    seen.sort();
    assert_eq!(seen, ["a", "b", "c", "d", "e"]);
    assert!(
        plan.entries.iter().all(|e| matches!(e.action, Action::Blocked { .. })),
        "{plan:?}"
    );
}

#[test]
fn blocked_reason_is_bounded() {
    let long = "p".repeat(100_000);
    let m = manifest(vec![
        pkg(&long, &[], &["x"], false),
        pkg("dep", &[&long], &["y"], false),
    ]);
    let plan = resolve(&caps(&["y"]), &none(), std::slice::from_ref(&long), &m);
    assert_eq!(plan.entries.len(), 2);
    for e in &plan.entries {
        let Action::Blocked { reason } = &e.action else {
            panic!("{e:?}")
        };
        assert!(reason.len() < 256, "{}", reason.len());
    }
}

#[test]
fn hostile_facts_do_not_panic_and_stay_bounded() {
    let mut facts = Facts::default();
    for i in 0..200_000 {
        facts.imports.push(match i % 4 {
            0 => "D3D11.DLL".into(),
            1 => format!("junk{i}\0\u{1F600}.dll"),
            2 => String::new(),
            _ => "x".repeat(i % 300),
        });
        facts.extra_capabilities.push(format!("cap{}", i % 1000));
    }
    let start = Instant::now();
    let plan = resolve(&facts, &none(), &["\0".into(), String::new()], Manifest::bundled());
    assert_eq!(ids(&plan), ["dxvk"]);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
}

#[test]
fn ten_thousand_packages_in_bounded_time() {
    // A 10k chain with fan-in to p0, built directly: 10k packages is over the 1 MiB `parse` cap.
    let n = 10_000;
    let names: Vec<String> = (0..n).map(|i| format!("p{i:05}")).collect();
    let packages = (0..n)
        .map(|i| {
            let requires: Vec<&str> = match i {
                0 => vec![],
                1 => vec![&names[0]],
                _ => vec![&names[i - 1], &names[0]],
            };
            pkg(&names[i], &requires, &[&format!("cap{i}")], i % 2 == 0)
        })
        .collect();
    let m = manifest(packages);
    let installed = InstalledSet(vec![installed_ref(&m.packages[0])]);
    let start = Instant::now();
    let plan = resolve(&caps(&["cap9999"]), &installed, &[names[5000].clone()], &m);
    assert!(start.elapsed() < Duration::from_secs(5), "{:?}", start.elapsed());
    assert_eq!(ids(&plan), names.iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(plan.entries[0].action, Action::AlreadyInstalled);
    assert_eq!(plan.entries[4999].action, Action::Install);
    assert!(
        plan.entries[5000..]
            .iter()
            .all(|e| matches!(e.action, Action::Blocked { .. }))
    );
}

/// Deterministic xorshift64 so failures reproduce.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

#[test]
fn random_facts_keep_plan_invariants() {
    let m = &graph();
    let mut pool: Vec<String> = crate::capabilities::TABLE
        .iter()
        .flat_map(|(k, _)| [k.to_string(), format!("{}.DLL", k.to_ascii_uppercase())])
        .collect();
    pool.extend(["kernel32.dll", "", "\0", "d3d11.dll.dll", "ntdll"].map(String::from));
    let ids_all: Vec<&str> = m.packages.iter().map(|p| p.id.as_str()).collect();
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    for round in 0..2_000 {
        let facts = Facts {
            imports: (0..rng.below(12))
                .map(|_| pool[rng.below(pool.len())].clone())
                .collect(),
            extra_capabilities: (0..rng.below(3)).map(|_| pool[rng.below(pool.len())].clone()).collect(),
        };
        let mut installed = InstalledSet::default();
        for p in &m.packages {
            match rng.below(4) {
                0 => installed.0.push(installed_ref(p)),
                1 => installed.0.push(InstalledRef {
                    sha256: "0".repeat(64),
                    ..installed_ref(p)
                }),
                _ => {}
            }
        }
        let denied: Vec<String> = ids_all
            .iter()
            .filter(|_| rng.below(4) == 0)
            .map(|s| s.to_string())
            .collect();
        let plan = resolve(&facts, &installed, &denied, m);
        assert_eq!(plan, resolve(&facts, &installed, &denied, m), "round {round}");

        let mut placed = HashSet::new();
        let mut blocked = HashSet::new();
        for e in &plan.entries {
            let p = m
                .get(&e.package)
                .unwrap_or_else(|| panic!("round {round}: unknown {}", e.package));
            for r in &p.requires {
                assert!(
                    placed.contains(r.as_str()),
                    "round {round}: {} before its dependency {r}",
                    p.id
                );
            }
            assert!(placed.insert(e.package.as_str()), "round {round}: {} twice", e.package);
            // Reference model over the acyclic test graph, checked in both directions.
            let exact = installed.0.contains(&installed_ref(p));
            let is_denied = denied.contains(&e.package);
            let dep_blocked = p.requires.iter().any(|r| blocked.contains(r.as_str()));
            let (blocks, consent) = if exact {
                (false, ConsentState::NotNeeded)
            } else if is_denied {
                (true, ConsentState::Denied)
            } else if p.requires_consent {
                (dep_blocked, ConsentState::Needed)
            } else {
                (dep_blocked, ConsentState::NotNeeded)
            };
            assert_eq!(e.action == Action::AlreadyInstalled, exact, "round {round}: {e:?}");
            assert_eq!(
                matches!(e.action, Action::Blocked { .. }),
                blocks,
                "round {round}: {e:?}"
            );
            assert_eq!(e.consent, consent, "round {round}: {e:?}");
            if blocks {
                blocked.insert(e.package.as_str());
            }
        }
        let mut unsatisfied: Vec<String> = required_capabilities(&facts)
            .into_iter()
            .filter(|c| !m.packages.iter().any(|p| p.provides.contains(c)))
            .collect();
        unsatisfied.dedup();
        assert_eq!(plan.unsatisfied, unsatisfied, "round {round}");
        // Every capability the facts need, if some package provides it, is covered by a plan entry.
        for cap in required_capabilities(&facts) {
            if let Some(p) = m.packages.iter().find(|p| p.provides.contains(&cap)) {
                assert!(placed.contains(p.id.as_str()), "round {round}: {cap} uncovered");
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------ block_for_vulkan

fn pkg_vk(id: &str, requires: &[&str], provides: &[&str], min: (u32, u32)) -> Package {
    Package {
        min_vulkan: Some(min),
        ..pkg(id, requires, provides, false)
    }
}

fn action_of<'a>(plan: &'a Plan, id: &str) -> &'a Action {
    &plan.entries.iter().find(|e| e.package == id).unwrap().action
}

fn unusable(_: Option<(u32, u32)>) -> VulkanVerdict {
    VulkanVerdict::Unusable("no device".into())
}

#[test]
fn unusable_vulkan_blocks_install_entries_that_need_it() {
    let m = manifest(vec![
        pkg_vk("dxvk", &[], &["d3d11"], (1, 3)),
        pkg("other", &[], &["x"], false),
    ]);
    let mut plan = resolve(&caps(&["d3d11", "x"]), &none(), &[], &m);
    block_for_vulkan(&mut plan, &m, &unusable);
    assert_eq!(
        action_of(&plan, "dxvk"),
        &Action::Blocked {
            reason: "Vulkan is unusable: no device; Wine's built-in Direct3D will be used".into()
        }
    );
    assert_eq!(action_of(&plan, "other"), &Action::Install);
}

#[test]
fn unknown_and_usable_change_nothing() {
    for v in [VulkanVerdict::Usable, VulkanVerdict::Unknown] {
        let m = manifest(vec![pkg_vk("dxvk", &[], &["d3d11"], (1, 3))]);
        let mut plan = resolve(&caps(&["d3d11"]), &none(), &[], &m);
        let before = plan.clone();
        block_for_vulkan(&mut plan, &m, &|_| v.clone());
        assert_eq!(plan, before);
    }
}

#[test]
fn an_already_installed_package_is_never_blocked() {
    let m = manifest(vec![pkg_vk("dxvk", &[], &["d3d11"], (1, 3))]);
    let installed = InstalledSet(vec![installed_ref(&m.packages[0])]);
    let mut plan = resolve(&caps(&["d3d11"]), &installed, &[], &m);
    block_for_vulkan(&mut plan, &m, &unusable);
    assert_eq!(action_of(&plan, "dxvk"), &Action::AlreadyInstalled);
}

#[test]
fn bundled_d3d12_plan_blocks_dxvk_and_vkd3d_proton_when_vulkan_is_unusable() {
    let m = Manifest::bundled();
    let mut plan = resolve(&imports(&["D3D12.dll"]), &none(), &[], m);
    block_for_vulkan(&mut plan, m, &unusable);
    assert_eq!(ids(&plan), ["dxvk", "vkd3d-proton"]);
    for id in ["dxvk", "vkd3d-proton"] {
        let Action::Blocked { reason } = action_of(&plan, id) else {
            panic!("{id}: {plan:?}")
        };
        assert!(reason.contains("Vulkan") || reason.contains("dxvk"), "{id}: {reason}");
    }
    assert!(plan.unsatisfied.is_empty(), "{plan:?}");
}

#[test]
fn a_package_requiring_a_blocked_one_is_blocked_too() {
    // vkd3d-proton has no minimum of its own here: it is blocked only because dxvk is.
    let m = manifest(vec![
        pkg_vk("dxvk", &[], &["d3d11"], (1, 3)),
        pkg("vkd3d-proton", &["dxvk"], &["d3d12"], false),
    ]);
    let mut plan = resolve(&caps(&["d3d12"]), &none(), &[], &m);
    block_for_vulkan(&mut plan, &m, &unusable);
    let Action::Blocked { reason } = action_of(&plan, "vkd3d-proton") else {
        panic!("{plan:?}")
    };
    assert_eq!(reason, "needs dxvk, which is blocked (Vulkan is unusable)");
    assert!(plan.unsatisfied.is_empty(), "blocked, not unsatisfied");
}

#[test]
fn the_verdict_closure_runs_once_per_distinct_minimum() {
    let m = manifest(vec![
        pkg_vk("a", &[], &["x"], (1, 3)),
        pkg_vk("b", &[], &["y"], (1, 3)),
        pkg_vk("c", &[], &["z"], (1, 1)),
        pkg("d", &[], &["w"], false),
    ]);
    let mut plan = resolve(&caps(&["x", "y", "z", "w"]), &none(), &[], &m);
    let calls = std::cell::RefCell::new(Vec::new());
    block_for_vulkan(&mut plan, &m, &|min| {
        calls.borrow_mut().push(min);
        VulkanVerdict::Usable
    });
    let mut calls = calls.into_inner();
    calls.sort();
    assert_eq!(calls, [Some((1, 1)), Some((1, 3))]);
}

#[test]
fn a_plan_with_no_vulkan_package_never_runs_the_closure() {
    let m = manifest(vec![pkg("d", &[], &["w"], false)]);
    let mut plan = resolve(&caps(&["w"]), &none(), &[], &m);
    block_for_vulkan(&mut plan, &m, &|_| panic!("must not probe"));
}
