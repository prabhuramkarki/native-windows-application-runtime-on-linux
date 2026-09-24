use super::*;
use rt_core::{AppId, BackendInfo, WinPath};

const HASH_A: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const HASH_B: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

fn md() -> Metadata {
    Metadata::new(
        AppId::parse("app").unwrap(),
        "App".into(),
        None,
        "x86_64",
        &WinPath::parse("C:\\app.exe").unwrap(),
        BackendInfo {
            id: "fake".into(),
            version: "1".into(),
        },
        "gui",
    )
}

fn rec(id: &str, version: &str) -> DependencyRecord {
    DependencyRecord {
        id: id.into(),
        version: version.into(),
        sha256: HASH_A.into(),
        installed_at: 1_800_000_000,
        consent: None,
    }
}

fn ids(md: &Metadata) -> Vec<&str> {
    md.dependencies.iter().map(|d| d.id.as_str()).collect()
}

#[test]
fn empty_metadata_has_nothing_installed_and_no_consent() {
    let m = md();
    assert_eq!(installed_set(&m), InstalledSet::default());
    assert_eq!(consent_of(&m, "vcrun2022", "14.40"), None);
    let mut m = m;
    assert!(!forget(&mut m, "vcrun2022"));
}

#[test]
fn installed_set_maps_id_version_and_sha256() {
    let mut m = md();
    let mut b = rec("vcrun2022", "14.40");
    b.sha256 = HASH_B.into();
    record(&mut m, b).unwrap();
    record(&mut m, rec("dxvk", "2.4")).unwrap();
    assert_eq!(
        installed_set(&m),
        InstalledSet(vec![
            InstalledRef {
                id: "dxvk".into(),
                version: "2.4".into(),
                sha256: HASH_A.into(),
            },
            InstalledRef {
                id: "vcrun2022".into(),
                version: "14.40".into(),
                sha256: HASH_B.into(),
            },
        ])
    );
}

#[test]
fn record_keeps_the_list_sorted_by_id() {
    let mut m = md();
    for id in ["m", "z", "a", "q"] {
        record(&mut m, rec(id, "1")).unwrap();
    }
    assert_eq!(ids(&m), ["a", "m", "q", "z"]);
    // A hand-edited, unsorted list is sorted by the next record.
    m.dependencies.reverse();
    record(&mut m, rec("b", "1")).unwrap();
    assert_eq!(ids(&m), ["a", "b", "m", "q", "z"]);
}

#[test]
fn record_replaces_an_entry_with_the_same_id() {
    let mut m = md();
    record(&mut m, rec("a", "1")).unwrap();
    record(&mut m, rec("b", "1")).unwrap();
    let mut newer = rec("a", "2");
    newer.consent = Some(ConsentRecord {
        given_at: 5,
        licence_text_sha256: HASH_B.into(),
    });
    record(&mut m, newer.clone()).unwrap();
    assert_eq!(ids(&m), ["a", "b"]);
    assert_eq!(m.dependencies[0], newer);
    assert_eq!(consent_of(&m, "a", "2").unwrap().given_at, 5);
    assert_eq!(consent_of(&m, "b", "1"), None);
    m.validate().unwrap();
}

#[test]
fn record_marks_an_old_schema_file_as_current() {
    let mut m = md();
    m.schema_version = 1;
    record(&mut m, rec("a", "1")).unwrap();
    assert_eq!(m.schema_version, SCHEMA_VERSION);
}

#[test]
fn record_enforces_the_count_cap_but_still_replaces_at_the_cap() {
    let mut m = md();
    for i in 0..MAX_DEPENDENCIES {
        record(&mut m, rec(&format!("p{i:04}"), "1")).unwrap();
    }
    m.validate().unwrap();
    let before = m.clone();
    assert_eq!(record(&mut m, rec("zzz", "1")), Err(StateError::TooMany));
    assert_eq!(m, before, "a refused record leaves the metadata unchanged");
    record(&mut m, rec("p0000", "2")).unwrap();
    assert_eq!(m.dependencies.len(), MAX_DEPENDENCIES);
    assert_eq!(m.dependencies[0].version, "2");
}

#[test]
fn forget_removes_only_that_id() {
    let mut m = md();
    for id in ["a", "b", "c"] {
        record(&mut m, rec(id, "1")).unwrap();
    }
    assert!(forget(&mut m, "b"));
    assert_eq!(ids(&m), ["a", "c"]);
    assert!(!forget(&mut m, "b"));
    assert_eq!(ids(&m), ["a", "c"]);
}

#[test]
fn consent_is_per_package_and_per_version() {
    let mut m = md();
    let mut vc = rec("vcrun2022", "14.40");
    vc.consent = Some(ConsentRecord {
        given_at: 7,
        licence_text_sha256: HASH_B.into(),
    });
    record(&mut m, vc).unwrap();
    record(&mut m, rec("dxvk", "2.4")).unwrap();
    assert_eq!(consent_of(&m, "vcrun2022", "14.40").unwrap().given_at, 7);
    assert_eq!(
        consent_of(&m, "vcrun2022", "14.42"),
        None,
        "old consent must not cover a new version"
    );
    assert_eq!(consent_of(&m, "vcrun2022", "14.4"), None, "exact match, not a prefix");
    assert_eq!(consent_of(&m, "missing", "14.40"), None);
    assert_eq!(consent_of(&m, "dxvk", "2.4"), None, "recorded without consent");
}
