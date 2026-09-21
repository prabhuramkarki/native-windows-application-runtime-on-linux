//! Tests against Windows binaries built by tools/build-fixtures.sh (needs mingw-w64).
use std::path::PathBuf;

fn load(name: &str) -> pe::PeInfo {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/build")
        .join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|_| panic!("missing fixture {name}: run tools/build-fixtures.sh"));
    pe::analyze(&bytes).expect("analyze fixture")
}

#[test]
fn version_info_is_read_from_the_hello_fixture() {
    let v = load("hello64.exe").version.expect("VERSIONINFO resource");
    assert_eq!(v.file_version.as_deref(), Some("1.2.3.4"));
    assert_eq!(
        v.strings.get("ProductName").map(String::as_str),
        Some("Runtime Fixture")
    );
}
