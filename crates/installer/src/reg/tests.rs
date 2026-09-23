use super::*;
use std::time::{Duration, Instant};

fn parse_ok(input: &str) -> WineReg {
    WineReg::parse(input.as_bytes()).expect("parse should not hard-fail on well-formed or malformed text")
}

#[test]
fn header_comment_arch_directive_and_time_lines_are_ignored_without_a_warning() {
    let mut input = String::new();
    input.push_str("WINE REGISTRY Version 2\n");
    input.push_str(";; All keys relative to REGISTRY\\\\Machine\n");
    input.push('\n');
    input.push_str("#arch=win64\n");
    input.push('\n');
    input.push_str("[Software\\\\Vendor] 1790095421\n");
    input.push_str("#time=1dd4ab186274fb4\n");
    input.push_str("\"Plain\"=\"value\"\n");
    let reg = parse_ok(&input);
    assert!(reg.warnings.is_empty(), "warnings: {:?}", reg.warnings);
    assert!(!reg.truncated);
    assert_eq!(reg.keys.len(), 1);
    let key = &reg.keys["Software\\Vendor"];
    assert_eq!(key.timestamp, Some(1790095421));
    assert_eq!(key.values["Plain"], RegValue::Str("value".into()));
}

#[test]
fn parses_string_dword_and_default_values() {
    let mut input = String::new();
    input.push_str("[Control Panel\\\\Desktop] 100\n");
    input.push_str("\"DragWidth\"=\"4\"\n");
    input.push_str("\"CaretWidth\"=dword:00000001\n");
    input.push_str("@=\"default text\"\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.warnings, Vec::<String>::new());
    let key = &reg.keys["Control Panel\\Desktop"];
    assert_eq!(key.values["DragWidth"], RegValue::Str("4".into()));
    assert_eq!(key.values["CaretWidth"], RegValue::Dword(1));
    assert_eq!(key.values[""], RegValue::Default("default text".into()));
}

/// Real line from a Wine 10.0 prefix after `hello.msi` installed (REG_EXPAND_SZ written as `str(2):`).
#[test]
fn str2_expand_sz_values_parse_as_strings() {
    let mut input = String::new();
    input.push_str("[Software\\\\Wow6432Node\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Uninstall\\\\{X}] 1\n");
    input.push_str("\"UninstallString\"=str(2):\"MsiExec.exe /I{X}\"\n");
    input.push_str("\"Path\"=str(2):\"%SystemRoot%\\\\a\"\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.warnings, Vec::<String>::new());
    let key = &reg.keys["Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{X}"];
    assert_eq!(key.values["UninstallString"], RegValue::Str("MsiExec.exe /I{X}".into()));
    assert_eq!(key.values["Path"], RegValue::Str("%SystemRoot%\\a".into()));
}

#[test]
fn escaped_backslash_quote_cr_and_lf_decode_like_real_wine_does() {
    // Real sample from a live Wine 10.0 prefix's system.reg (this exact shape, minus the surrounding key):
    // @="\"C:\\windows\\system32\\notepad.exe\" \"%1\""  ->  "C:\windows\system32\notepad.exe" "%1"
    // This test additionally folds in \r and \n, which were not present in that particular value but are
    // documented Wine escapes; nothing in the real files contradicts them.
    let mut input = String::new();
    input.push_str("[Software\\\\Escapes] 1\n");
    input.push_str("\"N\"=\"a\\\\b\\\"c\\r\\nd\"\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.warnings, Vec::<String>::new());
    let key = &reg.keys["Software\\Escapes"];
    assert_eq!(key.values["N"], RegValue::Str("a\\b\"c\r\nd".into()));
}

#[test]
fn x_hhhh_escape_decodes_a_surrogate_pair_exactly_like_a_real_prefix() {
    // Real sample from a live Wine 10.0 prefix's user.reg:
    // [Control Panel\\International\\\xd83c\xdf0e\xd83c\xdf0f\xd83c\xdf0d] 1790095416
    // Each \xHHHH pair is one UTF-16 surrogate; \xd83c\xdf0e decodes to U+1F30E.
    let mut input = String::new();
    input.push_str("[Control Panel\\\\International\\\\\\xd83c\\xdf0e] 1790095416\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.warnings, Vec::<String>::new());
    assert!(
        reg.keys.contains_key("Control Panel\\International\\\u{1F30E}"),
        "keys: {:?}",
        reg.keys.keys()
    );
}

#[test]
fn hex_binary_values_and_their_backslash_continuation_lines_are_skipped_without_a_warning() {
    let mut input = String::new();
    input.push_str("[Software\\\\Codec] 1\n");
    input.push_str("\"FilterData\"=hex:02,00,00,00,\\\n");
    input.push_str("  00,60,00,02,\\\n");
    input.push_str("  00,00\n");
    input.push_str("\"Next\"=\"ok\"\n");
    let reg = parse_ok(&input);
    assert_eq!(
        reg.warnings,
        Vec::<String>::new(),
        "hex values are real and common: never warn about them"
    );
    let key = &reg.keys["Software\\Codec"];
    assert_eq!(
        key.values.len(),
        1,
        "only the modelled value should survive: {:?}",
        key.values
    );
    assert_eq!(key.values["Next"], RegValue::Str("ok".into()));
}

#[test]
fn three_good_blocks_survive_two_interspersed_malformed_lines_with_one_aggregate_warning() {
    let mut input = String::new();
    input.push_str("[A] 1\n");
    input.push_str("\"X\"=\"1\"\n");
    input.push('\n');
    input.push_str("NoBracketAtAll\n"); // malformed: not recognised at all outside a key
    input.push('\n');
    input.push_str("[B] 2\n");
    input.push_str("\"Y\"=\"2\"\n");
    input.push('\n');
    input.push_str("[Unclosed 3\n"); // malformed: '[' with no ']'
    input.push('\n');
    input.push_str("[C] 3\n");
    input.push_str("\"Z\"=\"3\"\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.keys.len(), 3, "keys: {:?}", reg.keys.keys());
    assert!(reg.keys.contains_key("A") && reg.keys.contains_key("B") && reg.keys.contains_key("C"));
    assert_eq!(
        reg.warnings.len(),
        1,
        "exactly one AGGREGATE warning, never one per bad line: {:?}",
        reg.warnings
    );
    assert!(
        reg.warnings[0].contains('2'),
        "should mention the count of 2 skipped lines: {}",
        reg.warnings[0]
    );
}

#[test]
fn a_value_line_with_no_equals_sign_is_malformed_but_the_rest_of_the_key_survives() {
    let mut input = String::new();
    input.push_str("[K] 1\n");
    input.push_str("\"NoEquals\"\n");
    input.push_str("\"Good\"=\"kept\"\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.warnings.len(), 1, "{:?}", reg.warnings);
    let key = &reg.keys["K"];
    assert!(!key.values.contains_key("NoEquals"));
    assert_eq!(key.values["Good"], RegValue::Str("kept".into()));
}

#[test]
fn invalid_dword_hex_is_skipped_but_the_rest_of_the_key_survives() {
    let mut input = String::new();
    input.push_str("[K] 1\n");
    input.push_str("\"Bad\"=dword:zzzzzzzz\n");
    input.push_str("\"Good\"=\"kept\"\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.warnings.len(), 1);
    let key = &reg.keys["K"];
    assert!(!key.values.contains_key("Bad"));
    assert_eq!(key.values["Good"], RegValue::Str("kept".into()));
}

#[test]
fn an_unterminated_quoted_string_is_malformed_not_a_panic() {
    let mut input = String::new();
    input.push_str("[K] 1\n");
    input.push_str("\"Bad\"=\"never closed\n");
    let reg = parse_ok(&input);
    assert_eq!(reg.warnings.len(), 1);
    assert!(reg.keys["K"].values.is_empty());
}

#[test]
fn a_key_line_with_no_closing_bracket_is_malformed_not_a_panic() {
    let reg = parse_ok("[NoClose 1\n\"V\"=\"x\"\n");
    assert_eq!(reg.warnings.len(), 1);
    assert!(reg.keys.is_empty());
}

#[test]
fn a_key_path_deeper_than_the_cap_is_skipped_and_reported_not_silently_dropped() {
    let deep = (0..MAX_KEY_DEPTH + 1)
        .map(|i| format!("S{i}"))
        .collect::<Vec<_>>()
        .join("\\\\");
    let input = format!("[{deep}] 1\n");
    let reg = parse_ok(&input);
    assert!(reg.keys.is_empty(), "an over-deep key must not be added");
    assert_eq!(reg.warnings.len(), 1);
}

#[test]
fn control_characters_decoded_via_x_hhhh_never_panic() {
    let reg = parse_ok("[K] 1\n\"V\"=\"a\\x0001b\"\n");
    assert_eq!(reg.warnings, Vec::<String>::new());
    assert_eq!(reg.keys["K"].values["V"], RegValue::Str("a\u{1}b".into()));
}

#[test]
fn the_key_count_cap_stops_growth_and_sets_truncated_without_hanging() {
    let mut input = String::with_capacity((MAX_KEYS + 50) * 12);
    for i in 0..MAX_KEYS + 50 {
        input.push_str(&format!("[K{i}] 1\n\n"));
    }
    let started = Instant::now();
    let reg = parse_ok(&input);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    assert_eq!(reg.keys.len(), MAX_KEYS);
    assert!(reg.truncated);
}

#[test]
fn a_multi_megabyte_single_line_value_is_skipped_via_the_line_length_cap_not_allocated() {
    let huge = "A".repeat(3 * 1024 * 1024);
    let input = format!("[K] 1\n\"V\"=\"{huge}\"\n\n[K2] 2\n\"Ok\"=\"fine\"\n");
    let started = Instant::now();
    let reg = parse_ok(&input);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
    assert!(
        reg.keys["K"].values.is_empty(),
        "the oversized line must not have produced a value"
    );
    assert_eq!(reg.keys["K2"].values["Ok"], RegValue::Str("fine".into()));
    assert_eq!(reg.warnings.len(), 1);
}

// --- mutation checks (guards temporarily removed by hand, see the task report for the exact names) ---
// - `header_comment_arch_directive_and_time_lines_are_ignored_without_a_warning` and
//   `three_good_blocks_survive_two_interspersed_malformed_lines_with_one_aggregate_warning` fail if the
//   malformed-line-skip-not-abort behaviour is removed (i.e. `note_malformed` made to abort the whole parse).
// - `a_key_path_deeper_than_the_cap_is_skipped_and_reported_not_silently_dropped` fails if `MAX_KEY_DEPTH` is
//   removed or the check deleted.
// - `the_key_count_cap_stops_growth_and_sets_truncated_without_hanging` fails (times out or exceeds the cap) if
//   `MAX_KEYS` is removed.
// - `a_multi_megabyte_single_line_value_is_skipped_via_the_line_length_cap_not_allocated` fails if
//   `MAX_LINE_BYTES` is removed.
