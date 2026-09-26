//! Committed downstream regressions, replayed on every run.
//!
//! `regressions.tsv` holds one target per line: the path as a Rust debug string
//! (the same spelling as the reports and shrink artifacts), a tab, and free-text
//! provenance. Blank lines and lines starting with `#` are ignored.

pub struct Regression {
    pub path: String,
    pub provenance: String,
}

pub fn load() -> Vec<Regression> {
    parse(include_str!("regressions.tsv"))
        .unwrap_or_else(|error| panic!("regressions.tsv: {error}"))
}

pub fn parse(text: &str) -> Result<Vec<Regression>, String> {
    let mut regressions = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (path, provenance) = line
            .split_once('\t')
            .ok_or_else(|| format!("line {}: expected <path>\\t<provenance>", number + 1))?;
        let path =
            parse_debug_str(path).map_err(|error| format!("line {}: {error}", number + 1))?;
        if !path.starts_with('/') || path.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err(format!(
                "line {}: {path:?} is not an origin-form target without whitespace",
                number + 1
            ));
        }
        if provenance.trim().is_empty() {
            return Err(format!("line {}: missing provenance", number + 1));
        }
        regressions.push(Regression {
            path,
            provenance: provenance.trim().to_owned(),
        });
    }
    Ok(regressions)
}

/// Parses the subset of Rust's `{:?}` string syntax that `Debug for str` emits.
pub fn parse_debug_str(quoted: &str) -> Result<String, String> {
    let inner = quoted
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .ok_or_else(|| format!("{quoted} is not a quoted debug string"))?;
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '"' {
            return Err(format!("unescaped quote in {quoted}"));
        }
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next() {
            Some('0') => '\0',
            Some('t') => '\t',
            Some('r') => '\r',
            Some('n') => '\n',
            Some('\\') => '\\',
            Some('"') => '"',
            Some('\'') => '\'',
            Some('u') => {
                if chars.next() != Some('{') {
                    return Err(format!("malformed unicode escape in {quoted}"));
                }
                let mut hex = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(c) => hex.push(c),
                        None => return Err(format!("unterminated unicode escape in {quoted}")),
                    }
                }
                u32::from_str_radix(&hex, 16)
                    .ok()
                    .and_then(char::from_u32)
                    .ok_or_else(|| format!("invalid unicode escape {hex:?} in {quoted}"))?
            }
            other => return Err(format!("unsupported escape {other:?} in {quoted}")),
        });
    }
    Ok(out)
}

#[test]
fn debug_strings_round_trip() {
    for path in [
        "/a\\b",
        "/a\0b",
        "/a\"b",
        "/caf\u{e9}",
        "/a\u{1}b",
        "/a\u{301}b",
        "/%23",
    ] {
        assert_eq!(parse_debug_str(&format!("{path:?}")).unwrap(), path);
    }
    assert!(parse_debug_str("/unquoted").is_err());
    assert!(parse_debug_str("\"/a\\qb\"").is_err());
}

#[test]
fn committed_regressions_parse() {
    let regressions = load();
    assert!(!regressions.is_empty());
    assert!(regressions.iter().all(|r| !r.provenance.is_empty()));
    assert!(parse("\"/a\"").is_err(), "provenance is required");
    assert!(parse("\"a\"\tno leading slash").is_err());
    assert!(parse("# comment\n\n\"/a\"\tnote").unwrap().len() == 1);
}

#[test]
fn unicode_escapes_require_a_closing_brace() {
    assert!(parse_debug_str(r#""/\u{41""#).is_err());
    assert!(parse("\"/\\u{41\"\tmanual regression").is_err());
    assert_eq!(parse_debug_str(r#""/\u{41}b""#).unwrap(), "/Ab");
}
