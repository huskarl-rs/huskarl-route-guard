//! Bounded delta debugging for downstream mismatches.
//!
//! Deletes progressively smaller character ranges while the mismatch persists.
//! The leading `/` is never removed, so every candidate stays origin-form, and
//! deletion cannot introduce whitespace.

pub struct Shrunk {
    pub path: String,
    /// Predicate evaluations spent (each may cost one backend request).
    pub checks: usize,
    /// The budget ran out before reaching a local minimum.
    pub exhausted: bool,
}

pub fn shrink(path: &str, max_checks: usize, mut fails: impl FnMut(&str) -> bool) -> Shrunk {
    let mut current: Vec<char> = path.chars().collect();
    let mut checks = 0;
    let mut chunk = (current.len() / 2).max(1);
    loop {
        let mut reduced = false;
        let mut start = 1;
        while start < current.len() {
            if checks == max_checks {
                return Shrunk {
                    path: current.into_iter().collect(),
                    checks,
                    exhausted: true,
                };
            }
            let end = (start + chunk).min(current.len());
            let candidate: String = current[..start].iter().chain(&current[end..]).collect();
            checks += 1;
            if fails(&candidate) {
                current = candidate.chars().collect();
                reduced = true;
            } else {
                start += chunk;
            }
        }
        match (reduced, chunk) {
            (false, 1) => break,
            (false, _) => chunk /= 2,
            // Retry the same granularity: removals can enable earlier ones.
            (true, _) => chunk = chunk.min((current.len() / 2).max(1)),
        }
    }
    Shrunk {
        path: current.into_iter().collect(),
        checks,
        exhausted: false,
    }
}

#[test]
fn shrinks_to_a_minimal_failing_path() {
    let shrunk = shrink("/foo/secret%23/bar", 1000, |p| p.contains("%23"));
    assert_eq!(shrunk.path, "/%23");
    assert!(!shrunk.exhausted);
}

#[test]
fn keeps_the_leading_slash_and_respects_the_budget() {
    let shrunk = shrink("/abcdef", 1000, |_| true);
    assert_eq!(shrunk.path, "/");
    let shrunk = shrink("/foo/secret%23/bar", 3, |p| p.contains("%23"));
    assert_eq!(shrunk.checks, 3);
    assert!(shrunk.exhausted);
    assert!(shrunk.path.contains("%23"));
}

#[test]
fn a_non_failing_predicate_leaves_the_path_unchanged() {
    let shrunk = shrink("/a/b", 1000, |_| false);
    assert_eq!(shrunk.path, "/a/b");
    assert!(!shrunk.exhausted);
}
