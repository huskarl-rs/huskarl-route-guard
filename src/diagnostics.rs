//! Optional configuration lints with concrete routing witnesses.

use http::Method;

use crate::{
    MethodMatch, ResolveError,
    guard::PathConfusionGuard,
    route_tree::{Pattern, RuleId, Segment},
};

/// Raw routing identity for diagnostics, without an authorization rule reference.
///
/// This does not establish that ambiguity checks passed. Request handling must
/// use [`RuleRouter::resolve`](crate::RuleRouter::resolve).
///
/// ```compile_fail
/// use huskarl_route_guard::RawMatch;
/// let diagnostic = RawMatch::Matched { id: 0 };
/// let policy = diagnostic.rule(); // Diagnostics deliberately expose no policy.
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawMatch {
    /// A registration's position in construction order.
    Matched {
        /// The registration ID.
        id: u32,
    },
    /// No rule at the selected path serves this method, or no path matched.
    Default,
}

impl RawMatch {
    /// The registration ID, or `None` for the default.
    #[must_use]
    pub fn id(self) -> Option<u32> {
        match self {
            Self::Matched { id } => Some(id),
            Self::Default => None,
        }
    }

    /// Whether raw matching selects the default.
    #[must_use]
    pub fn is_default(self) -> bool {
        matches!(self, Self::Default)
    }
}

/// Diagnostic explanation of a path's configured guard checks.
///
/// No policy reference is returned. Use `resolve` for request handling; an
/// explanation may allocate and inspect the route table beyond the normal checks.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolutionExplanation {
    /// Identity selected by the original path spelling.
    pub raw_match: RawMatch,
    /// The first denial, in the same check order as `resolve`, or `None`.
    pub denial: Option<ResolveError>,
    /// Coverage used by a scoped structural denial, if that check was reached.
    /// Unconditional NUL denials, strict mode, and other checks have no anchor.
    pub structural: Option<StructuralExplanation>,
}

/// The conservative region responsible for a scoped structural denial.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct StructuralExplanation {
    /// Stable prefix retained after accounting for potential traversal.
    pub anchor: String,
    /// Registration IDs contributing to the region's coverage, sorted and unique.
    /// These are conservative possibilities, not necessarily actual normalized paths.
    pub registrations: Vec<u32>,
    /// Whether the default identity also contributes to the region's coverage.
    pub includes_default: bool,
}

/// A path terminal selects the default for methods served by its path fallback.
///
/// This is advisory: the gap may be intentional. It can also prevent uniform
/// structural coverage and cause encoded paths in the surrounding region to be
/// denied. Supplying a same-path rule fixes the gap, but a separate registration
/// still has a distinct identity. Group patterns in one registration when they
/// should share identity.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct MethodGapDiagnostic {
    /// A pattern at the terminal that prevents path fallback.
    pub pattern: String,
    /// A concrete raw path demonstrating the gap.
    pub example_path: String,
    /// Methods selecting the default at this path.
    ///
    /// Only standard HTTP methods and explicitly registered extension methods are
    /// examined; this list need not include every affected extension method.
    pub methods: Vec<Method>,
    /// Registration ID selected if the blocking path terminal were absent.
    ///
    /// All method rules at that terminal are ignored together for this comparison.
    pub shadowed_registration: u32,
}

impl std::fmt::Display for MethodGapDiagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "pattern {:?} selects the default for ", self.pattern)?;
        for (index, method) in self.methods.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{method}")?;
        }
        write!(
            f,
            " at {:?}, hiding registration {}; this method gap can also cause encoded paths in the surrounding region to be denied",
            self.example_path, self.shadowed_registration
        )
    }
}

pub(crate) struct DiagnosticPattern {
    pub(crate) parsed: Pattern,
    pub(crate) source: String,
    pub(crate) id: RuleId,
    pub(crate) methods: MethodMatch,
}

pub(crate) fn method_gaps(
    patterns: &[DiagnosticPattern],
    guard: &PathConfusionGuard,
) -> Vec<MethodGapDiagnostic> {
    let mut methods = vec![
        Method::GET,
        Method::HEAD,
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::CONNECT,
        Method::OPTIONS,
        Method::TRACE,
        Method::PATCH,
    ];
    for pattern in patterns {
        if let MethodMatch::OneOf(exact) = &pattern.methods {
            for method in exact {
                if !methods.contains(method) {
                    methods.push(method.clone());
                }
            }
        }
    }
    // An unconstrained capture should not accidentally hit another literal route.
    let mut capture = "_route_guard_probe".to_owned();
    while patterns.iter().any(|p| {
        p.parsed
            .segments
            .iter()
            .any(|segment| matches!(segment, Segment::Literal(literal) if literal == &capture))
    }) {
        capture.push('_');
    }
    let mut diagnostics: Vec<MethodGapDiagnostic> = Vec::new();
    for (index, pattern) in patterns.iter().enumerate() {
        let MethodMatch::OneOf(handled) = &pattern.methods else {
            continue;
        };
        // Co-located method registrations form one terminal, even if parameter
        // names differ. A same-terminal Any rule eliminates all method gaps.
        if patterns
            .iter()
            .any(|other| other.parsed == pattern.parsed && other.methods == MethodMatch::Any)
            || patterns
                .iter()
                .take(index)
                .any(|other| other.parsed == pattern.parsed)
        {
            continue;
        }
        for other in patterns {
            let Some(path) = overlap_path(&pattern.parsed, &other.parsed, &capture) else {
                continue;
            };
            if !handled
                .iter()
                .any(|method| guard.resolve(&path, method) == Some(pattern.id))
            {
                continue;
            }
            for method in &methods {
                let Some(shadowed_registration) = guard.method_gap(&path, method) else {
                    continue;
                };
                if let Some(existing) = diagnostics.iter_mut().find(|diagnostic| {
                    diagnostic.pattern == pattern.source
                        && diagnostic.example_path == path
                        && diagnostic.shadowed_registration == shadowed_registration
                }) {
                    if !existing.methods.contains(method) {
                        existing.methods.push(method.clone());
                    }
                } else {
                    diagnostics.push(MethodGapDiagnostic {
                        pattern: pattern.source.clone(),
                        example_path: path.clone(),
                        methods: vec![method.clone()],
                        shadowed_registration,
                    });
                }
            }
        }
    }
    diagnostics
}

/// One representative of a pairwise intersection. Actual matching subsequently
/// checks precedence against the whole table, so a hidden overlap cannot warn.
fn overlap_path(a: &Pattern, b: &Pattern, capture: &str) -> Option<String> {
    let a_tail = matches!(a.segments.last(), Some(Segment::CatchAll));
    let b_tail = matches!(b.segments.last(), Some(Segment::CatchAll));
    let count = a.segments.len().max(b.segments.len());
    if (!a_tail && a.segments.len() != count)
        || (!b_tail && b.segments.len() != count)
        || (!a_tail && !b_tail && a.trailing_slash != b.trailing_slash)
    {
        return None;
    }
    let mut path = String::new();
    for index in 0..count {
        let segment = match (a.segments.get(index), b.segments.get(index)) {
            (Some(Segment::Literal(a)), Some(Segment::Literal(b))) if a != b => return None,
            (Some(Segment::Literal(literal)), _) | (_, Some(Segment::Literal(literal))) => literal,
            _ => capture,
        };
        path.push('/');
        path.push_str(segment);
    }
    if path.is_empty() || (!a_tail && a.trailing_slash) || (!b_tail && b.trailing_slash) {
        path.push('/');
    }
    Some(path)
}
