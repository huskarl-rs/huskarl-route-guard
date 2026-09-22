//! Owned route grammar + segment-tree matcher.
//!
//! This is the keystone of the path-confusion redesign: a matcher we **own**, so the
//! scoped structural verdict can read the route structure directly — per-node
//! coverage summaries, the anchor walk — instead of reverse-engineering `matchit`'s
//! opaque parse tree. The grammar is a deliberately small, whole-segment, anonymous
//! subset of `matchit` syntax:
//!
//! - a segment is a **literal** (matched byte-for-byte) or a lone `*` **wildcard**;
//! - `*` matches exactly one non-empty segment, **except** the final `*` in a pattern,
//!   which is a **catch-all** matching the raw remainder (1+ chars, `//` and trailing
//!   slashes included — `matchit` catch-all semantics);
//! - a literal `*` is written by doubling: a segment of `k >= 2` stars is the literal
//!   string of `k - 1` stars (`**` → `*`, `***` → `**`);
//! - a trailing `/` is significant (`/a` and `/a/` are distinct routes, as in `matchit`).
//!
//! Capturing is anonymous and unrecorded — the auth layer never reads captured
//! values, only *which rule* matched; the structural verdict works from the scanner's
//! byte offsets and the tree's coverage summaries, not from capture spans.
//!
//! `matchit` is retained **only as a test oracle** (see the proptest below): the runtime
//! matcher has no external dependency. "Lowering equivalence" now lives entirely in the
//! tests — for every pattern in this grammar, the owned matcher must agree with `matchit`
//! on the pattern's lowered form.

use std::{collections::HashMap, sync::Arc};

use crate::{
    path_confusion::{
        CaseSensitivity, DecodeLayers, DenyReason, PathConfusion, StructuralClasses,
        StructuralProbe,
    },
    structural::{
        ClassSet, Encodings, ScanResult, classes_present, enabled_classes, enabled_encodings,
        primary_class, scan,
    },
};

/// Identifier for a registered rule. Patterns from one `route`/`subtree` call share one.
pub(crate) type RuleId = u32;

/// The rule id of the **default** rule (paths matching no registered route). The
/// coverage algebra treats it as an ordinary participating value, so "falls through to
/// the default" and "matches registration N" are compared on the same footing.
pub(crate) const DEFAULT_RULE: RuleId = u32::MAX;

/// A join-semilattice summary of a set of rule ids — the currency of the scoped
/// structural verdict. `Empty` is the identity, joining two equal `Uniform`s is
/// idempotent, and anything else is `Mixed`. [`DEFAULT_RULE`] is a legal `Uniform`
/// value (a wholly unrouted subtree is *uniformly the default rule*).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum Cover {
    /// No terminals contribute.
    #[default]
    Empty,
    /// Every contributing terminal resolves to this one rule id.
    Uniform(RuleId),
    /// At least two distinct rule ids contribute.
    Mixed,
}

impl Cover {
    /// The semilattice join.
    fn join(self, other: Cover) -> Cover {
        match (self, other) {
            (Cover::Empty, c) | (c, Cover::Empty) => c,
            (Cover::Uniform(a), Cover::Uniform(b)) if a == b => self,
            _ => Cover::Mixed,
        }
    }

    /// Join a single rule id into the summary.
    fn with(self, id: RuleId) -> Cover {
        self.join(Cover::Uniform(id))
    }
}

/// One segment of a parsed pattern.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Segment {
    /// A literal segment, already unescaped; matched byte-for-byte.
    Literal(String),
    /// A `*` in a non-final position: matches exactly one non-empty segment.
    Wildcard,
    /// A `*` in the final position: matches the raw remainder (1+ chars).
    CatchAll,
}

/// A parsed pattern: its segments plus whether it ends in a significant trailing slash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Pattern {
    pub(crate) segments: Vec<Segment>,
    pub(crate) trailing_slash: bool,
}

/// Why a pattern string is not a valid route in this grammar.
///
/// Test-only: production lowers public matchit syntax via [`lower_matchit`]; the native
/// `*`-grammar parser ([`parse_pattern`]) is exercised only by the unit tests and oracle.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PatternError {
    /// The pattern did not begin with `/`.
    MissingLeadingSlash,
    /// An interior `//` (an empty, non-trailing segment) — degenerate.
    EmptyInteriorSegment,
}

/// Why a public matchit-style pattern could not be lowered into this grammar.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LowerError {
    /// The pattern did not begin with `/`.
    MissingLeadingSlash,
    /// An interior `//` (an empty, non-trailing segment).
    EmptyInteriorSegment,
    /// A param with a static prefix or suffix in its segment (`/v{ver}`,
    /// `/img-{id}.png`). The whole-segment grammar cannot express these.
    PrefixSuffixParam,
    /// A catch-all `{*rest}` that is not the final segment.
    CatchAllNotLast,
    /// A malformed parameter group (stray or unterminated brace).
    MalformedParam,
    /// A parameter has no name, or its name contains `*`.
    InvalidParam,
}

/// Classify one segment's text into a [`Segment`], applying the star-doubling escape.
#[cfg(test)]
fn classify_segment(seg: &str) -> Segment {
    if !seg.is_empty() && seg.bytes().all(|b| b == b'*') {
        if seg.len() == 1 {
            Segment::Wildcard
        } else {
            // `k >= 2` stars → the literal string of `k - 1` stars.
            Segment::Literal("*".repeat(seg.len() - 1))
        }
    } else {
        Segment::Literal(seg.to_owned())
    }
}

/// Parse a pattern string into a [`Pattern`].
///
/// # Errors
///
/// [`PatternError`] if the pattern lacks a leading slash or contains an interior empty
/// segment.
#[cfg(test)]
pub(crate) fn parse_pattern(pat: &str) -> Result<Pattern, PatternError> {
    if !pat.starts_with('/') {
        return Err(PatternError::MissingLeadingSlash);
    }
    let trailing_slash = pat.len() > 1 && pat.ends_with('/');
    // Body: drop the leading slash and the single significant trailing slash.
    let end = pat.len() - usize::from(trailing_slash);
    let body = &pat[1..end];

    let mut segments = Vec::new();
    if !body.is_empty() {
        for seg in body.split('/') {
            if seg.is_empty() {
                return Err(PatternError::EmptyInteriorSegment);
            }
            segments.push(classify_segment(seg));
        }
    }
    // Positional arity: the final lone `*` (with no significant trailing slash) is the
    // catch-all; interior `*` stay single-segment wildcards.
    if !trailing_slash && matches!(segments.last(), Some(Segment::Wildcard)) {
        let last = segments.len() - 1;
        segments[last] = Segment::CatchAll;
    }
    Ok(Pattern {
        segments,
        trailing_slash,
    })
}

/// Lower a public **matchit-style** pattern string (`/users/{id}`, `/files/{*rest}`)
/// into an owned [`Pattern`]: `{name}` → [`Segment::Wildcard`], `{*name}` →
/// [`Segment::CatchAll`], static text → [`Segment::Literal`] (braces unescaped).
///
/// This is the build-time bridge from the public API's familiar `{name}` syntax to the
/// anonymous whole-segment grammar; the names are discarded (the auth layer never reads
/// captured values).
///
/// # Errors
///
/// [`LowerError`] for a missing leading slash, an empty interior segment, a non-final
/// catch-all, a malformed param, or a **prefix/suffix param** (`/v{ver}`) — which the
/// whole-segment grammar cannot represent.
pub(crate) fn lower_matchit(pat: &str) -> Result<Pattern, LowerError> {
    if !pat.starts_with('/') {
        return Err(LowerError::MissingLeadingSlash);
    }
    let trailing_slash = pat.len() > 1 && pat.ends_with('/');
    let end = pat.len() - usize::from(trailing_slash);
    let body = &pat[1..end];

    let mut segments = Vec::new();
    if !body.is_empty() {
        let parts: Vec<&str> = body.split('/').collect();
        let last = parts.len() - 1;
        for (idx, seg) in parts.iter().enumerate() {
            if seg.is_empty() {
                return Err(LowerError::EmptyInteriorSegment);
            }
            match lower_segment(seg)? {
                SegLower::Literal(s) => segments.push(Segment::Literal(s)),
                SegLower::Wildcard => segments.push(Segment::Wildcard),
                SegLower::CatchAll => {
                    // A significant trailing slash means the catch-all is not actually
                    // the final path component (`/{*rest}/`), which matchit rejects.
                    if idx != last || trailing_slash {
                        return Err(LowerError::CatchAllNotLast);
                    }
                    segments.push(Segment::CatchAll);
                }
            }
        }
    }
    Ok(Pattern {
        segments,
        trailing_slash,
    })
}

/// The lowering of a single matchit segment.
enum SegLower {
    Literal(String),
    Wildcard,
    CatchAll,
}

/// Lower one matchit segment. A segment is static, or a single `{…}` spanning the whole
/// segment; a `{…}` with surrounding static text is a prefix/suffix param and rejected.
fn lower_segment(seg: &str) -> Result<SegLower, LowerError> {
    let b = seg.as_bytes();
    let mut i = 0;
    // First *unescaped* `{` begins a parameter; `{{`/`}}` are literal braces.
    let open = loop {
        match b.get(i) {
            None => return Ok(SegLower::Literal(unescape_braces(seg))), // fully static
            Some(b'{') if b.get(i + 1) == Some(&b'{') => i += 2,
            Some(b'}') if b.get(i + 1) == Some(&b'}') => i += 2,
            Some(b'{') => break i,
            Some(b'}') => return Err(LowerError::MalformedParam), // stray unescaped `}`
            Some(_) => i += 1,
        }
    };
    // Param names contain no braces, so the next `}` closes the group.
    let close = open
        + 1
        + b.iter()
            .skip(open + 1)
            .position(|&c| c == b'}')
            .ok_or(LowerError::MalformedParam)?;
    // A whole-segment param spans the entire segment; anything else is prefix/suffix.
    if open != 0 || close != b.len() - 1 {
        return Err(LowerError::PrefixSuffixParam);
    }
    let inner = &seg[open + 1..close];
    let (catch_all, name) = inner
        .strip_prefix('*')
        .map_or((false, inner), |name| (true, name));
    // Matchit's parameter grammar requires a non-empty name and reserves `*` for
    // the one leading catch-all marker. `/` cannot occur here because segments have
    // already been split on it.
    if name.is_empty() || name.contains('*') {
        return Err(LowerError::InvalidParam);
    }
    if catch_all {
        Ok(SegLower::CatchAll)
    } else {
        Ok(SegLower::Wildcard)
    }
}

/// Unescape matchit's doubled braces (`{{` → `{`, `}}` → `}`) so a literal segment
/// matches the request path byte-for-byte.
fn unescape_braces(s: &str) -> String {
    if !s.contains("{{") && !s.contains("}}") {
        return s.to_owned();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let Some(&cur) = b.get(i) else { break };
        out.push(cur);
        i += usize::from(
            (cur == b'{' && b.get(i + 1) == Some(&b'{'))
                || (cur == b'}' && b.get(i + 1) == Some(&b'}')),
        ) + 1;
    }
    String::from_utf8(out).unwrap_or_else(|_| s.to_owned())
}

/// Which HTTP method(s) a registration applies to. `Any` (the default) matches every
/// method; `OneOf` matches the listed methods — all under the registration's **single
/// rule id**, so "this rule for GET and HEAD" is one registration, not two. Method is
/// **orthogonal to path**: it is consulted solely at terminal resolution, never during
/// path traversal or the structural verdict.
///
/// Builder methods taking `impl Into<MethodMatch>` accept a bare [`http::Method`], an
/// array, or a `Vec` of them. An empty `OneOf` matches nothing and is rejected at
/// build time ([`RuleRouterError::EmptyMethodSet`](crate::RuleRouterError::EmptyMethodSet))
/// rather than silently registering an unreachable rule.
///
/// # Path precedence
///
/// The router selects a path terminal before consulting this value. A literal path
/// terminal therefore remains more specific than a wildcard or catch-all terminal even
/// when it has no entry for the request method. In that case resolution uses an `Any`
/// entry at the same terminal, or the default rule; it does not backtrack to a
/// less-specific path. See the crate-level example.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum MethodMatch {
    /// Matches any method (the wildcard default).
    #[default]
    Any,
    /// Matches any of these methods (must be non-empty).
    OneOf(Vec<http::Method>),
}

impl From<http::Method> for MethodMatch {
    fn from(m: http::Method) -> Self {
        Self::OneOf(vec![m])
    }
}

impl<const N: usize> From<[http::Method; N]> for MethodMatch {
    fn from(ms: [http::Method; N]) -> Self {
        Self::OneOf(ms.into())
    }
}

impl From<Vec<http::Method>> for MethodMatch {
    fn from(ms: Vec<http::Method>) -> Self {
        Self::OneOf(ms)
    }
}

/// The rules terminating at one path position, keyed by method. A path can carry a
/// method-wildcard rule and any number of method-specific ones; resolution is
/// specific-method → wildcard → none.
#[derive(Default)]
struct MethodSlot {
    /// The method-wildcard rule, if any.
    any: Option<RuleId>,
    /// Method-specific rules.
    exact: Vec<(http::Method, RuleId)>,
}

impl MethodSlot {
    fn is_empty(&self) -> bool {
        self.any.is_none() && self.exact.is_empty()
    }

    /// Resolve a rule. `None` (method-blind) returns a stable **representative** for
    /// structural path-zone comparisons. `Some(m)` resolves specific-method → wildcard.
    fn get(&self, method: Option<&http::Method>) -> Option<RuleId> {
        match method {
            None => self.any.or_else(|| self.exact.first().map(|(_, id)| *id)),
            Some(m) => self
                .exact
                .iter()
                .find(|(em, _)| em == m)
                .map(|(_, id)| *id)
                .or(self.any),
        }
    }

    /// The [`Cover`] this slot contributes, over **all** methods — what makes the
    /// method-blind structural verdict sound. A slot is uniformly `X` only when its
    /// method-wildcard entry is `X` and every method-specific entry agrees; a slot
    /// with *only* method-specific entries resolves every other method to the default
    /// rule, so [`DEFAULT_RULE`] joins in (a method-qualified route inside an
    /// otherwise-uniform subtree keeps that subtree non-uniform).
    fn cover(&self) -> Cover {
        match self.any {
            Some(x) => {
                if self.exact.iter().all(|(_, id)| *id == x) {
                    Cover::Uniform(x)
                } else {
                    Cover::Mixed
                }
            }
            None => self
                .exact
                .iter()
                .fold(Cover::Empty, |c, (_, id)| c.with(*id))
                .join(if self.exact.is_empty() {
                    Cover::Empty
                } else {
                    Cover::Uniform(DEFAULT_RULE)
                }),
        }
    }

    /// Insert a rule for `method`; a duplicate `(position, method)` is a conflict
    /// ([`Router::build`] attributes it to the entry as [`BuildError::Conflict`]),
    /// including a method listed twice within one `OneOf`. An empty `OneOf` inserts
    /// nothing (the terminal stays unclaimed); `RuleRouter::build` rejects it before
    /// the tree is ever built.
    fn insert(&mut self, method: &MethodMatch, id: RuleId) -> Result<(), SlotConflict> {
        match method {
            MethodMatch::Any => {
                if self.any.is_some() {
                    return Err(SlotConflict);
                }
                self.any = Some(id);
            }
            MethodMatch::OneOf(ms) => {
                for m in ms {
                    if self.exact.iter().any(|(em, _)| em == m) {
                        return Err(SlotConflict);
                    }
                    self.exact.push((m.clone(), id));
                }
            }
        }
        Ok(())
    }
}

/// A node in the route tree. Structural bytes only ever land in a wildcard/catch-all
/// position (literals match canonical pattern bytes), and the scoped verdict reads the
/// per-node coverage summaries computed at build — the payoff of owning the matcher.
#[derive(Default)]
struct Node {
    /// Exact-segment children.
    literals: HashMap<String, Node>,
    /// The single `*` child at this depth, if any.
    wildcard: Option<Box<Node>>,
    /// Rules (no trailing slash) terminating here, keyed by method.
    leaf: MethodSlot,
    /// Rules *with* a trailing slash terminating here, keyed by method.
    leaf_slash: MethodSlot,
    /// Trailing catch-all rules rooted here, keyed by method.
    catchall: MethodSlot,
    /// Whether the catch-all was declared opaque (validated sibling-free at build). A
    /// path property, uniform across methods.
    catchall_opaque: bool,
    /// [`Cover`] of every terminal at or below this node, **including** its own
    /// [`leaf`](Node::leaf). Consulted when this node is entered from above (its whole
    /// subtree is reachable) and at the **root** anchor, where the empty remainder is
    /// the bare `/` — i.e. `root.leaf` (a `//` merge really can produce `/`).
    cov_all: Cover,
    /// Like [`cov_all`](Node::cov_all) but **excluding** this node's own `leaf`.
    /// Consulted at a non-root anchor-depth node: no modeled transform deletes the
    /// anchor's own clean trailing separator, so the bare no-slash form is unreachable.
    cov_below: Cover,
}

/// Why building a [`Router`] failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// Two rules claim the same terminal slot. `index` is the position, in the entries
    /// given to [`Router::build`], of the entry that hit the conflict — so the caller
    /// can name the offending pattern.
    Conflict {
        /// Index of the conflicting entry.
        index: usize,
    },
    /// An opaque catch-all shares its node with a routing sibling (a literal or wildcard
    /// child), so a boundary-shift byte in the blob could relocate into the sibling.
    OpaqueTailHasSibling {
        /// The literal path prefix of the offending catch-all's node (`*` stands for a
        /// wildcard segment).
        at: String,
    },
}

/// Internal marker for a terminal-slot conflict during insertion; [`Router::build`]
/// attributes it to the offending entry as [`BuildError::Conflict`].
struct SlotConflict;

/// A `path -> RuleId` matcher over the owned grammar.
pub(crate) struct Router {
    root: Node,
}

impl Router {
    /// Build a router from `(pattern, rule_id, opaque)` entries.
    ///
    /// `opaque` declares a pattern's trailing catch-all an opaque blob — a build-time
    /// guarantee that nothing else routes beneath it ([`validate_opaque`]), which is
    /// what keeps the subtree uniform for the scoped verdict; it is ignored for
    /// patterns without a catch-all and adds no runtime behavior of its own.
    ///
    /// # Errors
    ///
    /// [`BuildError`] on a terminal conflict or an opaque catch-all with a routing sibling.
    pub(crate) fn build(
        entries: &[(Pattern, RuleId, bool, MethodMatch)],
    ) -> Result<Self, BuildError> {
        let mut root = Node::default();
        for (i, (pat, id, opaque, method)) in entries.iter().enumerate() {
            insert(
                &mut root,
                &pat.segments,
                pat.trailing_slash,
                *id,
                *opaque,
                method,
            )
            .map_err(|SlotConflict| BuildError::Conflict { index: i })?;
        }
        validate_opaque(&root, &mut String::new())?;
        compute_cover(&mut root);
        Ok(Self { root })
    }

    /// Match `path`, then resolve the claimed terminal with `method` (`None` = method-blind
    /// representative). A path that claims a terminal but has no rule for `method` returns
    /// `None` — never a fall-back to a less-specific path.
    fn at(&self, path: &[u8], method: Option<&http::Method>) -> Option<RuleId> {
        let body = path.strip_prefix(b"/")?;
        let slot = if body.is_empty() {
            // The bare root path `/` claims the root leaf.
            (!self.root.leaf.is_empty()).then_some(&self.root.leaf)
        } else {
            route(&self.root, body)
        }?;
        // Method resolution happens once, on the claimed terminal — no backtracking.
        slot.get(method)
    }

    /// The matched rule id, **method-blind** (a stable per-terminal representative) — for
    /// structural path-zone comparisons and method-agnostic test oracles.
    pub(crate) fn route_id(&self, path: &str) -> Option<RuleId> {
        self.at(path.as_bytes(), None)
    }

    /// [`route_id`](Self::route_id) for a **raw byte** path — what a percent-decode can
    /// produce. Decoding `%FF` yields bytes that are not valid UTF-8, and a real backend
    /// routes them anyway; matching must model that rather than decline to answer. For
    /// valid UTF-8 this is identical to [`route_id`](Self::route_id) (splitting on the
    /// ASCII `/` keeps every segment valid), so the two can never disagree.
    #[cfg(test)]
    pub(crate) fn route_id_bytes(&self, path: &[u8]) -> Option<RuleId> {
        self.at(path, None)
    }

    /// The matched rule id for a raw-byte path and a specific method.
    pub(crate) fn resolve_bytes(&self, path: &[u8], method: &http::Method) -> Option<RuleId> {
        self.at(path, Some(method))
    }

    /// The matched rule id for a specific method (specific → wildcard → none).
    pub(crate) fn resolve(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        self.at(path.as_bytes(), Some(method))
    }

    /// The [`Cover`] of **every rule id reachable by any path extending `anchor`** — a
    /// clean, `/`-terminated prefix (`"/"`, `"/files/"`, …). This is the scoped
    /// structural verdict's core question: if the answer is `Uniform(matched)`, no
    /// reinterpretation confined to the anchor's subtree can relocate the request.
    ///
    /// Reachability must honor the matcher's backtracking (literal > wildcard >
    /// catch-all, [`route`]), so the walk is a small NFA-style descent: at each level
    /// both the literal child and the wildcard child matching the concrete segment stay
    /// viable (≤ 2 branches per level), and every viable node's catch-all joins in — a
    /// suffix that dead-ends deeper backtracks onto it. Paths that match *nothing*
    /// resolve to the default rule, so [`DEFAULT_RULE`] joins in unless the walk proves
    /// every suffix is covered (see [`walk_cover`]). The result is a superset of what
    /// concrete reinterpretations can reach — over-approximation only ever denies more.
    pub(crate) fn anchor_cover(&self, anchor: &str) -> Cover {
        let mut segs = anchor.split('/').filter(|s| !s.is_empty());
        if let Some(first) = segs.next() {
            let rest: Vec<&str> = segs.collect();
            let (cover, complete) = walk_cover(&self.root, first, &rest);
            if complete {
                cover
            } else {
                cover.with(DEFAULT_RULE)
            }
        } else {
            // Root anchor: the empty remainder is the bare `/`, which claims
            // `root.leaf` — so the *whole* table participates, own leaf included.
            // Complete only if both the bare `/` and every non-empty body are covered.
            let complete = !self.root.leaf.is_empty() && !self.root.catchall.is_empty();
            if complete {
                self.root.cov_all
            } else {
                self.root.cov_all.with(DEFAULT_RULE)
            }
        }
    }
}

/// Fill [`Node::cov_all`] / [`Node::cov_below`] bottom-up: a child's whole subtree is
/// reachable from its parent, so a child contributes its `cov_all`.
fn compute_cover(node: &mut Node) {
    let mut below = node.leaf_slash.cover().join(node.catchall.cover());
    for child in node.literals.values_mut() {
        compute_cover(child);
        below = below.join(child.cov_all);
    }
    if let Some(w) = node.wildcard.as_deref_mut() {
        compute_cover(w);
        below = below.join(w.cov_all);
    }
    node.cov_below = below;
    node.cov_all = below.join(node.leaf.cover());
}

/// One step of the [`Router::anchor_cover`] descent: the cover reachable from `node`
/// for paths whose next concrete segment is `seg` (then `rest`, then any suffix), and
/// whether **every** such path is covered by a registered terminal (`complete`).
///
/// Mirrors the matcher's precedence with short-circuit: a suffix consults the literal
/// child first, falls to the wildcard child only on a dead-end, and to this node's
/// catch-all only when both dead-end — so once a tier is complete, later tiers are
/// unreachable and must not join the cover (else a fully-registered subtree nested
/// under a broader catch-all would falsely read as mixed). At anchor depth a node
/// contributes `cov_below`, and its completeness requires its own catch-all (all
/// non-empty remainders) *and* `leaf_slash` (the empty remainder — a `;`-strip can
/// produce exactly the anchor path). That conjunction is per-node rather than across
/// tiers — cheaper, and wrong only toward denial.
fn walk_cover(node: &Node, seg: &str, rest: &[&str]) -> (Cover, bool) {
    let descend = |child: &Node| match rest.split_first() {
        Some((next, tail)) => walk_cover(child, next, tail),
        None => (
            child.cov_below,
            !child.catchall.is_empty() && !child.leaf_slash.is_empty(),
        ),
    };
    let mut cover = Cover::Empty;
    if let Some(child) = node.literals.get(seg) {
        let (c, done) = descend(child);
        cover = cover.join(c);
        if done {
            return (cover, true);
        }
    }
    if let Some(child) = node.wildcard.as_deref() {
        let (c, done) = descend(child);
        cover = cover.join(c);
        if done {
            return (cover, true);
        }
    }
    (cover.join(node.catchall.cover()), !node.catchall.is_empty())
}

/// Recursive insert. `matchit`-style catch-all is always the final segment (guaranteed
/// by `parse_pattern` / `lower_matchit`), so its `rest` is empty.
fn insert(
    node: &mut Node,
    segs: &[Segment],
    trailing_slash: bool,
    id: RuleId,
    opaque: bool,
    method: &MethodMatch,
) -> Result<(), SlotConflict> {
    match segs.split_first() {
        None => {
            let slot = if trailing_slash {
                &mut node.leaf_slash
            } else {
                &mut node.leaf
            };
            slot.insert(method, id)
        }
        Some((Segment::Literal(s), rest)) => insert(
            node.literals.entry(s.clone()).or_default(),
            rest,
            trailing_slash,
            id,
            opaque,
            method,
        ),
        Some((Segment::Wildcard, rest)) => insert(
            node.wildcard.get_or_insert_with(Box::default),
            rest,
            trailing_slash,
            id,
            opaque,
            method,
        ),
        Some((Segment::CatchAll, _rest)) => {
            node.catchall.insert(method, id)?;
            // Blob-ness is a path property: opaque if any registration declares it.
            node.catchall_opaque |= opaque;
            Ok(())
        }
    }
}

/// Reject an opaque catch-all that shares its node with a routing sibling: a
/// boundary-shift byte in the blob could then relocate into that sibling. This is the
/// "surprise-live" footgun, promoted from a debug lint to a hard, fail-closed error on
/// an explicit opt-in.
///
/// `prefix` accumulates the literal path down to the node under inspection, so the
/// error can name where the offending blob is rooted.
fn validate_opaque(node: &Node, prefix: &mut String) -> Result<(), BuildError> {
    if !node.catchall.is_empty()
        && node.catchall_opaque
        && (!node.literals.is_empty() || node.wildcard.is_some())
    {
        return Err(BuildError::OpaqueTailHasSibling {
            at: if prefix.is_empty() {
                "/".to_owned()
            } else {
                prefix.clone()
            },
        });
    }
    for (seg, child) in &node.literals {
        let len = prefix.len();
        prefix.push('/');
        prefix.push_str(seg);
        validate_opaque(child, prefix)?;
        prefix.truncate(len);
    }
    if let Some(w) = &node.wildcard {
        let len = prefix.len();
        prefix.push_str("/*");
        validate_opaque(w, prefix)?;
        prefix.truncate(len);
    }
    Ok(())
}

/// Find the terminal `s` (a non-empty path body) claims under `node` — its method-slot,
/// resolved later. Traversal is **method-blind** — a position is "matched" iff *some*
/// rule terminates there (`!slot.is_empty()`), so method never drives path
/// backtracking. Precedence is literal > wildcard > catch-all, **with backtracking**: a
/// higher-priority branch that dead-ends falls through to the next.
fn route<'a>(node: &'a Node, s: &[u8]) -> Option<&'a MethodSlot> {
    let (seg, after) = match s.iter().position(|&b| b == b'/') {
        // `i` came from `position`, so both slices exist; the `get` form keeps a bad
        // offset from panicking, degrading to "one whole segment" instead.
        Some(i) => (s.get(..i).unwrap_or(s), s.get(i + 1..)),
        None => (s, None),
    };

    // 1. literal child — highest priority. A segment that is not valid UTF-8 can never
    //    equal a registered literal (patterns arrive as `&str`), so it simply has no
    //    literal child and falls through — exactly how a byte-routing backend behaves.
    if let Some(child) = str::from_utf8(seg).ok().and_then(|t| node.literals.get(t))
        && let Some(slot) = descend(child, after)
    {
        return Some(slot);
    }
    // 2. single-segment wildcard — requires a non-empty segment.
    if !seg.is_empty()
        && let Some(child) = node.wildcard.as_deref()
        && let Some(slot) = descend(child, after)
    {
        return Some(slot);
    }
    // 3. catch-all — lowest priority; consumes the whole raw remainder `s` (>= 1 char).
    (!node.catchall.is_empty()).then_some(&node.catchall)
}

/// After matching a segment against `child`, either terminate (leaf / leaf-with-trailing-
/// slash, by method-blind presence) or recurse on the remaining body.
fn descend<'a>(child: &'a Node, after: Option<&[u8]>) -> Option<&'a MethodSlot> {
    match after {
        // No `/` followed the segment: path ended here → a leaf match.
        None => (!child.leaf.is_empty()).then_some(&child.leaf),
        // A `/` followed, with nothing after it: a trailing-slash match.
        Some([]) => (!child.leaf_slash.is_empty()).then_some(&child.leaf_slash),
        // More path remains after the `/`.
        Some(rest) => route(child, rest),
    }
}

/// Length cap for a *suspicious* path: once a structural byte is flagged, a path over
/// this length is denied. Clean paths bypass it (they cannot be ambiguous). Defense in
/// depth — Pingora bounds the request line well below this.
const MAX_PATH_LEN: usize = 8192;

/// The runtime path-confusion verdict, driven by the owned [`Router`].
///
/// This is the liveness runtime built on the **scoped-denial** model. Every modeled
/// boundary-shift transform (`%2F` decode, `//` merge, `;` strip, `\`-as-separator,
/// and the enabled alternate encodings) rewrites the path only *at or after* the byte
/// that triggers it, so the paths a backend could reinterpret a request into all
/// extend the **stable prefix** — the path up to the last clean separator before the
/// earliest structural occurrence. A boundary-shift byte therefore denies only when
/// the route table makes some *other* rule reachable past that anchor
/// ([`Router::anchor_cover`] ≠ uniformly the matched rule, counting fall-through to
/// the default rule). Dot-segments climb — each `..`-capable segment pops at most one
/// level — so they raise the anchor toward the root before the same check; NUL
/// truncation denies unconditionally (its legitimate-use rate is ~nil). Because
/// registered patterns are canonical, any structural byte in a matched path
/// necessarily falls in a capture — the build-time canonicality check in
/// `path_router` is load-bearing for that.
///
/// Three checks compose under the default mode — the positional verdict above, then
/// the precise case-fold and content-decode verdicts (apply the declared transform,
/// re-route, deny only a rule change), then any break-glass probes. The full decision
/// story, including why positional over-approximates (it treats every path extending
/// the anchor as reachable, not just actual transform images) while the fold/decode
/// checks are exact, is [`crate::_docs::explanation::decision`].
pub(crate) struct StructuralGuard {
    router: Router,
    mode: PathConfusion,
    /// Byte classes that deny, derived from the configured classes plus (when the backend
    /// folds case) [`ClassSet::CASE`].
    enabled: ClassSet,
    /// Which alternate encodings the scanner recognises.
    enc: Encodings,
    /// Whether the backend folds ASCII case (drives the content-decode lowercasing).
    case_insensitive: bool,
    /// Custom break-glass probes — a structural form the built-in alphabet doesn't ship,
    /// denied on whole-path presence.
    probes: Vec<Arc<dyn StructuralProbe>>,
}

impl StructuralGuard {
    /// Build a guard over `router` for the given mode and structural configuration.
    pub(crate) fn new(
        router: Router,
        mode: PathConfusion,
        classes: StructuralClasses,
        layers: DecodeLayers,
        case: CaseSensitivity,
    ) -> Self {
        let mut enabled = enabled_classes(&classes);
        if case.is_insensitive() {
            enabled.insert(ClassSet::CASE);
        }
        Self {
            router,
            mode,
            enabled,
            enc: enabled_encodings(&classes, layers),
            case_insensitive: case.is_insensitive(),
            probes: classes.probes,
        }
    }

    /// The deny reason for `path`, or `None` to allow — the attributed core used by
    /// the router. [`DenyReason::message`] gives the static response-body string;
    /// its `Display` gives the attributed log line.
    pub(crate) fn verdict(&self, path: &str, method: &http::Method) -> Option<DenyReason> {
        match self.mode {
            PathConfusion::Off => None,
            PathConfusion::RejectStructural => self
                .positional_deny(path)
                .or_else(|| self.case_fold_deny(path, method))
                .or_else(|| self.content_decode_deny(path, method))
                .or_else(|| self.custom_probe_deny(path)),
            // Strict: every position live (opaque ignored) and any percent-escape is
            // itself non-canonical.
            PathConfusion::RejectNonCanonical => self
                .noncanonical_deny(path)
                .or_else(|| escape_present(path).then_some(DenyReason::NonCanonicalEscape))
                .or_else(|| self.custom_probe_deny(path)),
        }
    }

    /// Break-glass verdict: deny if any registered custom probe recognises its form
    /// anywhere in `path`, attributing the probe by name. A no-op (one `is_empty`)
    /// when no probe is registered.
    fn custom_probe_deny(&self, path: &str) -> Option<DenyReason> {
        let probe = self.probes.iter().find(|p| p.matches(path))?;
        if path.len() > MAX_PATH_LEN {
            Some(DenyReason::TooLong)
        } else {
            Some(DenyReason::Probe(probe.name()))
        }
    }

    /// Whether `path` must be denied for GET. Test-only convenience for method-agnostic
    /// route tables; production calls `verdict` with the request's actual method.
    #[cfg(test)]
    pub(crate) fn ambiguous(&self, path: &str) -> bool {
        self.verdict(path, &http::Method::GET).is_some()
    }

    /// The method-resolved rule id — for the router's unchecked match operation.
    pub(crate) fn resolve(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        self.router.resolve(path, method)
    }

    /// Positional verdict for [`PathConfusion::RejectStructural`] — the **scoped
    /// denial**. A clean path (no enabled structural byte) is the fast path and never
    /// walks the tree; a flagged path is denied unless every rule reachable past its
    /// anchor is the very rule it matched (see [`Router::anchor_cover`]).
    ///
    /// The anchor: boundary-shift bytes cannot rewrite anything before the last clean
    /// separator preceding the earliest structural occurrence, so that stable prefix
    /// bounds their reach. A dot-segment climbs, so it widens the anchor to the root
    /// (a table that routes uniformly even at the root — one rule, or nothing but the
    /// default — cannot be traversed *between* rules). NUL truncation keeps its
    /// unconditional deny: it has essentially no legitimate use, so the scoping win
    /// is not worth modeling.
    ///
    /// [`ClassSet::CASE`] is masked out here: case folding is handled by the precise
    /// [`case_fold_deny`](Self::case_fold_deny) instead, so an uppercase byte alone
    /// never denies positionally (only an actual fold relocation does).
    fn positional_deny(&self, path: &str) -> Option<DenyReason> {
        let enabled = self.enabled.without(ClassSet::CASE);
        let scan = scan(path, enabled, self.enc);
        let present = scan.classes.intersect(enabled);
        if present.is_empty() {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(DenyReason::TooLong);
        }
        if present.contains_any(ClassSet::TRUNCATION) {
            return Some(DenyReason::Structural(primary_class(present)));
        }
        // `present` non-empty guarantees an offset (a fuzzed ScanResult invariant);
        // fail closed rather than panic if it ever doesn't.
        let Some(offset) = scan.earliest else {
            return Some(DenyReason::Structural(primary_class(present)));
        };
        let anchor = self.anchor_for(path, &scan, offset);
        let matched = self.router.route_id(path).unwrap_or(DEFAULT_RULE);
        if self.router.anchor_cover(anchor) == Cover::Uniform(matched) {
            None
        } else {
            Some(DenyReason::Structural(primary_class(present)))
        }
    }

    /// The **anchor** for a flagged `path`: the prefix the reachable-set argument
    /// treats as invariant under every modeled transform, so that whatever a backend
    /// does to this path, the result still starts here.
    ///
    /// That invariance is the load-bearing premise of the whole positional verdict —
    /// it is why bounding `anchor_cover` bounds the relocation. It holds because:
    ///
    /// - Boundary-shift and climb transforms act at or after their own (enabled)
    ///   occurrence, which `offset` bounds.
    /// - A *content* transform rewrites bytes with no structural class — a
    ///   percent-escape decodes (`%61`→`a`, possibly to bytes that are not valid UTF-8,
    ///   which [`content_decode_deny`](Self::content_decode_deny) routes as bytes rather
    ///   than declining) and an uppercase
    ///   byte folds under a declared case-folding backend — so the anchor is cut
    ///   before the first such byte too. Everything ahead of it is a literal,
    ///   canonical byte no modeled backend rewrites, so every reinterpretation extends
    ///   the anchor and `anchor_cover` bounds it. Bounding by the config-independent
    ///   `%` position is also what keeps the verdict monotone in the configuration: an
    ///   enabled encoding moving `offset` earlier can only raise the anchor further,
    ///   never uncover a laxer one (the `l2_monotone` law).
    /// - Dot-segments climb, so each `..`-capable segment pops one level of the stable
    ///   prefix and `k` of them raise the anchor `k` segments toward the root (see
    ///   [`ScanResult::dot_pops`]; overcounting only denies more).
    ///
    /// A premise, not a theorem: it is a property of the *current* transform set, and
    /// a class that rewrote **before** its own trigger would break it silently. So it
    /// is also asserted directly, against the executable backend model — see
    /// `path_confusion_proptest`'s anchor-invariance property, which reaches this
    /// function through `structural_anchor` (test-only).
    fn anchor_for<'p>(&self, path: &'p str, scan: &ScanResult, offset: usize) -> &'p str {
        let bound = first_content_byte(path, self.case_insensitive)
            .map_or(offset, |content| offset.min(content));
        raise(stable_prefix(path, bound), scan.dot_pops)
    }

    /// The anchor [`positional_deny`](Self::positional_deny) would reason over for
    /// `path`, or `None` where it never reaches the anchor check — a clean path, an
    /// over-length one, or an unconditional truncation deny. Test-only window onto
    /// [`anchor_for`](Self::anchor_for), so the premise above can be asserted against
    /// the reference backend rather than trusted.
    ///
    /// The early-return conditions are mirrored from `positional_deny` (the anchor
    /// *computation* is shared, so only the reachability guard is restated); a mirror
    /// that drifted would make this return `Some` where production denies outright,
    /// which costs a stricter test, never a weaker one.
    #[cfg(test)]
    pub(crate) fn structural_anchor<'p>(&self, path: &'p str) -> Option<&'p str> {
        let enabled = self.enabled.without(ClassSet::CASE);
        let scan = scan(path, enabled, self.enc);
        let present = scan.classes.intersect(enabled);
        if present.is_empty()
            || path.len() > MAX_PATH_LEN
            || present.contains_any(ClassSet::TRUNCATION)
        {
            return None;
        }
        Some(self.anchor_for(path, &scan, scan.earliest?))
    }

    /// Case-fold verdict: model a case-folding backend (declared via
    /// [`CaseSensitivity::Insensitive`]) and deny iff lowercasing the path **relocates**
    /// it to a different rule than the raw path matched. Precise, like the
    /// content-decode check — `/files/ReadMe.TXT` folds within its own rule and keeps
    /// flowing; `/ADMIN` folding onto a distinct `/admin` rule is denied.
    ///
    /// Sound on two build-time invariants: patterns are all-lowercase under
    /// `Insensitive` (uppercase is a build error), so the folded path re-routes through
    /// the very table the backend resolves against; and folding composed with
    /// percent-decoding is covered by [`content_decode_deny`](Self::content_decode_deny),
    /// which folds the decoded path before re-routing. Only ASCII case is modeled,
    /// mirroring [`CaseSensitivity`].
    fn case_fold_deny(&self, path: &str, method: &http::Method) -> Option<DenyReason> {
        if !self.case_insensitive || !path.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(DenyReason::TooLong);
        }
        let folded = path.to_ascii_lowercase();
        (self.router.resolve(&folded, method) != self.router.resolve(path, method))
            .then_some(DenyReason::CaseFoldRelocation)
    }

    /// Positional verdict for [`PathConfusion::RejectNonCanonical`]: every position live,
    /// opaque declarations ignored, so any enabled structural byte denies.
    fn noncanonical_deny(&self, path: &str) -> Option<DenyReason> {
        let present = classes_present(path, self.enabled, self.enc).intersect(self.enabled);
        if present.is_empty() {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(DenyReason::TooLong);
        }
        Some(DenyReason::NonCanonical(primary_class(present)))
    }

    /// Content-decode verdict: model every possible complete-path result — one decode
    /// pass, plus two under [`DecodeLayers::UpToTwo`] — and deny if any possible result
    /// **relocates** the path to a different rule than the raw path matched. Precise —
    /// results that all land on the same rule (`/foo%20bar`) are allowed, so opaque
    /// content flows.
    fn content_decode_deny(&self, path: &str, method: &http::Method) -> Option<DenyReason> {
        if !path.contains('%') {
            return None;
        }
        if path.len() > MAX_PATH_LEN {
            return Some(DenyReason::TooLong);
        }
        let passes = if self.enc.double_decode { 2 } else { 1 };
        let raw = path.as_bytes();
        let raw_rule = self.router.resolve_bytes(raw, method);
        let mut decoded = raw.to_vec();
        for _ in 0..passes {
            decoded = percent_decode_once(&decoded);
            let decoded_rule = if self.case_insensitive {
                let mut folded = decoded.clone();
                folded.make_ascii_lowercase();
                self.router.resolve_bytes(&folded, method)
            } else {
                self.router.resolve_bytes(&decoded, method)
            };
            if decoded_rule != raw_rule {
                return Some(DenyReason::DecodeRelocation);
            }
        }
        None
    }
}

/// Offset of the first byte a modeled **content** transform could rewrite: any `%`
/// (a percent-escape — counted even when malformed, since a lenient decoder may
/// still consume it) and, under a case-folding backend, any ASCII uppercase.
/// `None` when the path carries neither. Bounds the positional verdict's anchor
/// alongside the earliest enabled structural occurrence.
fn first_content_byte(path: &str, case_insensitive: bool) -> Option<usize> {
    path.bytes()
        .position(|b| b == b'%' || (case_insensitive && b.is_ascii_uppercase()))
}

/// The clean prefix of `path` up to and **including** the last `/` strictly before
/// `offset` — everything a boundary-shift transform triggered at `offset` or later
/// provably cannot rewrite. `"/"` when no such separator exists (the occurrence sits
/// in the first segment, or the path is degenerate).
///
/// `offset` always lands on a char boundary (it is the first byte of a scanner
/// occurrence or an ASCII content byte), but the lookup stays `get`-based so a bad
/// offset degrades to the root anchor — the fail-closed direction — instead of
/// panicking.
fn stable_prefix(path: &str, offset: usize) -> &str {
    path.get(..offset)
        .and_then(|p| p.rfind('/'))
        .and_then(|i| path.get(..=i))
        .unwrap_or("/")
}

/// Raise a `/`-terminated anchor prefix by `k` segments — the dot-segment climb
/// radius. Each pop drops the last segment (`"/a/b/"` → `"/a/"`); the root absorbs
/// any excess (`..` cannot climb above `/`). Pure slicing, allocation-free.
fn raise(prefix: &str, k: usize) -> &str {
    let mut p = prefix;
    for _ in 0..k {
        if p == "/" {
            break;
        }
        // Drop the trailing `/`, then cut after the previous one.
        p = p
            .get(..p.len() - 1)
            .and_then(|q| q.rfind('/').and_then(|i| q.get(..=i)))
            .unwrap_or("/");
    }
    p
}

/// Whether `path` carries any complete `%XX` escape — the [`PathConfusion::RejectNonCanonical`]
/// "any escape is non-canonical" rule.
fn escape_present(path: &str) -> bool {
    let b = path.as_bytes();
    (0..b.len()).any(|i| crate::percent::byte_at(b, i).is_some())
}

/// Percent-decode every complete `%XX` escape once (one pass: `%252F` → `%2F`).
///
/// Yields raw **bytes**, and is total. Decoding can produce sequences that are not valid
/// UTF-8 (`%FF`, a lone surrogate, a truncated multi-byte form); a backend decodes to
/// bytes and routes on bytes regardless, so refusing to model those inputs would leave
/// the relocation check unevaluated on exactly the paths an attacker controls.
fn percent_decode_once(path: &[u8]) -> Vec<u8> {
    if !path.contains(&b'%') {
        return path.to_vec();
    }
    let mut out = Vec::with_capacity(path.len());
    let mut i = 0;
    while i < path.len() {
        let Some(&cur) = path.get(i) else { break };
        if let Some(byte) = crate::percent::byte_at(path, i) {
            out.push(byte);
            i += 3;
        } else {
            out.push(cur);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    // Test-only conveniences: small rule-id casts, by-value helpers, and a wide config
    // struct don't warrant the production-grade pedantic lints.
    #![allow(
        clippy::cast_possible_truncation,
        clippy::needless_pass_by_value,
        clippy::struct_excessive_bools
    )]

    use super::*;

    /// Lower a [`Pattern`] to the equivalent `matchit` pattern string (oracle side only).
    /// Literal braces are escaped; wildcards get unique synthetic names.
    fn lower(p: &Pattern) -> String {
        let mut s = String::new();
        for (i, seg) in p.segments.iter().enumerate() {
            s.push('/');
            match seg {
                Segment::Literal(t) => s.push_str(&t.replace('{', "{{").replace('}', "}}")),
                Segment::Wildcard => {
                    s.push_str("{w");
                    s.push_str(&i.to_string());
                    s.push('}');
                }
                Segment::CatchAll => s.push_str("{*rest}"),
            }
        }
        if p.trailing_slash {
            s.push('/');
        }
        if s.is_empty() {
            s.push('/');
        }
        s
    }

    fn router(rows: &[(&str, RuleId)]) -> Router {
        let entries: Vec<_> = rows
            .iter()
            .map(|(p, id)| {
                (
                    parse_pattern(p).expect("parse"),
                    *id,
                    false,
                    MethodMatch::Any,
                )
            })
            .collect();
        Router::build(&entries).expect("build")
    }

    // ── parsing ──────────────────────────────────────────────────────────────

    #[test]
    fn parse_basic_shapes() {
        assert_eq!(parse_pattern("/").expect("root").segments, vec![]);
        assert_eq!(
            parse_pattern("/admin").expect("lit").segments,
            vec![Segment::Literal("admin".into())]
        );
        assert_eq!(
            parse_pattern("/a/*/b").expect("interior wildcard").segments,
            vec![
                Segment::Literal("a".into()),
                Segment::Wildcard,
                Segment::Literal("b".into())
            ]
        );
        // The final `*` is a catch-all, not a single-segment wildcard.
        assert_eq!(
            parse_pattern("/files/*").expect("catchall").segments,
            vec![Segment::Literal("files".into()), Segment::CatchAll]
        );
        // Bare root catch-all.
        assert_eq!(
            parse_pattern("/*").expect("root catchall").segments,
            vec![Segment::CatchAll]
        );
    }

    #[test]
    fn parse_star_escaping() {
        // `**` → literal `*`, `***` → literal `**`.
        assert_eq!(
            parse_pattern("/**").expect("escaped").segments,
            vec![Segment::Literal("*".into())]
        );
        assert_eq!(
            parse_pattern("/***").expect("escaped").segments,
            vec![Segment::Literal("**".into())]
        );
        // A `*` inside a mixed segment is a literal byte, not a wildcard.
        assert_eq!(
            parse_pattern("/v*").expect("mixed").segments,
            vec![Segment::Literal("v*".into())]
        );
    }

    #[test]
    fn parse_trailing_slash_is_significant() {
        let a = parse_pattern("/admin").expect("a");
        let b = parse_pattern("/admin/").expect("b");
        assert!(!a.trailing_slash);
        assert!(b.trailing_slash);
        assert_eq!(a.segments, b.segments);
    }

    #[test]
    fn parse_rejects_bad_patterns() {
        assert_eq!(
            parse_pattern("no-slash"),
            Err(PatternError::MissingLeadingSlash)
        );
        assert_eq!(
            parse_pattern("/a//b"),
            Err(PatternError::EmptyInteriorSegment)
        );
    }

    // ── matchit-syntax lowering (the public-API bridge) ───────────────────────

    #[test]
    fn lower_matchit_maps_params() {
        assert_eq!(lower_matchit("/").expect("root").segments, vec![]);
        // Trailing single-segment param stays a single-segment Wildcard (not a catch-all).
        assert_eq!(
            lower_matchit("/users/{id}").expect("param").segments,
            vec![Segment::Literal("users".into()), Segment::Wildcard]
        );
        assert_eq!(
            lower_matchit("/files/{*rest}").expect("catchall").segments,
            vec![Segment::Literal("files".into()), Segment::CatchAll]
        );
        assert_eq!(
            lower_matchit("/a/{x}/b").expect("interior").segments,
            vec![
                Segment::Literal("a".into()),
                Segment::Wildcard,
                Segment::Literal("b".into())
            ]
        );
        // Escaped braces are a literal segment.
        assert_eq!(
            lower_matchit("/{{cfg}}").expect("escaped").segments,
            vec![Segment::Literal("{cfg}".into())]
        );
    }

    #[test]
    fn lower_matchit_rejects_unrepresentable() {
        // Prefix/suffix params — the dropped feature.
        assert_eq!(lower_matchit("/v{ver}"), Err(LowerError::PrefixSuffixParam));
        assert_eq!(
            lower_matchit("/img-{id}.png"),
            Err(LowerError::PrefixSuffixParam)
        );
        // Catch-all must be final.
        assert_eq!(
            lower_matchit("/files/{*rest}/x"),
            Err(LowerError::CatchAllNotLast)
        );
        assert_eq!(
            lower_matchit("/files/{*rest}/"),
            Err(LowerError::CatchAllNotLast)
        );
        assert_eq!(lower_matchit("/{}"), Err(LowerError::InvalidParam));
        assert_eq!(lower_matchit("/{*}"), Err(LowerError::InvalidParam));
        assert_eq!(lower_matchit("/{foo*bar}"), Err(LowerError::InvalidParam));
        assert_eq!(
            lower_matchit("no-slash"),
            Err(LowerError::MissingLeadingSlash)
        );
        assert_eq!(
            lower_matchit("/a//b"),
            Err(LowerError::EmptyInteriorSegment)
        );
    }

    // ── build gates ──────────────────────────────────────────────────────────

    #[test]
    fn build_rejects_terminal_conflict() {
        let entries = vec![
            (parse_pattern("/a").expect("p"), 0, false, MethodMatch::Any),
            (parse_pattern("/a").expect("p"), 1, false, MethodMatch::Any),
        ];
        // The conflict is attributed to the second entry.
        assert!(matches!(
            Router::build(&entries),
            Err(BuildError::Conflict { index: 1 })
        ));
    }

    #[test]
    fn build_rejects_opaque_with_sibling() {
        let entries = vec![
            (
                parse_pattern("/files/*").expect("blob"),
                0,
                true,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/secret").expect("sib"),
                1,
                false,
                MethodMatch::Any,
            ),
        ];
        // The error names where the blob is rooted.
        assert!(matches!(
            Router::build(&entries),
            Err(BuildError::OpaqueTailHasSibling { at }) if at == "/files"
        ));
    }

    #[test]
    fn build_accepts_lone_opaque_blob() {
        // The opaque flag is a build-time guarantee (sibling-free, hence uniform);
        // it no longer has a runtime span — matching is identical either way.
        let entries = vec![(
            parse_pattern("/files/*").expect("blob"),
            0,
            true,
            MethodMatch::Any,
        )];
        let r = Router::build(&entries).expect("lone opaque builds");
        assert_eq!(r.route_id("/files/a/b"), Some(0));
        let plain = router(&[("/files/*", 0)]);
        assert_eq!(plain.route_id("/files/a/b"), Some(0));
    }

    // ── coverage annotation + anchor walk (the scoped verdict's substrate) ────

    #[test]
    fn anchor_cover_full_subtree_is_uniform() {
        let r = router(&[("/files", 0), ("/files/", 0), ("/files/*", 0)]);
        assert_eq!(r.anchor_cover("/files/"), Cover::Uniform(0));
        // Anchors deeper inside the catch-all stay uniform — the walk bottoms out at
        // the catch-all node, which covers everything beneath it.
        assert_eq!(r.anchor_cover("/files/a/b/"), Cover::Uniform(0));
        // The root anchor sees the default fall-through for paths outside /files.
        assert_eq!(r.anchor_cover("/"), Cover::Mixed);
    }

    #[test]
    fn anchor_cover_lone_catchall_leaks_default() {
        // Without `/files/` (leaf_slash), the empty remainder — reachable via e.g. a
        // `;`-strip emptying the tail — falls to the default rule: not uniform.
        let r = router(&[("/files/*", 0)]);
        assert_eq!(r.anchor_cover("/files/"), Cover::Mixed);
    }

    #[test]
    fn anchor_cover_unrouted_space_is_uniformly_default() {
        // Nothing under /public and no ancestor catch-all: every path there resolves
        // to the default rule, which is itself a uniform outcome.
        let r = router(&[("/admin", 0)]);
        assert_eq!(r.anchor_cover("/public/"), Cover::Uniform(DEFAULT_RULE));
    }

    #[test]
    fn anchor_cover_sees_ancestor_wildcard_branch() {
        // A suffix dead-ending under /files/*/deep backtracks into /*/c: rule 1 is
        // reachable under the /files/ anchor even though its pattern never spells
        // "files" — the walk must follow the wildcard branch alongside the literal.
        let r = router(&[("/files/*/deep", 0), ("/*/c", 1)]);
        assert_eq!(r.anchor_cover("/files/"), Cover::Mixed);
    }

    #[test]
    fn anchor_cover_complete_tier_shadows_ancestor_catchall() {
        // A fully-registered /files subtree under a root-wide catch-all: nothing under
        // /files/ can ever backtrack to the root catch-all (the subtree is complete),
        // so the anchor stays uniform despite the differently-ruled ancestor.
        let r = router(&[
            ("/files", 0),
            ("/files/", 0),
            ("/files/*", 0),
            ("/", 1),
            ("/*", 1),
        ]);
        assert_eq!(r.anchor_cover("/files/"), Cover::Uniform(0));
        // But an *incomplete* subtree leaks into the ancestor catch-all: mixed.
        let leaky = router(&[("/files/*", 0), ("/", 1), ("/*", 1)]);
        assert_eq!(leaky.anchor_cover("/files/"), Cover::Mixed);
    }

    #[test]
    fn anchor_cover_root_counts_the_bare_leaf() {
        // The `//`-merge regression: at the root anchor the empty remainder is the
        // bare `/` (root.leaf), which slash-merging really can produce. A table whose
        // `/` and `/{*rest}` carry different rules must read Mixed at "/".
        let r = router(&[("/", 1), ("/*", 0)]);
        assert_eq!(r.anchor_cover("/"), Cover::Mixed);
        // Same table with one shared rule id is uniform — and complete (leaf +
        // catch-all), so the default never joins.
        let uni = router(&[("/", 0), ("/*", 0)]);
        assert_eq!(uni.anchor_cover("/"), Cover::Uniform(0));
    }

    #[test]
    fn anchor_cover_method_gap_injects_default() {
        // A method-qualified terminal resolves other methods to the default rule, so
        // it can never make a subtree uniform on its own.
        let entries = vec![
            (
                parse_pattern("/x/y").expect("pat"),
                0,
                false,
                MethodMatch::from(http::Method::GET),
            ),
            (
                parse_pattern("/x/").expect("pat"),
                0,
                false,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/x/*").expect("pat"),
                0,
                false,
                MethodMatch::Any,
            ),
        ];
        let r = Router::build(&entries).expect("build");
        assert_eq!(r.anchor_cover("/x/"), Cover::Mixed);
        // The same shape with a method-wildcard terminal is uniform.
        let all = router(&[("/x/y", 0), ("/x/", 0), ("/x/*", 0)]);
        assert_eq!(all.anchor_cover("/x/"), Cover::Uniform(0));
    }

    #[test]
    fn multi_method_slot_resolves_each_and_stays_method_gapped() {
        // A OneOf registration claims each listed method under its single rule id;
        // unlisted methods still resolve to the default rule, so the terminal keeps
        // injecting the default into cover exactly like a single-method one — the
        // method-blind structural verdict stays sound for multi-method rules.
        let entries = vec![(
            parse_pattern("/x").expect("pat"),
            0,
            false,
            MethodMatch::from([http::Method::GET, http::Method::HEAD]),
        )];
        let r = Router::build(&entries).expect("build");
        assert_eq!(r.resolve("/x", &http::Method::GET), Some(0));
        assert_eq!(r.resolve("/x", &http::Method::HEAD), Some(0));
        assert_eq!(r.resolve("/x", &http::Method::POST), None);
        assert_eq!(r.anchor_cover("/"), Cover::Mixed);
    }

    // ── matching: precedence + backtracking (the load-bearing behavior) ───────

    /// Byte paths route. An invalid-UTF-8 segment can never equal a registered literal
    /// (patterns arrive as `&str`), but it must still fall through to the wildcard or
    /// catch-all exactly as a byte-routing backend does — declining to answer is what
    /// made the content-decode check fail open.
    #[test]
    fn byte_paths_route_past_invalid_utf8() {
        let r = router(&[("/files/secret", 0), ("/files/*", 1)]);
        assert_eq!(r.route_id_bytes(b"/files/secret"), Some(0), "literal wins");
        assert_eq!(
            r.route_id_bytes(b"/files/\xFF"),
            Some(1),
            "invalid UTF-8 segment falls through to the catch-all"
        );
        assert_eq!(
            r.route_id_bytes(b"/\xFFiles/secret"),
            None,
            "invalid UTF-8 matches no literal"
        );
        // Equivalence with the `&str` entry point on everything that is valid UTF-8.
        for p in ["/files/secret", "/files/other", "/files/x/y", "/nope"] {
            assert_eq!(r.route_id(p), r.route_id_bytes(p.as_bytes()), "{p}");
        }
    }

    #[test]
    fn literal_beats_wildcard_and_catchall() {
        let r = router(&[("/files/secret", 0), ("/files/*", 1)]);
        assert_eq!(r.route_id("/files/secret"), Some(0)); // literal wins
        assert_eq!(r.route_id("/files/other"), Some(1)); // catch-all fallback
        assert_eq!(r.route_id("/files/x/y"), Some(1)); // catch-all spans segments
    }

    #[test]
    fn backtracks_from_literal_into_wildcard() {
        // The case that a non-backtracking trie gets wrong: `/a/b` shadows the literal
        // `a` branch, but `/a/c` must still reach `/*/c`.
        let r = router(&[("/a/b", 0), ("/*/c", 1)]);
        assert_eq!(r.route_id("/a/b"), Some(0));
        assert_eq!(r.route_id("/a/c"), Some(1));
    }

    #[test]
    fn trailing_slash_and_empty_segments() {
        let r = router(&[("/users", 0), ("/users/", 1), ("/users/*", 2)]);
        assert_eq!(r.route_id("/users"), Some(0)); // leaf
        assert_eq!(r.route_id("/users/"), Some(1)); // leaf_slash — distinct route
        assert_eq!(r.route_id("/users/x"), Some(2)); // catch-all
    }

    #[test]
    fn single_segment_wildcard_requires_one_segment() {
        let r = router(&[("/a/*/b", 0)]);
        assert_eq!(r.route_id("/a/x/b"), Some(0));
        assert_eq!(r.route_id("/a/b"), None); // wildcard needs a segment
        assert_eq!(r.route_id("/a/x/y/b"), None); // and exactly one
    }

    // ── matchit equivalence (the oracle) ──────────────────────────────────────

    /// Catalog of patterns in the owned grammar. Chosen to coexist (no conflicts) and to
    /// exercise literals, siblings, catch-alls, interior wildcards, and trailing slashes.
    const CATALOG: &[&str] = &[
        "/",
        "/health",
        "/admin",
        "/admin/",
        "/admin/*",
        "/admin/super",
        "/public",
        "/public/*",
        "/users/*",
        "/a/*/edit",
        "/files/*",
    ];

    /// Instantiate a pattern into a path that matches it (each `*` → "x").
    fn fill(pat: &str) -> String {
        if pat == "/" {
            return "/".to_owned();
        }
        pat.split('/')
            .map(|s| if s == "*" { "x" } else { s })
            .collect::<Vec<_>>()
            .join("/")
    }

    /// Derive a probe path from a base pattern by one of several perturbations — the ways
    /// a request bends around the route boundaries where matcher bugs hide.
    fn perturbation(pat: &str, kind: u8, extra: &str) -> String {
        let base = fill(pat);
        match kind {
            0 => base,                        // exact match
            1 => format!("{base}/{extra}"),   // extra trailing segment
            2 => format!("{base}/"),          // trailing slash
            3 => base.replacen('/', "//", 1), // injected empty segment
            4 => format!("/{extra}"),         // unrelated short path
            _ => base // last segment dropped
                .rsplit_once('/')
                .map_or(base.clone(), |(head, _)| head.to_owned()),
        }
    }

    proptest::proptest! {
        #[test]
        fn matches_matchit(
            include in proptest::collection::vec(proptest::prelude::any::<bool>(), CATALOG.len()),
            base_idx in 0..CATALOG.len(),
            kind in 0u8..6,
            extra in "[a-z]{1,3}",
        ) {
            // Build both routers from the same accepted subset. matchit is the oracle, so
            // its acceptance gates the subset (the clean catalog never conflicts anyway).
            let mut ours_entries = Vec::new();
            let mut oracle = matchit::Router::new();
            for (i, pat) in CATALOG.iter().enumerate() {
                if !include[i] {
                    continue;
                }
                let parsed = parse_pattern(pat).expect("catalog parses");
                if oracle.insert(lower(&parsed), i as RuleId).is_err() {
                    continue; // keep ours in lockstep with the oracle
                }
                ours_entries.push((parsed, i as RuleId, false, MethodMatch::Any));
            }
            let ours = Router::build(&ours_entries).expect("ours builds");

            let probe = perturbation(CATALOG[base_idx], kind, &extra);
            let our_id = ours.route_id(&probe);
            let their_id = oracle.at(&probe).ok().map(|m| *m.value);
            proptest::prop_assert_eq!(our_id, their_id, "diverged on {:?}", probe);
        }
    }

    /// Catalog in the **public matchit syntax**, lowered via [`lower_matchit`]. Crucially
    /// includes a trailing single-segment param (`/users/{id}`) and a deeper route under
    /// it (`/users/{id}/posts`) — the case the `*`-grammar catalog can't express, where a
    /// trailing wildcard must match exactly one segment and not swallow deeper paths.
    const MATCHIT_CATALOG: &[&str] = &[
        "/",
        "/health",
        "/admin",
        "/admin/",
        "/admin/{*rest}",
        "/admin/super",
        "/users/{id}",
        "/users/{id}/posts",
        "/a/{x}/edit",
        "/files/{*rest}",
    ];

    /// Instantiate a matchit-syntax pattern into a matching path (`{…}` → "x").
    fn fill_matchit(pat: &str) -> String {
        if pat == "/" {
            return "/".to_owned();
        }
        pat.split('/')
            .map(|s| if s.starts_with('{') { "x" } else { s })
            .collect::<Vec<_>>()
            .join("/")
    }

    proptest::proptest! {
        #[test]
        fn matches_matchit_syntax(
            include in proptest::collection::vec(proptest::prelude::any::<bool>(), MATCHIT_CATALOG.len()),
            base_idx in 0..MATCHIT_CATALOG.len(),
            kind in 0u8..6,
            extra in "[a-z]{1,3}",
        ) {
            let mut ours_entries = Vec::new();
            let mut oracle = matchit::Router::new();
            for (i, pat) in MATCHIT_CATALOG.iter().enumerate() {
                if !include[i] {
                    continue;
                }
                // The catalog *is* matchit syntax, so the oracle takes it verbatim.
                if oracle.insert(*pat, i as RuleId).is_err() {
                    continue;
                }
                let lowered = lower_matchit(pat).expect("catalog lowers");
                ours_entries.push((lowered, i as RuleId, false, MethodMatch::Any));
            }
            let ours = Router::build(&ours_entries).expect("ours builds");

            let probe = perturbation_matchit(MATCHIT_CATALOG[base_idx], kind, &extra);
            let our_id = ours.route_id(&probe);
            let their_id = oracle.at(&probe).ok().map(|m| *m.value);
            proptest::prop_assert_eq!(our_id, their_id, "diverged on {:?}", probe);
        }
    }

    /// As [`perturbation`], but over a matchit-syntax base pattern.
    fn perturbation_matchit(pat: &str, kind: u8, extra: &str) -> String {
        let base = fill_matchit(pat);
        match kind {
            0 => base,
            1 => format!("{base}/{extra}"),
            2 => format!("{base}/"),
            3 => base.replacen('/', "//", 1),
            4 => format!("/{extra}"),
            _ => base
                .rsplit_once('/')
                .map_or(base.clone(), |(head, _)| head.to_owned()),
        }
    }

    // ── fuzz target: owned matcher vs `matchit` (engine-agnostic body) ─────────
    //
    // The differential the existing oracle proptest runs over a fixed perturbation scheme,
    // re-expressed as a `fn(&[u8])` so a coverage-guided fuzzer can drive *arbitrary* probe
    // paths against the matcher. A divergence from `matchit` is exactly where a relocation
    // bug would hide, so this is the highest-value target — and one Kani could never reach,
    // since it walks the router. Wire later via bolero/cargo-fuzz; the body is the engine.

    /// Engine-agnostic fuzz body: build the owned matcher and `matchit` from the same
    /// included subset of [`MATCHIT_CATALOG`], then assert they resolve an arbitrary probe
    /// to the same rule. Input layout: `[include_mask, probe bytes…]`.
    pub(crate) fn fuzz_matcher_differential(data: &[u8]) {
        let include = data.first().copied().unwrap_or(0xFF);
        let probe = String::from_utf8_lossy(data.get(1..).unwrap_or(&[]));

        let mut ours_entries = Vec::new();
        let mut oracle = matchit::Router::new();
        for (i, pat) in MATCHIT_CATALOG.iter().enumerate() {
            // The first 8 entries are mask-controlled; any beyond are always included.
            if i < 8 && include & (1 << i) == 0 {
                continue;
            }
            if oracle.insert(*pat, i as RuleId).is_err() {
                continue; // keep ours in lockstep with the oracle
            }
            let lowered = lower_matchit(pat).expect("catalog lowers");
            ours_entries.push((lowered, i as RuleId, false, MethodMatch::Any));
        }
        let ours = Router::build(&ours_entries).expect("ours builds");

        let our_id = ours.route_id(&probe);
        let their_id = oracle.at(&probe).ok().map(|m| *m.value);
        assert_eq!(
            our_id, their_id,
            "matcher diverged from matchit on {probe:?}"
        );
    }

    /// Bolero harness for [`fuzz_matcher_differential`]. Runs under `cargo test` and as a
    /// coverage-guided fuzzer under `cargo bolero test matcher_differential`.
    #[test]
    fn matcher_differential() {
        bolero::check!().for_each(|data: &[u8]| fuzz_matcher_differential(data));
    }

    // ── liveness runtime ──────────────────────────────────────────────────────

    use crate::path_confusion::{CaseSensitivity, DecodeLayers, PathConfusion, StructuralClasses};

    fn guard(
        rows: &[(&str, RuleId, bool)],
        mode: PathConfusion,
        classes: StructuralClasses,
        case: CaseSensitivity,
    ) -> StructuralGuard {
        guard_layers(rows, mode, classes, DecodeLayers::Single, case)
    }

    fn guard_layers(
        rows: &[(&str, RuleId, bool)],
        mode: PathConfusion,
        classes: StructuralClasses,
        layers: DecodeLayers,
        case: CaseSensitivity,
    ) -> StructuralGuard {
        let entries: Vec<_> = rows
            .iter()
            .map(|(p, id, op)| (parse_pattern(p).expect("parse"), *id, *op, MethodMatch::Any))
            .collect();
        StructuralGuard::new(
            Router::build(&entries).expect("build"),
            mode,
            classes,
            layers,
            case,
        )
    }

    /// L1: a path with no enabled structural byte is never denied.
    #[test]
    fn clean_paths_allowed() {
        let g = guard(
            &[("/admin/*", 0, false), ("/users/*", 1, false)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/admin/users"));
        assert!(!g.ambiguous("/users/42"));
        assert!(!g.ambiguous("/nope/clean"));
    }

    /// The scoped relaxation: a **fully-registered, uniformly-ruled** subtree tolerates
    /// boundary-shift bytes beneath it (no other rule is reachable past the anchor),
    /// while dot-segments still anchor wide and deny against this multi-rule table.
    /// No opaque declaration needed — uniformity is derived from the table.
    #[test]
    fn uniform_subtree_allows_separator_denies_dotdot() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !g.ambiguous("/files/a%2fb"),
            "encoded slash in a uniform subtree"
        );
        assert!(
            !g.ambiguous("/files/a;b"),
            "matrix param in a uniform subtree"
        );
        // Dot-segments anchor `k` levels wider (one per `..`-capable segment): a climb
        // that provably resolves *within* the subtree flows, one that can reach the
        // root — where this table is not uniform — denies.
        assert!(
            !g.ambiguous("/files/a/../b"),
            "one `..` under /files/a/ climbs at most to /files/"
        );
        assert!(
            !g.ambiguous("/files/a/%2e%2e/b"),
            "encoded form of the same in-subtree climb"
        );
        assert!(
            g.ambiguous("/files/../b"),
            "one `..` under /files/ can climb out"
        );
        assert!(
            g.ambiguous("/files/%2e%2e/b"),
            "encoded climb out of the subtree"
        );
        assert!(
            g.ambiguous("/files/a/../../b"),
            "two `..` under /files/a/ can climb out"
        );
        // The relaxation is anchored: the same separator byte in the *first* segment
        // has the root as its anchor, where the table is not uniform.
        assert!(g.ambiguous("/fi%2fles/a"), "separator before the subtree");
    }

    /// A lone catch-all pattern is **not** a uniform subtree: without its `/files/`
    /// (and `/files`) companions, the empty remainder — reachable via a `;`-strip —
    /// falls to the default rule, so boundary-shift bytes keep denying. Register the
    /// full subtree (`subtree`/`blob_subtree` do) to get the relaxation.
    #[test]
    fn lone_catchall_is_not_uniform() {
        let g = guard(
            &[("/files/*", 0, true)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/files/a%2fb"), "gap to the default rule");
        assert!(!g.ambiguous("/files/clean"), "clean paths still flow");
    }

    /// An *encoded* matrix param that reveals a dot-segment (`..%3bx` — a `;`-stripping
    /// servlet backend climbs out of the blob) is denied just like the literal `..;x`.
    /// The blob tolerates a `;` as a boundary-shift byte, but never the traversal it hides.
    #[test]
    fn opaque_blob_denies_encoded_param_traversal() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, true),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        // A plain matrix param on a real segment stays tolerated.
        assert!(
            !g.ambiguous("/files/a;b/c"),
            "matrix param on a real key segment"
        );
        // The literal Tomcat `..;` vector is denied even in the blob.
        assert!(g.ambiguous("/files/..;x/secret"), "literal `..;x`");
        // The encoded equivalents must be denied too — the bug this closes.
        assert!(g.ambiguous("/files/..%3bx/secret"), "encoded `..%3bx`");
        assert!(g.ambiguous("/files/..%3Bx/secret"), "encoded `..%3Bx`");
    }

    /// Incomplete coverage denies everywhere: a lone `/files/*/*` leaves gaps (the
    /// one-segment and empty remainders fall to the default rule), so no anchor under
    /// it is uniform — boundary-shift bytes deny in the tail and in the preceding
    /// wildcard alike. (Under the old span model the tail was tolerated; the scoped
    /// model is stricter exactly because a `;`-strip could shorten the tail into the
    /// default rule.)
    #[test]
    fn incomplete_coverage_denies_boundary_shift_everywhere() {
        let g = guard(
            &[("/files/*/*", 0, true)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/files/ab/c%2fd"), "%2f in the catch-all tail");
        assert!(
            g.ambiguous("/files/a%2fb/c"),
            "%2f in the preceding wildcard"
        );
        assert!(!g.ambiguous("/files/ab/cd"), "clean paths still flow");
    }

    /// Unrouted URL space is uniformly the default rule: a structural byte there
    /// cannot relocate between rules, so it flows. (Deliberate behavior change from
    /// the uniform-live model; the default rule governs those paths either way.)
    #[test]
    fn unrouted_space_tolerates_structural_bytes() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !g.ambiguous("/public/a%2fb"),
            "everything under /public/ is the default rule"
        );
        // At the root the table is not uniform (admin vs default), so a first-segment
        // separator still denies…
        assert!(g.ambiguous("/pub%2flic/a"), "root anchor is mixed");
        // …as does a dot-segment (root-anchored), and NUL everywhere.
        assert!(g.ambiguous("/public/../x"), "dot-segment anchors at root");
        assert!(g.ambiguous("/public/a%00b"), "NUL denies unconditionally");
    }

    /// The `//`-merge root regression: `/` (root leaf) and `/{*rest}` carry different
    /// rules, and slash-merging `//` → `/` relocates between them — the root anchor
    /// must count the bare leaf. With one shared rule the same path flows.
    #[test]
    fn root_leaf_merge_relocation_denied() {
        let split = guard(
            &[("/", 1, false), ("/*", 0, false)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            split.ambiguous("//"),
            "merge relocates catch-all → root leaf"
        );
        let uniform = guard(
            &[("/", 0, false), ("/*", 0, false)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!uniform.ambiguous("//"), "one-rule table cannot relocate");
    }

    /// A method-qualified route inside an otherwise-uniform subtree resolves other
    /// methods to the default rule, so the subtree is not uniform and boundary-shift
    /// bytes keep denying — the guard is method-blind, and this is what keeps that
    /// sound.
    #[test]
    fn method_only_route_keeps_subtree_denying() {
        let entries = vec![
            (
                parse_pattern("/files").expect("p"),
                0,
                false,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/").expect("p"),
                0,
                false,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/*").expect("p"),
                0,
                false,
                MethodMatch::Any,
            ),
            (
                parse_pattern("/files/upload").expect("p"),
                1,
                false,
                MethodMatch::from(http::Method::POST),
            ),
        ];
        let g = StructuralGuard::new(
            Router::build(&entries).expect("build"),
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        );
        assert!(
            g.ambiguous("/files/a%2fb"),
            "method-split terminal keeps the subtree mixed"
        );
    }

    /// Strict mode ignores opaque declarations and treats any escape as non-canonical.
    #[test]
    fn noncanonical_ignores_opaque_and_denies_escapes() {
        let g = guard(
            &[("/files/*", 0, true)],
            PathConfusion::RejectNonCanonical,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/files/a%2fb"), "opaque ignored when strict");
        assert!(g.ambiguous("/files/a%20b"), "any escape is non-canonical");
        assert!(!g.ambiguous("/files/ab"), "clean path still allowed");
    }

    /// Case is structural only under a case-folding backend.
    #[test]
    fn case_sensitivity_gates_uppercase() {
        let rows = &[("/admin", 0, false)];
        let sensitive = guard(
            rows,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !sensitive.ambiguous("/Admin"),
            "case ignored when sensitive"
        );

        let insensitive = guard(
            rows,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(insensitive.ambiguous("/Admin"), "/Admin folds onto /admin");
        assert!(
            !insensitive.ambiguous("/admin"),
            "lowercase clean path allowed"
        );
    }

    /// The case-fold check is **precise** (fold-and-reroute, like content-decode), not a
    /// presence deny: uppercase that folds *within its own rule* is allowed; uppercase
    /// that folds onto a *different* rule is denied.
    #[test]
    fn case_fold_is_precise_not_presence() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, false),
                ("/users/*", 1, false),
                ("/users/admin", 2, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        // Same-rule folds keep flowing: the capital sits in a capture and the folded
        // path lands on the same rule.
        assert!(
            !g.ambiguous("/files/ReadMe.TXT"),
            "mixed-case content within one rule"
        );
        assert!(
            !g.ambiguous("/users/Alice"),
            "folds to /users/alice — same catch-all rule"
        );
        // Cross-rule folds deny: the folded path reaches a rule the raw path missed.
        assert!(
            g.ambiguous("/users/ADMIN"),
            "folds onto the /users/admin literal — a different rule"
        );
        assert!(
            g.ambiguous("/Files/x"),
            "folds onto the /files subtree from the default rule"
        );
        // Strict mode stays blunt: any uppercase is non-canonical there.
        let strict = guard(
            &[("/files/*", 0, false)],
            PathConfusion::RejectNonCanonical,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(
            strict.ambiguous("/files/ReadMe.TXT"),
            "strict denies on presence"
        );
    }

    /// A mixed-case key inside an opaque blob folds within the blob's own rule and is
    /// allowed; folding can never *escape* the blob (a differently-cased prefix that
    /// folds onto the blob is still denied — it relocates from the default rule).
    #[test]
    fn opaque_blob_allows_mixed_case_keys() {
        let g = guard(
            &[
                ("/files", 0, false),
                ("/files/", 0, false),
                ("/files/*", 0, true),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(!g.ambiguous("/files/Key%2FPart"), "mixed-case opaque key");
        assert!(
            g.ambiguous("/FILES/x"),
            "folding prefix relocates into the blob"
        );
        assert!(
            g.ambiguous("/files/A/../b"),
            "dot-segment still denied in the blob"
        );
    }

    /// Regression (found by the `guard_relocation` fuzz target): under a NUL-truncating
    /// backend, a *raw* NUL must be denied — `/a\0junk` matched the default rule and was
    /// allowed, while the backend truncates it to `/a` (a different rule). Raw and encoded
    /// NUL are treated alike, mirroring raw vs encoded `;`/`\` — and the class is
    /// **always-on** (NUL has no legitimate use in a path, so denying it by default
    /// costs nothing while an undeclared C-string backend is a silent bypass).
    #[test]
    fn raw_nul_truncation_denied_by_default() {
        let g = guard(
            &[("/a", 0, false), ("/a/", 0, false), ("/a/*", 0, false)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/a\u{0}b"), "raw NUL truncates to /a");
        assert!(g.ambiguous("/a%00b"), "encoded NUL truncates to /a");
        assert!(!g.ambiguous("/a"), "clean path allowed");
        // Denied even inside an opaque blob — truncation, like a dot-segment,
        // escapes any span.
        let blob = guard(
            &[("/files/*", 0, true)],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(blob.ambiguous("/files/a%00b"), "NUL denied in a blob key");
    }

    /// Up-to-two decode is a required declaration, not a class toggle: under
    /// [`DecodeLayers::UpToTwo`] the double-encoded traversal that slips a single-pass
    /// front (the CVE-2025-0108 shape) is denied; under `Single` a `%252e` reaches the
    /// lone backend as the literal `%2e` and is not structure.
    #[test]
    fn decode_layers_gates_double_encoding() {
        let rows: &[(&str, RuleId, bool)] = &[
            ("/public", 0, false),
            ("/public/", 0, false),
            ("/public/*", 0, false),
            ("/admin", 1, false),
        ];
        let up_to_two = guard_layers(
            rows,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::UpToTwo,
            CaseSensitivity::Sensitive,
        );
        assert!(
            up_to_two.ambiguous("/public/%252e%252e/admin"),
            "double-encoded traversal denied under UpToTwo"
        );
        // A double-encoded separator *before* any rule boundary (first segment →
        // root anchor, where /public and /admin diverge) is structure under UpToTwo…
        assert!(
            up_to_two.ambiguous("/pub%252flic/a"),
            "double-encoded separator at a rule boundary denied under UpToTwo"
        );
        // …but inside the uniform /public subtree it cannot relocate: scoped-allowed
        // even under UpToTwo (this is the blob-key case UpToTwo's docs promise).
        assert!(
            !up_to_two.ambiguous("/public/a%252fb"),
            "double-encoded separator inside a uniform subtree stays tolerated"
        );
        let single = guard_layers(
            rows,
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::Single,
            CaseSensitivity::Sensitive,
        );
        assert!(
            !single.ambiguous("/pub%252flic/a"),
            "a lone backend sees literal %2f content — not structure"
        );
    }

    /// Content-decode catches a relocation the positional scan cannot see.
    #[test]
    fn content_decode_relocation_denied() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(g.ambiguous("/%61dmin"), "/%61dmin decodes to /admin");
        // Precise: a same-rule decode (opaque content) is allowed.
        assert!(!g.ambiguous("/admin/a%20b"), "encoded space under /admin");
        assert!(!g.ambiguous("/admin/x"), "clean path allowed");
    }

    /// Regression: a decode yielding **invalid UTF-8** must still be routed, not waved
    /// through. Treating it as "undecodable, therefore not a modeled relocation" let a
    /// single trailing `%FF` anywhere in the path suppress the whole content-decode
    /// check: `/%61dmin/x%FF` was authorized under the *default* rule and forwarded raw,
    /// and any backend that decodes to bytes served it inside `/admin`.
    #[test]
    fn content_decode_relocation_survives_invalid_utf8() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        for p in [
            "/%61dmin/x%FF",       // lone continuation byte
            "/%61dmin/x%C0",       // truncated two-byte lead
            "/%61dmin/x%E2%82",    // truncated three-byte sequence
            "/%61dmin/x%ED%A0%80", // encoded surrogate half
        ] {
            assert!(g.ambiguous(p), "{p} decodes into the /admin subtree");
        }
        // Still precise: invalid UTF-8 that does *not* relocate stays allowed, so the fix
        // is byte-routing rather than a blanket deny on undecodable input.
        assert!(
            !g.ambiguous("/admin/caf%E9.txt"),
            "latin-1 content decodes to the same rule"
        );
    }

    /// The other half of the detection-table audit's CASE row: *encoded* uppercase is not a
    /// positional concern (the byte scan flags only raw `A-Z`) — it is the content-decode
    /// check's job under a case-folding backend. `/%41dmin` → `/Admin` → `/admin` relocates.
    #[test]
    fn content_decode_catches_encoded_uppercase() {
        let g = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Insensitive,
        );
        assert!(
            g.ambiguous("/%41dmin"),
            "/%41dmin → /Admin → /admin under case folding"
        );
        // A case-sensitive backend distinguishes /Admin from /admin, so it is not a relocation.
        let sensitive = guard(
            &[
                ("/admin", 0, false),
                ("/admin/", 0, false),
                ("/admin/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(
            !sensitive.ambiguous("/%41dmin"),
            "/%41dmin → /Admin, a distinct path when case-sensitive"
        );
    }

    /// `Off` disables the guard entirely.
    #[test]
    fn off_allows_everything() {
        let g = guard(
            &[("/files/*", 0, false)],
            PathConfusion::Off,
            StructuralClasses::new(),
            CaseSensitivity::Sensitive,
        );
        assert!(!g.ambiguous("/files/a/../b"));
    }

    // ── metamorphic laws ──────────────────────────────────────────────────────
    //
    // The matcher has an oracle (matchit); the liveness verdict has none, so these are
    // invariants the verdict must satisfy for *all* inputs, plus a CVE ground-truth
    // corpus. The generators are constructive (a vocabulary mixing clean segments and
    // structural payloads, biased to hit the route prefixes) — random strings would pass
    // every law vacuously by never being denied.

    use proptest::prelude::*;

    use crate::path_confusion::StructuralChar;

    /// A structural configuration, with a monotone `tighten` for the L2 law.
    #[derive(Clone, Debug)]
    struct Cfg {
        mode: PathConfusion,
        insensitive: bool,
        backslash: bool,
        up_to_two: bool,
        unicode: bool,
        overlong: bool,
    }

    impl Cfg {
        /// The default-config baseline: positional reject, standard alphabet, sensitive.
        fn structural() -> Self {
            Self {
                mode: PathConfusion::RejectStructural,
                insensitive: false,
                backslash: false,
                up_to_two: false,
                unicode: false,
                overlong: false,
            }
        }

        fn classes(&self) -> StructuralClasses {
            let mut c = StructuralClasses::new();
            if self.backslash {
                c = c.with_backslash();
            }
            if self.unicode {
                c = c.with_unicode_normalization();
            }
            if self.overlong {
                c = c.with_overlong([StructuralChar::Slash, StructuralChar::Dot]);
            }
            c
        }

        fn layers(&self) -> DecodeLayers {
            if self.up_to_two {
                DecodeLayers::UpToTwo
            } else {
                DecodeLayers::Single
            }
        }

        fn case(&self) -> CaseSensitivity {
            if self.insensitive {
                CaseSensitivity::Insensitive
            } else {
                CaseSensitivity::Sensitive
            }
        }
    }

    /// One knob, in its safe (deny-more) direction — the L2 monotonicity steps.
    #[derive(Clone, Copy, Debug)]
    enum Tighten {
        Insensitive,
        Backslash,
        UpToTwo,
        Unicode,
        Overlong,
        NonCanonical,
    }

    impl Tighten {
        fn apply(self, base: &Cfg) -> Cfg {
            let mut c = base.clone();
            match self {
                Tighten::Insensitive => c.insensitive = true,
                Tighten::Backslash => c.backslash = true,
                Tighten::UpToTwo => c.up_to_two = true,
                Tighten::Unicode => c.unicode = true,
                Tighten::Overlong => c.overlong = true,
                Tighten::NonCanonical => c.mode = PathConfusion::RejectNonCanonical,
            }
            c
        }
    }

    /// Segment vocabulary mixing clean names (hitting the tables) with structural
    /// payloads across every class — including opt-in forms that stay inert unless the
    /// matching toggle is on, so config tightening visibly changes the verdict.
    const SEG_VOCAB: &[&str] = &[
        "a", "b", "x", "admin", "users", "files", "edit", "super", "secret", "a%2fb", "..",
        "%2e%2e", "a;b", "..;x", "a%5cb", "a%00b", "a%252fb", "a%c0%afb", "Abc",
    ];

    fn arb_cfg() -> impl Strategy<Value = Cfg> {
        (
            prop_oneof![
                Just(PathConfusion::RejectStructural),
                Just(PathConfusion::RejectNonCanonical)
            ],
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(
                |(mode, insensitive, backslash, up_to_two, unicode, overlong)| Cfg {
                    mode,
                    insensitive,
                    backslash,
                    up_to_two,
                    unicode,
                    overlong,
                },
            )
    }

    fn arb_tighten() -> impl Strategy<Value = Tighten> {
        prop_oneof![
            Just(Tighten::Insensitive),
            Just(Tighten::Backslash),
            Just(Tighten::UpToTwo),
            Just(Tighten::Unicode),
            Just(Tighten::Overlong),
            Just(Tighten::NonCanonical),
        ]
    }

    /// A request path of vocab segments — mixes clean and structural, hits the prefixes.
    fn arb_request_path() -> impl Strategy<Value = String> {
        proptest::collection::vec(0..SEG_VOCAB.len(), 1..4).prop_map(|idxs| {
            let segs: Vec<&str> = idxs.iter().map(|&i| SEG_VOCAB[i]).collect();
            format!("/{}", segs.join("/"))
        })
    }

    /// A clean path: lowercase alphanumerics, no escape, no structural byte — clean under
    /// every config, including `Insensitive` and `RejectNonCanonical`.
    fn arb_clean_path() -> impl Strategy<Value = String> {
        proptest::collection::vec("[a-z][a-z0-9]{0,4}", 1..4)
            .prop_map(|segs| format!("/{}", segs.join("/")))
    }

    /// A path under `/files` carrying a dot-segment in one of its forms — for L4.
    fn arb_dotty_path() -> impl Strategy<Value = String> {
        const DOTS: &[&str] = &[
            "..",
            "%2e%2e",
            "%2E%2e",
            ".%2e",
            "..;x",
            "..%3bx",
            "..%3Bx",
            "a%2f..%2fb",
        ];
        const TAILS: &[&str] = &["", "/x", "/admin"];
        (0..DOTS.len(), 0..TAILS.len()).prop_map(|(d, t)| format!("/files/{}{}", DOTS[d], TAILS[t]))
    }

    const GENERAL: &[(&str, RuleId, bool)] = &[
        ("/admin", 0, false),
        ("/admin/", 0, false),
        ("/admin/*", 0, false),
        ("/admin/super", 1, false),
        ("/users/*", 2, false),
        ("/a/*/edit", 3, false),
    ];

    fn guard_cfg(rows: &[(&str, RuleId, bool)], cfg: &Cfg) -> StructuralGuard {
        guard_layers(rows, cfg.mode, cfg.classes(), cfg.layers(), cfg.case())
    }

    fn files_rows(opaque: bool) -> Vec<(&'static str, RuleId, bool)> {
        vec![
            ("/files", 0, false),
            ("/files/", 0, false),
            ("/files/*", 0, opaque),
        ]
    }

    proptest! {
        /// L1: a path with no enabled structural byte is never denied, under any config.
        #[test]
        fn l1_clean_never_denied(cfg in arb_cfg(), path in arb_clean_path()) {
            let g = guard_cfg(GENERAL, &cfg);
            prop_assert!(!g.ambiguous(&path), "clean path denied: {:?}", path);
        }

        /// L2: tightening the config (a class on, case-fold on, or strict mode) only ever
        /// turns allows into denies — every knob's unsafe direction is the same direction.
        #[test]
        fn l2_monotone(cfg in arb_cfg(), step in arb_tighten(), path in arb_request_path()) {
            let base = guard_cfg(GENERAL, &cfg);
            let stricter = guard_cfg(GENERAL, &step.apply(&cfg));
            prop_assert!(
                !base.ambiguous(&path) || stricter.ambiguous(&path),
                "{:?} via {:?} turned a deny into an allow",
                path,
                step
            );
        }

        /// L3: the opaque flag is **runtime-irrelevant** — scoped denial derives the
        /// relaxation from subtree uniformity, which a validated blob has by
        /// construction, so declaring it changes no verdict. (Its value is the
        /// build-time sibling guarantee, pinned by L6.) And the relaxation is
        /// class-bounded: boundary-shift bytes are scoped to their anchor,
        /// dot-segments to their climb radius — but NUL truncation is **never**
        /// relaxed on any allowed path.
        #[test]
        fn l3_opaque_flag_is_runtime_irrelevant(path in arb_request_path()) {
            let cfg = Cfg::structural();
            let normal = guard_cfg(&files_rows(false), &cfg);
            let blob = guard_cfg(&files_rows(true), &cfg);
            prop_assert_eq!(
                normal.ambiguous(&path),
                blob.ambiguous(&path),
                "opaque flag changed a verdict on {:?}", path
            );

            let enabled = enabled_classes(&StructuralClasses::new());
            let enc = enabled_encodings(&StructuralClasses::new(), DecodeLayers::Single);
            let present = classes_present(&path, enabled, enc).intersect(enabled);
            if !normal.ambiguous(&path) {
                prop_assert!(
                    !present.contains_any(ClassSet::TRUNCATION),
                    "truncation was relaxed: {:?} ({:?})", path, present
                );
            }
        }

        /// L4: a dot-segment is denied under RejectStructural regardless of placement —
        /// opaque cannot reopen traversal.
        #[test]
        fn l4_dot_segment_inviolable(path in arb_dotty_path()) {
            let cfg = Cfg::structural();
            prop_assert!(guard_cfg(&files_rows(false), &cfg).ambiguous(&path), "normal: {:?}", path);
            prop_assert!(guard_cfg(&files_rows(true), &cfg).ambiguous(&path), "blob: {:?}", path);
        }

        /// L5: RejectNonCanonical denies a superset of RejectStructural (same classes).
        #[test]
        fn l5_noncanonical_dominates(cfg in arb_cfg(), path in arb_request_path()) {
            let rs = guard_cfg(GENERAL, &Cfg { mode: PathConfusion::RejectStructural, ..cfg.clone() });
            let rn = guard_cfg(GENERAL, &Cfg { mode: PathConfusion::RejectNonCanonical, ..cfg });
            prop_assert!(!rs.ambiguous(&path) || rn.ambiguous(&path), "{:?}", path);
        }

        /// L6: an opaque catch-all with a routing sibling is unconstructable.
        #[test]
        fn l6_opaque_with_sibling_rejected(leaf in "[a-z]{1,4}") {
            let entries = vec![
                (parse_pattern("/p/*").expect("blob"), 0, true, MethodMatch::Any),
                (
                    parse_pattern(&format!("/p/{leaf}")).expect("sibling"),
                    1,
                    false,
                    MethodMatch::Any,
                ),
            ];
            // Explicit message: prop_assert! stringifies its condition into a format
            // string, and the `{ .. }` pattern would break that.
            prop_assert!(
                matches!(Router::build(&entries), Err(BuildError::OpaqueTailHasSibling { .. })),
                "opaque catch-all with a routing sibling must be rejected"
            );
        }
    }

    /// L7: CVE ground truth — known-bad inputs must deny, and declaring the public prefix
    /// an opaque blob must not reopen any of them.
    #[test]
    fn cve_corpus_denied() {
        let classes = StructuralClasses::new();
        // CVE-2019-9901 (Envoy): `/public/../admin` climbs into a protected route.
        let envoy = |opaque| {
            guard(
                &[
                    ("/public", 0, false),
                    ("/public/", 0, false),
                    ("/public/*", 0, opaque),
                    ("/admin", 1, false),
                ],
                PathConfusion::RejectStructural,
                classes.clone(),
                CaseSensitivity::Sensitive,
            )
        };
        assert!(envoy(false).ambiguous("/public/../admin"));
        assert!(
            envoy(true).ambiguous("/public/../admin"),
            "opaque blob must not reopen the traversal"
        );

        // CVE-2021-31920 (Istio): `//admin` and `%2f`-escaped slashes bypass policy.
        let istio = guard(
            &[("/admin", 0, false)],
            PathConfusion::RejectStructural,
            classes.clone(),
            CaseSensitivity::Sensitive,
        );
        assert!(istio.ambiguous("//admin"));
        assert!(istio.ambiguous("/x%2fadmin"));

        // CVE-2021-41773 (Apache): encoded `%2e%2e` dot-segments escape an alias.
        let apache = guard(
            &[
                ("/cgi-bin", 0, false),
                ("/cgi-bin/", 0, false),
                ("/cgi-bin/*", 0, false),
                ("/secret", 1, false),
            ],
            PathConfusion::RejectStructural,
            classes.clone(),
            CaseSensitivity::Sensitive,
        );
        assert!(apache.ambiguous("/cgi-bin/%2e%2e/secret"));

        // CVE-2025-0108 (PAN-OS): nginx decoded `%252e%252e` once and let it past a
        // no-auth prefix; Apache decoded again and traversed. The topology is declared
        // (`DecodeLayers::UpToTwo`), and the double-encoded traversal is denied.
        let panos = guard_layers(
            &[
                ("/unauth", 0, false),
                ("/unauth/", 0, false),
                ("/unauth/*", 0, false),
                ("/php", 1, false),
            ],
            PathConfusion::RejectStructural,
            classes,
            DecodeLayers::UpToTwo,
            CaseSensitivity::Sensitive,
        );
        assert!(panos.ambiguous("/unauth/%252e%252e/php"));
        // The single-encoded form is caught by the default quartet regardless.
        assert!(panos.ambiguous("/unauth/%2e%2e/php"));

        // CVE-2026-73511 / GHSA-m745-gh6x-349x (Envoy): Envoy matched the raw `:path`
        // while a servlet backend (Tomcat) strips `;params` **per segment**, so
        // `/auth;x=y/` and `/;x=y/auth/` both reached a `/auth/` route that returned 403
        // for the literal path. Envoy's `ignore_path_parameters_in_path_matching` only
        // truncated at the *first* `;` in the whole path, which is why the second shape —
        // the param in a segment *before* the protected one — survived the option.
        //
        // Here the strip is a relocation *into* the protected rule from the default, and
        // PARAM is in the default quartet, so both shapes deny with no declaration.
        let servlet = |opaque| {
            guard(
                &[
                    ("/auth", 0, false),
                    ("/auth/", 0, false),
                    ("/auth/*", 0, opaque),
                ],
                PathConfusion::RejectStructural,
                StructuralClasses::new(),
                CaseSensitivity::Sensitive,
            )
        };
        assert!(servlet(false).ambiguous("/auth;x=y/"));
        assert!(
            servlet(false).ambiguous("/;x=y/auth/"),
            "the param sits in a segment before the protected one — the shape Envoy's \
             first-`;` truncation missed"
        );
        // Every form the byte scan treats as PARAM introduces the strip, so an *encoded*
        // matrix param is denied exactly as the literal one is.
        assert!(servlet(false).ambiguous("/auth%3bx=y/"));
        assert!(servlet(false).ambiguous("/%3bx=y/auth/"));
        // An opaque blob beneath /auth must not reopen the relocation into it: the
        // boundary the param crosses is the subtree anchor, not a byte inside the blob.
        assert!(
            servlet(true).ambiguous("/auth;x=y/"),
            "opaque blob must not reopen the param strip at the anchor"
        );
        // The double-encoded form is a topology fact, not a default: under `Single` a
        // `%253b` never becomes a `;`, so it routes to the default rule and is allowed;
        // declaring the second decoder denies it.
        let servlet_two = guard_layers(
            &[
                ("/auth", 0, false),
                ("/auth/", 0, false),
                ("/auth/*", 0, false),
            ],
            PathConfusion::RejectStructural,
            StructuralClasses::new(),
            DecodeLayers::UpToTwo,
            CaseSensitivity::Sensitive,
        );
        assert!(!servlet(false).ambiguous("/auth%253bx=y/"));
        assert!(servlet_two.ambiguous("/auth%253bx=y/"));
    }
}
