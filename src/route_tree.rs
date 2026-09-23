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

use std::collections::HashMap;

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
/// **orthogonal to path**: path traversal is method-independent; terminal resolution
/// and structural coverage use the request method.
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
/// less-specific path. See [Routing behavior](crate::_docs::reference::routing).
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

    /// Resolve specific-method → all-method rule → default.
    fn get(&self, method: &http::Method) -> Option<RuleId> {
        self.exact
            .iter()
            .find(|(registered, _)| registered == method)
            .map(|(_, id)| *id)
            .or(self.any)
    }

    /// Coverage for one method, or for all unregistered methods (`None`). An empty
    /// slot contributes nothing, but a claimed path with no rule for this method
    /// contributes the default: path matching must not fall back in that case.
    fn cover(&self, method: Option<&http::Method>) -> Cover {
        if self.is_empty() {
            Cover::Empty
        } else {
            Cover::Uniform(
                method
                    .map_or(self.any, |m| self.get(m))
                    .unwrap_or(DEFAULT_RULE),
            )
        }
    }

    /// Insert a rule for `method`; a duplicate `(position, method)` is a conflict
    /// ([`Router::build`] attributes it to the entry as [`BuildError::Conflict`]),
    /// including a method listed twice within one `OneOf`. An empty `OneOf` inserts
    /// nothing (the terminal stays unclaimed); `RuleRouter::from_registrations` rejects it before
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
    /// Coverage for methods without an explicit registration anywhere in the table.
    other_cover: RegionCover,
    /// Coverage in the router's method-index order. Empty for all-method tables.
    method_covers: Vec<RegionCover>,
}

/// Summaries for one method category at a node.
#[derive(Clone, Copy, Default)]
struct RegionCover {
    /// All terminals, including the bare leaf (also used at the root anchor).
    all: Cover,
    /// Excludes the bare leaf: a non-root anchor retains its trailing separator.
    below: Cover,
}

impl Node {
    fn cover(&self, method_index: Option<usize>) -> RegionCover {
        method_index.map_or(self.other_cover, |index| {
            self.method_covers
                .get(index)
                .copied()
                .unwrap_or(RegionCover {
                    all: Cover::Mixed,
                    below: Cover::Mixed,
                })
        })
    }
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
    /// Another pattern can take precedence beneath an exclusive catch-all,
    /// including through an overlapping literal or wildcard branch.
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
    method_indices: HashMap<http::Method, usize>,
}

impl Router {
    /// Expand the same conservative coverage used by `anchor_cover` for diagnostics.
    pub(crate) fn anchor_identities(&self, anchor: &str, method: &http::Method) -> Vec<RuleId> {
        let segments: Vec<_> = anchor.split('/').filter(|s| !s.is_empty()).collect();
        let mut ids = Vec::new();
        let complete = if let Some((first, rest)) = segments.split_first() {
            walk_identities(&self.root, first, rest, method, &mut ids)
        } else {
            collect_identities(&self.root, method, true, &mut ids);
            !self.root.leaf.is_empty() && !self.root.catchall.is_empty()
        };
        if !complete {
            ids.push(DEFAULT_RULE);
        }
        ids.sort_unstable();
        ids.dedup();
        ids
    }

    /// Find a method gap and the rule hidden by the claimed path terminal.
    pub(crate) fn method_gap(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        let body = path.as_bytes().strip_prefix(b"/")?;
        if body.is_empty() {
            return None;
        }
        let claimed = route(&self.root, body)?;
        if claimed.get(method).is_some() {
            return None;
        }
        route_skipping(&self.root, body, Some(claimed))?.get(method)
    }

    /// Build a router from `(pattern, rule_id, opaque)` entries.
    ///
    /// `opaque` declares a pattern's trailing catch-all an opaque blob — a build-time
    /// guarantee that no more-specific path takes over beneath it ([`validate_opaque`]);
    /// it is ignored for
    /// patterns without a catch-all and adds no runtime behavior of its own.
    ///
    /// # Errors
    ///
    /// [`BuildError`] on a terminal conflict or an opaque catch-all with a routing sibling.
    pub(crate) fn build(
        entries: &[(Pattern, RuleId, bool, MethodMatch)],
    ) -> Result<Self, BuildError> {
        let mut root = Node::default();
        for (i, (pat, id, _, method)) in entries.iter().enumerate() {
            insert(&mut root, &pat.segments, pat.trailing_slash, *id, method)
                .map_err(|SlotConflict| BuildError::Conflict { index: i })?;
        }
        validate_opaque(entries)?;
        let mut method_indices = HashMap::new();
        let mut methods = Vec::new();
        for (_, _, _, selection) in entries {
            if let MethodMatch::OneOf(exact) = selection {
                for method in exact {
                    if let std::collections::hash_map::Entry::Vacant(entry) =
                        method_indices.entry(method.clone())
                    {
                        entry.insert(methods.len());
                        methods.push(method.clone());
                    }
                }
            }
        }
        compute_cover(&mut root, &methods);
        Ok(Self {
            root,
            method_indices,
        })
    }

    /// Match `path`, then resolve the claimed terminal with `method`.
    /// A path that claims a terminal but has no rule for `method` returns
    /// `None` — never a fall-back to a less-specific path.
    fn at(&self, path: &[u8], method: &http::Method) -> Option<RuleId> {
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

    /// GET matching for method-agnostic test oracles.
    #[cfg(test)]
    pub(crate) fn route_id(&self, path: &str) -> Option<RuleId> {
        self.at(path.as_bytes(), &http::Method::GET)
    }

    /// [`route_id`](Self::route_id) for a **raw byte** path — what a percent-decode can
    /// produce. Decoding `%FF` yields bytes that are not valid UTF-8, and a real backend
    /// routes them anyway; matching must model that rather than decline to answer. For
    /// valid UTF-8 this is identical to [`route_id`](Self::route_id) (splitting on the
    /// ASCII `/` keeps every segment valid), so the two can never disagree.
    #[cfg(test)]
    pub(crate) fn route_id_bytes(&self, path: &[u8]) -> Option<RuleId> {
        self.at(path, &http::Method::GET)
    }

    /// The matched rule id for a raw-byte path and a specific method.
    pub(crate) fn resolve_bytes(&self, path: &[u8], method: &http::Method) -> Option<RuleId> {
        self.at(path, method)
    }

    /// The matched rule id for a specific method (specific → wildcard → none).
    pub(crate) fn resolve(&self, path: &str, method: &http::Method) -> Option<RuleId> {
        self.at(path.as_bytes(), method)
    }

    /// The [`Cover`] of **every rule id reachable by any path extending `anchor`** — a
    /// clean, `/`-terminated prefix (`"/"`, `"/files/"`, …), for the request method. This is the scoped
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
    pub(crate) fn anchor_cover(&self, anchor: &str, method: &http::Method) -> Cover {
        let method_index = self.method_indices.get(method).copied();
        let mut segs = anchor.split('/').filter(|s| !s.is_empty());
        if let Some(first) = segs.next() {
            let rest: Vec<&str> = segs.collect();
            let (cover, complete) = walk_cover(&self.root, first, &rest, method, method_index);
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
                self.root.cover(method_index).all
            } else {
                self.root.cover(method_index).all.with(DEFAULT_RULE)
            }
        }
    }
}

/// Precompute coverage for each explicitly registered method and one shared
/// category for every other method. All-method tables need no per-method vectors.
fn compute_cover(node: &mut Node, methods: &[http::Method]) {
    for child in node.literals.values_mut() {
        compute_cover(child, methods);
    }
    if let Some(child) = node.wildcard.as_deref_mut() {
        compute_cover(child, methods);
    }
    node.other_cover = summarize(node, None, None);
    node.method_covers = methods
        .iter()
        .enumerate()
        .map(|(index, method)| summarize(node, Some(method), Some(index)))
        .collect();
}

fn summarize(node: &Node, method: Option<&http::Method>, index: Option<usize>) -> RegionCover {
    let mut below = node
        .leaf_slash
        .cover(method)
        .join(node.catchall.cover(method));
    for child in node.literals.values() {
        below = below.join(child.cover(index).all);
    }
    if let Some(child) = node.wildcard.as_deref() {
        below = below.join(child.cover(index).all);
    }
    RegionCover {
        all: below.join(node.leaf.cover(method)),
        below,
    }
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
/// contributes its method-specific `below` summary, and its completeness requires its own catch-all (all
/// non-empty remainders) *and* `leaf_slash` (the empty remainder — a `;`-strip can
/// produce exactly the anchor path). That conjunction is per-node rather than across
/// tiers — cheaper, and wrong only toward denial. Completeness remains method-blind:
/// a claimed terminal with no rule for this method resolves to the default and blocks
/// fallback, just as it does in `route`.
fn walk_cover(
    node: &Node,
    seg: &str,
    rest: &[&str],
    method: &http::Method,
    method_index: Option<usize>,
) -> (Cover, bool) {
    let descend = |child: &Node| match rest.split_first() {
        Some((next, tail)) => walk_cover(child, next, tail, method, method_index),
        None => (
            child.cover(method_index).below,
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
    (
        cover.join(node.catchall.cover(Some(method))),
        !node.catchall.is_empty(),
    )
}

/// Expand cached summaries only on the optional explanation path. This follows
/// `summarize` and `walk_cover`, including their conservative completeness rules.
fn collect_identities(node: &Node, method: &http::Method, leaf: bool, ids: &mut Vec<RuleId>) {
    let slots = [&node.leaf_slash, &node.catchall];
    for slot in slots.into_iter().chain(leaf.then_some(&node.leaf)) {
        if !slot.is_empty() {
            ids.push(slot.get(method).unwrap_or(DEFAULT_RULE));
        }
    }
    for child in node.literals.values().chain(node.wildcard.as_deref()) {
        collect_identities(child, method, true, ids);
    }
}

fn walk_identities(
    node: &Node,
    segment: &str,
    rest: &[&str],
    method: &http::Method,
    ids: &mut Vec<RuleId>,
) -> bool {
    for child in node
        .literals
        .get(segment)
        .into_iter()
        .chain(node.wildcard.as_deref())
    {
        let complete = if let Some((next, tail)) = rest.split_first() {
            walk_identities(child, next, tail, method, ids)
        } else {
            collect_identities(child, method, false, ids);
            !child.catchall.is_empty() && !child.leaf_slash.is_empty()
        };
        if complete {
            return true;
        }
    }
    if node.catchall.is_empty() {
        false
    } else {
        ids.push(node.catchall.get(method).unwrap_or(DEFAULT_RULE));
        true
    }
}

/// Recursive insert. `matchit`-style catch-all is always the final segment (guaranteed
/// by `parse_pattern` / `lower_matchit`), so its `rest` is empty.
fn insert(
    node: &mut Node,
    segs: &[Segment],
    trailing_slash: bool,
    id: RuleId,
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
            method,
        ),
        Some((Segment::Wildcard, rest)) => insert(
            node.wildcard.get_or_insert_with(Box::default),
            rest,
            trailing_slash,
            id,
            method,
        ),
        Some((Segment::CatchAll, _rest)) => {
            node.catchall.insert(method, id)?;
            Ok(())
        }
    }
}

/// Check parsed patterns rather than only tree descendants: a literal branch can
/// override an exclusive wildcard branch even though neither node contains the other.
/// Methods do not participate because path precedence is resolved first. Separate
/// method slots at the same catch-all remain allowed.
fn validate_opaque(entries: &[(Pattern, RuleId, bool, MethodMatch)]) -> Result<(), BuildError> {
    for (pattern, _, opaque, _) in entries {
        if !opaque {
            continue;
        }
        let Some((Segment::CatchAll, prefix)) = pattern.segments.split_last() else {
            continue;
        };
        if entries
            .iter()
            .any(|(other, _, _, _)| overrides_tail(prefix, &other.segments))
        {
            let mut at = String::new();
            for segment in prefix {
                at.push('/');
                match segment {
                    Segment::Literal(literal) => at.push_str(literal),
                    Segment::Wildcard | Segment::CatchAll => at.push('*'),
                }
            }
            if at.is_empty() {
                at.push('/');
            }
            return Err(BuildError::OpaqueTailHasSibling { at });
        }
    }
    Ok(())
}

/// Whether `candidate` can win for a path in the exclusive catch-all's tail.
/// The first differing segment fixes precedence (literal > wildcard > catch-all).
/// Later segments still have to overlap, but cannot reverse that precedence.
fn overrides_tail(prefix: &[Segment], mut candidate: &[Segment]) -> bool {
    let mut higher = false;
    for protected in prefix {
        let Some((next, rest)) = candidate.split_first() else {
            // An exact ancestor or the bare prefix does not consume the tail.
            return false;
        };
        match (protected, next) {
            (Segment::Literal(a), Segment::Literal(b)) if a != b => return false,
            (Segment::Wildcard, Segment::Literal(_)) => higher = true,
            (Segment::Literal(_), Segment::Wildcard) if !higher => return false,
            (_, Segment::CatchAll) => return higher,
            _ => {}
        }
        candidate = rest;
    }
    match candidate {
        [] => false,
        [Segment::CatchAll] => higher,
        _ => true,
    }
}

/// Find the terminal `s` (a non-empty path body) claims under `node` — its method-slot,
/// resolved later. Traversal is **method-blind** — a position is "matched" iff *some*
/// rule terminates there (`!slot.is_empty()`), so method never drives path
/// backtracking. Precedence is literal > wildcard > catch-all, **with backtracking**: a
/// higher-priority branch that dead-ends falls through to the next.
fn route<'a>(node: &'a Node, s: &[u8]) -> Option<&'a MethodSlot> {
    route_skipping(node, s, None)
}

/// Diagnostic matching can ignore one terminal to expose its path fallback.
fn route_skipping<'a>(
    node: &'a Node,
    s: &[u8],
    ignored: Option<&MethodSlot>,
) -> Option<&'a MethodSlot> {
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
        && let Some(slot) = descend(child, after, ignored)
    {
        return Some(slot);
    }
    // 2. single-segment wildcard — requires a non-empty segment.
    if !seg.is_empty()
        && let Some(child) = node.wildcard.as_deref()
        && let Some(slot) = descend(child, after, ignored)
    {
        return Some(slot);
    }
    // 3. catch-all — lowest priority; consumes the whole raw remainder `s` (>= 1 char).
    available(&node.catchall, ignored)
}

fn available<'a>(slot: &'a MethodSlot, ignored: Option<&MethodSlot>) -> Option<&'a MethodSlot> {
    (!slot.is_empty() && !ignored.is_some_and(|other| std::ptr::eq(slot, other))).then_some(slot)
}

/// After matching a segment against `child`, either terminate (leaf / leaf-with-trailing-
/// slash, by method-blind presence) or recurse on the remaining body.
fn descend<'a>(
    child: &'a Node,
    after: Option<&[u8]>,
    ignored: Option<&MethodSlot>,
) -> Option<&'a MethodSlot> {
    match after {
        // No `/` followed the segment: path ended here → a leaf match.
        None => available(&child.leaf, ignored),
        // A `/` followed, with nothing after it: a trailing-slash match.
        Some([]) => available(&child.leaf_slash, ignored),
        // More path remains after the `/`.
        Some(rest) => route_skipping(child, rest, ignored),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::cast_possible_truncation,
        clippy::needless_pass_by_value,
        clippy::struct_excessive_bools
    )]

    proptest::proptest! {
        #[test]
        fn expanded_diagnostic_coverage_agrees_with_cached_summaries(
            selections in proptest::collection::vec(0u8..4, 9),
            anchor in proptest::sample::select(vec!["/", "/files/", "/files/special/", "/other/", "/other/deep/"]),
        ) {
            let patterns = ["/", "/{*rest}", "/files", "/files/", "/files/{*rest}",
                "/files/special", "/{tenant}/deep", "/other/", "/other/{*rest}"];
            let entries: Vec<_> = patterns.into_iter().zip(selections).enumerate()
                .filter_map(|(index, (pattern, selection))| {
                    let methods = match selection {
                        0 => return None,
                        1 => MethodMatch::Any,
                        2 => MethodMatch::from(http::Method::GET),
                        _ => MethodMatch::from(http::Method::POST),
                    };
                    Some((lower_matchit(pattern).unwrap(), u32::try_from(index % 3).unwrap(), false, methods))
                }).collect();
            let router = Router::build(&entries).unwrap();
            for method in [http::Method::GET, http::Method::POST, http::Method::from_bytes(b"PURGE").unwrap()] {
                let expanded = router.anchor_identities(anchor, &method).into_iter()
                    .fold(Cover::Empty, Cover::with);
                proptest::prop_assert_eq!(expanded, router.anchor_cover(anchor, &method));
            }
        }
    }

    // Test-only conveniences: small rule-id casts, by-value helpers, and a wide config
    // struct don't warrant the production-grade pedantic lints.
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
        assert_eq!(
            r.anchor_cover("/files/", &http::Method::GET),
            Cover::Uniform(0)
        );
        // Anchors deeper inside the catch-all stay uniform — the walk bottoms out at
        // the catch-all node, which covers everything beneath it.
        assert_eq!(
            r.anchor_cover("/files/a/b/", &http::Method::GET),
            Cover::Uniform(0)
        );
        // The root anchor sees the default fall-through for paths outside /files.
        assert_eq!(r.anchor_cover("/", &http::Method::GET), Cover::Mixed);
    }

    #[test]
    fn anchor_cover_lone_catchall_leaks_default() {
        // Without `/files/` (leaf_slash), the empty remainder — reachable via e.g. a
        // `;`-strip emptying the tail — falls to the default rule: not uniform.
        let r = router(&[("/files/*", 0)]);
        assert_eq!(r.anchor_cover("/files/", &http::Method::GET), Cover::Mixed);
    }

    #[test]
    fn anchor_cover_unrouted_space_is_uniformly_default() {
        // Nothing under /public and no ancestor catch-all: every path there resolves
        // to the default rule, which is itself a uniform outcome.
        let r = router(&[("/admin", 0)]);
        assert_eq!(
            r.anchor_cover("/public/", &http::Method::GET),
            Cover::Uniform(DEFAULT_RULE)
        );
    }

    #[test]
    fn anchor_cover_sees_ancestor_wildcard_branch() {
        // A suffix dead-ending under /files/*/deep backtracks into /*/c: rule 1 is
        // reachable under the /files/ anchor even though its pattern never spells
        // "files" — the walk must follow the wildcard branch alongside the literal.
        let r = router(&[("/files/*/deep", 0), ("/*/c", 1)]);
        assert_eq!(r.anchor_cover("/files/", &http::Method::GET), Cover::Mixed);
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
        assert_eq!(
            r.anchor_cover("/files/", &http::Method::GET),
            Cover::Uniform(0)
        );
        // But an *incomplete* subtree leaks into the ancestor catch-all: mixed.
        let leaky = router(&[("/files/*", 0), ("/", 1), ("/*", 1)]);
        assert_eq!(
            leaky.anchor_cover("/files/", &http::Method::GET),
            Cover::Mixed
        );
    }

    #[test]
    fn anchor_cover_root_counts_the_bare_leaf() {
        // The `//`-merge regression: at the root anchor the empty remainder is the
        // bare `/` (root.leaf), which slash-merging really can produce. A table whose
        // `/` and `/{*rest}` carry different rules must read Mixed at "/".
        let r = router(&[("/", 1), ("/*", 0)]);
        assert_eq!(r.anchor_cover("/", &http::Method::GET), Cover::Mixed);
        // Same table with one shared rule id is uniform — and complete (leaf +
        // catch-all), so the default never joins.
        let uni = router(&[("/", 0), ("/*", 0)]);
        assert_eq!(uni.anchor_cover("/", &http::Method::GET), Cover::Uniform(0));
    }

    #[test]
    fn anchor_cover_method_gap_injects_default() {
        // GET stays uniform, but POST selects the default at the GET-only leaf
        // instead of falling back to the surrounding all-method catch-all.
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
        assert_eq!(r.anchor_cover("/x/", &http::Method::GET), Cover::Uniform(0));
        assert_eq!(r.anchor_cover("/x/", &http::Method::POST), Cover::Mixed);
        // The same shape with a method-wildcard terminal is uniform.
        let all = router(&[("/x/y", 0), ("/x/", 0), ("/x/*", 0)]);
        assert_eq!(
            all.anchor_cover("/x/", &http::Method::GET),
            Cover::Uniform(0)
        );
    }

    #[test]
    fn multi_method_slot_resolves_each_and_stays_method_gapped() {
        // A OneOf registration claims each listed method under its single rule id;
        // unlisted methods resolve uniformly to the default, while listed methods
        // have default-rule gaps outside the registered path.
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
        assert_eq!(r.anchor_cover("/", &http::Method::GET), Cover::Mixed);
        assert_eq!(r.anchor_cover("/", &http::Method::HEAD), Cover::Mixed);
        assert_eq!(
            r.anchor_cover("/", &http::Method::POST),
            Cover::Uniform(DEFAULT_RULE)
        );
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
}
