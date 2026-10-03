//! Real-server oracles, explicitly run by `mise run test-downstream`.
//! Fixtures identify resources/handlers without using our matcher.

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, hash_map::Entry},
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};

use http::Method;
use huskarl_route_guard::{
    GuardConfig, PathRegistration, ResolveError, RuleRouter, StructuralClasses,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Public,
    Admin,
    Files,
    Private,
    Exact,
    Parameterized,
}

#[path = "downstream/profiles.rs"]
mod profiles;

#[path = "downstream/corpus.rs"]
mod generated;

#[path = "downstream/regressions.rs"]
mod regressions;

#[path = "downstream/shrink.rs"]
mod shrink;

#[path = "downstream/shrink_pipeline.rs"]
mod shrink_pipeline;

use profiles::{DeploymentSettings, Profile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    Nested,
    Uniform,
    PrivateOnly,
    Methods,
    ExactException,
    ParameterizedException,
    Distinct,
}

fn router(layout: Layout, settings: DeploymentSettings) -> RuleRouter<Policy> {
    let classes = if settings.backslash {
        StructuralClasses::new()
    } else {
        StructuralClasses::new().without_backslash()
    };
    let classes = if settings.query_truncation {
        classes
    } else {
        classes.without_query_truncation()
    };
    let classes = if settings.fragment_truncation {
        classes
    } else {
        classes.without_fragment_truncation()
    };
    let config = GuardConfig::new(settings.case, settings.decode).with_structural_classes(classes);
    if matches!(
        layout,
        Layout::ExactException | Layout::ParameterizedException
    ) {
        let path = if layout == Layout::ExactException {
            "/exact.txt"
        } else {
            "/foo/{segment}/bar"
        };
        return RuleRouter::builder(Policy::Admin, config)
            .register_path(path, |p| p.all(Policy::Public))
            .register_path(format!("{path}/"), |p| p.all(Policy::Public))
            .build()
            .unwrap();
    }
    let mut builder = RuleRouter::builder(Policy::Public, config);
    let mut methods = if settings.include_head {
        vec![Method::GET, Method::HEAD]
    } else {
        vec![Method::GET]
    };
    if settings.static_post {
        methods.push(Method::POST);
    }
    for (path, policy) in [
        ("/admin", Policy::Admin),
        ("/files", Policy::Files),
        ("/files/private", Policy::Private),
    ] {
        if (layout == Layout::Uniform && policy == Policy::Private)
            || (layout == Layout::PrivateOnly && policy != Policy::Private)
        {
            continue;
        }
        let registration = PathRegistration::subtree(path);
        builder = builder.register(if layout == Layout::Methods {
            registration.methods(methods.clone(), policy)
        } else {
            registration.all(policy)
        });
    }
    if layout == Layout::Methods && !settings.static_post {
        builder = builder
            .register(PathRegistration::subtree("/files").method(Method::POST, Policy::Files));
        if settings.private_post_fallback {
            builder = builder.register(
                PathRegistration::subtree("/files/private").method(Method::POST, Policy::Files),
            );
        }
    }
    if layout == Layout::Distinct {
        for (path, policy) in [
            ("/exact.txt", Policy::Exact),
            ("/foo/{segment}/bar", Policy::Parameterized),
        ] {
            builder = builder
                .register_path(path, |p| p.all(policy))
                .register_path(format!("{path}/"), |p| p.all(policy));
        }
    }
    builder.build().unwrap()
}

struct Response {
    status: u16,
    body: String,
    location: Option<String>,
    route_id: Option<String>,
}

fn request(address: SocketAddr, path: &str, method: &Method) -> std::io::Result<Response> {
    // The generated corpus never contains request-line delimiters.
    assert!(!path.bytes().any(|b| b.is_ascii_whitespace()));
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "{method} {path} HTTP/1.0\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )?;
    let mut bytes = Vec::new();
    stream.take(64 * 1024).read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "connection closed without an HTTP response",
        ));
    }
    assert!(bytes.len() < 64 * 1024, "oversized response for {path:?}");
    let text = String::from_utf8(bytes).expect("fixture response is UTF-8");
    let (headers, body) = text.split_once("\r\n\r\n").expect("HTTP response");
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .expect("HTTP status")
        .parse()
        .expect("numeric status");
    Ok(Response {
        status,
        body: body.trim().to_owned(),
        route_id: headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("x-route-id"))
            .map(|(_, value)| value.trim().to_owned()),
        location: headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.trim().to_owned()),
    })
}

fn wait_until_ready(address: SocketAddr) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match request(address, "/public/probe.txt", &Method::GET) {
            Ok(response) if response.status == 200 && response.body == "public" => return,
            result => assert!(
                Instant::now() < deadline,
                "downstream fixture did not become ready: {:?}",
                result.err()
            ),
        }
        thread::sleep(Duration::from_millis(100));
    }
}

/// Each target with the input families that produced it.
type Corpus = BTreeMap<String, BTreeSet<&'static str>>;

/// Seeded composed-mutation search, enabled by `ROUTE_GUARD_DOWNSTREAM_SEED`.
#[derive(Clone, Copy)]
struct Search {
    seed: u64,
    budget: usize,
}

const DEFAULT_SEARCH_BUDGET: usize = 2_000;
// Shrinking costs real requests. Bound both the cases and the work per case.
const SHRINK_CASES_PER_CANDIDATE: usize = 5;
const SHRINK_CHECKS_PER_CASE: usize = 400;

fn search_from_env() -> Option<Search> {
    let seed = std::env::var("ROUTE_GUARD_DOWNSTREAM_SEED")
        .ok()
        .filter(|s| !s.is_empty())?;
    let seed = seed
        .parse()
        .expect("ROUTE_GUARD_DOWNSTREAM_SEED must be an unsigned 64-bit integer");
    let budget = std::env::var("ROUTE_GUARD_DOWNSTREAM_BUDGET")
        .ok()
        .filter(|s| !s.is_empty())
        .map_or(DEFAULT_SEARCH_BUDGET, |b| {
            b.parse()
                .expect("ROUTE_GUARD_DOWNSTREAM_BUDGET must be a count")
        });
    Some(Search { seed, budget })
}

/// The deterministic corpus, committed regressions, and optional seeded search.
fn corpus(search: Option<Search>) -> Corpus {
    let mut corpus = Corpus::new();
    let mut tag = |path: String, family: &'static str| {
        corpus.entry(path).or_default().insert(family);
    };
    for path in targeted_paths() {
        tag(path, "targeted");
    }
    for path in generated::grammar_paths() {
        tag(path, "grammar");
    }
    for regression in regressions::load() {
        tag(regression.path, "regression");
    }
    if let Some(search) = search {
        for (path, mutations) in generated::seeded_paths(search.seed, search.budget) {
            tag(path.clone(), "seeded");
            for mutation in mutations {
                tag(path.clone(), mutation);
            }
        }
    }
    corpus
}

fn targeted_paths() -> BTreeSet<String> {
    let mut paths = BTreeSet::new();
    for seed in [
        "/public/probe.txt",
        "/admin/probe.txt",
        "/files/probe.txt",
        "/files/private/probe.txt",
        "/files/a/b.txt",
    ] {
        paths.insert(seed.to_owned());
        // Vary one byte at a time, including percent decoding of literal content.
        for (index, byte) in seed.bytes().enumerate().skip(1) {
            for replacement in [format!("%{byte:02X}"), format!("%25{byte:02x}")] {
                paths.insert(format!(
                    "{}{replacement}{}",
                    &seed[..index],
                    &seed[index + 1..]
                ));
            }
        }
        for separator in ["//", "/./", "/x/../", "%2f", "%2F", "%252f", "\\", "%5c"] {
            paths.insert(format!("/{}", seed[1..].replace('/', separator)));
        }
        for prefix in ["/", "/./", "/x/../", "/public/../", "/public/%2e%2e/"] {
            paths.insert(format!("{prefix}{}", &seed[1..]));
        }
        for suffix in ["/", "/extra", ";x=1", "%00", "%FF", "%", "%2", "%GG"] {
            paths.insert(format!("{seed}{suffix}"));
        }
        paths.insert(seed.to_ascii_uppercase());
    }
    for path in [
        "/",
        "/admin",
        "/admin/",
        "/files",
        "/files/",
        "/files/private",
        "/files/private/",
        "/missing",
        "/admin;x=1/probe.txt",
        "/;x=1/admin/probe.txt",
        "/public/..;x=1/admin/probe.txt",
        "/public/%252e%252e/admin/probe.txt",
        "/files/a%2fb.txt",
        "/files/a%252fb.txt",
        "/files/literal%2fkey.txt",
        "/files/literal%252fkey.txt",
        "/files/%2e%2e/admin/probe.txt",
        "/files/a/../../admin/probe.txt",
        "/files/%70rivate/probe.txt",
    ] {
        paths.insert(path.to_owned());
    }
    for seed in [
        "/admin/probe.txt",
        "/files/private/probe.txt",
        "/files/a/b.txt",
    ] {
        for (index, byte) in seed.bytes().enumerate() {
            if byte.is_ascii_lowercase() {
                paths.insert(format!(
                    "{}{}{}",
                    &seed[..index],
                    (byte as char).to_ascii_uppercase(),
                    &seed[index + 1..]
                ));
            }
        }
        for spelling in [
            seed.to_owned(),
            seed.replace('a', "%61"),
            seed.replace('a', "%2561"),
            seed.replace('p', "%70"),
        ] {
            for separator in [
                "/", "//", "/./", "/x/../", "%2f", "%252f", "\\", "%5c", "%255c",
            ] {
                paths.insert(format!("/{}", spelling[1..].replace('/', separator)));
            }
        }
    }
    paths
}

#[test]
#[ignore = "requires isolated server fixtures; run mise run test-downstream"]
fn downstream_baseline() {
    let address: SocketAddr = std::env::var("ROUTE_GUARD_DOWNSTREAM_ADDR")
        .expect("run mise run test-downstream")
        .parse()
        .expect("loopback socket address");
    assert!(address.ip().is_loopback(), "fixture must be local");
    let backend = std::env::var("ROUTE_GUARD_DOWNSTREAM_BACKEND").expect("backend");
    let profile = std::env::var("ROUTE_GUARD_DOWNSTREAM_PROFILE").expect("profile");
    let deployment = profiles::find(&backend, &profile);
    wait_until_ready(address);

    let nested = router(Layout::Nested, deployment.guard);
    for (path, marker, policy) in [
        ("/public/probe.txt", "public", Policy::Public),
        ("/admin/probe.txt", "admin", Policy::Admin),
        ("/files/probe.txt", "files", Policy::Files),
        ("/files/private/probe.txt", "private", Policy::Private),
        ("/files/a/b.txt", "files", Policy::Files),
        ("/exact.txt", "exact", Policy::Public),
        ("/foo/secret/bar", "parameterized", Policy::Public),
    ] {
        assert_eq!(*nested.resolve(path, &Method::GET).unwrap().rule(), policy);
        let response = request(address, path, &Method::GET).unwrap();
        assert_eq!(response.status, 200, "{profile}: {path}");
        assert_eq!(response.body, marker, "{profile}: {path}");
    }
    // Pin successful HEAD identity and method-gap behavior before fuzzed paths.
    for method in [Method::HEAD, Method::POST] {
        let guard = router(Layout::Methods, deployment.guard);
        for path in [
            "/admin/probe.txt",
            "/files/probe.txt",
            "/files/private/probe.txt",
        ] {
            let resolution = guard.resolve(path, &method);
            let response = request(address, path, &method).unwrap();
            if method == Method::HEAD
                || deployment.guard.static_post
                || path == "/files/probe.txt"
                || (deployment.guard.private_post_fallback && method == Method::POST)
            {
                assert_eq!(response.status, 200, "{method} {path}");
                match resolution {
                    Ok(matched) => assert_eq!(
                        response_policy(&response),
                        Some(*matched.rule()),
                        "{method} {path}"
                    ),
                    Err(error) => {
                        // A native public fallback may serve a method the guard's
                        // more-specific path intentionally blocks. This probe is
                        // independent backend characterization, not forwarding.
                        assert_eq!(error, ResolveError::MethodNotConfigured);
                        assert_eq!(
                            response_policy(&response),
                            Some(Policy::Public),
                            "{method} {path}"
                        );
                    }
                }
            } else {
                assert_eq!(resolution.unwrap_err(), ResolveError::MethodNotConfigured);
                assert_eq!(response.status, 405, "{method} {path}: expected method gap");
            }
            if method == Method::HEAD {
                assert!(response.body.is_empty(), "HEAD body");
            }
        }
    }
    compare_corpus(address, deployment);
}

fn response_policy(response: &Response) -> Option<Policy> {
    classify(response).unwrap_or_else(|error| panic!("{error}"))
}

fn classify(response: &Response) -> Result<Option<Policy>, String> {
    match response.status {
        200 => match response.route_id.as_deref() {
            Some("public") => Ok(Some(Policy::Public)),
            Some("admin") => Ok(Some(Policy::Admin)),
            Some("files") => Ok(Some(Policy::Files)),
            Some("private") => Ok(Some(Policy::Private)),
            Some("exact") => Ok(Some(Policy::Exact)),
            Some("parameterized") => Ok(Some(Policy::Parameterized)),
            Some(other) => Err(format!("unknown resource marker {other:?}")),
            None => Err("successful response must identify its route".to_owned()),
        },
        // A redirect requires fresh authorization. No resource policy to compare.
        301 | 302 | 307 | 308 | 400 | 403 | 404 | 405 => Ok(None),
        // Spring parsing errors can return 500; require no route marker.
        500 if response.route_id.is_none() => Ok(None),
        status => Err(format!("unexpected downstream status {status}")),
    }
}

/// Evidence per input family. Generated inputs the guard denies exercise the
/// guard but say nothing about the backend; only accepted inputs that reach a
/// resource are downstream evidence.
#[derive(Default)]
struct FamilyStats {
    /// Guard evaluations, or method/target observations for characterization.
    inputs: usize,
    accepted: usize,
    served: usize,
    confusions: usize,
}

struct Confusion {
    layout: Layout,
    method: Method,
    path: String,
}

fn compare_corpus(address: SocketAddr, deployment: &Profile) {
    let mut report = std::env::var_os("ROUTE_GUARD_DOWNSTREAM_REPORT")
        .map(|path| File::create(path).expect("create downstream report"));
    if let Some(report) = &mut report {
        writeln!(
            report,
            "candidate\tlayout\tmethod\tpath\tguard_policy\tstatus\troute_id\tlocation\toutcome"
        )
        .unwrap();
    }
    let search = search_from_env();
    let corpus = corpus(search);
    let paths: BTreeSet<String> = corpus.keys().cloned().collect();
    match search {
        Some(Search { seed, budget }) => println!(
            "shared corpus: {} paths (seeded search: seed={seed}, budget={budget})",
            paths.len()
        ),
        None => println!("shared corpus: {} paths", paths.len()),
    }
    let mut responses = characterize_corpus(&paths, &mut report, |path, method| {
        request(address, path, method)
            .unwrap_or_else(|error| panic!("characterization/{method}/{path:?}: {error}"))
    });
    let mut families: BTreeMap<(&str, &str), FamilyStats> = BTreeMap::new();
    for (path, tags) in &corpus {
        for method in [Method::GET, Method::HEAD, Method::POST] {
            let reached = response_policy(&responses[&(method, path.clone())]).is_some();
            for &family in tags {
                let stats = families.entry(("characterization", family)).or_default();
                stats.inputs += 1;
                stats.served += usize::from(reached);
            }
        }
    }
    // Reuse corpus observations for fixed probes where possible. Profile probes
    // can also cover targets outside the shared corpus.
    for probe in deployment.parsing_probes {
        let response = responses
            .entry((Method::GET, probe.path.to_owned()))
            .or_insert_with(|| {
                let response =
                    request(address, probe.path, &Method::GET).expect("parsing probe response");
                response_policy(&response);
                if let Some(report) = &mut report {
                    writeln!(
                        report,
                        "characterization\t-\tGET\t{:?}\t-\t{}\t{:?}\t{:?}\tobserved",
                        probe.path, response.status, response.route_id, response.location
                    )
                    .unwrap();
                }
                response
            });
        assert_eq!(
            (response.status, response.route_id.as_deref()),
            (probe.status, probe.route_id),
            "{}/{} parsing probe {:?}",
            deployment.backend,
            deployment.name,
            probe.path
        );
    }
    let mut shrink_report = ShrinkReport::new(deployment, search);
    let candidates = std::iter::once(("recommended", deployment.guard, None, false)).chain(
        deployment
            .ablations
            .iter()
            .map(|a| (a.name, a.guard, Some(a.witness), a.expect_method_denial)),
    );
    let mut failures = Vec::new();
    for (candidate, settings, required_witness, expect_method_denial) in candidates {
        let require_confusion = required_witness.is_some() && !expect_method_denial;
        let mut witness_observed = false;
        let mut forwarded = 0;
        let mut served = 0;
        let mut skipped = 0;
        let mut confusion = 0;
        let mut unexpected = Vec::new();
        for layout in [
            Layout::Nested,
            Layout::Uniform,
            Layout::PrivateOnly,
            Layout::Methods,
            Layout::ExactException,
            Layout::ParameterizedException,
            Layout::Distinct,
        ] {
            let guard = router(layout, settings);
            let methods = if layout == Layout::Methods {
                vec![Method::GET, Method::HEAD, Method::POST]
            } else {
                vec![Method::GET, Method::HEAD]
            };
            for method in methods {
                let mut method_served = 0;
                for (path, tags) in &corpus {
                    for &family in tags {
                        families.entry((candidate, family)).or_default().inputs += 1;
                    }
                    let resolution = guard.resolve(path, &method);
                    let Ok(matched) = resolution else {
                        if expect_method_denial
                            && layout == Layout::Methods
                            && required_witness == Some((method.as_str(), path.as_str()))
                        {
                            assert_eq!(resolution.unwrap_err(), ResolveError::MethodNotConfigured);
                            witness_observed = true;
                        }
                        skipped += 1;
                        if let Some(report) = &mut report {
                            writeln!(
                            report,
                            "{candidate}\t{layout:?}\t{method}\t{path:?}\t-\t-\t-\t-\tnot-forwarded"
                        )
                        .unwrap();
                        }
                        continue;
                    };
                    // Only accepted requests contribute safety evidence. Reuse
                    // the independent characterization of our stateless fixtures.
                    let response = responses
                        .get(&(method.clone(), path.clone()))
                        .expect("every method/target has been characterized");
                    forwarded += 1;
                    let expected =
                        response_policy(response).map(|policy| layout_policy(layout, policy));
                    let outcome = match expected {
                        Some(policy) if policy != *matched.rule() => {
                            confusion += 1;
                            witness_observed |=
                                required_witness == Some((method.as_str(), path.as_str()));
                            if !require_confusion && unexpected.len() < SHRINK_CASES_PER_CANDIDATE {
                                unexpected.push(Confusion {
                                    layout,
                                    method: method.clone(),
                                    path: path.clone(),
                                });
                            }
                            "route-confusion"
                        }
                        Some(_) => "agreement",
                        None => "no-resource",
                    };
                    if expected.is_some() {
                        served += 1;
                        method_served += 1;
                    }
                    for &family in tags {
                        let stats = families.entry((candidate, family)).or_default();
                        stats.accepted += 1;
                        stats.served += usize::from(expected.is_some());
                        stats.confusions += usize::from(outcome == "route-confusion");
                    }
                    if let Some(report) = &mut report {
                        writeln!(
                        report,
                        "{candidate}\t{layout:?}\t{method}\t{path:?}\t{:?}\t{}\t{:?}\t{:?}\t{outcome}",
                        matched.rule(),
                        response.status,
                        response.route_id,
                        response.location
                    )
                    .unwrap();
                    }
                    if outcome == "route-confusion" && confusion <= 8 {
                        println!(
                            "{}/{}/{candidate}/{layout:?}/{method}: {path:?}: authorized {:?}, reached {:?}",
                            deployment.backend,
                            deployment.name,
                            matched.rule(),
                            expected.unwrap()
                        );
                    }
                }
                assert!(
                    method_served >= 5,
                    "{candidate}/{layout:?}/{method}: insufficient served requests"
                );
            }
        }
        assert!(
            served >= 10,
            "{candidate}: too few forwarded resource requests"
        );
        // Unexpected mismatches only: removal witnesses are expected confusion.
        for case in &unexpected {
            let shrunk = shrink_confusion(address, &mut responses, settings, case);
            shrink_report.record(candidate, case, &shrunk, &corpus[&case.path]);
        }
        if required_witness.is_some() && !witness_observed {
            failures.push(format!("{candidate}: required witness {required_witness:?} did not produce its expected outcome (method denial: {expect_method_denial})"));
        }
        if require_confusion && confusion == 0 {
            failures.push(format!("{candidate}: removal found no confusion; review and remove the unsupported recommendation for this profile"));
        } else if !require_confusion && confusion != 0 {
            failures.push(format!(
                "{candidate}: configuration permits {confusion} route confusions; fix the profile or model and document required settings{}",
                shrink_report.hint()
            ));
        }
        println!(
            "{}/{}/{candidate}: forwarded={forwarded}, served={served}, not-forwarded={skipped}, route-confusions={confusion}",
            deployment.backend, deployment.name
        );
    }
    write_family_report(&families);
    println!(
        "unique downstream method/target observations: {}",
        responses.len()
    );
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn write_family_report(families: &BTreeMap<(&str, &str), FamilyStats>) {
    let mut report = std::env::var_os("ROUTE_GUARD_DOWNSTREAM_FAMILY_REPORT")
        .map(|path| File::create(path).expect("create family report"));
    if let Some(report) = &mut report {
        writeln!(
            report,
            "candidate\tfamily\tinputs\taccepted\tserved\tconfusions"
        )
        .unwrap();
    }
    for ((candidate, family), stats) in families {
        println!(
            "family {candidate}/{family}: inputs={}, accepted={}, served={}, confusions={}",
            stats.inputs, stats.accepted, stats.served, stats.confusions
        );
        if let Some(report) = &mut report {
            writeln!(
                report,
                "{candidate}\t{family}\t{}\t{}\t{}\t{}",
                stats.inputs, stats.accepted, stats.served, stats.confusions
            )
            .unwrap();
        }
    }
}

/// Minimizes an unexpected mismatch against the live backend. Any accepted
/// policy mismatch counts as still failing; it need not keep the same policies.
fn shrink_confusion(
    address: SocketAddr,
    responses: &mut HashMap<(Method, String), Response>,
    settings: DeploymentSettings,
    case: &Confusion,
) -> (shrink::Shrunk, Policy, Policy) {
    shrink_confusion_with(responses, settings, case, |path, method| {
        request(address, path, method)
    })
}

fn shrink_confusion_with(
    responses: &mut HashMap<(Method, String), Response>,
    settings: DeploymentSettings,
    case: &Confusion,
    mut fetch: impl FnMut(&str, &Method) -> std::io::Result<Response>,
) -> (shrink::Shrunk, Policy, Policy) {
    let guard = router(case.layout, settings);
    let mut mismatch = |path: &str| -> Option<(Policy, Policy)> {
        let authorized = *guard.resolve(path, &case.method).ok()?.rule();
        let response = match responses.entry((case.method.clone(), path.to_owned())) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(fetch(path, &case.method).ok()?),
        };
        let reached = layout_policy(case.layout, classify(response).ok()??);
        (reached != authorized).then_some((authorized, reached))
    };
    let shrunk = shrink::shrink(&case.path, SHRINK_CHECKS_PER_CASE, |path| {
        mismatch(path).is_some()
    });
    let (authorized, reached) = mismatch(&shrunk.path).expect("shrinking preserves a mismatch");
    (shrunk, authorized, reached)
}

/// Shrunk mismatches in `regressions.tsv` format, with reproduction details.
struct ShrinkReport {
    backend: &'static str,
    profile: &'static str,
    search: Option<Search>,
    path: Option<std::ffi::OsString>,
    file: Option<File>,
    /// Distinct originals often minimize to the same mismatch; report it once.
    seen: BTreeSet<(String, String, String, String)>,
}

impl ShrinkReport {
    fn new(deployment: &Profile, search: Option<Search>) -> Self {
        Self {
            backend: deployment.backend,
            profile: deployment.name,
            search,
            path: std::env::var_os("ROUTE_GUARD_DOWNSTREAM_SHRINK_REPORT"),
            file: None,
            seen: BTreeSet::new(),
        }
    }

    fn reproduce(&self) -> String {
        let prefix = self
            .search
            .map_or_else(String::new, |Search { seed, budget }| {
                format!(
                    "ROUTE_GUARD_DOWNSTREAM_SEED={seed} ROUTE_GUARD_DOWNSTREAM_BUDGET={budget} "
                )
            });
        format!("{prefix}mise run test-downstream {}", self.backend)
    }

    fn hint(&self) -> String {
        match &self.path {
            Some(path) => format!(" (shrunk cases: {})", path.to_string_lossy()),
            None => String::new(),
        }
    }

    fn record(
        &mut self,
        candidate: &str,
        case: &Confusion,
        (shrunk, authorized, reached): &(shrink::Shrunk, Policy, Policy),
        families: &BTreeSet<&str>,
    ) {
        let key = (
            candidate.to_owned(),
            format!("{:?}", case.layout),
            case.method.to_string(),
            shrunk.path.clone(),
        );
        if !self.seen.insert(key) {
            println!("shrunk: {:?} (duplicate from {:?})", shrunk.path, case.path);
            return;
        }
        let search = self.search.map_or_else(
            || "deterministic".to_owned(),
            |Search { seed, budget }| format!("seed={seed} budget={budget}"),
        );
        let families = families.iter().copied().collect::<Vec<_>>().join(",");
        let line = format!(
            "{:?}\t{}/{} candidate={candidate} layout={:?} method={} authorized={authorized:?} reached={reached:?} original={:?} families={families} {search} checks={} exhausted={}",
            shrunk.path,
            self.backend,
            self.profile,
            case.layout,
            case.method,
            case.path,
            shrunk.checks,
            shrunk.exhausted
        );
        println!("shrunk: {line}");
        let Some(path) = &self.path else { return };
        if self.file.is_none() {
            let mut file = File::create(path).expect("create shrink report");
            writeln!(
                file,
                "# Shrunk downstream mismatches ({}/{}), in regressions.tsv format.\n# Reproduce: {}",
                self.backend,
                self.profile,
                self.reproduce()
            )
            .unwrap();
            self.file = Some(file);
        }
        writeln!(self.file.as_mut().unwrap(), "{line}").unwrap();
    }
}

// This deliberately bypasses the guard. Observations are not authorization or
// model-agreement evidence, including when a backend serves a denied target.
fn characterize_corpus(
    paths: &BTreeSet<String>,
    report: &mut Option<impl Write>,
    mut fetch: impl FnMut(&str, &Method) -> Response,
) -> HashMap<(Method, String), Response> {
    let mut responses = HashMap::new();
    for method in [Method::GET, Method::HEAD, Method::POST] {
        let mut served = 0;
        let mut server_errors = 0;
        for path in paths {
            let response = fetch(path, &method);
            // Malformed request lines may be rejected before the server knows
            // this is HEAD, so only successful responses must suppress bodies.
            if method == Method::HEAD && response.status == 200 {
                assert!(response.body.is_empty(), "HEAD body for {path:?}");
            }
            if let Some(report) = report {
                writeln!(
                    report,
                    "characterization\t-\t{method}\t{path:?}\t-\t{}\t{:?}\t{:?}\tobserved",
                    response.status, response.route_id, response.location
                )
                .unwrap();
            }
            // Record before validation to preserve failing inputs.
            served += usize::from(
                classify(&response)
                    .unwrap_or_else(|error| panic!("characterization/{method}/{path:?}: {error}"))
                    .is_some(),
            );
            server_errors += usize::from(response.status == 500);
            responses.insert((method.clone(), path.clone()), response);
        }
        println!(
            "characterization/{method}: observed={}, served={served}, no-resource={}, server-errors={server_errors}",
            paths.len(),
            paths.len() - served
        );
    }
    responses
}

// Assign policies to independently reported resource identities, never to the
// request path (which would repeat the guard's interpretation in the oracle).
fn layout_policy(layout: Layout, policy: Policy) -> Policy {
    match layout {
        Layout::Distinct => policy,
        Layout::ExactException => {
            if policy == Policy::Exact {
                Policy::Public
            } else {
                Policy::Admin
            }
        }
        Layout::ParameterizedException => {
            if policy == Policy::Parameterized {
                Policy::Public
            } else {
                Policy::Admin
            }
        }
        Layout::Uniform if policy == Policy::Private => Policy::Files,
        Layout::PrivateOnly if policy != Policy::Private => Policy::Public,
        _ if matches!(policy, Policy::Exact | Policy::Parameterized) => Policy::Public,
        _ => policy,
    }
}

#[test]
fn distinct_layout_preserves_each_fixture_identity() {
    let guard = router(Layout::Distinct, profiles::find("axum", "Sensitive").guard);
    for method in [Method::GET, Method::HEAD] {
        for (path, policy) in [
            ("/public/probe.txt", Policy::Public),
            ("/admin/probe.txt", Policy::Admin),
            ("/files/probe.txt", Policy::Files),
            ("/files/private/probe.txt", Policy::Private),
            ("/exact.txt", Policy::Exact),
            ("/exact.txt/", Policy::Exact),
            ("/foo/secret/bar", Policy::Parameterized),
            ("/foo/other/bar/", Policy::Parameterized),
        ] {
            assert_eq!(*guard.resolve(path, &method).unwrap().rule(), policy);
            assert_eq!(layout_policy(Layout::Distinct, policy), policy);
        }
    }
    // The older nested layout merges these routes into its public default.
    assert_ne!(
        layout_policy(Layout::Distinct, Policy::Exact),
        layout_policy(Layout::Distinct, Policy::Parameterized)
    );
    assert_eq!(layout_policy(Layout::Nested, Policy::Exact), Policy::Public);
}

#[test]
fn characterization_observes_denied_paths_without_claiming_agreement() {
    let denied = "/admin\0/probe.txt";
    let guard = router(Layout::Distinct, profiles::find("axum", "Sensitive").guard);
    assert!(guard.resolve(denied, &Method::GET).is_err());
    let paths = BTreeSet::from([denied.to_owned(), "/public/probe.txt".to_owned()]);
    let mut report = Some(Vec::new());
    let mut requests = Vec::new();
    let responses = characterize_corpus(&paths, &mut report, |path, method| {
        requests.push((method.clone(), path.to_owned()));
        Response {
            status: if path == denied { 400 } else { 200 },
            // Early request-line errors can have bodies even for HEAD.
            body: if path == denied { "bad request" } else { "" }.to_owned(),
            location: None,
            route_id: (path != denied).then(|| "public".to_owned()),
        }
    });
    assert_eq!(requests.len(), 6);
    assert_eq!(responses.len(), 6);
    for method in [Method::GET, Method::HEAD, Method::POST] {
        assert_eq!(responses[&(method, denied.to_owned())].status, 400);
    }
    let report = String::from_utf8(report.unwrap()).unwrap();
    assert_eq!(report.lines().count(), 6);
    for line in report.lines() {
        let columns: Vec<_> = line.split('\t').collect();
        assert_eq!(columns.len(), 9);
        assert_eq!(columns[0], "characterization");
        assert_eq!(columns[1], "-");
        assert_eq!(columns[4], "-");
        assert_eq!(columns[8], "observed");
    }
}

#[test]
fn characterization_records_server_errors_without_resource_evidence() {
    let path = "/files/../suffix;x=1%%3253bx";
    let mut report = Some(Vec::new());
    let responses = characterize_corpus(&BTreeSet::from([path.to_owned()]), &mut report, |_, _| {
        Response {
            status: 500,
            body: "parser exception".to_owned(),
            location: None,
            route_id: None,
        }
    });
    for method in [Method::GET, Method::HEAD, Method::POST] {
        assert_eq!(classify(&responses[&(method, path.to_owned())]), Ok(None));
    }
    let report = String::from_utf8(report.unwrap()).unwrap();
    assert_eq!(report.lines().count(), 3);
    assert!(
        report
            .lines()
            .all(|line| line.contains("\t500\tNone\tNone\tobserved"))
    );
}

#[test]
fn characterization_preserves_unexpected_response_diagnostics() {
    for (status, route_id) in [(500, Some("admin")), (502, None), (503, None), (200, None)] {
        let path = "/probe;bad=%";
        let mut report = Some(Vec::new());
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            characterize_corpus(&BTreeSet::from([path.to_owned()]), &mut report, |_, _| {
                Response {
                    status,
                    body: String::new(),
                    location: None,
                    route_id: route_id.map(str::to_owned),
                }
            });
        }))
        .expect_err("unexpected responses must still fail");
        let message = panic.downcast_ref::<String>().unwrap();
        assert!(message.contains(&format!("characterization/GET/{path:?}:")));
        let report = String::from_utf8(report.unwrap()).unwrap();
        assert!(report.contains(&format!("{path:?}\t-\t{status}\t")));
    }
}
