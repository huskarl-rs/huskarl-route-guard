//! Real-server oracles, explicitly run by `mise run test-downstream`.
//! Fixtures identify resources/handlers without using our matcher.

use std::{
    collections::BTreeSet,
    fs::File,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
    time::{Duration, Instant},
};

use http::Method;
use huskarl_route_guard::{GuardConfig, Registration, RuleRouter, StructuralClasses};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Policy {
    Public,
    Admin,
    Files,
    Private,
}

#[path = "downstream/profiles.rs"]
mod profiles;

use profiles::{DeploymentSettings, Profile};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Layout {
    Nested,
    Uniform,
    PrivateOnly,
    Methods,
}

fn router(layout: Layout, settings: DeploymentSettings) -> RuleRouter<Policy> {
    let classes = if settings.backslash {
        StructuralClasses::new().with_backslash()
    } else {
        StructuralClasses::new()
    };
    let mut builder = RuleRouter::builder(
        Policy::Public,
        GuardConfig::new(settings.case, settings.decode).with_structural_classes(classes),
    );
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
        let registration = Registration::subtree(path, policy);
        builder = builder.register(if layout == Layout::Methods {
            registration.for_methods(methods.clone())
        } else {
            registration
        });
    }
    if layout == Layout::Methods && !settings.static_post {
        builder = builder
            .register(Registration::subtree("/files", Policy::Files).for_methods(Method::POST));
        if settings.private_post_fallback {
            builder = builder.register(
                Registration::subtree("/files/private", Policy::Files).for_methods(Method::POST),
            );
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

fn corpus() -> BTreeSet<String> {
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
            let policy = *guard.resolve(path, &method).unwrap().rule();
            let response = request(address, path, &method).unwrap();
            if method == Method::HEAD
                || deployment.guard.static_post
                || path == "/files/probe.txt"
                || (deployment.guard.private_post_fallback && method == Method::POST)
            {
                assert_eq!(response.status, 200, "{method} {path}");
                assert_eq!(response_policy(&response), Some(policy), "{method} {path}");
            } else {
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
    match response.status {
        200 => Some(
            match response
                .route_id
                .as_deref()
                .expect("successful response must identify its route")
            {
                "public" => Policy::Public,
                "admin" => Policy::Admin,
                "files" | "literal-slash" => Policy::Files,
                "private" => Policy::Private,
                other => panic!("unknown resource marker {other:?}"),
            },
        ),
        // A redirect requires fresh authorization. No resource policy to compare.
        301 | 302 | 307 | 308 | 400 | 403 | 404 | 405 => None,
        status => panic!("unexpected downstream status {status}"),
    }
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
    let candidates = std::iter::once(("recommended", deployment.guard, None)).chain(
        deployment
            .ablations
            .iter()
            .map(|a| (a.name, a.guard, Some(a.witness))),
    );
    let mut failures = Vec::new();
    for (candidate, settings, required_witness) in candidates {
        let require_confusion = required_witness.is_some();
        let mut witness_observed = false;
        let mut forwarded = 0;
        let mut served = 0;
        let mut skipped = 0;
        let mut confusion = 0;
        for layout in [
            Layout::Nested,
            Layout::Uniform,
            Layout::PrivateOnly,
            Layout::Methods,
        ] {
            let guard = router(layout, settings);
            let methods = if layout == Layout::Methods {
                vec![Method::GET, Method::HEAD, Method::POST]
            } else {
                vec![Method::GET, Method::HEAD]
            };
            for method in methods {
                let mut method_served = 0;
                for path in corpus() {
                    let Ok(matched) = guard.resolve(&path, &method) else {
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
                    // Only accepted requests leave this simulated gateway. Each
                    // candidate gets the same input corpus, before guard filtering.
                    let response = request(address, &path, &method).unwrap_or_else(|error| {
                        panic!("{candidate}/{layout:?}/{method}/{path:?}: {error}")
                    });
                    forwarded += 1;
                    let expected = response_policy(&response).map(|policy| {
                        if layout == Layout::Uniform && policy == Policy::Private {
                            Policy::Files
                        } else if layout == Layout::PrivateOnly && policy != Policy::Private {
                            Policy::Public
                        } else {
                            policy
                        }
                    });
                    let outcome = match expected {
                        Some(policy) if policy != *matched.rule() => {
                            confusion += 1;
                            witness_observed |=
                                required_witness == Some((method.as_str(), path.as_str()));
                            "route-confusion"
                        }
                        Some(_) => "agreement",
                        None => "no-resource",
                    };
                    if expected.is_some() {
                        served += 1;
                        method_served += 1;
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
        if require_confusion && !witness_observed {
            failures.push(format!("{candidate}: required accepted-request counterexample {required_witness:?} no longer reproduces"));
        }
        if require_confusion && confusion == 0 {
            failures.push(format!("{candidate}: removal found no confusion; review and remove the unsupported recommendation for this profile"));
        } else if !require_confusion && confusion != 0 {
            failures.push(format!("recommended configuration permits {confusion} route confusions; fix the profile or model and document required settings"));
        }
        println!(
            "{}/{}/{candidate}: forwarded={forwarded}, served={served}, not-forwarded={skipped}, route-confusions={confusion}",
            deployment.backend, deployment.name
        );
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
