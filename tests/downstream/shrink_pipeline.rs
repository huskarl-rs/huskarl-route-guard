//! Exercise failure reporting without requiring Docker or an actual guard bug.

use super::*;

struct Artifact(std::path::PathBuf);

impl Drop for Artifact {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

// Deliberately disagree with the guard on an encoded marker. Other targets
// agree, so shrinking must preserve the marker to retain the mismatch.
fn controlled_backend(path: &str, _method: &Method) -> Response {
    Response {
        status: 200,
        body: String::new(),
        location: None,
        route_id: Some(
            if path.contains("%41") {
                "admin"
            } else {
                "public"
            }
            .to_owned(),
        ),
    }
}

#[test]
fn mismatch_is_shrunk_written_and_replayed() {
    let deployment = profiles::find("axum", "Sensitive");
    let case = Confusion {
        layout: Layout::Nested,
        method: Method::GET,
        path: "/public/padding%41".to_owned(),
    };
    let mut responses = HashMap::new();
    let mut requests = 0;
    let shrunk = shrink_confusion_with(&mut responses, deployment.guard, &case, |path, method| {
        requests += 1;
        Ok(controlled_backend(path, method))
    });
    assert_eq!(shrunk.0.path, "/%41");
    assert!(!shrunk.0.exhausted);
    assert!(requests > 0 && requests <= SHRINK_CHECKS_PER_CASE);
    assert_eq!((shrunk.1, shrunk.2), (Policy::Public, Policy::Admin));

    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "route-guard-shrink-{}-{nonce}.tsv",
        std::process::id()
    ));
    File::create_new(&path).unwrap();
    let artifact = Artifact(path);
    let mut report = ShrinkReport::new(
        deployment,
        Some(Search {
            seed: 123,
            budget: 2000,
        }),
    );
    report.path = Some(artifact.0.clone().into_os_string());
    let families = BTreeSet::from(["seeded", "seeded/escape"]);
    report.record("recommended", &case, &shrunk, &families);
    // Repeated findings should still produce only one replayable entry.
    report.record("recommended", &case, &shrunk, &families);
    drop(report);

    let text = std::fs::read_to_string(&artifact.0).unwrap();
    assert!(text.contains(
        "# Reproduce: ROUTE_GUARD_DOWNSTREAM_SEED=123 ROUTE_GUARD_DOWNSTREAM_BUDGET=2000 mise run test-downstream axum"
    ));
    let regressions = regressions::parse(&text).unwrap();
    assert_eq!(regressions.len(), 1);
    assert_eq!(regressions[0].path, shrunk.0.path);
    for detail in [
        "candidate=recommended",
        "layout=Nested",
        "method=GET",
        "authorized=Public reached=Admin",
        "original=\"/public/padding%41\"",
        "families=seeded,seeded/escape",
        "seed=123 budget=2000",
    ] {
        assert!(
            regressions[0].provenance.contains(detail),
            "missing {detail}"
        );
    }

    // Replay the artifact through characterization and the real guard, without
    // reusing the shrinker's cached responses or its returned policy pair.
    let paths = regressions.into_iter().map(|r| r.path).collect();
    let observed = characterize_corpus(&paths, &mut None::<Vec<u8>>, controlled_backend);
    let guard = router(case.layout, deployment.guard);
    for path in paths {
        let authorized = *guard.resolve(&path, &case.method).unwrap().rule();
        let reached = layout_policy(
            case.layout,
            response_policy(&observed[&(case.method.clone(), path)]).unwrap(),
        );
        assert_ne!(
            authorized, reached,
            "replayed target must retain the mismatch"
        );
    }
}
