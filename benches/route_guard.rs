//! End-to-end benchmarks over the public API.
//!
//! Request benchmarks build the router outside the measured loop. Build benchmarks
//! generate their registration inputs outside the measured loop, then measure only
//! `RuleRouter::from_registrations` and the allocations it performs.

use std::{hint::black_box, time::Duration};

use criterion::{
    BatchSize, BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
    measurement::WallTime,
};
use http::Method;
use huskarl_route_guard::{
    GuardConfig, Registration, RuleRouter,
    config::{CaseSensitivity, DecodeDepth, GuardMode, StructuralClasses},
};

const DEFAULT_RULE: u32 = u32::MAX;

fn registrations() -> Vec<Registration<u32>> {
    vec![
        Registration::subtree("/admin", 0),
        Registration::exclusive_subtree("/files", 1),
        Registration::route("/health", 2),
        Registration::route("/users/{id}", 3),
        Registration::route("/method", 4),
        Registration::route("/method", 5).for_methods(Method::GET),
    ]
}

fn router(mode: GuardMode, layers: DecodeDepth, case: CaseSensitivity) -> RuleRouter<u32> {
    RuleRouter::from_registrations(
        DEFAULT_RULE,
        GuardConfig {
            mode,
            structural_classes: StructuralClasses::new(),
            decode_depth: layers,
            case_sensitivity: case,
        },
        registrations(),
    )
    .expect("benchmark route table is valid")
}

/// Consume a resolution as a small owned value so the benchmark does not return a
/// reference into its router and the optimizer cannot discard the result.
fn resolve_token(router: &RuleRouter<u32>, path: &str, method: &Method) -> u64 {
    match black_box(router).resolve(black_box(path), black_box(method)) {
        Ok(matched) => u64::from(*matched.rule()),
        Err(reason) => (1_u64 << 63) | reason.message().len() as u64,
    }
}

fn resolve_case(
    group: &mut BenchmarkGroup<'_, WallTime>,
    name: &str,
    router: RuleRouter<u32>,
    path: &'static str,
    method: Method,
) {
    group.throughput(Throughput::Bytes(path.len() as u64));
    group.bench_function(name, move |b| {
        b.iter(|| resolve_token(&router, path, &method));
    });
}

fn clean_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve/clean");

    resolve_case(
        &mut group,
        "guard_off/literal_hit",
        router(
            GuardMode::Disabled,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/health",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "default_guard/literal_hit",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/health",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "default_guard/wildcard_hit",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/users/42",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "default_guard/catchall_hit",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/admin/users/42",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "default_guard/default_miss",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/public/missing",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "method/exact_hit",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/method",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "method/method_wildcard_fallback",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/method",
        Method::POST,
    );

    group.finish();
}

fn suspicious_resolution(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve/suspicious");

    resolve_case(
        &mut group,
        "encoded_content_allowed",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/files/a%20b",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "encoded_separator_allowed",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/files/a%2fb",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "encoded_separator_denied",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/admin%2fusers",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "traversal_denied",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/files/../admin",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "double_decode_allowed",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToTwo,
            CaseSensitivity::Sensitive,
        ),
        "/files/a%2520b",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "case_fold_allowed",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Insensitive,
        ),
        "/files/README",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "case_fold_denied",
        router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Insensitive,
        ),
        "/ADMIN",
        Method::GET,
    );
    resolve_case(
        &mut group,
        "strict_escape_denied",
        router(
            GuardMode::RequireCanonical,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        ),
        "/files/a%20b",
        Method::GET,
    );

    group.finish();
}

fn path_length_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve/path_length");

    for len in [16_usize, 128, 1_024, 8_192] {
        let path = format!("/files/{}", "a".repeat(len - "/files/".len()));
        let router = router(
            GuardMode::RejectAmbiguous,
            DecodeDepth::UpToOne,
            CaseSensitivity::Sensitive,
        );
        let method = Method::GET;

        group.throughput(Throughput::Bytes(path.len() as u64));
        group.bench_function(BenchmarkId::from_parameter(len), move |b| {
            b.iter(|| resolve_token(&router, path.as_str(), &method));
        });
    }

    group.finish();
}

fn exact_registrations(count: usize) -> Vec<Registration<u32>> {
    (0..count)
        .map(|i| Registration::route(format!("/routes/item-{i}"), i as u32))
        .collect()
}

fn subtree_registrations(count: usize) -> Vec<Registration<u32>> {
    (0..count)
        .map(|i| Registration::subtree(&format!("/tenant-{i}"), i as u32))
        .collect()
}

fn build_router(registrations: Vec<Registration<u32>>) -> RuleRouter<u32> {
    RuleRouter::from_registrations(
        DEFAULT_RULE,
        GuardConfig {
            mode: GuardMode::RejectAmbiguous,
            structural_classes: StructuralClasses::new(),
            decode_depth: DecodeDepth::UpToOne,
            case_sensitivity: CaseSensitivity::Sensitive,
        },
        registrations,
    )
    .expect("generated benchmark route table is valid")
}

fn route_count_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("resolve/route_count");

    for count in [16_usize, 256, 4_096] {
        let router = build_router(exact_registrations(count));
        let path = format!("/routes/item-{}", count - 1);
        let method = Method::GET;

        group.bench_function(BenchmarkId::from_parameter(count), move |b| {
            b.iter(|| resolve_token(&router, path.as_str(), &method));
        });
    }

    group.finish();
}

fn build_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("build");

    for count in [16_usize, 256, 4_096] {
        group.throughput(Throughput::Elements(count as u64));
        group.bench_function(BenchmarkId::new("exact", count), |b| {
            b.iter_batched(
                || exact_registrations(count),
                build_router,
                BatchSize::LargeInput,
            );
        });
        group.bench_function(BenchmarkId::new("subtree", count), |b| {
            b.iter_batched(
                || subtree_registrations(count),
                build_router,
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

fn benchmark_config() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(50)
}

criterion_group! {
    name = benches;
    config = benchmark_config();
    targets = clean_resolution,
        suspicious_resolution,
        path_length_scaling,
        route_count_scaling,
        build_scaling
}
criterion_main!(benches);
