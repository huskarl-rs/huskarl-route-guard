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
    GuardConfig, PathRegistration, RuleRouter,
    config::{CaseSensitivity, DecodeDepth, GuardMode, StructuralClasses},
};

const DEFAULT_RULE: u32 = u32::MAX;

fn registrations() -> Vec<PathRegistration<u32>> {
    vec![
        PathRegistration::subtree("/admin").all(0),
        PathRegistration::exclusive_subtree("/files").all(1),
        PathRegistration::path("/health").all(2),
        PathRegistration::path("/users/{id}").all(3),
        PathRegistration::path("/method").all(4),
        PathRegistration::path("/method").method(Method::GET, 5),
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

fn exact_registrations(count: usize) -> Vec<PathRegistration<u32>> {
    (0..count)
        .map(|i| PathRegistration::path(format!("/routes/item-{i}")).all(i as u32))
        .collect()
}

fn subtree_registrations(count: usize) -> Vec<PathRegistration<u32>> {
    (0..count)
        .map(|i| PathRegistration::subtree(&format!("/tenant-{i}")).all(i as u32))
        .collect()
}

fn build_router(registrations: Vec<PathRegistration<u32>>) -> RuleRouter<u32> {
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

fn inheritance_scaling(c: &mut Criterion) {
    let config = || GuardConfig::new(CaseSensitivity::Sensitive, DecodeDepth::UpToOne);
    let make_paths = |count: usize, method_count: usize| {
        let methods = [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::DELETE,
            Method::PATCH,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
        ];
        let mut paths = vec![PathRegistration::subtree("/files").all(0)];
        paths.extend((0..count).map(|i| {
            PathRegistration::path(format!("/files/item-{i}"))
                .fallback_inherit(true)
                .methods(methods.iter().take(method_count).cloned(), i as u32 + 1)
        }));
        paths
    };
    let mut group = c.benchmark_group("build/method_views");
    for count in [256, 4096] {
        for methods in [1, 4, 8] {
            group.bench_function(BenchmarkId::new(format!("{methods}_methods"), count), |b| {
                b.iter_batched(
                    || make_paths(count, methods),
                    |paths| RuleRouter::from_registrations(DEFAULT_RULE, config(), paths).unwrap(),
                    BatchSize::LargeInput,
                );
            });
        }
    }
    group.finish();

    let router = RuleRouter::builder(DEFAULT_RULE, config())
        .register_subtree("/files", |p| p.method(Method::GET, 0))
        .register_subtree("/files/nested", |p| {
            p.fallback_inherit(true).method(Method::POST, 1)
        })
        .register_path("/files/nested/item", |p| {
            p.fallback_inherit(true).method(Method::PUT, 2)
        })
        .build()
        .unwrap();
    let mut group = c.benchmark_group("resolve/inheritance");
    resolve_case(
        &mut group,
        "two_fallbacks",
        router,
        "/files/nested/item",
        Method::GET,
    );
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
        build_scaling,
        inheritance_scaling
}
criterion_main!(benches);
