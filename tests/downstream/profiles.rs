//! Fixed deployment recommendations and independent behavioral witnesses.
//! Adding a server or proxy chain should require data here, not harness branches.
use huskarl_route_guard::{CaseSensitivity, DecodeDepth};

#[derive(Clone, Copy)]
pub struct DeploymentSettings {
    pub case: CaseSensitivity,
    pub decode: DecodeDepth,
    pub backslash: bool,
    pub query_truncation: bool,
    pub fragment_truncation: bool,
    pub include_head: bool,
    pub static_post: bool,
    pub private_post_fallback: bool,
}

pub struct Ablation {
    pub name: &'static str,
    /// Method-registration removals deny safely; parsing removals expose confusion.
    pub expect_method_denial: bool,
    pub guard: DeploymentSettings,
    pub witness: (&'static str, &'static str),
}

pub struct ParsingProbe {
    pub path: &'static str,
    pub status: u16,
    pub route_id: Option<&'static str>,
}

pub struct Profile {
    pub backend: &'static str,
    /// Direct fixture observations, independent of guard acceptance.
    pub parsing_probes: &'static [ParsingProbe],
    pub name: &'static str,
    pub guard: DeploymentSettings,
    // Parsing recommendations require accepted-request counterexamples when removed.
    // Method registrations instead require a safely denied witness when omitted.
    pub ablations: &'static [Ablation],
}

const SENSITIVE: DeploymentSettings = DeploymentSettings {
    case: CaseSensitivity::Sensitive,
    decode: DecodeDepth::UpToOne,
    backslash: true,
    query_truncation: true,
    fragment_truncation: true,
    include_head: true,
    static_post: false,
    private_post_fallback: false,
};
const INSENSITIVE: DeploymentSettings = DeploymentSettings {
    case: CaseSensitivity::Insensitive,
    private_post_fallback: true,
    ..SENSITIVE
};
const PARENT_POST_FALLBACK: DeploymentSettings = DeploymentSettings {
    private_post_fallback: true,
    ..SENSITIVE
};

const REMOVE_CASE_FOLDING: &[Ablation] = &[
    Ablation {
        name: "without-case-folding",
        expect_method_denial: false,
        witness: ("GET", "/ADMIN/PROBE.TXT"),
        guard: PARENT_POST_FALLBACK,
    },
    Ablation {
        name: "without-head",
        expect_method_denial: true,
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..INSENSITIVE
        },
    },
    Ablation {
        name: "without-private-post-fallback",
        expect_method_denial: true,
        witness: ("POST", "/files/private/probe.txt"),
        guard: DeploymentSettings {
            private_post_fallback: false,
            ..INSENSITIVE
        },
    },
];
const REMOVE_BACKSLASH: &[Ablation] = &[
    Ablation {
        name: "without-backslash",
        expect_method_denial: false,
        witness: ("GET", "/admin\\probe.txt"),
        guard: DeploymentSettings {
            backslash: false,
            ..SENSITIVE
        },
    },
    Ablation {
        name: "without-head",
        expect_method_denial: true,
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..SENSITIVE
        },
    },
];

const HEAD: &[Ablation] = &[Ablation {
    name: "without-head",
    expect_method_denial: true,
    witness: ("HEAD", "/admin/probe.txt"),
    guard: DeploymentSettings {
        include_head: false,
        ..SENSITIVE
    },
}];
const PARENT_POST_METHODS: &[Ablation] = &[
    Ablation {
        name: "without-head",
        expect_method_denial: true,
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..PARENT_POST_FALLBACK
        },
    },
    Ablation {
        name: "without-private-post-fallback",
        expect_method_denial: true,
        witness: ("POST", "/files/private/probe.txt"),
        guard: SENSITIVE,
    },
];
const STATIC: DeploymentSettings = DeploymentSettings {
    static_post: true,
    ..SENSITIVE
};
const STATIC_METHODS: &[Ablation] = &[
    Ablation {
        name: "without-head",
        expect_method_denial: true,
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..STATIC
        },
    },
    Ablation {
        name: "without-static-post",
        expect_method_denial: true,
        witness: ("POST", "/admin/probe.txt"),
        guard: SENSITIVE,
    },
];
const TWO_DECODES: DeploymentSettings = DeploymentSettings {
    decode: DecodeDepth::UpToTwo,
    ..STATIC
};
const REMOVE_SECOND_DECODE: &[Ablation] = &[
    Ablation {
        name: "without-second-decode",
        expect_method_denial: false,
        witness: ("GET", "/%2561dmin/probe.txt"),
        guard: STATIC,
    },
    Ablation {
        name: "without-head",
        expect_method_denial: true,
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..TWO_DECODES
        },
    },
    Ablation {
        name: "without-static-post",
        expect_method_denial: true,
        witness: ("POST", "/admin/probe.txt"),
        guard: DeploymentSettings {
            static_post: false,
            ..TWO_DECODES
        },
    },
];

const REMOVE_TRUNCATION: &[Ablation] = &[
    Ablation {
        name: "without-query-truncation",
        expect_method_denial: false,
        guard: DeploymentSettings {
            query_truncation: false,
            ..PARENT_POST_FALLBACK
        },
        witness: ("GET", "/foo/secret%3F/bar"),
    },
    Ablation {
        name: "without-fragment-truncation",
        expect_method_denial: false,
        guard: DeploymentSettings {
            fragment_truncation: false,
            ..PARENT_POST_FALLBACK
        },
        witness: ("GET", "/foo/secret%23/bar"),
    },
];

const TWO_PROXY_DECODES: DeploymentSettings = DeploymentSettings {
    decode: DecodeDepth::UpToTwo,
    ..PARENT_POST_FALLBACK
};

// Explicit profiles with independently specified witnesses. Only accepted requests contribute
// candidate safety evidence. Parsing removals expose confusion; method removals pin safe denial.
const PROFILES: &[Profile] = &[
    Profile {
        backend: "nginx-axum",
        name: "DecodedUri",
        guard: SENSITIVE,
        ablations: HEAD,
        parsing_probes: &[
            ParsingProbe {
                path: "/%61dmin/probe.txt",
                status: 200,
                route_id: Some("admin"),
            },
            ParsingProbe {
                path: "/%2561dmin/probe.txt",
                status: 200,
                route_id: Some("public"),
            },
        ],
    },
    Profile {
        backend: "nginx-raw-express",
        name: "OriginalUri",
        guard: PARENT_POST_FALLBACK,
        ablations: PARENT_POST_METHODS,
        parsing_probes: &[
            ParsingProbe {
                path: "/%61dmin/probe.txt",
                status: 200,
                route_id: Some("public"),
            },
            ParsingProbe {
                path: "/foo/secret%3F/bar",
                status: 200,
                route_id: Some("parameterized"),
            },
        ],
    },
    Profile {
        backend: "apache-proxy-express",
        name: "NoCanon",
        guard: PARENT_POST_FALLBACK,
        ablations: PARENT_POST_METHODS,
        parsing_probes: &[
            ParsingProbe {
                path: "/%61dmin/probe.txt",
                status: 200,
                route_id: Some("public"),
            },
            ParsingProbe {
                path: "/foo/secret%3F/bar",
                status: 200,
                route_id: Some("parameterized"),
            },
        ],
    },
    Profile {
        backend: "nginx-nginx-express",
        name: "DecodedUri",
        guard: TWO_PROXY_DECODES,
        ablations: &[
            Ablation {
                name: "without-second-decode",
                expect_method_denial: false,
                witness: ("GET", "/%2561dmin/probe.txt"),
                guard: PARENT_POST_FALLBACK,
            },
            Ablation {
                name: "without-query-truncation",
                expect_method_denial: false,
                witness: ("GET", "/foo/secret%253F/bar"),
                guard: DeploymentSettings {
                    query_truncation: false,
                    ..TWO_PROXY_DECODES
                },
            },
            Ablation {
                name: "without-fragment-truncation",
                expect_method_denial: false,
                witness: ("GET", "/foo/secret%2523/bar"),
                guard: DeploymentSettings {
                    fragment_truncation: false,
                    ..TWO_PROXY_DECODES
                },
            },
        ],
        parsing_probes: &[
            ParsingProbe {
                path: "/%2561dmin/probe.txt",
                status: 200,
                route_id: Some("admin"),
            },
            ParsingProbe {
                path: "/%252561dmin/probe.txt",
                status: 200,
                route_id: Some("public"),
            },
        ],
    },
    Profile {
        backend: "nginx-raw-nginx-apache",
        name: "Mixed",
        guard: TWO_DECODES,
        ablations: REMOVE_SECOND_DECODE,
        parsing_probes: &[ParsingProbe {
            path: "/%2561dmin/probe.txt",
            status: 200,
            route_id: Some("admin"),
        }],
    },
    Profile {
        backend: "apache-proxy-nginx-express",
        name: "Mixed",
        guard: PARENT_POST_FALLBACK,
        ablations: REMOVE_TRUNCATION,
        parsing_probes: &[
            ParsingProbe {
                path: "/%61dmin/probe.txt",
                status: 200,
                route_id: Some("admin"),
            },
            ParsingProbe {
                path: "/%2561dmin/probe.txt",
                status: 200,
                route_id: Some("public"),
            },
        ],
    },
    Profile {
        parsing_probes: &[
            ParsingProbe {
                path: "/admin;x=1/probe.txt",
                status: 200,
                route_id: Some("admin"),
            },
            ParsingProbe {
                path: "/public/..;x=1/admin/probe.txt",
                status: 200,
                route_id: Some("public"),
            },
            ParsingProbe {
                path: "/admin%3Bx=1/probe.txt",
                status: 200,
                route_id: Some("public"),
            },
            ParsingProbe {
                path: "/admin%2fprobe.txt",
                status: 400,
                route_id: None,
            },
        ],
        backend: "tomcat-spring",
        name: "PathPattern",
        guard: PARENT_POST_FALLBACK,
        ablations: PARENT_POST_METHODS,
    },
    Profile {
        parsing_probes: &[],
        backend: "nginx-express",
        name: "DecodedUri",
        guard: PARENT_POST_FALLBACK,
        ablations: REMOVE_TRUNCATION,
    },
    Profile {
        parsing_probes: &[],
        backend: "nginx-apache",
        name: "DecodedUri",
        guard: TWO_DECODES,
        ablations: REMOVE_SECOND_DECODE,
    },
    Profile {
        parsing_probes: &[],
        backend: "apache",
        name: "Off",
        guard: STATIC,
        ablations: STATIC_METHODS,
    },
    Profile {
        parsing_probes: &[],
        backend: "apache",
        name: "On",
        guard: STATIC,
        ablations: STATIC_METHODS,
    },
    Profile {
        parsing_probes: &[],
        backend: "apache",
        name: "NoDecode",
        guard: STATIC,
        ablations: STATIC_METHODS,
    },
    Profile {
        parsing_probes: &[],
        backend: "express",
        name: "Default",
        guard: INSENSITIVE,
        ablations: REMOVE_CASE_FOLDING,
    },
    Profile {
        parsing_probes: &[],
        backend: "express",
        name: "Insensitive",
        guard: INSENSITIVE,
        ablations: REMOVE_CASE_FOLDING,
    },
    Profile {
        parsing_probes: &[],
        backend: "express",
        name: "Sensitive",
        guard: PARENT_POST_FALLBACK,
        ablations: PARENT_POST_METHODS,
    },
    Profile {
        parsing_probes: &[],
        backend: "axum",
        name: "Sensitive",
        guard: SENSITIVE,
        ablations: HEAD,
    },
    Profile {
        parsing_probes: &[],
        backend: "sveltekit",
        name: "Sensitive",
        guard: SENSITIVE,
        ablations: REMOVE_BACKSLASH,
    },
];

pub fn find(backend: &str, name: &str) -> &'static Profile {
    PROFILES
        .iter()
        .find(|profile| profile.backend == backend && profile.name == name)
        .unwrap_or_else(|| panic!("unknown deployment profile {backend}/{name}"))
}

#[test]
fn topology_registry_matches_guard_profiles() {
    use std::collections::BTreeSet;
    let mut seen = BTreeSet::new();
    for line in include_str!("topologies.tsv").lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        assert_eq!(fields.len(), 5, "invalid topology: {line}");
        let [backend, name, origin, origin_profile, proxies] = fields[..] else {
            unreachable!()
        };
        assert!(seen.insert((backend, name)), "duplicate topology: {line}");
        find(backend, name);
        find(origin, origin_profile);
        if proxies != "-" {
            for proxy in proxies.split(',') {
                assert!(
                    matches!(proxy, "nginx-raw" | "nginx-decoded" | "apache-proxy"),
                    "unknown proxy: {proxy}"
                );
            }
        }
    }
    assert_eq!(
        seen.len(),
        PROFILES.len(),
        "every guard profile must have a runnable topology"
    );
}
