//! Fixed deployment recommendations and independent behavioral witnesses.
//! Adding a server or proxy chain should require data here, not harness branches.
use huskarl_route_guard::{CaseSensitivity, DecodeDepth};

#[derive(Clone, Copy)]
pub struct DeploymentSettings {
    pub case: CaseSensitivity,
    pub decode: DecodeDepth,
    pub backslash: bool,
    pub include_head: bool,
    pub static_post: bool,
    pub private_post_fallback: bool,
}

pub struct Ablation {
    pub name: &'static str,
    pub guard: DeploymentSettings,
    pub witness: (&'static str, &'static str),
}

pub struct Profile {
    pub backend: &'static str,
    pub name: &'static str,
    pub guard: DeploymentSettings,
    // Each additional recommendation must have an accepted-request counterexample
    // when removed. No counterexample means the recommendation needs review.
    pub ablations: &'static [Ablation],
}

const SENSITIVE: DeploymentSettings = DeploymentSettings {
    case: CaseSensitivity::Sensitive,
    decode: DecodeDepth::UpToOne,
    backslash: false,
    include_head: true,
    static_post: false,
    private_post_fallback: false,
};
const INSENSITIVE: DeploymentSettings = DeploymentSettings {
    case: CaseSensitivity::Insensitive,
    private_post_fallback: true,
    ..SENSITIVE
};
const EXPRESS_SENSITIVE: DeploymentSettings = DeploymentSettings {
    private_post_fallback: true,
    ..SENSITIVE
};
const BACKSLASH: DeploymentSettings = DeploymentSettings {
    backslash: true,
    ..SENSITIVE
};

const REMOVE_CASE_FOLDING: &[Ablation] = &[
    Ablation {
        name: "without-case-folding",
        witness: ("GET", "/ADMIN/PROBE.TXT"),
        guard: EXPRESS_SENSITIVE,
    },
    Ablation {
        name: "without-head",
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..INSENSITIVE
        },
    },
    Ablation {
        name: "without-private-post-fallback",
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
        witness: ("GET", "/admin\\probe.txt"),
        guard: SENSITIVE,
    },
    Ablation {
        name: "without-head",
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..BACKSLASH
        },
    },
];

const HEAD: &[Ablation] = &[Ablation {
    name: "without-head",
    witness: ("HEAD", "/admin/probe.txt"),
    guard: DeploymentSettings {
        include_head: false,
        ..SENSITIVE
    },
}];
const EXPRESS_METHODS: &[Ablation] = &[
    Ablation {
        name: "without-head",
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..EXPRESS_SENSITIVE
        },
    },
    Ablation {
        name: "without-private-post-fallback",
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
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..STATIC
        },
    },
    Ablation {
        name: "without-static-post",
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
        witness: ("GET", "/%2561dmin/probe.txt"),
        guard: STATIC,
    },
    Ablation {
        name: "without-head",
        witness: ("HEAD", "/admin/probe.txt"),
        guard: DeploymentSettings {
            include_head: false,
            ..TWO_DECODES
        },
    },
    Ablation {
        name: "without-static-post",
        witness: ("POST", "/admin/probe.txt"),
        guard: DeploymentSettings {
            static_post: false,
            ..TWO_DECODES
        },
    },
];

// Fixed before observations. The harness tests only outgoing requests for each
// candidate, and requires real confusion to justify retaining each extra setting.
const PROFILES: &[Profile] = &[
    Profile {
        backend: "nginx-apache",
        name: "DecodedUri",
        guard: TWO_DECODES,
        ablations: REMOVE_SECOND_DECODE,
    },
    Profile {
        backend: "apache",
        name: "Off",
        guard: STATIC,
        ablations: STATIC_METHODS,
    },
    Profile {
        backend: "apache",
        name: "On",
        guard: STATIC,
        ablations: STATIC_METHODS,
    },
    Profile {
        backend: "apache",
        name: "NoDecode",
        guard: STATIC,
        ablations: STATIC_METHODS,
    },
    Profile {
        backend: "express",
        name: "Default",
        guard: INSENSITIVE,
        ablations: REMOVE_CASE_FOLDING,
    },
    Profile {
        backend: "express",
        name: "Insensitive",
        guard: INSENSITIVE,
        ablations: REMOVE_CASE_FOLDING,
    },
    Profile {
        backend: "express",
        name: "Sensitive",
        guard: EXPRESS_SENSITIVE,
        ablations: EXPRESS_METHODS,
    },
    Profile {
        backend: "axum",
        name: "Sensitive",
        guard: SENSITIVE,
        ablations: HEAD,
    },
    Profile {
        backend: "sveltekit",
        name: "Sensitive",
        guard: BACKSLASH,
        ablations: REMOVE_BACKSLASH,
    },
];

pub fn find(backend: &str, name: &str) -> &'static Profile {
    PROFILES
        .iter()
        .find(|profile| profile.backend == backend && profile.name == name)
        .unwrap_or_else(|| panic!("unknown deployment profile {backend}/{name}"))
}
