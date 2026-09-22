//! Learn, configure, and understand the route guard.
//!
//! Choose the page that matches what you are doing:
//!
//! - **New to the crate?** Work through [Getting started](tutorial).
//! - **Integrating it?** Use [Choosing a configuration](guide::configuring).
//! - **Investigating a `400`?** Use [Handling a denial](guide::handling_denials).
//! - **Reviewing the security claim?** Read the [Security contract](reference::contract)
//!   and [Supported interpretations](reference::coverage).
//! - **Trying to understand the design?** Read [How the guard decides](explanation::decision),
//!   [Why it forwards the raw path](explanation::no_rewrite), and
//!   [Where the parser disagreement lives](explanation::topology). For the testing
//!   argument, read [How the security claim is tested](explanation::testing).
//! - **Looking up a term?** Use the [Glossary](reference::glossary). It marks the
//!   small amount of library-specific terminology explicitly.
//!
//! This follows the [Diátaxis](https://diataxis.fr) split: the tutorial teaches by
//! doing, the guides solve operational tasks, the explanations give rationale, and
//! the reference pages state the exact contract and coverage. API items remain the
//! reference for individual types and methods.

#[doc = include_str!("../docs/tutorial/getting-started.md")]
pub mod tutorial {}

/// Exact statements to consult while configuring or reviewing the guard.
pub mod reference {
    #[doc = include_str!("../docs/reference/contract.md")]
    pub mod contract {}

    #[doc = include_str!("../docs/reference/coverage.md")]
    pub mod coverage {}

    #[doc = include_str!("../docs/reference/glossary.md")]
    pub mod glossary {}
}

/// Understanding-oriented background on how the guard works and why.
pub mod explanation {
    #[doc = include_str!("../docs/explanation/decision.md")]
    pub mod decision {}

    #[doc = include_str!("../docs/explanation/no_rewrite.md")]
    pub mod no_rewrite {}

    #[doc = include_str!("../docs/explanation/topology.md")]
    pub mod topology {}

    #[doc = include_str!("../docs/explanation/testing.md")]
    pub mod testing {}
}

/// Task-oriented guidance for configuring the guard and operating it.
pub mod guide {
    #[doc = include_str!("../docs/guide/configuring.md")]
    pub mod configuring {}

    #[doc = include_str!("../docs/guide/handling-denials.md")]
    pub mod handling_denials {}
}
