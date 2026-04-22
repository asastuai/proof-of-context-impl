//! Shared error type for the crate.
//!
//! Phase 1 uses a hand-rolled enum. Phase 2 will convert to `thiserror`
//! once a dependency is added.

use std::fmt;

/// Errors that can arise during commitment, verification, or settlement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PocError {
    /// The three clocks diverge beyond the configured skew threshold.
    AnchorDivergence,
    /// Signature verification failed.
    InvalidSignature,
    /// Attestation chain is malformed or does not terminate at a
    /// known-good enclave measurement.
    InvalidAttestation,
    /// A freshness type is past its horizon.
    StaleFreshness(crate::freshness::FreshnessType),
    /// A required field in the execution-context root was missing.
    ContextRootMalformed(&'static str),
    /// Generic implementation-not-yet error for scaffold-phase methods.
    /// Should never surface at runtime in a real deployment.
    Unimplemented(&'static str),
    /// Wrapper for other / vendor-specific errors.
    Other(String),
}

impl fmt::Display for PocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AnchorDivergence => write!(f, "triple-anchor clocks diverge beyond skew threshold"),
            Self::InvalidSignature => write!(f, "commitment signature verification failed"),
            Self::InvalidAttestation => write!(f, "TEE attestation chain invalid"),
            Self::StaleFreshness(t) => write!(f, "freshness violation on {t:?}"),
            Self::ContextRootMalformed(s) => write!(f, "execution-context root malformed: {s}"),
            Self::Unimplemented(s) => write!(f, "scaffold stub not yet implemented: {s}"),
            Self::Other(s) => write!(f, "{s}"),
        }
    }
}

impl std::error::Error for PocError {}
