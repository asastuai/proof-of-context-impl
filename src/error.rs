//! Shared error type for the crate.

use crate::freshness::FreshnessType;

/// Errors that can arise during commitment, verification, or settlement.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PocError {
    /// The three clocks diverge beyond the configured skew threshold.
    #[error("triple-anchor clocks diverge beyond skew threshold")]
    AnchorDivergence,

    /// Signature verification failed.
    #[error("commitment signature verification failed")]
    InvalidSignature,

    /// Attestation chain is malformed or does not terminate at a
    /// known-good enclave measurement.
    #[error("TEE attestation chain invalid")]
    InvalidAttestation,

    /// A freshness type is past its horizon.
    #[error("freshness violation on {0:?}")]
    StaleFreshness(FreshnessType),

    /// A required field in the execution-context root was missing.
    #[error("execution-context root malformed: {0}")]
    ContextRootMalformed(&'static str),

    /// The commitment's output hash does not match the claimed output.
    #[error("output hash mismatch")]
    OutputHashMismatch,

    /// The disclosed execution-context root does not hash to the
    /// `context_root` committed to. A worker disclosed a context different
    /// from what it signed — settlement must abort before reading any field.
    #[error("disclosed context root does not match committed root")]
    RootMismatch,

    /// The canonical-state oracle could not answer (e.g. the model is not in
    /// the canonical lineage, or the input-world state is unknown). The gate
    /// maps this to a freshness rejection rather than clearing on ignorance.
    #[error("canonical-state oracle unavailable for the queried state")]
    OracleUnavailable,

    /// The canonical root on-chain is ahead of the commitment's snapshot,
    /// and the renewal window has closed. Worker must re-commit.
    #[error("commitment expired — canonical root advanced past renewal window")]
    CommitmentExpired,

    /// Generic "not yet implemented" marker for scaffold-stage methods.
    /// Should never surface at runtime in a production deployment.
    #[error("scaffold stub not yet implemented: {0}")]
    Unimplemented(&'static str),

    /// Wrapper for other / vendor-specific errors.
    #[error("{0}")]
    Other(String),
}
