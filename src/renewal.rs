//! Prospective-only root bump semantics (§7 constraint 5 of the paper).
//!
//! When a publisher bumps the execution-context root from `t` to `t+1`,
//! that bump does *not* invalidate attestations already committed against
//! `t`. Workers with in-flight commitments continue to settle against
//! `t` within their settlement window; new commitments after the bump
//! reference `t+1`.
//!
//! This eliminates retroactive griefing without requiring a publisher
//! bond. The [`Renewal`] trait exists to capture the renewal check — a
//! worker asking the protocol "can I still settle against root `t`?"

use crate::commitment::FreshnessCommitment;
use crate::context::Hash32;
use crate::error::PocError;

/// Renewal outcome for an in-flight commitment facing a new canonical root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// Commitment's root is still within the settlement window. Worker
    /// may continue toward settlement.
    StillValid,
    /// Root has been bumped but the settlement window for this
    /// commitment is still open. Worker is protected by prospective-only
    /// semantics.
    ProtectedByProspectiveOnly,
    /// Commitment has expired — settlement window closed. No renewal
    /// possible; worker must re-commit against the new root.
    ExpiredRequireRecommit,
}

/// A trait that implementers use to check whether an existing commitment
/// is still eligible for settlement given the current canonical root.
pub trait Renewal {
    /// Evaluate whether `commitment` is still valid for settlement given
    /// the `current_canonical_root` the protocol now recognizes.
    fn evaluate(
        &self,
        commitment: &FreshnessCommitment,
        current_canonical_root: Hash32,
    ) -> Result<RenewalOutcome, PocError>;
}
