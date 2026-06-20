//! The settlement gate — the trait that refuses to clear stale commitments.
//!
//! This is where proof-of-context differs from prior-work property
//! attestation (PAL\*M). A [`SettlementGate`] is queried *at payment time*
//! and answers: "given the current state of the world, should this
//! commitment's attached payment clear?"
//!
//! If the commitment's anchor is within freshness horizons of the
//! current canonical state, yes. If not, no — the computation may have
//! been correct, but the protocol refuses to settle against it.

use crate::anchor::TripleAnchor;
use crate::commitment::FreshnessCommitment;
use crate::context::ExecutionContextRoot;
use crate::error::PocError;
use crate::freshness::{FreshnessThresholds, FreshnessType};

/// Outcome of a settlement check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementResult {
    /// Commitment is fresh; payment may clear.
    Clear,
    /// Commitment is stale on one or more freshness types. Payment must
    /// not clear. The violated freshness type(s) are reported so the
    /// protocol can emit the right refund / slash event.
    Rejected(Vec<FreshnessType>),
}

/// A gate that decides whether a commitment is eligible for settlement.
pub trait SettlementGate {
    /// Quick boolean check without producing a reason. Useful for UI /
    /// mempool filtering. For actual settlement, use
    /// [`verify_and_settle`](Self::verify_and_settle).
    fn is_settlement_eligible(
        &self,
        commitment: &FreshnessCommitment,
        root: &ExecutionContextRoot,
        now: &TripleAnchor,
        thresholds: &FreshnessThresholds,
    ) -> Result<bool, PocError> {
        Ok(matches!(
            self.verify_and_settle(commitment, root, now, thresholds)?,
            SettlementResult::Clear
        ))
    }

    /// Full check with structured reason.
    ///
    /// `root` is the **disclosed** execution-context root (mechanism (i)):
    /// the commitment carries only the opaque `context_root` hash, but
    /// deciding `f_m`/`f_i` requires reading `weights_hash` and
    /// `input_manifest_root`. The caller discloses the full root; the gate
    /// recomputes `root.merkle_root()` and rejects unless it equals
    /// `commitment.context_root` before reading any field.
    fn verify_and_settle(
        &self,
        commitment: &FreshnessCommitment,
        root: &ExecutionContextRoot,
        now: &TripleAnchor,
        thresholds: &FreshnessThresholds,
    ) -> Result<SettlementResult, PocError>;
}
