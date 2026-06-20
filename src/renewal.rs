//! Prospective-only root bump semantics (§7 constraint 5 of the paper).
//!
//! When a publisher bumps the execution-context root from `t` to `t+1`,
//! that bump does *not* invalidate attestations already committed against
//! `t`. Workers with in-flight commitments continue to settle against
//! `t` within their settlement window; new commitments after the bump
//! reference `t+1`.
//!
//! This eliminates retroactive griefing without requiring a publisher
//! bond. The [`Renewal`] trait captures the renewal check — a worker asking
//! the protocol "can I still settle against root `t`?" — and
//! [`WindowedRenewal`] is the concrete prospective-only implementation.

use crate::anchor::TripleAnchor;
use crate::commitment::FreshnessCommitment;
use crate::context::Hash32;
use crate::error::PocError;
use crate::freshness::FreshnessThresholds;

/// Renewal outcome for an in-flight commitment facing a new canonical root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalOutcome {
    /// The commitment's root is still the current canonical root. Worker may
    /// continue toward settlement.
    StillValid,
    /// The canonical root has been bumped, but this commitment's settlement
    /// window is still open. Worker is protected by prospective-only semantics
    /// and may still settle against the old root.
    ProtectedByProspectiveOnly,
    /// The canonical root was bumped and the settlement window has closed. No
    /// renewal possible; the worker must re-commit against the new root.
    ExpiredRequireRecommit,
}

/// A trait that implementers use to check whether an existing commitment is
/// still eligible for settlement given the current canonical root.
///
/// Unlike the earlier draft, `evaluate` takes the settlement clock `now` and
/// the `thresholds`: deciding prospective-only protection vs. expiry is a
/// function of the commitment's age against its settlement window (`f_s`),
/// which cannot be determined from the roots alone.
pub trait Renewal {
    /// Evaluate whether `commitment` is still settleable given the
    /// `current_canonical_root` the protocol now recognizes, the settlement
    /// clock `now`, and the freshness `thresholds`.
    fn evaluate(
        &self,
        commitment: &FreshnessCommitment,
        current_canonical_root: Hash32,
        now: &TripleAnchor,
        thresholds: &FreshnessThresholds,
    ) -> Result<RenewalOutcome, PocError>;
}

/// The concrete prospective-only renewal policy: a commitment against a
/// now-superseded canonical root remains settleable for as long as it is
/// within its `f_s` settlement window (`max_fs_blocks`).
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowedRenewal;

impl Renewal for WindowedRenewal {
    fn evaluate(
        &self,
        commitment: &FreshnessCommitment,
        current_canonical_root: Hash32,
        now: &TripleAnchor,
        thresholds: &FreshnessThresholds,
    ) -> Result<RenewalOutcome, PocError> {
        if commitment.context_root == current_canonical_root {
            return Ok(RenewalOutcome::StillValid);
        }
        // The canonical root has been bumped. The commitment is protected only
        // while it remains within its settlement window (the same f_s horizon
        // the gate enforces). A backwards clock (now before commit) is treated
        // as out-of-window.
        let within_window = now.block_height >= commitment.anchor.block_height
            && now.block_height - commitment.anchor.block_height <= thresholds.max_fs_blocks;
        if within_window {
            Ok(RenewalOutcome::ProtectedByProspectiveOnly)
        } else {
            Ok(RenewalOutcome::ExpiredRequireRecommit)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::{AttestationChain, AttestationVendor};

    fn commitment_with(context_root: Hash32, commit_block: u64) -> FreshnessCommitment {
        FreshnessCommitment {
            context_root,
            anchor: TripleAnchor::new(commit_block, 0, 0),
            output_hash: [0u8; 32],
            signature: [0u8; 64],
            public_key: [0u8; 32],
            attestation_chain: AttestationChain {
                payload: Vec::new(),
                vendor: AttestationVendor::MockSoftware,
            },
        }
    }

    #[test]
    fn matching_root_is_still_valid() {
        let root = [0x11; 32];
        let c = commitment_with(root, 1_000);
        let now = TripleAnchor::new(1_010, 0, 0);
        let out = WindowedRenewal
            .evaluate(&c, root, &now, &FreshnessThresholds::default_base_mainnet())
            .unwrap();
        assert_eq!(out, RenewalOutcome::StillValid);
    }

    #[test]
    fn bumped_root_within_window_is_protected() {
        let c = commitment_with([0x11; 32], 1_000);
        let now = TripleAnchor::new(1_100, 0, 0); // 100 ≤ max_fs (300)
        let out = WindowedRenewal
            .evaluate(&c, [0x22; 32], &now, &FreshnessThresholds::default_base_mainnet())
            .unwrap();
        assert_eq!(out, RenewalOutcome::ProtectedByProspectiveOnly);
    }

    #[test]
    fn bumped_root_past_window_requires_recommit() {
        let c = commitment_with([0x11; 32], 1_000);
        let now = TripleAnchor::new(1_400, 0, 0); // 400 > max_fs (300)
        let out = WindowedRenewal
            .evaluate(&c, [0x22; 32], &now, &FreshnessThresholds::default_base_mainnet())
            .unwrap();
        assert_eq!(out, RenewalOutcome::ExpiredRequireRecommit);
    }

    #[test]
    fn backwards_clock_requires_recommit() {
        let c = commitment_with([0x11; 32], 1_000);
        let now = TripleAnchor::new(900, 0, 0); // now before commit
        let out = WindowedRenewal
            .evaluate(&c, [0x22; 32], &now, &FreshnessThresholds::default_base_mainnet())
            .unwrap();
        assert_eq!(out, RenewalOutcome::ExpiredRequireRecommit);
    }
}
