//! The canonical-state oracle — settlement-time lookups for the two
//! freshness predicates that need state external to the commitment.
//!
//! `consistent` and `f_s` are decidable from the commitment `C` and the
//! settlement clock `now` alone (see [`crate::settle`]). `f_m` (model
//! freshness) and `f_i` (input freshness) are not: deciding them requires
//! knowing what the *canonical* model version and input-world state are at
//! `now`. That knowledge lives outside the commitment, in an oracle.
//!
//! This is the surface the paper's **H4** assumption (an honest
//! canonical-state oracle) attaches to. v0.3 ships the trait plus a software
//! [`crate::mock::MockCanonicalStateOracle`]; the real implementation
//! (BaseOracle for `f_i`, an on-chain model-root+epoch registry for `f_m`)
//! is pieza 1b.

use crate::anchor::TripleAnchor;
use crate::context::Hash32;
use crate::error::PocError;

/// Settlement-time canonical-state lookups for `f_m` and `f_i`.
///
/// Both methods take the queried state (by hash) and the settlement-time
/// anchor, and return a *distance* the gate compares against its thresholds.
/// Returning `Err` means the oracle cannot vouch for the queried state; the
/// gate treats that as a freshness rejection (it does not clear on ignorance).
pub trait CanonicalStateOracle {
    /// `f_m`: version-epoch distance between the committed model (identified
    /// by its weights hash) and the canonical model at `now`.
    ///
    /// `0` = the committed model is current; larger = staler. `Err`
    /// (typically [`PocError::OracleUnavailable`]) if the weights hash is
    /// not in the canonical lineage — an unregistered model is not fresh.
    fn model_epoch_distance(&self, weights_hash: Hash32, now: &TripleAnchor)
        -> Result<u64, PocError>;

    /// `f_i`: how many blocks the committed input-world state (identified by
    /// its input-manifest root) lags the canonical input-world state at
    /// `now`. `0` = current; larger = staler. `Err` if the input state is
    /// unknown to the oracle.
    fn input_lag_blocks(&self, input_manifest_root: Hash32, now: &TripleAnchor)
        -> Result<u64, PocError>;
}
