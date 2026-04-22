//! The triple anchor: three clocks with orthogonal failure physics.
//!
//! As argued in §7 constraint 6 of the paper, temporal validity in the
//! protocol is anchored to three independent clocks — block height,
//! TEE timestamp, Drand round. Each clock fails differently, so a
//! divergence between them beyond expected skew is cause for slash.
//!
//! **Important threat-model caveat** (paper §9): the triple anchor is
//! *not* a defense against a compromised TEE — an enclave observes the
//! other two clocks and can echo them. Defense against TEE compromise is
//! the attestation chain (see [`crate::attestation`]), not the anchor.
//! The anchor defends against accidental skew and single-clock failure
//! under the assumption of a valid attestation chain.

/// The block height from the settlement chain (e.g., Base).
pub type BlockHeight = u64;

/// Unix-nanoseconds timestamp reported by the enclave.
pub type TeeTimestamp = u128;

/// Drand mainnet round number (one round every 30 s by construction).
pub type DrandRound = u64;

/// A commitment to all three clocks at the moment the worker signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TripleAnchor {
    /// Chain-local clock. Vulnerable to MEV, reorder, chain reorg.
    pub block_height: BlockHeight,
    /// Enclave-local clock. Vulnerable to manipulation inside a
    /// compromised enclave (e.g., TDXdown attack).
    pub tee_timestamp: TeeTimestamp,
    /// External threshold-BLS clock. Vulnerable to compromise of 2/3 of
    /// the Drand League of Entropy.
    pub drand_round: DrandRound,
}

impl TripleAnchor {
    /// Construct an anchor from its three components.
    pub const fn new(
        block_height: BlockHeight,
        tee_timestamp: TeeTimestamp,
        drand_round: DrandRound,
    ) -> Self {
        Self {
            block_height,
            tee_timestamp,
            drand_round,
        }
    }

    /// Return the anchor's estimated wall-clock time in Unix seconds,
    /// computed from the Drand round (most reliable external clock) plus
    /// Drand mainnet genesis (1595431050). Returns `None` if the anchor
    /// is malformed.
    ///
    /// Phase 1 stub.
    pub fn approx_wall_time_secs(&self) -> Option<u64> {
        unimplemented!(
            "Phase 2: compute 1595431050 + 30 * drand_round; validate sanity vs block/TEE."
        )
    }

    /// Return true if the three clocks diverge beyond the given skew
    /// thresholds. Used during commitment verification to detect
    /// tampering or accidental skew.
    ///
    /// Phase 1 stub.
    pub fn diverges_beyond(&self, _other: &TripleAnchor, _thresholds: &crate::freshness::FreshnessThresholds) -> bool {
        unimplemented!(
            "Phase 2: pairwise check (block_height skew, tee_timestamp skew, drand_round skew) \
             against thresholds. Returns true if any axis violates."
        )
    }
}
