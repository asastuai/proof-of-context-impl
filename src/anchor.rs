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

use serde::{Deserialize, Serialize};

/// The block height from the settlement chain (e.g., Base).
pub type BlockHeight = u64;

/// Unix-nanoseconds timestamp reported by the enclave.
pub type TeeTimestamp = u128;

/// Drand mainnet round number (one round every 30 s by construction).
pub type DrandRound = u64;

/// Drand mainnet genesis (2020-07-22 15:17:30 UTC).
pub const DRAND_GENESIS_UNIX: u64 = 1_595_431_050;

/// Drand mainnet period in seconds.
pub const DRAND_PERIOD_SECS: u64 = 30;

/// A commitment to all three clocks at the moment the worker signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
        Self { block_height, tee_timestamp, drand_round }
    }

    /// Return the anchor's wall-clock time in Unix seconds, computed from
    /// the Drand round (most reliable external clock) plus mainnet genesis.
    ///
    /// Drand is deterministic: round N is emitted at
    /// `genesis + N * period`. This function returns that scheduled
    /// emission time, not the observed arrival time.
    pub fn drand_wall_time_secs(&self) -> u64 {
        DRAND_GENESIS_UNIX + self.drand_round.saturating_mul(DRAND_PERIOD_SECS)
    }

    /// Absolute skew between this anchor and another across the three
    /// clocks, reported as a typed tuple for per-axis threshold checks.
    pub fn skew_vs(&self, other: &TripleAnchor) -> AnchorSkew {
        let block_delta = abs_diff_u64(self.block_height, other.block_height);
        let tee_delta_ns = abs_diff_u128(self.tee_timestamp, other.tee_timestamp);
        let drand_delta = abs_diff_u64(self.drand_round, other.drand_round);
        AnchorSkew { block_delta, tee_delta_ns, drand_delta }
    }

    /// Return `true` if the three clocks diverge beyond any of the given
    /// skew thresholds. Under a valid TEE attestation chain, this
    /// detects accidental skew or single-clock failure (paper §9).
    pub fn diverges_beyond(
        &self,
        other: &TripleAnchor,
        thresholds: &crate::freshness::FreshnessThresholds,
    ) -> bool {
        let s = self.skew_vs(other);
        let tee_secs = s.tee_delta_ns / 1_000_000_000u128;
        s.block_delta > thresholds.block_skew
            || tee_secs > u128::from(thresholds.tee_skew_secs)
            || s.drand_delta > thresholds.drand_skew
    }
}

/// Per-axis skew between two `TripleAnchor` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnchorSkew {
    /// |block_height_a - block_height_b| in blocks.
    pub block_delta: u64,
    /// |tee_timestamp_a - tee_timestamp_b| in nanoseconds.
    pub tee_delta_ns: u128,
    /// |drand_round_a - drand_round_b| in rounds.
    pub drand_delta: u64,
}

fn abs_diff_u64(a: u64, b: u64) -> u64 {
    if a > b { a - b } else { b - a }
}

fn abs_diff_u128(a: u128, b: u128) -> u128 {
    if a > b { a - b } else { b - a }
}
