//! The four freshness types (§6 of the paper) and their threshold parameters.
//!
//! Freshness is not a scalar. The paper decomposes it into four distinct
//! types, each with a different measurement mechanism, different failure
//! modes, and different tolerance semantics. The protocol exposes a
//! per-type threshold so operators can tune the economic envelope of
//! what counts as "still worth settling on".

/// The four freshness types, one enum variant each. Each variant
/// corresponds to an independent axis of staleness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FreshnessType {
    /// `f_c` — computational freshness. Elapsed time between when a
    /// computation was performed and when its attestation was submitted.
    Computational,
    /// `f_m` — model freshness. Distance between the model version used
    /// and the canonical on-chain model version at settlement.
    Model,
    /// `f_i` — input freshness. Temporal validity of consumed input-world
    /// state (oracle feeds, RAG corpus, tool-call results, prompt-cache
    /// entries).
    Input,
    /// `f_s` — settlement freshness. Permitted window between commit and
    /// settlement clearance.
    Settlement,
}

/// Threshold parameters for the four freshness types plus the
/// three-clock skew tolerances.
///
/// Default constructors are provided for common deployment targets
/// (e.g., [`Self::default_base_mainnet`]) using the empirically-justified
/// values from §9 of the paper.
#[derive(Debug, Clone)]
pub struct FreshnessThresholds {
    // Triple-anchor skew thresholds (§9).
    /// Allowed skew in block height between committed and canonical anchor.
    /// Default (Base mainnet): 2.
    pub block_skew: u64,
    /// Allowed skew in TEE timestamp, in seconds. Default: 5.
    pub tee_skew_secs: u64,
    /// Allowed skew in Drand rounds. Default: 1 (±30 s).
    pub drand_skew: u64,

    // Freshness-type horizons.
    /// Maximum `f_c` — how long a worker can hold a result before committing.
    /// Measured in block heights.
    pub max_fc_blocks: u64,
    /// Maximum `f_m` — how many root bumps between used model and current.
    pub max_fm_epochs: u64,
    /// Maximum `f_i` — how many blocks the input-world state can lag.
    pub max_fi_blocks: u64,
    /// Maximum `f_s` — window between commit and settlement.
    pub max_fs_blocks: u64,
}

impl FreshnessThresholds {
    /// Empirically-justified defaults for a Base-mainnet deployment, per §9.
    pub const fn default_base_mainnet() -> Self {
        Self {
            // Triple-anchor (§9): ±2 blocks, ±5 s, ±1 Drand round.
            block_skew: 2,
            tee_skew_secs: 5,
            drand_skew: 1,
            // Conservative defaults for initial deployment. Operators
            // should tune per use case; real-time agent inference
            // wants tight f_c and f_i, batched analysis can tolerate
            // wider f_s.
            max_fc_blocks: 30,   // ~60 s at 2 s/block
            max_fm_epochs: 1,    // one model-root-bump allowed before slash
            max_fi_blocks: 15,   // ~30 s at 2 s/block
            max_fs_blocks: 300,  // ~10 min settlement window
        }
    }

    /// Permissive defaults useful for test deployments and demos. NOT
    /// suitable for mainnet economic workflows.
    pub const fn permissive_testnet() -> Self {
        Self {
            block_skew: 10,
            tee_skew_secs: 60,
            drand_skew: 5,
            max_fc_blocks: 600,
            max_fm_epochs: 5,
            max_fi_blocks: 600,
            max_fs_blocks: 3600,
        }
    }
}

impl Default for FreshnessThresholds {
    fn default() -> Self {
        Self::default_base_mainnet()
    }
}
