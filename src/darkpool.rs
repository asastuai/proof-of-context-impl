//! Multi-party freshness gate for the SUR Solana agent-to-agent dark pool.
//!
//! In SUR's `a2a_darkpool`, agent A posts an `Intent` (a price band) and agent B
//! posts a `Response` (a price); they negotiate and `accept_and_settle` clears
//! the trade. Each agent's quoted price is the output of reasoning over
//! **context** — the market/price state it observed. Proof-of-context gates the
//! settlement so a negotiated trade clears **only if every party's quote was
//! made against fresh context**. This is the multi-party generalization of the
//! crate's single-commitment [`crate::settle::SettlementGate`].
//!
//! Seconds-native: the dark pool runs on unix seconds (`Clock::unix_timestamp`),
//! so freshness here is measured in seconds against the parties' anchor wall
//! clocks ([`crate::anchor::TripleAnchor::tee_drand_consistent`] for the
//! `consistent` check — TEE↔Drand only, since a Solana anchor's block is not a
//! Base block) and a seconds-based price-as-of ([`crate::price_freshness`]).
//! The block-denominated [`crate::oracle::CanonicalStateOracle`] path is untouched.
//!
//! `f_c` is not enforced (crate-wide, see the gate). `f_m` (agent model/policy
//! version) is **deferred** for quotes — agent policy versioning is not yet a
//! SUR on-chain concept; it can be composed later via an
//! [`crate::oracle::CanonicalStateOracle`] keyed on the disclosed
//! `weights_hash`.

use crate::commitment::{CommitmentVerifier, FreshnessCommitment};
use crate::context::ExecutionContextRoot;
use crate::error::PocError;
use crate::freshness::{FreshnessThresholds, FreshnessType};
use crate::price_freshness::PriceFreshnessOracle;

/// Seconds-native freshness budgets for a unix-seconds settlement venue. The
/// block-denominated [`FreshnessThresholds`] is reused only for the `consistent`
/// (TEE↔Drand internal-agreement) skew tolerances, which are chain-neutral.
#[derive(Debug, Clone)]
pub struct DarkPoolThresholds {
    /// `f_i`: max age (now − price_as_of) of the market price a quote used.
    pub max_price_age_secs: u64,
    /// `f_s`: max window from a quote's `created_at` to settlement `now`.
    pub max_settle_window_secs: u64,
    /// Anchor internal-consistency skews (TEE↔Drand) for the `consistent` check.
    pub anchor_consistency: FreshnessThresholds,
}

impl Default for DarkPoolThresholds {
    /// 30 s price age, 10 min settle window, default anchor skews.
    fn default() -> Self {
        Self {
            max_price_age_secs: 30,
            max_settle_window_secs: 600,
            anchor_consistency: FreshnessThresholds::default_base_mainnet(),
        }
    }
}

/// Which negotiating party a verdict belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PartyRole {
    /// Agent that posted the `Intent` (the price band).
    Intent,
    /// Agent that posted the `Response` (the price).
    Response,
    /// Future N-party generalization.
    Other(u32),
}

/// One negotiating agent's context for a dark-pool quote.
pub struct PartyContext {
    /// Which side of the negotiation this is (for per-party attribution).
    pub role: PartyRole,
    /// The agent's signed proof-of-context commitment.
    pub commitment: FreshnessCommitment,
    /// The disclosed execution-context root (bound to `commitment.context_root`).
    pub root: ExecutionContextRoot,
    /// The market this quote was made on (`a2a_darkpool` `intent.market_id`).
    pub market_id: [u8; 32],
    /// Unix seconds the quote was created (`intent`/`response.created_at`).
    pub quote_created_at_secs: u64,
}

/// Per-party freshness verdict. `violations` empty ⇒ this party is fresh.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartyVerdict {
    /// The party this verdict is for.
    pub role: PartyRole,
    /// Freshness types this party violated (empty ⇒ fresh).
    pub violations: Vec<FreshnessType>,
}

/// Outcome of a multi-party dark-pool freshness check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DarkPoolSettlement {
    /// Every party's quote used fresh context → the negotiated trade may clear.
    Clear,
    /// One or more parties stale → must not clear. Carries only the failing
    /// parties' verdicts so the caller can attribute the abort to the right agent.
    Rejected(Vec<PartyVerdict>),
}

/// Gate an agent-to-agent negotiated trade on the freshness of every party's
/// context. Clears iff all parties are fresh.
///
/// `verifier` checks each commitment's signature + attestation chain (an
/// **integrity** failure — bad signature, bad attestation, or a disclosed root
/// that does not bind to the committed `context_root` — is a hard `Err` that
/// aborts the whole settlement, distinct from a per-party freshness rejection).
/// `price_oracle` answers the seconds-based `f_i` (price-as-of age) per market;
/// `now_secs` is the settlement clock in unix seconds (as `Clock::unix_timestamp`
/// yields on-chain).
pub fn verify_party_contexts<V: CommitmentVerifier>(
    verifier: &V,
    parties: &[PartyContext],
    price_oracle: &PriceFreshnessOracle,
    now_secs: u64,
    thresholds: &DarkPoolThresholds,
) -> Result<DarkPoolSettlement, PocError> {
    let mut failing: Vec<PartyVerdict> = Vec::new();

    for party in parties {
        // 1. Integrity (hard abort): signature + attestation, then context
        //    binding. Reuses the exact primitives the single-commitment gate
        //    calls — see `mock.rs`.
        verifier.verify(&party.commitment)?;
        if party.root.merkle_root() != party.commitment.context_root {
            return Err(PocError::RootMismatch);
        }

        let mut violations = Vec::new();

        // 2. consistent — internal anchor agreement. Uses the TEE↔Drand
        //    (wall-clock) check only: a Solana anchor's block_height is a slot,
        //    not a Base block, so the Base block leg must NOT apply here.
        if !party
            .commitment
            .anchor
            .tee_drand_consistent(&thresholds.anchor_consistency)
        {
            violations.push(FreshnessType::Computational);
        }

        // 3. f_i (seconds) — age of the price this quote was made against.
        //    Unknown market (Err) is treated as stale.
        let price_stale = match price_oracle.price_age_secs(&party.market_id, now_secs) {
            Ok(age) => age > thresholds.max_price_age_secs,
            Err(_) => true,
        };
        if price_stale {
            violations.push(FreshnessType::Input);
        }

        // 4. f_s (seconds) — quote→settle window. A backwards clock (now before
        //    the quote) is itself a settlement-window violation.
        let settle_stale = now_secs < party.quote_created_at_secs
            || now_secs - party.quote_created_at_secs > thresholds.max_settle_window_secs;
        if settle_stale {
            violations.push(FreshnessType::Settlement);
        }

        // No f_m (deferred for quotes) and no f_c (crate-wide).

        if !violations.is_empty() {
            failing.push(PartyVerdict { role: party.role.clone(), violations });
        }
    }

    if failing.is_empty() {
        Ok(DarkPoolSettlement::Clear)
    } else {
        Ok(DarkPoolSettlement::Rejected(failing))
    }
}
