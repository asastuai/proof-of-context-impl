//! Pieza 1 — oracle-gated settlement tests (crate v0.3).
//!
//! Exercises the gate enforcing `consistent` + `f_m` + `f_i` + `f_s`
//! (integrity + three of the four freshness types) against a mock
//! canonical-state oracle. `f_c` is deliberately not enforced — it is not
//! measurable from `(A, now)` and is handled structurally
//! (commit-at-completion), per SPEC-ORACLE-GATING-v0.3.

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;

use proof_of_context::{
    anchor::{
        TripleAnchor, BASE_BLOCK_PERIOD_SECS, BASE_MAINNET_GENESIS_UNIX, DRAND_GENESIS_UNIX,
        DRAND_PERIOD_SECS,
    },
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::{FreshnessThresholds, FreshnessType},
    mock::{MockCanonicalStateOracle, MockCommitter, MockSettlementGate, MockVerifier},
    settle::{SettlementGate, SettlementResult},
    ContextCommitter, PocError,
};

const WEIGHTS_HASH: [u8; 32] = [0xAA; 32];
const INPUT_MANIFEST_ROOT: [u8; 32] = [0x11; 32];

/// Deterministic sample root; `seed` perturbs the sampling seed so distinct
/// values yield distinct `merkle_root()`s (used by the mismatch test).
fn sample_root(seed: u64) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: WEIGHTS_HASH,
        tokenizer_hash: [0xBB; 32],
        system_prompt_hash: [0xCC; 32],
        sampling_params: SamplingParams { temperature: 0.7, top_k: 50, top_p: 0.9, seed },
        runtime_version: [0xDD; 32],
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 256,
            stop_sequences_root: [0xEE; 32],
            penalty_params_root: [0xFF; 32],
        },
        input_manifest_root: INPUT_MANIFEST_ROOT,
        kv_cache_root: None,
    }
}

fn mock_committer(seed: u64) -> MockCommitter {
    let mut rng = StdRng::seed_from_u64(seed);
    MockCommitter::new(SigningKey::generate(&mut rng), "pieza1-worker")
}

/// A Drand round whose wall-time (~2025-04-29) sits well after Base genesis,
/// so a Base block height can be derived for it.
const COMMIT_DRAND: u64 = 5_015_631;

/// Build a **fully** internally-consistent commit anchor from a Drand round:
/// block, TEE, and Drand all derive from the one wall-time, so `consistent`
/// passes under both default and `real-anchors` (block↔Drand leg) features.
fn consistent_anchor(drand_round: u64) -> TripleAnchor {
    let wall = DRAND_GENESIS_UNIX + drand_round * DRAND_PERIOD_SECS;
    let block = (wall - BASE_MAINNET_GENESIS_UNIX) / BASE_BLOCK_PERIOD_SECS;
    TripleAnchor::new(block, (wall as u128) * 1_000_000_000, drand_round)
}

/// Settlement clock at a block height (only `f_s` reads `now`'s block; `now`
/// is never checked for internal consistency).
fn now_at_block(block_height: u64) -> TripleAnchor {
    TripleAnchor::new(block_height, 0, 0)
}

fn commit_anchor() -> TripleAnchor {
    consistent_anchor(COMMIT_DRAND)
}

#[test]
fn all_fresh_clears() {
    let committer = mock_committer(1);
    let gate = MockSettlementGate::new(MockVerifier::new(), MockCanonicalStateOracle::always_fresh());
    let thresholds = FreshnessThresholds::default_base_mainnet();
    let root = sample_root(42);

    let commitment = committer.commit(root.clone(), [0x22; 32], commit_anchor()).unwrap();
    let now = now_at_block(commit_anchor().block_height + 1);

    let result = gate.verify_and_settle(&commitment, &root, &now, &thresholds).unwrap();
    assert_eq!(result, SettlementResult::Clear);
}

#[test]
fn stale_model_rejected() {
    let committer = mock_committer(2);
    // Model is 5 epochs behind canonical; max_fm_epochs = 1.
    let oracle = MockCanonicalStateOracle::always_fresh().with_model_epoch(WEIGHTS_HASH, 5);
    let gate = MockSettlementGate::new(MockVerifier::new(), oracle);
    let thresholds = FreshnessThresholds::default_base_mainnet();
    let root = sample_root(42);

    let commitment = committer.commit(root.clone(), [0u8; 32], commit_anchor()).unwrap();
    let now = now_at_block(commit_anchor().block_height + 1);

    match gate.verify_and_settle(&commitment, &root, &now, &thresholds).unwrap() {
        SettlementResult::Rejected(v) => {
            assert!(v.contains(&FreshnessType::Model), "stale model must trip f_m: {v:?}");
            assert!(!v.contains(&FreshnessType::Input), "input is fresh here: {v:?}");
        }
        SettlementResult::Clear => panic!("stale model must not clear"),
    }
}

#[test]
fn stale_input_rejected() {
    let committer = mock_committer(3);
    // Input lags 100 blocks; max_fi_blocks = 15.
    let oracle = MockCanonicalStateOracle::always_fresh().with_input_lag(INPUT_MANIFEST_ROOT, 100);
    let gate = MockSettlementGate::new(MockVerifier::new(), oracle);
    let thresholds = FreshnessThresholds::default_base_mainnet();
    let root = sample_root(42);

    let commitment = committer.commit(root.clone(), [0u8; 32], commit_anchor()).unwrap();
    let now = now_at_block(commit_anchor().block_height + 1);

    match gate.verify_and_settle(&commitment, &root, &now, &thresholds).unwrap() {
        SettlementResult::Rejected(v) => {
            assert!(v.contains(&FreshnessType::Input), "stale input must trip f_i: {v:?}");
            assert!(!v.contains(&FreshnessType::Model), "model is fresh here: {v:?}");
        }
        SettlementResult::Clear => panic!("stale input must not clear"),
    }
}

#[test]
fn settled_late_rejected() {
    let committer = mock_committer(4);
    let gate = MockSettlementGate::new(MockVerifier::new(), MockCanonicalStateOracle::always_fresh());
    let thresholds = FreshnessThresholds::default_base_mainnet();
    let root = sample_root(42);

    let commitment = committer.commit(root.clone(), [0u8; 32], commit_anchor()).unwrap();
    // "Sat on it" / late settlement — beyond max_fs_blocks (300). Caught by
    // f_s, NOT a separate f_c predicate.
    let now = now_at_block(commit_anchor().block_height + thresholds.max_fs_blocks + 1);

    match gate.verify_and_settle(&commitment, &root, &now, &thresholds).unwrap() {
        SettlementResult::Rejected(v) => {
            assert!(v.contains(&FreshnessType::Settlement), "late settle must trip f_s: {v:?}");
        }
        SettlementResult::Clear => panic!("late settlement must not clear"),
    }
}

#[test]
fn inconsistent_anchor_rejected() {
    let committer = mock_committer(5);
    let gate = MockSettlementGate::new(MockVerifier::new(), MockCanonicalStateOracle::always_fresh());
    let thresholds = FreshnessThresholds::default_base_mainnet();
    let root = sample_root(42);

    // TEE wall-time 120 s ahead of the Drand-derived wall-time — past the
    // ±35 s internal tolerance. A property of the commit anchor alone.
    let base = consistent_anchor(COMMIT_DRAND);
    let tee_ns = base.tee_timestamp + 120 * 1_000_000_000;
    let bad_anchor = TripleAnchor::new(base.block_height, tee_ns, base.drand_round);

    let commitment = committer.commit(root.clone(), [0u8; 32], bad_anchor).unwrap();
    let now = now_at_block(commit_anchor().block_height + 1);

    match gate.verify_and_settle(&commitment, &root, &now, &thresholds).unwrap() {
        SettlementResult::Rejected(v) => {
            assert!(
                v.contains(&FreshnessType::Computational),
                "inconsistent commit anchor must trip Computational: {v:?}"
            );
        }
        SettlementResult::Clear => panic!("inconsistent anchor must not clear"),
    }
}

#[test]
fn disclosed_root_mismatch_errs() {
    let committer = mock_committer(6);
    let gate = MockSettlementGate::new(MockVerifier::new(), MockCanonicalStateOracle::always_fresh());
    let thresholds = FreshnessThresholds::default_base_mainnet();

    // Commit against root(42), but disclose a different root(99) at settlement.
    let committed = sample_root(42);
    let disclosed = sample_root(99);
    assert_ne!(committed.merkle_root(), disclosed.merkle_root());

    let commitment = committer.commit(committed, [0u8; 32], commit_anchor()).unwrap();
    let now = now_at_block(commit_anchor().block_height + 1);

    let err = gate.verify_and_settle(&commitment, &disclosed, &now, &thresholds).unwrap_err();
    assert_eq!(err, PocError::RootMismatch);
}

#[test]
fn unknown_model_rejected() {
    let committer = mock_committer(7);
    // Strict on model (unknown weights → Err), fresh on input.
    let oracle = MockCanonicalStateOracle::strict().with_default_input(Some(0));
    let gate = MockSettlementGate::new(MockVerifier::new(), oracle);
    let thresholds = FreshnessThresholds::default_base_mainnet();
    let root = sample_root(42);

    let commitment = committer.commit(root.clone(), [0u8; 32], commit_anchor()).unwrap();
    let now = now_at_block(commit_anchor().block_height + 1);

    match gate.verify_and_settle(&commitment, &root, &now, &thresholds).unwrap() {
        SettlementResult::Rejected(v) => {
            assert!(
                v.contains(&FreshnessType::Model),
                "unregistered model (oracle Err) must be treated as stale: {v:?}"
            );
            assert!(!v.contains(&FreshnessType::Input), "input default is fresh: {v:?}");
        }
        SettlementResult::Clear => panic!("unknown model must not clear"),
    }
}
