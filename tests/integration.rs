//! End-to-end integration tests for the Phase 2 mock backend.
//!
//! Walks the full flow:
//!   commit → verify signature → settle within horizon → reject stale
//!
//! Uses software-only keys (MockCommitter + MockVerifier) — not
//! economic settlement, but proves the trait surface composes correctly
//! and that the freshness rejection paths fire.

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;

use proof_of_context::{
    anchor::{
        TripleAnchor, BASE_BLOCK_PERIOD_SECS, BASE_MAINNET_GENESIS_UNIX, DRAND_GENESIS_UNIX,
        DRAND_PERIOD_SECS,
    },
    commitment::{CommitmentVerifier, ContextCommitter},
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::{FreshnessThresholds, FreshnessType},
    mock::{MockCanonicalStateOracle, MockCommitter, MockSettlementGate, MockVerifier},
    settle::{SettlementGate, SettlementResult},
};

/// A Drand round whose wall-time (~2025-04-29) sits well after Base genesis,
/// so a Base block height can be derived for it. Used as the commit clock.
const BASE_ROUND: u64 = 5_015_631;

/// Build a **fully** internally-consistent commit anchor from a Drand round:
/// all three clocks (block, TEE, Drand) are derived from the one wall-time,
/// so the gate's `consistent` predicate passes under both the default and
/// `real-anchors` features (the latter also checks the block↔Drand leg).
fn consistent_anchor(drand_round: u64) -> TripleAnchor {
    let wall = DRAND_GENESIS_UNIX + drand_round * DRAND_PERIOD_SECS;
    let block = (wall - BASE_MAINNET_GENESIS_UNIX) / BASE_BLOCK_PERIOD_SECS;
    TripleAnchor::new(block, (wall as u128) * 1_000_000_000, drand_round)
}

/// A settlement-time clock at a given block height. `now` is never checked
/// for internal consistency (only the commit anchor is), so only its block
/// height — which drives `f_s` — is meaningful here.
fn now_at_block(block_height: u64) -> TripleAnchor {
    TripleAnchor::new(block_height, 0, 0)
}

/// Build a deterministic sample context root.  Tests drive seeds into this
/// to produce distinct roots when needed.
fn sample_root(seed: u64) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: [0xAA; 32],
        tokenizer_hash: [0xBB; 32],
        system_prompt_hash: [0xCC; 32],
        sampling_params: SamplingParams {
            temperature: 0.7,
            top_k: 50,
            top_p: 0.9,
            seed,
        },
        runtime_version: [0xDD; 32],
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 256,
            stop_sequences_root: [0xEE; 32],
            penalty_params_root: [0xFF; 32],
        },
        input_manifest_root: [0x11; 32],
        kv_cache_root: None,
    }
}

fn mock_committer(seed: u64) -> MockCommitter {
    let mut rng = StdRng::seed_from_u64(seed);
    let signing_key = SigningKey::generate(&mut rng);
    MockCommitter::new(signing_key, "mock-worker")
}

#[test]
fn end_to_end_fresh_commitment_clears_settlement() {
    let committer = mock_committer(1);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier, MockCanonicalStateOracle::always_fresh());

    let root = sample_root(42);
    let output_hash = [0x22; 32];
    let commit_anchor = consistent_anchor(BASE_ROUND);

    let commitment = committer.commit(root.clone(), output_hash, commit_anchor).unwrap();

    // "Now" is 1 block later — well within all thresholds.
    let now = now_at_block(commit_anchor.block_height + 1);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let result = gate
        .verify_and_settle(&commitment, &root, &now, &thresholds)
        .unwrap();
    assert_eq!(result, SettlementResult::Clear);
}

#[test]
fn end_to_end_stale_block_height_is_rejected() {
    let committer = mock_committer(2);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier, MockCanonicalStateOracle::always_fresh());

    let root = sample_root(42);
    let commit_anchor = consistent_anchor(BASE_ROUND);

    let commitment = committer.commit(root.clone(), [0u8; 32], commit_anchor).unwrap();

    // Jump forward 500 blocks — beyond max_fs_blocks (300) → trips f_s.
    let now = now_at_block(commit_anchor.block_height + 500);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let result = gate
        .verify_and_settle(&commitment, &root, &now, &thresholds)
        .unwrap();
    match result {
        SettlementResult::Rejected(violations) => {
            assert!(
                violations.contains(&FreshnessType::Settlement),
                "500-block gap MUST trip settlement-freshness (max_fs_blocks = 300)"
            );
        }
        SettlementResult::Clear => panic!("expected rejection but got Clear"),
    }
}

#[test]
fn end_to_end_inconsistent_anchor_triggers_computational_freshness() {
    let committer = mock_committer(3);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier, MockCanonicalStateOracle::always_fresh());

    let root = sample_root(42);

    // A tampered/desynced commit anchor: TEE wall-time disagrees with the
    // Drand-derived wall-time by 120 s — far past the ±35 s internal
    // tolerance. `consistent` is now a property of the commit anchor alone
    // (not A-vs-now), so this is what trips Computational.
    let base = consistent_anchor(BASE_ROUND);
    let tee_ns = base.tee_timestamp + 120 * 1_000_000_000;
    let commit_anchor = TripleAnchor::new(base.block_height, tee_ns, base.drand_round);

    let commitment = committer.commit(root.clone(), [0u8; 32], commit_anchor).unwrap();

    // "Now" is a normal, near settlement clock — within max_fs.
    let now = now_at_block(commit_anchor.block_height + 1);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let result = gate
        .verify_and_settle(&commitment, &root, &now, &thresholds)
        .unwrap();
    match result {
        SettlementResult::Rejected(violations) => {
            assert!(
                violations.contains(&FreshnessType::Computational),
                "internally inconsistent commit anchor MUST trip computational-freshness"
            );
        }
        SettlementResult::Clear => panic!("expected rejection but got Clear"),
    }
}

#[test]
fn tampered_signature_fails_verification() {
    let committer = mock_committer(4);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier, MockCanonicalStateOracle::always_fresh());

    let root = sample_root(42);
    let commit_anchor = consistent_anchor(BASE_ROUND);
    let mut commitment = committer.commit(root.clone(), [0u8; 32], commit_anchor).unwrap();

    // Flip a byte of the signature.
    commitment.signature[0] ^= 0xFF;

    let now = now_at_block(commit_anchor.block_height + 1);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let err = gate
        .verify_and_settle(&commitment, &root, &now, &thresholds)
        .unwrap_err();
    assert_eq!(err, proof_of_context::PocError::InvalidSignature);
}

#[test]
fn tampered_output_hash_fails_verification() {
    let committer = mock_committer(5);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier, MockCanonicalStateOracle::always_fresh());

    let root = sample_root(42);
    let commit_anchor = consistent_anchor(BASE_ROUND);
    let mut commitment = committer.commit(root.clone(), [0x11; 32], commit_anchor).unwrap();

    // Corrupt the claimed output hash after signing.
    commitment.output_hash = [0x99; 32];

    let now = now_at_block(commit_anchor.block_height + 1);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    // The signing digest no longer matches → signature verification fails.
    let err = gate
        .verify_and_settle(&commitment, &root, &now, &thresholds)
        .unwrap_err();
    assert_eq!(err, proof_of_context::PocError::InvalidSignature);
}

#[test]
fn different_committers_produce_distinct_public_keys() {
    let a = mock_committer(100).verifying_key().to_bytes();
    let b = mock_committer(101).verifying_key().to_bytes();
    assert_ne!(a, b, "distinct seeds must produce distinct committers");
}

#[test]
fn same_seed_produces_same_committer() {
    let a = mock_committer(200).verifying_key().to_bytes();
    let b = mock_committer(200).verifying_key().to_bytes();
    assert_eq!(a, b, "deterministic seed must produce identical committer");
}

#[test]
fn commitment_roundtrips_through_serde() {
    let committer = mock_committer(7);
    let root = sample_root(42);
    let anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);
    let commitment = committer.commit(root, [0x55; 32], anchor).unwrap();

    // JSON roundtrip — validates that all public types derive serde
    // correctly, including the custom fixed-size byte array handling.
    let json = serde_json::to_string(&commitment).expect("serialize");
    let round: proof_of_context::commitment::FreshnessCommitment =
        serde_json::from_str(&json).expect("deserialize");

    assert_eq!(round.context_root, commitment.context_root);
    assert_eq!(round.anchor, commitment.anchor);
    assert_eq!(round.output_hash, commitment.output_hash);
    assert_eq!(round.signature, commitment.signature);
    assert_eq!(round.public_key, commitment.public_key);

    // Re-verify the deserialized commitment.
    let verifier = MockVerifier::new();
    verifier.verify(&round).expect("deserialized commitment must still verify");
}
