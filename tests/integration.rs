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
    anchor::TripleAnchor,
    commitment::{CommitmentVerifier, ContextCommitter},
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::{FreshnessThresholds, FreshnessType},
    mock::{MockCommitter, MockSettlementGate, MockVerifier},
    settle::{SettlementGate, SettlementResult},
};

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
    let gate = MockSettlementGate::new(verifier);

    let root = sample_root(42);
    let output_hash = [0x22; 32];
    let commit_anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);

    let commitment = committer.commit(root, output_hash, commit_anchor).unwrap();

    // "Now" is 1 block later — well within all thresholds.
    let now = TripleAnchor::new(1_001, 1_700_000_002_000_000_000, 60_000);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let result = gate.verify_and_settle(&commitment, &now, &thresholds).unwrap();
    assert_eq!(result, SettlementResult::Clear);
}

#[test]
fn end_to_end_stale_block_height_is_rejected() {
    let committer = mock_committer(2);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier);

    let root = sample_root(42);
    let commit_anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);

    let commitment = committer.commit(root, [0u8; 32], commit_anchor).unwrap();

    // Jump forward 100 blocks (well beyond max_fs_blocks = 300 at this
    // scale? No — 300 is the max, so 100 alone is fine. Use 500 to
    // trip settlement-window).
    let now = TripleAnchor::new(1_500, 1_700_000_000_000_000_000, 60_000);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let result = gate.verify_and_settle(&commitment, &now, &thresholds).unwrap();
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
fn end_to_end_drand_skew_triggers_computational_freshness() {
    let committer = mock_committer(3);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier);

    let root = sample_root(42);
    let commit_anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);

    let commitment = committer.commit(root, [0u8; 32], commit_anchor).unwrap();

    // "Now" is close on block (inside max_fs) but Drand round has
    // advanced 5 rounds past the commit — beyond the ±1 skew tolerance.
    let now = TripleAnchor::new(1_001, 1_700_000_002_000_000_000, 60_005);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let result = gate.verify_and_settle(&commitment, &now, &thresholds).unwrap();
    match result {
        SettlementResult::Rejected(violations) => {
            assert!(
                violations.contains(&FreshnessType::Computational),
                "5-round Drand divergence MUST trip computational-freshness"
            );
        }
        SettlementResult::Clear => panic!("expected rejection but got Clear"),
    }
}

#[test]
fn tampered_signature_fails_verification() {
    let committer = mock_committer(4);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier);

    let root = sample_root(42);
    let commit_anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);
    let mut commitment = committer.commit(root, [0u8; 32], commit_anchor).unwrap();

    // Flip a byte of the signature.
    commitment.signature[0] ^= 0xFF;

    let now = TripleAnchor::new(1_001, 1_700_000_002_000_000_000, 60_000);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let err = gate.verify_and_settle(&commitment, &now, &thresholds).unwrap_err();
    assert_eq!(err, proof_of_context::PocError::InvalidSignature);
}

#[test]
fn tampered_output_hash_fails_verification() {
    let committer = mock_committer(5);
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier);

    let root = sample_root(42);
    let commit_anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);
    let mut commitment = committer.commit(root, [0x11; 32], commit_anchor).unwrap();

    // Corrupt the claimed output hash after signing.
    commitment.output_hash = [0x99; 32];

    let now = TripleAnchor::new(1_001, 1_700_000_002_000_000_000, 60_000);
    let thresholds = FreshnessThresholds::default_base_mainnet();

    // The signing digest no longer matches → signature verification fails.
    let err = gate.verify_and_settle(&commitment, &now, &thresholds).unwrap_err();
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
