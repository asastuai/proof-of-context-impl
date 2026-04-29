//! Integration tests that mirror the `eigencompute_freshness_receipt` example.
//!
//! Each test exercises one slice of the EigenCloud-shaped flow and asserts
//! that the receipt format catches the corresponding cheating modality (or
//! clears the honest case). The example prints a narrative; these tests
//! verify the same invariants under `cargo test`.

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

use proof_of_context::{
    anchor::TripleAnchor,
    attestation::{AttestationChain, AttestationVendor},
    commitment::{ContextCommitter, FreshnessCommitment},
    context::{
        AttentionImpl, ExecutionContextRoot, Hash32, InferenceConfig, PrecisionMode,
        SamplingParams,
    },
    freshness::{FreshnessThresholds, FreshnessType},
    mock::{MockCommitter, MockSettlementGate, MockVerifier},
    settle::{SettlementGate, SettlementResult},
    PocError,
};

fn hash_label(s: impl AsRef<[u8]>) -> Hash32 {
    let mut h = Sha256::new();
    h.update(s);
    h.finalize().into()
}

fn hash_output(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(b"output-blob-v1");
    h.update(bytes);
    h.finalize().into()
}

fn run_inference(weights_hash: &Hash32, prompt_hash: &Hash32) -> Vec<u8> {
    let mut h = Sha256::new();
    h.update(b"mock-eigenai-output-v1");
    h.update(weights_hash);
    h.update(prompt_hash);
    h.finalize().to_vec()
}

fn build_root(
    weights_hash: Hash32,
    prompt_hash: Hash32,
    input_manifest_root: Hash32,
) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash,
        tokenizer_hash: hash_label("eigenai/canonical-tokenizer@v1"),
        system_prompt_hash: prompt_hash,
        sampling_params: SamplingParams {
            temperature: 0.0,
            top_k: 1,
            top_p: 1.0,
            seed: 7,
        },
        runtime_version: hash_label("cuda-12.4 + flash-attn-2.6.3"),
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 64,
            stop_sequences_root: hash_label("stop:[]"),
            penalty_params_root: hash_label("penalties:default"),
        },
        input_manifest_root,
        kv_cache_root: None,
    }
}

fn make_committer(seed: u64) -> MockCommitter {
    let mut rng = StdRng::seed_from_u64(seed);
    let signing_key = SigningKey::generate(&mut rng);
    MockCommitter::new(signing_key, "eigencompute-worker")
}

const COMMIT_BLOCK: u64 = 281_520_119;
const COMMIT_TEE_NS: u128 = 1_745_900_000_000_000_000;
const COMMIT_DRAND: u64 = 60_000;

fn commit_anchor() -> TripleAnchor {
    TripleAnchor::new(COMMIT_BLOCK, COMMIT_TEE_NS, COMMIT_DRAND)
}

fn fresh_now() -> TripleAnchor {
    TripleAnchor::new(COMMIT_BLOCK + 1, COMMIT_TEE_NS + 2_000_000_000, COMMIT_DRAND)
}

fn canonical_weights() -> Hash32 {
    hash_label("eigenai/canonical-weights@v1")
}

fn shadow_weights() -> Hash32 {
    hash_label("eigenai/shadow-cheaper-weights@v0")
}

fn canonical_prompt() -> Hash32 {
    hash_label("Quote the BTC/USD mid from the supplied Pyth feed at the indicated slot.")
}

fn canonical_input_manifest() -> Hash32 {
    hash_label("pyth:BTC/USD@base-mainnet@slot-281520119")
}

#[test]
fn honest_path_clears() {
    let committer = make_committer(0x100);
    let gate = MockSettlementGate::new(MockVerifier::new());
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let root = build_root(canonical_weights(), canonical_prompt(), canonical_input_manifest());
    let output = run_inference(&canonical_weights(), &canonical_prompt());
    let receipt = committer
        .commit(root, hash_output(&output), commit_anchor())
        .unwrap();

    let result = gate
        .verify_and_settle(&receipt, &fresh_now(), &thresholds)
        .unwrap();
    assert_eq!(result, SettlementResult::Clear);
}

#[test]
fn stale_path_rejected_even_when_reexecution_agrees() {
    let committer = make_committer(0x101);
    let gate = MockSettlementGate::new(MockVerifier::new());
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let root = build_root(canonical_weights(), canonical_prompt(), canonical_input_manifest());
    let output = run_inference(&canonical_weights(), &canonical_prompt());
    let receipt = committer
        .commit(root, hash_output(&output), commit_anchor())
        .unwrap();

    let stale = TripleAnchor::new(
        COMMIT_BLOCK + thresholds.max_fs_blocks + 200,
        COMMIT_TEE_NS + 600_000_000_000,
        COMMIT_DRAND + 20,
    );
    let result = gate
        .verify_and_settle(&receipt, &stale, &thresholds)
        .unwrap();

    match result {
        SettlementResult::Rejected(violations) => {
            assert!(violations.contains(&FreshnessType::Settlement));
        }
        SettlementResult::Clear => panic!("stale receipt must not clear"),
    }
}

#[test]
fn m1_model_substitution_detected_by_reexecution() {
    let committer = make_committer(0x102);
    let claimed_root = build_root(
        canonical_weights(),
        canonical_prompt(),
        canonical_input_manifest(),
    );
    let cheat_output = run_inference(&shadow_weights(), &canonical_prompt());
    let receipt = committer
        .commit(claimed_root.clone(), hash_output(&cheat_output), commit_anchor())
        .unwrap();

    let truth_output = run_inference(&canonical_weights(), &canonical_prompt());
    let truth_output_hash = hash_output(&truth_output);
    assert_ne!(receipt.output_hash, truth_output_hash);
    assert_eq!(receipt.context_root, claimed_root.merkle_root());
}

#[test]
fn m2_request_mutation_detected_by_context_root_mismatch() {
    let committer = make_committer(0x103);
    let mutated_manifest = hash_label("pyth:BTC/USD@base-mainnet@slot-OLDER");
    let mutated_root = build_root(canonical_weights(), canonical_prompt(), mutated_manifest);
    let mutated_output = run_inference(&canonical_weights(), &canonical_prompt());
    let receipt = committer
        .commit(mutated_root, hash_output(&mutated_output), commit_anchor())
        .unwrap();

    let canonical_root = build_root(
        canonical_weights(),
        canonical_prompt(),
        canonical_input_manifest(),
    );
    assert_ne!(receipt.context_root, canonical_root.merkle_root());
}

#[test]
fn m3_billing_inflation_detected_by_output_hash_binding() {
    let committer = make_committer(0x104);
    let root = build_root(canonical_weights(), canonical_prompt(), canonical_input_manifest());
    let inflated_blob: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let receipt = committer
        .commit(root, hash_output(&inflated_blob), commit_anchor())
        .unwrap();

    let shipped_output = run_inference(&canonical_weights(), &canonical_prompt());
    assert_ne!(receipt.output_hash, hash_output(&shipped_output));
}

#[test]
fn m4_capacity_falsification_rejected_by_attestation_verifier() {
    let committer = make_committer(0x105);
    let gate = MockSettlementGate::new(MockVerifier::new());
    let thresholds = FreshnessThresholds::default_base_mainnet();

    let root = build_root(canonical_weights(), canonical_prompt(), canonical_input_manifest());
    let output = run_inference(&canonical_weights(), &canonical_prompt());
    let mut receipt: FreshnessCommitment = committer
        .commit(root, hash_output(&output), commit_anchor())
        .unwrap();

    receipt.attestation_chain = AttestationChain {
        payload: b"mock-software-attestation".to_vec(),
        vendor: AttestationVendor::NvidiaH100,
    };

    let err = gate
        .verify_and_settle(&receipt, &fresh_now(), &thresholds)
        .unwrap_err();
    assert_eq!(err, PocError::InvalidAttestation);
}
