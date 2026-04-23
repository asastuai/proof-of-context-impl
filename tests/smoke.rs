//! Smoke tests — verify the crate compiles, basic type construction works,
//! and the real primitives (Merkle root, anchor divergence) produce
//! sensible outputs. Extended integration tests for signature +
//! settlement live in tests/integration.rs (Phase 2 onwards).

use proof_of_context::{
    anchor::TripleAnchor,
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::{FreshnessThresholds, FreshnessType},
};

#[test]
fn thresholds_default_is_base_mainnet() {
    let thresh = FreshnessThresholds::default();
    assert_eq!(thresh.block_skew, 2);
    assert_eq!(thresh.tee_skew_secs, 5);
    assert_eq!(thresh.drand_skew, 1);
}

#[test]
fn thresholds_permissive_is_wider() {
    let strict = FreshnessThresholds::default_base_mainnet();
    let permissive = FreshnessThresholds::permissive_testnet();
    assert!(permissive.block_skew > strict.block_skew);
    assert!(permissive.max_fc_blocks > strict.max_fc_blocks);
}

#[test]
fn triple_anchor_construction() {
    let anchor = TripleAnchor::new(100, 1_700_000_000_000_000_000, 50_000);
    assert_eq!(anchor.block_height, 100);
    assert_eq!(anchor.drand_round, 50_000);
}

fn sample_root() -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: [0u8; 32],
        tokenizer_hash: [0u8; 32],
        system_prompt_hash: [0u8; 32],
        sampling_params: SamplingParams {
            temperature: 0.7,
            top_k: 50,
            top_p: 0.9,
            seed: 42,
        },
        runtime_version: [0u8; 32],
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 256,
            stop_sequences_root: [0u8; 32],
            penalty_params_root: [0u8; 32],
        },
        input_manifest_root: [0u8; 32],
        kv_cache_root: None,
    }
}

#[test]
fn execution_context_root_can_be_built() {
    let root = sample_root();
    assert!(matches!(root.precision_mode, PrecisionMode::Bf16));
}

#[test]
fn merkle_root_is_deterministic() {
    let a = sample_root().merkle_root();
    let b = sample_root().merkle_root();
    assert_eq!(a, b, "same root input must produce same hash");
    assert_ne!(a, [0u8; 32], "hash output must not be all-zeros");
}

#[test]
fn merkle_root_changes_with_fields() {
    let a = sample_root().merkle_root();

    let mut perturbed = sample_root();
    perturbed.sampling_params.seed = 43;
    let b = perturbed.merkle_root();
    assert_ne!(a, b, "changing sampling seed must change merkle root");

    let mut perturbed_kv = sample_root();
    perturbed_kv.kv_cache_root = Some([1u8; 32]);
    let c = perturbed_kv.merkle_root();
    assert_ne!(a, c, "adding a KV-cache root must change merkle root");
}

#[test]
fn merkle_root_distinguishes_attention_impls() {
    let mut a = sample_root();
    a.attention_impl_id = AttentionImpl::FlashAttention2;
    let mut b = sample_root();
    b.attention_impl_id = AttentionImpl::Sdpa;
    assert_ne!(a.merkle_root(), b.merkle_root(),
        "attention-impl is a TOPLOC-attributed attack vector and MUST be in the root");
}

#[test]
fn merkle_root_distinguishes_precision_modes() {
    let mut a = sample_root();
    a.precision_mode = PrecisionMode::Bf16;
    let mut b = sample_root();
    b.precision_mode = PrecisionMode::Fp32;
    assert_ne!(a.merkle_root(), b.merkle_root(),
        "precision mode is a TOPLOC-attributed attack vector and MUST be in the root");
}

#[test]
fn freshness_type_variants() {
    let _ = FreshnessType::Computational;
    let _ = FreshnessType::Model;
    let _ = FreshnessType::Input;
    let _ = FreshnessType::Settlement;
}

#[test]
fn anchor_divergence_under_thresholds() {
    let a = TripleAnchor::new(100, 1_700_000_000_000_000_000, 50_000);
    let b = TripleAnchor::new(101, 1_700_000_000_200_000_000, 50_000);
    let thresholds = FreshnessThresholds::default_base_mainnet();
    // 1-block delta, 0.2s TEE delta, same Drand round — inside all bounds.
    assert!(!a.diverges_beyond(&b, &thresholds));
}

#[test]
fn anchor_divergence_exceeds_block_skew() {
    let a = TripleAnchor::new(100, 0, 50_000);
    let b = TripleAnchor::new(110, 0, 50_000); // 10 blocks apart
    let thresholds = FreshnessThresholds::default_base_mainnet();
    assert!(a.diverges_beyond(&b, &thresholds));
}

#[test]
fn anchor_divergence_exceeds_drand_skew() {
    let a = TripleAnchor::new(100, 0, 50_000);
    let b = TripleAnchor::new(100, 0, 50_003); // 3 rounds apart
    let thresholds = FreshnessThresholds::default_base_mainnet();
    assert!(a.diverges_beyond(&b, &thresholds));
}

#[test]
fn anchor_drand_wall_time_matches_schedule() {
    // Round 0 = genesis.
    let a = TripleAnchor::new(0, 0, 0);
    assert_eq!(a.drand_wall_time_secs(), proof_of_context::anchor::DRAND_GENESIS_UNIX);

    // Round 10 = genesis + 300s.
    let b = TripleAnchor::new(0, 0, 10);
    assert_eq!(
        b.drand_wall_time_secs(),
        proof_of_context::anchor::DRAND_GENESIS_UNIX + 300
    );
}
