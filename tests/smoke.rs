//! Smoke tests — verify the crate compiles and the type relationships
//! are sensible. No runtime logic is exercised; stubs return
//! `unimplemented!()` and panic if called.

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

#[test]
fn execution_context_root_can_be_built() {
    let root = ExecutionContextRoot {
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
    };
    // Building succeeds. Calling merkle_root() would panic (unimplemented!).
    // We do not call it here — we only prove the struct is constructible.
    assert!(matches!(root.precision_mode, PrecisionMode::Bf16));
}

#[test]
fn freshness_type_variants() {
    // Simply confirm the four variants exist with the expected names.
    let _ = FreshnessType::Computational;
    let _ = FreshnessType::Model;
    let _ = FreshnessType::Input;
    let _ = FreshnessType::Settlement;
}

#[test]
#[should_panic(expected = "Phase 2")]
fn merkle_root_is_unimplemented_at_scaffold_stage() {
    let root = ExecutionContextRoot {
        weights_hash: [0u8; 32],
        tokenizer_hash: [0u8; 32],
        system_prompt_hash: [0u8; 32],
        sampling_params: SamplingParams {
            temperature: 0.0,
            top_k: 0,
            top_p: 1.0,
            seed: 0,
        },
        runtime_version: [0u8; 32],
        attention_impl_id: AttentionImpl::Sdpa,
        precision_mode: PrecisionMode::Fp32,
        inference_config: InferenceConfig {
            max_tokens: 1,
            stop_sequences_root: [0u8; 32],
            penalty_params_root: [0u8; 32],
        },
        input_manifest_root: [0u8; 32],
        kv_cache_root: None,
    };
    // Expected to panic with the scaffold message.
    let _ = root.merkle_root();
}
