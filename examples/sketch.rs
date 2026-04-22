//! A minimal sketch of how the API is intended to be used.
//!
//! This example does not run useful logic (stubs are `unimplemented!()`).
//! Its purpose is to let a reader see the shape of a real integration
//! in ~30 lines of code before diving into trait definitions.

use proof_of_context::{
    anchor::TripleAnchor,
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    freshness::FreshnessThresholds,
};

fn main() {
    // 1. Protocol-level thresholds (empirically justified defaults from paper §9).
    let thresholds = FreshnessThresholds::default_base_mainnet();
    println!(
        "Thresholds: ±{} blocks, ±{}s TEE, ±{} Drand round",
        thresholds.block_skew, thresholds.tee_skew_secs, thresholds.drand_skew
    );

    // 2. Worker builds the execution-context root after running an inference.
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

    // 3. The triple anchor at commit time — in Phase 3 this is read from
    //    a JSON-RPC client + enclave clock + Drand fetch.
    let anchor = TripleAnchor::new(
        /* block_height */ 45_050_000,
        /* tee_timestamp_ns */ 1_714_000_000_000_000_000,
        /* drand_round */ 6_048_600,
    );

    // 4. In Phase 2+, a concrete `ContextCommitter` implementation would
    //    produce the commitment here. A `SettlementGate` would verify it
    //    at payment time. At scaffold stage, the types are constructible
    //    but the methods panic with "Phase 2: ..." messages — readable
    //    roadmap baked into the code itself.
    println!(
        "Committing root (merkle_root will panic at scaffold stage): attention={:?}, precision={:?}, anchor at block {}",
        root.attention_impl_id, root.precision_mode, anchor.block_height
    );
}
