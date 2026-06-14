//! Cost measurement for the paper's "Reference Implementation" section (v0.7).
//!
//! Reports throughput of the three hot primitives:
//!   - `ExecutionContextRoot::merkle_root` (one SHA-256 over the canonical preimage)
//!   - `MockCommitter::commit`            (merkle_root + signing digest + Ed25519 sign)
//!   - `MockVerifier::verify`             (Ed25519 verify + attestation check)
//!
//! Run with: `cargo run --release --example measure_costs`
//! The canonical *sizes* are computed by hand from the struct layout
//! (see the paper); this binary only measures wall-clock throughput, so the
//! paper can cite a real per-op cost with a machine + toolchain footnote.

use std::time::Instant;

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;

use proof_of_context::{
    anchor::TripleAnchor,
    commitment::{CommitmentVerifier, ContextCommitter},
    context::{
        AttentionImpl, ExecutionContextRoot, InferenceConfig, PrecisionMode, SamplingParams,
    },
    mock::{MockCommitter, MockVerifier},
};

fn sample_root() -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: [0xAA; 32],
        tokenizer_hash: [0xBB; 32],
        system_prompt_hash: [0xCC; 32],
        sampling_params: SamplingParams { temperature: 0.7, top_k: 50, top_p: 0.9, seed: 42 },
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

fn main() {
    let n: u32 = 200_000;
    let root = sample_root();
    let mut rng = StdRng::seed_from_u64(1);
    let committer = MockCommitter::new(SigningKey::generate(&mut rng), "measure");
    let verifier = MockVerifier::new();
    let anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);

    // merkle_root
    let t = Instant::now();
    let mut acc = 0u8;
    for _ in 0..n {
        acc ^= root.merkle_root()[0];
    }
    let mr = t.elapsed();

    // commit (merkle_root + digest + Ed25519 sign); includes one cheap struct clone
    let t = Instant::now();
    for _ in 0..n {
        let c = committer.commit(root.clone(), [0x22; 32], anchor).unwrap();
        acc ^= c.context_root[0];
    }
    let commit = t.elapsed();

    // verify (Ed25519 verify + attestation check)
    let c = committer.commit(root.clone(), [0x22; 32], anchor).unwrap();
    let t = Instant::now();
    for _ in 0..n {
        verifier.verify(&c).unwrap();
    }
    let verify = t.elapsed();

    println!("iterations = {n}  (sink = {acc})");
    println!("merkle_root  : {:>8.3} us/op  ({:.0} op/s)", us(mr, n), ops(mr, n));
    println!("commit(sign) : {:>8.3} us/op  ({:.0} op/s)", us(commit, n), ops(commit, n));
    println!("verify       : {:>8.3} us/op  ({:.0} op/s)", us(verify, n), ops(verify, n));
}

fn us(d: std::time::Duration, n: u32) -> f64 {
    d.as_secs_f64() * 1e6 / f64::from(n)
}
fn ops(d: std::time::Duration, n: u32) -> f64 {
    f64::from(n) / d.as_secs_f64()
}
