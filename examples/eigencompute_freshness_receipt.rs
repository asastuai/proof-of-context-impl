//! # eigencompute_freshness_receipt
//!
//! End-to-end demo of `proof-of-context` as the freshness layer above an
//! `EigenCompute` / `EigenAI`-style verifiable-execution primitive.
//!
//! ## Why this example exists
//!
//! `EigenVerify` answers *"was the computation deterministic?"* through three
//! modes (objective re-execution, intersubjective majority, AI-adjudicated).
//! `proof-of-context` answers a different question: *"is the result still
//! economically valid to settle on?"* — by binding every commitment to a
//! triple-anchored freshness window. A bit-identical re-execution of a
//! stale price-feed inference returns the same number, yet settling on it
//! is economically wrong. That gap is what this example demonstrates.
//!
//! ## What it shows
//!
//! 1. The **honest path** — fresh commitment clears the settlement gate.
//! 2. The **stale path** — same receipt that previously cleared, attempted
//!    after the freshness window, is rejected. Re-execution still agrees.
//! 3. The **four cheating modalities** named in `Proof of Context applied
//!    to Verifiable Inference` (v0.1) — each caught by a distinct field of
//!    the receipt format.
//!    - `M1` model substitution
//!    - `M2` request mutation
//!    - `M3` billing inflation
//!    - `M4` capacity falsification
//!
//! ## Flow at a glance
//!
//! ```text
//!  agent ──request──> worker ─inference→ output
//!                       │
//!                       └─ ContextCommitter ──┐
//!                                              ↓
//!                       FreshnessCommitment { context_root, anchor, output_hash, sig, attestation }
//!                                              │
//!                       ┌──────────────────────┴──────────────────────┐
//!                       │                                              │
//!                  honest verifier                              settlement gate
//!                  (re-executes against committed root)         (triple-anchor freshness check)
//! ```
//!
//! Run with:
//! ```bash
//! cargo run --example eigencompute_freshness_receipt
//! ```

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
};

// =============================================================================
// Mock EigenAI-style model
// =============================================================================

/// A deterministic mock of the kind of model an `EigenAI` endpoint would
/// expose. Same `(weights_hash, request)` pair always yields the same output
/// bytes — that is the property `EigenVerify-Objective` would verify by
/// re-execution. proof-of-context binds *which* `weights_hash` and *when*
/// the output was committed.
struct MockEigenAIModel {
    weights_hash: Hash32,
    tokenizer_hash: Hash32,
    runtime_version: Hash32,
}

impl MockEigenAIModel {
    fn canonical() -> Self {
        Self {
            weights_hash: hash_label("eigenai/canonical-weights@v1"),
            tokenizer_hash: hash_label("eigenai/canonical-tokenizer@v1"),
            runtime_version: hash_label("cuda-12.4 + flash-attn-2.6.3"),
        }
    }

    /// A second model that the worker could secretly swap in. Smaller,
    /// cheaper, and produces different output bytes for the same prompt.
    fn shadow_substitute() -> Self {
        Self {
            weights_hash: hash_label("eigenai/shadow-cheaper-weights@v0"),
            tokenizer_hash: hash_label("eigenai/canonical-tokenizer@v1"),
            runtime_version: hash_label("cuda-12.4 + flash-attn-2.6.3"),
        }
    }

    /// Run the inference. Returned bytes are a SHA-256 of
    /// `(weights_hash || prompt_bytes)` so different weights or prompts
    /// always produce different output bytes.
    fn run(&self, prompt_hash: &Hash32) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"mock-eigenai-output-v1");
        h.update(self.weights_hash);
        h.update(prompt_hash);
        h.finalize().to_vec()
    }
}

// =============================================================================
// Agent request + receipt construction
// =============================================================================

/// What an agent sends to the worker.
struct AgentRequest {
    system_prompt: &'static str,
    /// The agent commits to a set of input-world sources (oracle feeds,
    /// RAG corpus version, tool bindings) by their root hash. A worker
    /// that mutates these silently is what `M2 request-mutation` detects.
    input_manifest_root: Hash32,
}

impl AgentRequest {
    fn pyth_btc_query() -> Self {
        Self {
            system_prompt: "Quote the BTC/USD mid from the supplied Pyth feed at the indicated slot.",
            input_manifest_root: hash_label("pyth:BTC/USD@base-mainnet@slot-281520119"),
        }
    }

    fn prompt_hash(&self) -> Hash32 {
        hash_label(self.system_prompt)
    }
}

/// Build the execution-context root the worker commits to. Every field
/// either affects determinism or is an attack-surface vector documented
/// in the literature.
fn build_root(model: &MockEigenAIModel, req: &AgentRequest) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: model.weights_hash,
        tokenizer_hash: model.tokenizer_hash,
        system_prompt_hash: req.prompt_hash(),
        sampling_params: SamplingParams {
            temperature: 0.0,
            top_k: 1,
            top_p: 1.0,
            seed: 7,
        },
        runtime_version: model.runtime_version,
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 64,
            stop_sequences_root: hash_label("stop:[]"),
            penalty_params_root: hash_label("penalties:default"),
        },
        input_manifest_root: req.input_manifest_root,
        kv_cache_root: None,
    }
}

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

fn make_committer(seed: u64, identity: &str) -> MockCommitter {
    let mut rng = StdRng::seed_from_u64(seed);
    let signing_key = SigningKey::generate(&mut rng);
    MockCommitter::new(signing_key, identity)
}

// =============================================================================
// Verifier helper — what an honest re-executor does
// =============================================================================

/// Re-execute the inference against the receipt's committed context root and
/// compare the recomputed output hash with the receipt. This is the EigenVerify
/// -Objective layer: bit-identical determinism check.
fn reexecute_and_compare(
    canonical_model: &MockEigenAIModel,
    request: &AgentRequest,
    receipt: &FreshnessCommitment,
) -> bool {
    let truth_output = canonical_model.run(&request.prompt_hash());
    let truth_output_hash = hash_output(&truth_output);

    // Bind the receipt to the canonical context root — if the worker
    // committed against a different root, the comparison still surfaces it
    // through the receipt's `context_root` field.
    let canonical_root = build_root(canonical_model, request).merkle_root();
    let context_root_matches = receipt.context_root == canonical_root;
    let output_hash_matches = receipt.output_hash == truth_output_hash;

    context_root_matches && output_hash_matches
}

// =============================================================================
// Demo scenarios
// =============================================================================

fn main() {
    println!("=== eigencompute_freshness_receipt — demo ===\n");
    println!("Stack analog under test:");
    println!("  EigenCompute   — runs the worker container");
    println!("  EigenAI        — deterministic-inference primitive");
    println!("  EigenVerify-Obj — re-execution determinism check");
    println!("  proof-of-context — freshness gate above the determinism check\n");

    let thresholds = FreshnessThresholds::default_base_mainnet();
    let canonical = MockEigenAIModel::canonical();
    let request = AgentRequest::pyth_btc_query();
    let committer = make_committer(0x100, "eigencompute-worker");
    let verifier = MockVerifier::new();
    let gate = MockSettlementGate::new(verifier);

    let commit_anchor = TripleAnchor::new(281_520_119, 1_745_900_000_000_000_000, 60_000);

    // -------------------------------------------------------------------------
    // 0. Honest path
    // -------------------------------------------------------------------------
    println!("--- 0. honest path ---");
    let honest_root = build_root(&canonical, &request);
    let honest_output = canonical.run(&request.prompt_hash());
    let honest_output_hash = hash_output(&honest_output);
    let honest_receipt = committer
        .commit(honest_root.clone(), honest_output_hash, commit_anchor)
        .expect("commit must succeed");

    let now_fresh = TripleAnchor::new(281_520_120, 1_745_900_002_000_000_000, 60_000);
    let result = gate
        .verify_and_settle(&honest_receipt, &now_fresh, &thresholds)
        .expect("verify_and_settle must not error on a valid receipt");
    println!("  settlement result: {:?}", result);
    assert_eq!(result, SettlementResult::Clear);
    let reexec_ok = reexecute_and_compare(&canonical, &request, &honest_receipt);
    println!("  reexecution agrees: {}", reexec_ok);
    println!("  → fresh + deterministic → payment clears\n");

    // -------------------------------------------------------------------------
    // 1. Stale path: re-execution still agrees, settlement rejected anyway
    // -------------------------------------------------------------------------
    println!("--- 1. stale path (re-execution agrees, anchor expired) ---");
    let now_stale = TripleAnchor::new(
        commit_anchor.block_height + thresholds.max_fs_blocks + 200,
        commit_anchor.tee_timestamp + 600_000_000_000,
        commit_anchor.drand_round + 20,
    );
    let result = gate
        .verify_and_settle(&honest_receipt, &now_stale, &thresholds)
        .expect("verify_and_settle must succeed even when rejecting");
    println!("  settlement result: {:?}", result);
    let reexec_ok = reexecute_and_compare(&canonical, &request, &honest_receipt);
    println!("  reexecution agrees: {}", reexec_ok);
    match result {
        SettlementResult::Rejected(violations) => {
            assert!(violations.contains(&FreshnessType::Settlement));
            println!("  → this is the gap above EigenVerify-Objective.");
            println!("    determinism alone cannot reject this; freshness binding does.\n");
        }
        SettlementResult::Clear => panic!("stale receipt must not clear"),
    }

    // -------------------------------------------------------------------------
    // 2. M1 — model substitution
    // -------------------------------------------------------------------------
    println!("--- 2. M1 model substitution ---");
    println!("  worker claims canonical weights but actually serves shadow model.");
    let shadow = MockEigenAIModel::shadow_substitute();
    let cheat_output = shadow.run(&request.prompt_hash());
    let cheat_output_hash = hash_output(&cheat_output);
    // Worker signs with the *canonical* root because the agent will only
    // pay against that root, then ships the shadow-model output.
    let m1_receipt = committer
        .commit(honest_root.clone(), cheat_output_hash, commit_anchor)
        .expect("commit must succeed");

    let signature_verifies = gate
        .verify_and_settle(&m1_receipt, &now_fresh, &thresholds)
        .expect("freshness check is independent of cheating");
    println!("  signature + freshness: {:?}", signature_verifies);
    println!("  (settlement gate alone cannot tell — it does not re-execute)");
    let reexec_ok = reexecute_and_compare(&canonical, &request, &m1_receipt);
    println!("  reexecution agrees: {}", reexec_ok);
    assert!(!reexec_ok, "M1 must be caught by re-execution");
    println!("  → M1 caught: output_hash on receipt does not match canonical re-execution.\n");

    // -------------------------------------------------------------------------
    // 3. M2 — request mutation
    // -------------------------------------------------------------------------
    println!("--- 3. M2 request mutation ---");
    println!("  worker silently swaps the input manifest (e.g. older oracle slot).");
    let mutated_request = AgentRequest {
        system_prompt: request.system_prompt,
        input_manifest_root: hash_label("pyth:BTC/USD@base-mainnet@slot-OLDER"),
    };
    let mutated_root = build_root(&canonical, &mutated_request);
    let mutated_output = canonical.run(&mutated_request.prompt_hash());
    let mutated_output_hash = hash_output(&mutated_output);
    let m2_receipt = committer
        .commit(mutated_root, mutated_output_hash, commit_anchor)
        .expect("commit must succeed");

    // The agent presents its *original* request to the verifier. The
    // committed `context_root` will not match the canonical root that
    // would be derived from the original request.
    let reexec_ok = reexecute_and_compare(&canonical, &request, &m2_receipt);
    println!("  reexecution against original request: {}", reexec_ok);
    assert!(
        !reexec_ok,
        "M2 must be caught by ExecutionContextRoot mismatch"
    );
    println!("  → M2 caught: receipt's context_root binds the mutated input_manifest_root.\n");

    // -------------------------------------------------------------------------
    // 4. M3 — billing inflation
    // -------------------------------------------------------------------------
    println!("--- 4. M3 billing inflation ---");
    println!("  worker ships honest output but invoices for a larger output blob.");
    // The worker generates the honest output but issues an invoice that
    // claims it produced a much larger blob (inflated billable units).
    // Whatever output_hash they put on the receipt MUST match either the
    // shipped bytes (honest) or the inflated bytes (caught by hashing).
    let inflated_blob: Vec<u8> = (0..4096).map(|i| (i % 256) as u8).collect();
    let inflated_output_hash = hash_output(&inflated_blob);
    let m3_receipt = committer
        .commit(honest_root.clone(), inflated_output_hash, commit_anchor)
        .expect("commit must succeed");

    // The agent receives the honest output bytes (small) and recomputes
    // the hash, comparing against the receipt.
    let shipped_output_hash = hash_output(&honest_output);
    let inflated_matches_shipped = m3_receipt.output_hash == shipped_output_hash;
    println!(
        "  receipt output_hash matches shipped bytes: {}",
        inflated_matches_shipped
    );
    assert!(!inflated_matches_shipped, "M3 must be caught by hash binding");
    println!("  → M3 caught: output_hash binds to the bytes the agent receives.");
    println!("    inflated invoice cannot be honored — receipt would have to commit");
    println!("    against the inflated bytes, which the agent never received.\n");

    // -------------------------------------------------------------------------
    // 5. M4 — capacity falsification
    // -------------------------------------------------------------------------
    println!("--- 5. M4 capacity falsification ---");
    println!("  worker claims H100-confidential-compute attestation but produces");
    println!("  a software-only payload (no real hardware trust root).");

    // Build a receipt by hand so we can inject a misrepresented attestation
    // chain. Sign over the canonical digest with the same in-memory key as
    // the honest mock committer would, but stamp the chain as NvidiaH100.
    let m4_receipt = forge_capacity_falsification(
        &committer,
        honest_root.clone(),
        honest_output_hash,
        commit_anchor,
    );

    let result = gate.verify_and_settle(&m4_receipt, &now_fresh, &thresholds);
    println!("  settlement result: {:?}", result);
    match result {
        Err(proof_of_context::PocError::InvalidAttestation) => {
            println!("  → M4 caught: production verifier rejects the chain because");
            println!("    the payload does not parse as a valid NvidiaH100 attestation.");
            println!("    in this mock, MockVerifier accepts only MockSoftware vendor.\n");
        }
        other => panic!("M4 must reject InvalidAttestation, got {:?}", other),
    }

    // -------------------------------------------------------------------------
    // Closing summary
    // -------------------------------------------------------------------------
    println!("=== summary ===");
    println!("EigenVerify-Objective       — was the computation deterministic?");
    println!("                              answered by re-execution + signature.");
    println!("proof-of-context (this crate) — is the result still economically");
    println!("                              valid to settle on?");
    println!("                              answered by the triple-anchor freshness gate.");
    println!("EigenVerify-Intersubjective — token-fork backstop. invoked only");
    println!("                              when freshness passes but result disputed.");
    println!("EigenVerify-AI-adjudicated  — dispute layer. consumes the four");
    println!("                              cheating modalities as structured evidence.");
}

/// Build a receipt that claims `NvidiaH100` attestation but carries the
/// software-only payload the mock committer produces. This is the shape
/// of `M4 capacity-falsification`: a worker who lies about the hardware
/// class providing the attestation.
fn forge_capacity_falsification(
    committer: &MockCommitter,
    root: ExecutionContextRoot,
    output_hash: Hash32,
    anchor: TripleAnchor,
) -> FreshnessCommitment {
    let mut honest = committer
        .commit(root, output_hash, anchor)
        .expect("commit must succeed");
    honest.attestation_chain = AttestationChain {
        payload: b"mock-software-attestation".to_vec(),
        vendor: AttestationVendor::NvidiaH100,
    };
    honest
}
