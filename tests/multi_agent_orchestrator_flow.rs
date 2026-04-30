//! Integration tests for the patterns demonstrated by the
//! `multi_agent_orchestrator` example: agent runtime + sequential
//! orchestration + retry / circuit-breaker + receipt chaining.
//!
//! The tests duplicate just enough of the example's structure to
//! exercise each pattern programmatically. Mechanism walk-throughs
//! live in the example; this file asserts behavior.

use std::cell::Cell;
use std::collections::HashMap;

use ed25519_dalek::SigningKey;
use rand::rngs::StdRng;
use rand::SeedableRng;
use sha2::{Digest, Sha256};

use proof_of_context::{
    anchor::TripleAnchor,
    commitment::{ContextCommitter, FreshnessCommitment},
    context::{
        AttentionImpl, ExecutionContextRoot, Hash32, InferenceConfig, PrecisionMode,
        SamplingParams,
    },
    mock::MockCommitter,
};

// =============================================================================
// Minimal duplicate of the example's surface — kept private to this test
// file. Production code would split this into a library crate.
// =============================================================================

#[derive(Clone)]
struct Task {
    id: u64,
    input: Vec<u8>,
}

#[derive(Debug, Clone)]
enum AgentError {
    Transient(String),
    Permanent(String),
}

trait Agent {
    fn identity(&self) -> &str;
    fn execute(
        &self,
        task: &Task,
        mem: &mut HashMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>, AgentError>;
}

// Oracle agent — fail flakiness times then succeed; or always-permanent.
struct Oracle {
    flakiness: u32,
    count: Cell<u32>,
    permanent: bool,
}
impl Oracle {
    fn flaky(n: u32) -> Self {
        Self { flakiness: n, count: Cell::new(0), permanent: false }
    }
    fn permanent() -> Self {
        Self { flakiness: 0, count: Cell::new(0), permanent: true }
    }
}
impl Agent for Oracle {
    fn identity(&self) -> &str { "oracle" }
    fn execute(
        &self,
        _task: &Task,
        mem: &mut HashMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>, AgentError> {
        if self.permanent {
            return Err(AgentError::Permanent("unreachable".into()));
        }
        let c = self.count.get();
        if c < self.flakiness {
            self.count.set(c + 1);
            return Err(AgentError::Transient(format!("transient {}", c + 1)));
        }
        let price: u64 = 28_500_000_000;
        let bytes = price.to_le_bytes().to_vec();
        mem.insert("price".to_string(), bytes.clone());
        Ok(bytes)
    }
}

// Decision agent — reads price, threshold check, writes signal.
struct Decision { threshold: u64 }
impl Agent for Decision {
    fn identity(&self) -> &str { "decision" }
    fn execute(
        &self,
        _task: &Task,
        mem: &mut HashMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>, AgentError> {
        let p = mem.get("price").ok_or_else(|| AgentError::Permanent("no price".into()))?;
        let mut a = [0u8; 8];
        a.copy_from_slice(p);
        let signal: u8 = if u64::from_le_bytes(a) > self.threshold { 1 } else { 0 };
        mem.insert("signal".to_string(), vec![signal]);
        Ok(vec![signal])
    }
}

// Settlement agent — reads signal, computes settlement payload hash.
struct Settlement;
impl Agent for Settlement {
    fn identity(&self) -> &str { "settlement" }
    fn execute(
        &self,
        task: &Task,
        mem: &mut HashMap<String, Vec<u8>>,
    ) -> Result<Vec<u8>, AgentError> {
        let s = mem.get("signal").ok_or_else(|| AgentError::Permanent("no signal".into()))?;
        let mut h = Sha256::new();
        h.update(b"settlement-v1");
        h.update(task.id.to_le_bytes());
        h.update(s);
        Ok(h.finalize().to_vec())
    }
}

// =============================================================================
// Orchestrator — minimal version for tests
// =============================================================================

struct Orchestrator {
    agents: Vec<Box<dyn Agent>>,
    max_retries: u32,
    committer: MockCommitter,
}

#[derive(Debug)]
enum Outcome {
    Complete {
        commitments: Vec<FreshnessCommitment>,
        chain_hash: Hash32,
    },
    Failed {
        failed_agent: String,
        partial: Vec<FreshnessCommitment>,
    },
}

impl Orchestrator {
    fn run(&self, task: &Task, start: TripleAnchor) -> Outcome {
        let mut mem = HashMap::new();
        let mut commitments = Vec::new();
        let mut anchor = start;

        for agent in &self.agents {
            let id = agent.identity().to_string();
            let mut transient_attempts = 0;
            let result = loop {
                match agent.execute(task, &mut mem) {
                    Ok(out) => break Ok(out),
                    Err(AgentError::Permanent(e)) => break Err(format!("permanent: {}", e)),
                    Err(AgentError::Transient(e)) => {
                        transient_attempts += 1;
                        if transient_attempts >= self.max_retries {
                            break Err(format!("retries exhausted: {}", e));
                        }
                    }
                }
            };
            match result {
                Ok(output) => {
                    let root = build_root(&id, task);
                    let output_hash = hash_output(&output);
                    let c = self.committer.commit(root, output_hash, anchor).unwrap();
                    commitments.push(c);
                    anchor = TripleAnchor::new(
                        anchor.block_height + 1,
                        anchor.tee_timestamp + 2_000_000_000,
                        anchor.drand_round,
                    );
                }
                Err(_) => {
                    return Outcome::Failed { failed_agent: id, partial: commitments };
                }
            }
        }

        let chain_hash = chain_hash(&commitments);
        Outcome::Complete { commitments, chain_hash }
    }
}

// =============================================================================
// Helpers
// =============================================================================

fn build_root(agent: &str, task: &Task) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: hash_label(format!("agent:{}", agent)),
        tokenizer_hash: hash_label("orchestrator/v1"),
        system_prompt_hash: hash_label(format!("task:{}", task.id)),
        sampling_params: SamplingParams {
            temperature: 0.0,
            top_k: 1,
            top_p: 1.0,
            seed: task.id,
        },
        runtime_version: hash_label("rust-orchestrator-v1"),
        attention_impl_id: AttentionImpl::FlashAttention2,
        precision_mode: PrecisionMode::Bf16,
        inference_config: InferenceConfig {
            max_tokens: 0,
            stop_sequences_root: hash_label("none"),
            penalty_params_root: hash_label("none"),
        },
        input_manifest_root: hash_label(format!("input:{:?}", task.input)),
        kv_cache_root: None,
    }
}

fn hash_label(s: impl AsRef<[u8]>) -> Hash32 {
    let mut h = Sha256::new();
    h.update(s);
    h.finalize().into()
}

fn hash_output(b: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(b"agent-output-v1");
    h.update(b);
    h.finalize().into()
}

fn chain_hash(cs: &[FreshnessCommitment]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(b"orchestration-chain-v1");
    for c in cs {
        h.update(c.signing_digest());
    }
    h.finalize().into()
}

fn make_committer(seed: u64) -> MockCommitter {
    let mut rng = StdRng::seed_from_u64(seed);
    let signing_key = SigningKey::generate(&mut rng);
    MockCommitter::new(signing_key, "orchestrator-test")
}

fn start_anchor() -> TripleAnchor {
    TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000)
}

fn pipeline(oracle: Box<dyn Agent>, committer: MockCommitter) -> Orchestrator {
    Orchestrator {
        agents: vec![
            oracle,
            Box::new(Decision { threshold: 20_000_000_000 }),
            Box::new(Settlement),
        ],
        max_retries: 3,
        committer,
    }
}

// =============================================================================
// Tests
// =============================================================================

#[test]
fn honest_path_produces_three_chained_receipts() {
    let p = pipeline(Box::new(Oracle::flaky(0)), make_committer(0x100));
    let task = Task { id: 1, input: b"BTC".to_vec() };

    match p.run(&task, start_anchor()) {
        Outcome::Complete { commitments, .. } => {
            assert_eq!(commitments.len(), 3, "all three agents must commit");
        }
        Outcome::Failed { failed_agent, .. } => {
            panic!("honest path must not fail (failed at {})", failed_agent);
        }
    }
}

#[test]
fn transient_failures_recover_within_max_retries() {
    // Oracle fails twice then succeeds. max_retries = 3, so attempt 3 succeeds.
    let p = pipeline(Box::new(Oracle::flaky(2)), make_committer(0x101));
    let task = Task { id: 2, input: b"BTC".to_vec() };

    match p.run(&task, start_anchor()) {
        Outcome::Complete { commitments, .. } => {
            assert_eq!(commitments.len(), 3);
        }
        Outcome::Failed { failed_agent, .. } => {
            panic!("expected recovery (failed at {})", failed_agent);
        }
    }
}

#[test]
fn permanent_failure_short_circuits_pipeline() {
    let p = pipeline(Box::new(Oracle::permanent()), make_committer(0x102));
    let task = Task { id: 3, input: b"BTC".to_vec() };

    match p.run(&task, start_anchor()) {
        Outcome::Complete { .. } => panic!("permanent failure must not produce a complete receipt"),
        Outcome::Failed { failed_agent, partial } => {
            assert_eq!(failed_agent, "oracle");
            assert_eq!(partial.len(), 0, "no commitments should accumulate before first failure");
        }
    }
}

#[test]
fn chain_hash_is_deterministic_for_fixed_seed() {
    let task = Task { id: 4, input: b"BTC".to_vec() };

    let p1 = pipeline(Box::new(Oracle::flaky(0)), make_committer(0x103));
    let h1 = match p1.run(&task, start_anchor()) {
        Outcome::Complete { chain_hash, .. } => chain_hash,
        _ => panic!("expected complete"),
    };

    let p2 = pipeline(Box::new(Oracle::flaky(0)), make_committer(0x103));
    let h2 = match p2.run(&task, start_anchor()) {
        Outcome::Complete { chain_hash, .. } => chain_hash,
        _ => panic!("expected complete"),
    };

    assert_eq!(h1, h2, "same seed + same task must produce identical chain_hash");
}

#[test]
fn chain_hash_differs_across_distinct_tasks() {
    let p_seed = 0x104;

    let task_a = Task { id: 100, input: b"BTC".to_vec() };
    let p1 = pipeline(Box::new(Oracle::flaky(0)), make_committer(p_seed));
    let h_a = match p1.run(&task_a, start_anchor()) {
        Outcome::Complete { chain_hash, .. } => chain_hash,
        _ => panic!("expected complete"),
    };

    let task_b = Task { id: 200, input: b"BTC".to_vec() };
    let p2 = pipeline(Box::new(Oracle::flaky(0)), make_committer(p_seed));
    let h_b = match p2.run(&task_b, start_anchor()) {
        Outcome::Complete { chain_hash, .. } => chain_hash,
        _ => panic!("expected complete"),
    };

    assert_ne!(h_a, h_b, "different task ids must produce distinct chain hashes");
}

#[test]
fn each_committed_step_has_distinct_context_root() {
    let p = pipeline(Box::new(Oracle::flaky(0)), make_committer(0x105));
    let task = Task { id: 5, input: b"BTC".to_vec() };

    match p.run(&task, start_anchor()) {
        Outcome::Complete { commitments, .. } => {
            let mut seen = std::collections::HashSet::new();
            for c in &commitments {
                assert!(seen.insert(c.context_root), "every step must have a distinct context_root");
            }
        }
        _ => panic!("expected complete"),
    }
}
