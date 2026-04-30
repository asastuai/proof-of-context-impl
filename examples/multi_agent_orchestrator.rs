//! # multi_agent_orchestrator
//!
//! Standalone demo of a 3-agent orchestration pipeline with retry,
//! circuit-breaker, shared memory, observability events, and chained
//! Proof of Context receipts.
//!
//! ## What this shows
//!
//! - **Agent runtime:** an [`Agent`] trait that any concrete agent implements.
//! - **Orchestration:** sequential pipeline coordinated by [`Orchestrator`].
//! - **Tool use:** three concrete agents covering distinct patterns
//!   (`OraclePriceAgent` = I/O, `DecisionAgent` = pure compute,
//!   `SettlementAgent` = state mutation).
//! - **Memory:** [`MemoryStore`] passed between agents for shared state.
//! - **Reliability:** retry with exponential backoff and circuit-breaker
//!   semantics on permanent failure.
//! - **Observability:** pluggable [`Observer`] trait with a default
//!   `ConsoleObserver` that prints structured events.
//! - **Verifiability:** each agent execution produces a
//!   [`FreshnessCommitment`] from the proof-of-context library; the
//!   orchestrator chains them into an [`OrchestrationReceipt`].
//!
//! Run with:
//! ```bash
//! cargo run --example multi_agent_orchestrator
//! ```

use std::collections::HashMap;
use std::thread;
use std::time::Duration;

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
// Core types
// =============================================================================

/// A unit of work given to the orchestrator.
#[derive(Debug, Clone)]
pub struct AgentTask {
    pub task_id: u64,
    pub input: Vec<u8>,
}

/// What an agent returns on a successful execution.
#[derive(Debug, Clone)]
pub struct AgentResult {
    pub task_id: u64,
    pub output: Vec<u8>,
    pub emitted_at: TripleAnchor,
}

/// Typed failure modes. The orchestrator branches on these:
/// `Transient` is retried; `Permanent` short-circuits the pipeline.
#[derive(Debug, Clone)]
pub enum AgentError {
    Transient(String),
    Permanent(String),
}

/// Uniform agent interface. Any concrete agent implements this and is
/// composable into an [`Orchestrator`].
pub trait Agent {
    fn identity(&self) -> &str;
    fn execute(
        &self,
        task: &AgentTask,
        mem: &mut MemoryStore,
        anchor: TripleAnchor,
    ) -> Result<AgentResult, AgentError>;
}

/// Shared key-value memory passed across agents in a pipeline.
#[derive(Default)]
pub struct MemoryStore {
    kv: HashMap<String, Vec<u8>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn get(&self, key: &str) -> Option<&Vec<u8>> {
        self.kv.get(key)
    }
    pub fn put(&mut self, key: impl Into<String>, value: Vec<u8>) {
        self.kv.insert(key.into(), value);
    }
}

// =============================================================================
// Observability
// =============================================================================

/// Structured events emitted by the orchestrator. Decoupled from any
/// concrete sink so production deployments can route to logs / traces.
#[derive(Debug, Clone)]
pub enum Event {
    AgentStarted { agent: String, attempt: u32 },
    AgentRetrying { agent: String, attempt: u32, error: String },
    AgentFailed { agent: String, error: String },
    AgentSucceeded { agent: String },
    OrchestratorComplete { receipts: usize },
}

pub trait Observer {
    fn on_event(&mut self, event: &Event);
}

/// Default observer that prints to stdout. Production observers
/// would forward to OpenTelemetry / structured-log pipelines.
#[derive(Default)]
pub struct ConsoleObserver;

impl Observer for ConsoleObserver {
    fn on_event(&mut self, event: &Event) {
        match event {
            Event::AgentStarted { agent, attempt } => {
                println!("  [event] agent={} attempt={} → started", agent, attempt);
            }
            Event::AgentRetrying { agent, attempt, error } => {
                println!(
                    "  [event] agent={} attempt={} → retrying ({})",
                    agent, attempt, error
                );
            }
            Event::AgentFailed { agent, error } => {
                println!("  [event] agent={} → FAILED ({})", agent, error);
            }
            Event::AgentSucceeded { agent } => {
                println!("  [event] agent={} → succeeded", agent);
            }
            Event::OrchestratorComplete { receipts } => {
                println!(
                    "  [event] orchestrator complete, {} receipt(s) chained",
                    receipts
                );
            }
        }
    }
}

/// Silent observer — useful for tests where event prints would be noise.
#[derive(Default)]
pub struct NullObserver;
impl Observer for NullObserver {
    fn on_event(&mut self, _event: &Event) {}
}

// =============================================================================
// Concrete agents
// =============================================================================

/// I/O agent. Mocks an external price-feed fetch. Configurable to fail
/// `flakiness_seed` times before succeeding (exercises retry path) or
/// to fail permanently (exercises circuit breaker).
pub struct OraclePriceAgent {
    flakiness_seed: u32,
    failure_count: std::cell::Cell<u32>,
    permanent: bool,
}

impl OraclePriceAgent {
    /// Fails `flakiness_seed` times with `Transient`, then succeeds.
    pub fn new(flakiness_seed: u32) -> Self {
        Self {
            flakiness_seed,
            failure_count: std::cell::Cell::new(0),
            permanent: false,
        }
    }
    /// Always returns `Permanent` failure.
    pub fn permanent() -> Self {
        Self {
            flakiness_seed: 0,
            failure_count: std::cell::Cell::new(0),
            permanent: true,
        }
    }
}

impl Agent for OraclePriceAgent {
    fn identity(&self) -> &str {
        "oracle-price"
    }

    fn execute(
        &self,
        task: &AgentTask,
        mem: &mut MemoryStore,
        anchor: TripleAnchor,
    ) -> Result<AgentResult, AgentError> {
        if self.permanent {
            return Err(AgentError::Permanent("oracle endpoint unreachable".into()));
        }
        let count = self.failure_count.get();
        if count < self.flakiness_seed {
            self.failure_count.set(count + 1);
            return Err(AgentError::Transient(format!(
                "oracle timeout (attempt {})",
                count + 1
            )));
        }
        // Mocked price. A real implementation would call a Pyth / Drand
        // / oracle endpoint here.
        let price_e6: u64 = 28_500_000_000;
        let output = price_e6.to_le_bytes().to_vec();
        mem.put("price_e6", output.clone());
        Ok(AgentResult {
            task_id: task.task_id,
            output,
            emitted_at: anchor,
        })
    }
}

/// Pure-compute agent. Reads price from memory, applies threshold,
/// writes a binary signal back.
pub struct DecisionAgent {
    threshold_e6: u64,
}

impl DecisionAgent {
    pub fn new(threshold_e6: u64) -> Self {
        Self { threshold_e6 }
    }
}

impl Agent for DecisionAgent {
    fn identity(&self) -> &str {
        "decision"
    }

    fn execute(
        &self,
        task: &AgentTask,
        mem: &mut MemoryStore,
        anchor: TripleAnchor,
    ) -> Result<AgentResult, AgentError> {
        let price_bytes = mem
            .get("price_e6")
            .ok_or_else(|| AgentError::Permanent("price not in memory".into()))?;
        if price_bytes.len() != 8 {
            return Err(AgentError::Permanent("malformed price".into()));
        }
        let mut arr = [0u8; 8];
        arr.copy_from_slice(price_bytes);
        let price = u64::from_le_bytes(arr);
        let signal: u8 = if price > self.threshold_e6 { 1 } else { 0 };
        mem.put("signal", vec![signal]);
        Ok(AgentResult {
            task_id: task.task_id,
            output: vec![signal],
            emitted_at: anchor,
        })
    }
}

/// State-mutation agent. Reads the upstream signal, computes a
/// settlement-payload hash, writes it to memory and returns it.
pub struct SettlementAgent;

impl Agent for SettlementAgent {
    fn identity(&self) -> &str {
        "settlement"
    }

    fn execute(
        &self,
        task: &AgentTask,
        mem: &mut MemoryStore,
        anchor: TripleAnchor,
    ) -> Result<AgentResult, AgentError> {
        let signal = mem
            .get("signal")
            .ok_or_else(|| AgentError::Permanent("signal not in memory".into()))?;
        if signal.len() != 1 {
            return Err(AgentError::Permanent("malformed signal".into()));
        }
        let mut h = Sha256::new();
        h.update(b"settlement-output-v1");
        h.update(task.task_id.to_le_bytes());
        h.update(signal);
        let output = h.finalize().to_vec();
        mem.put("settlement_hash", output.clone());
        Ok(AgentResult {
            task_id: task.task_id,
            output,
            emitted_at: anchor,
        })
    }
}

// =============================================================================
// Orchestrator
// =============================================================================

/// Receipt chained from each successful agent step.
#[derive(Debug, Clone)]
pub struct OrchestrationReceipt {
    pub task_id: u64,
    pub commitments: Vec<FreshnessCommitment>,
    /// SHA-256 over the ordered list of per-agent signing digests.
    pub chain_hash: Hash32,
    pub final_anchor: TripleAnchor,
}

/// Outcome of a full orchestration run.
#[derive(Debug)]
pub enum OrchestrationOutcome {
    Complete(OrchestrationReceipt),
    Failed {
        failed_agent: String,
        error: String,
        partial_receipts: Vec<FreshnessCommitment>,
    },
}

pub struct Orchestrator {
    agents: Vec<Box<dyn Agent>>,
    pub max_retries: u32,
    pub backoff_base_ms: u64,
    committer: MockCommitter,
}

impl Orchestrator {
    pub fn new(agents: Vec<Box<dyn Agent>>, committer: MockCommitter) -> Self {
        Self {
            agents,
            max_retries: 3,
            backoff_base_ms: 50,
            committer,
        }
    }

    /// Configure max retries (default 3).
    pub fn with_max_retries(mut self, n: u32) -> Self {
        self.max_retries = n;
        self
    }

    /// Configure exponential backoff base in milliseconds (default 50).
    pub fn with_backoff_base_ms(mut self, ms: u64) -> Self {
        self.backoff_base_ms = ms;
        self
    }

    /// Run the pipeline against `task` starting at `start_anchor`.
    ///
    /// On full success, every agent in the configured order has emitted
    /// a Proof of Context commitment and the chain is sealed by a
    /// SHA-256 over the ordered signing digests.
    ///
    /// On permanent failure of any agent, the pipeline short-circuits
    /// and returns whatever receipts accumulated up to that point.
    pub fn run(
        &self,
        task: &AgentTask,
        start_anchor: TripleAnchor,
        observer: &mut dyn Observer,
    ) -> OrchestrationOutcome {
        let mut mem = MemoryStore::new();
        let mut commitments: Vec<FreshnessCommitment> = Vec::new();
        let mut current_anchor = start_anchor;

        for agent in &self.agents {
            let agent_id = agent.identity().to_string();
            let result = self.run_agent_with_retry(
                agent.as_ref(),
                task,
                &mut mem,
                current_anchor,
                observer,
            );

            match result {
                Ok(agent_result) => {
                    let root = build_step_root(&agent_id, task, &agent_result.output);
                    let output_hash = hash_output(&agent_result.output);
                    let commitment = self
                        .committer
                        .commit(root, output_hash, current_anchor)
                        .expect("MockCommitter::commit cannot fail");
                    commitments.push(commitment);
                    observer.on_event(&Event::AgentSucceeded { agent: agent_id });
                    current_anchor = TripleAnchor::new(
                        current_anchor.block_height + 1,
                        current_anchor.tee_timestamp + 2_000_000_000,
                        current_anchor.drand_round,
                    );
                }
                Err(e) => {
                    let err_str = format!("{:?}", e);
                    observer.on_event(&Event::AgentFailed {
                        agent: agent_id.clone(),
                        error: err_str.clone(),
                    });
                    return OrchestrationOutcome::Failed {
                        failed_agent: agent_id,
                        error: err_str,
                        partial_receipts: commitments,
                    };
                }
            }
        }

        let chain_hash = compute_chain_hash(&commitments);
        observer.on_event(&Event::OrchestratorComplete {
            receipts: commitments.len(),
        });

        OrchestrationOutcome::Complete(OrchestrationReceipt {
            task_id: task.task_id,
            commitments,
            chain_hash,
            final_anchor: current_anchor,
        })
    }

    fn run_agent_with_retry(
        &self,
        agent: &dyn Agent,
        task: &AgentTask,
        mem: &mut MemoryStore,
        anchor: TripleAnchor,
        observer: &mut dyn Observer,
    ) -> Result<AgentResult, AgentError> {
        let mut last_transient: Option<AgentError> = None;
        for attempt in 1..=self.max_retries {
            observer.on_event(&Event::AgentStarted {
                agent: agent.identity().to_string(),
                attempt,
            });
            match agent.execute(task, mem, anchor) {
                Ok(res) => return Ok(res),
                Err(AgentError::Permanent(e)) => return Err(AgentError::Permanent(e)),
                Err(AgentError::Transient(e)) => {
                    if attempt < self.max_retries {
                        observer.on_event(&Event::AgentRetrying {
                            agent: agent.identity().to_string(),
                            attempt,
                            error: e.clone(),
                        });
                        let backoff = self.backoff_base_ms * 2u64.pow(attempt - 1);
                        thread::sleep(Duration::from_millis(backoff));
                        last_transient = Some(AgentError::Transient(e));
                    } else {
                        return Err(AgentError::Transient(e));
                    }
                }
            }
        }
        Err(last_transient.unwrap_or(AgentError::Permanent("unknown".into())))
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Build the per-step ExecutionContextRoot. Each agent step is treated
/// as its own committable computation, so the root identifies the
/// agent, the task, and the inputs that drove its output.
fn build_step_root(agent_id: &str, task: &AgentTask, _output: &[u8]) -> ExecutionContextRoot {
    ExecutionContextRoot {
        weights_hash: hash_label(format!("agent:{}", agent_id)),
        tokenizer_hash: hash_label("orchestrator/v1"),
        system_prompt_hash: hash_label(format!("task:{}", task.task_id)),
        sampling_params: SamplingParams {
            temperature: 0.0,
            top_k: 1,
            top_p: 1.0,
            seed: task.task_id,
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

fn hash_output(bytes: &[u8]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(b"agent-output-v1");
    h.update(bytes);
    h.finalize().into()
}

fn compute_chain_hash(commitments: &[FreshnessCommitment]) -> Hash32 {
    let mut h = Sha256::new();
    h.update(b"orchestration-chain-v1");
    for c in commitments {
        h.update(c.signing_digest());
    }
    h.finalize().into()
}

fn make_committer(seed: u64) -> MockCommitter {
    let mut rng = StdRng::seed_from_u64(seed);
    let signing_key = SigningKey::generate(&mut rng);
    MockCommitter::new(signing_key, "orchestrator-mock")
}

// =============================================================================
// Demo
// =============================================================================

fn main() {
    println!("=== multi_agent_orchestrator — demo ===\n");
    println!("Pipeline: oracle-price → decision → settlement\n");

    let start_anchor = TripleAnchor::new(1_000, 1_700_000_000_000_000_000, 60_000);
    let task = AgentTask {
        task_id: 42,
        input: b"observe BTC".to_vec(),
    };
    let mut observer = ConsoleObserver;

    // Scenario 1 — honest path
    println!("--- 1. honest path ---");
    let oracle = Box::new(OraclePriceAgent::new(0));
    let decision = Box::new(DecisionAgent::new(20_000_000_000));
    let settlement = Box::new(SettlementAgent);
    let orchestrator = Orchestrator::new(vec![oracle, decision, settlement], make_committer(0x100));
    match orchestrator.run(&task, start_anchor, &mut observer) {
        OrchestrationOutcome::Complete(r) => {
            println!(
                "  outcome: COMPLETE — {} commitments, chain_hash={}\n",
                r.commitments.len(),
                hex::encode(&r.chain_hash[..8])
            );
        }
        OrchestrationOutcome::Failed { failed_agent, error, .. } => {
            panic!("honest path must not fail: {} {}", failed_agent, error);
        }
    }

    // Scenario 2 — retry then success
    println!("--- 2. retry then success (oracle fails 2x then succeeds) ---");
    let oracle = Box::new(OraclePriceAgent::new(2));
    let decision = Box::new(DecisionAgent::new(20_000_000_000));
    let settlement = Box::new(SettlementAgent);
    let orchestrator = Orchestrator::new(vec![oracle, decision, settlement], make_committer(0x101));
    match orchestrator.run(&task, start_anchor, &mut observer) {
        OrchestrationOutcome::Complete(r) => {
            println!(
                "  outcome: COMPLETE after retries — {} commitments\n",
                r.commitments.len()
            );
        }
        OrchestrationOutcome::Failed { .. } => panic!("expected success after retries"),
    }

    // Scenario 3 — permanent failure → circuit break
    println!("--- 3. permanent failure (oracle endpoint unreachable) ---");
    let oracle = Box::new(OraclePriceAgent::permanent());
    let decision = Box::new(DecisionAgent::new(20_000_000_000));
    let settlement = Box::new(SettlementAgent);
    let orchestrator = Orchestrator::new(vec![oracle, decision, settlement], make_committer(0x102));
    match orchestrator.run(&task, start_anchor, &mut observer) {
        OrchestrationOutcome::Complete(_) => panic!("expected failure"),
        OrchestrationOutcome::Failed {
            failed_agent,
            error,
            partial_receipts,
        } => {
            println!(
                "  outcome: FAILED — agent={}, error={}, partial_receipts={}\n",
                failed_agent,
                error,
                partial_receipts.len()
            );
        }
    }

    // Scenario 4 — receipt chain integrity
    println!("--- 4. receipt chain integrity check ---");
    let oracle = Box::new(OraclePriceAgent::new(0));
    let decision = Box::new(DecisionAgent::new(20_000_000_000));
    let settlement = Box::new(SettlementAgent);
    let orchestrator = Orchestrator::new(vec![oracle, decision, settlement], make_committer(0x103));
    match orchestrator.run(&task, start_anchor, &mut NullObserver) {
        OrchestrationOutcome::Complete(r) => {
            let recomputed = compute_chain_hash(&r.commitments);
            assert_eq!(recomputed, r.chain_hash, "chain_hash must be reproducible");
            println!(
                "  chain_hash recomputed and matches: {}\n",
                hex::encode(&r.chain_hash[..8])
            );
        }
        _ => panic!("expected complete"),
    }

    println!("=== summary ===");
    println!("  Agent runtime    — Agent trait + 3 concrete agents (I/O / compute / state-mut)");
    println!("  Orchestration    — sequential pipeline with shared MemoryStore");
    println!("  Reliability      — typed errors, retries, exponential backoff, circuit-breaker");
    println!("  Observability    — pluggable Observer trait, ConsoleObserver / NullObserver");
    println!("  Verifiability    — chained Proof of Context commitments per step + chain hash");
}
