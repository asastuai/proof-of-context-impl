//! The execution-context root: Merkle commitment over everything that
//! affects computation output, as defined in §8 of the paper.
//!
//! Getting the scope of this root right is load-bearing: any component
//! that affects output but is *not* in the root is a trivial evasion
//! vector. The fields below are the minimum scope; future work will
//! formalize proofs of sufficiency for specific inference runtimes.

/// 32-byte cryptographic digest. Phase 1 uses a type alias; Phase 2
/// will introduce a newtype with `Display` and deserialization.
pub type Hash32 = [u8; 32];

/// Sampling parameters that affect inference output.
#[derive(Debug, Clone, PartialEq)]
pub struct SamplingParams {
    /// Softmax temperature.
    pub temperature: f32,
    /// Top-k sampling cutoff (0 = disabled).
    pub top_k: u32,
    /// Top-p nucleus sampling (1.0 = disabled).
    pub top_p: f32,
    /// RNG seed for the inference. Zero means "not fixed" but protocol
    /// implementations may require non-zero.
    pub seed: u64,
}

/// Attention kernel identity. Attribution: identified as an attack-surface
/// vector by Prime Intellect's TOPLOC paper (Ong et al., arXiv:2501.16007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttentionImpl {
    /// FlashAttention 2.
    FlashAttention2,
    /// PyTorch Scaled Dot-Product Attention.
    Sdpa,
    /// PyTorch Flex Attention.
    FlexAttention,
    /// Other implementation identified by string tag in the root.
    Other(u8),
}

/// Floating-point precision mode. Attribution: identified as an
/// attack-surface vector by Prime Intellect's TOPLOC paper
/// (Ong et al., arXiv:2501.16007).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecisionMode {
    /// Brain-float 16.
    Bf16,
    /// IEEE half-precision.
    Fp16,
    /// IEEE single-precision.
    Fp32,
    /// 8-bit floating point.
    Fp8,
}

/// Inference configuration parameters that affect output deterministically.
#[derive(Debug, Clone, PartialEq)]
pub struct InferenceConfig {
    /// Maximum tokens generated.
    pub max_tokens: u32,
    /// Stop sequences encoded as a single Merkle root.
    pub stop_sequences_root: Hash32,
    /// Repetition penalty, frequency penalty, presence penalty — folded
    /// into one root for compactness.
    pub penalty_params_root: Hash32,
}

/// Runtime identity (CUDA version, driver version, inference engine).
/// Phase 1 uses a single hash; Phase 2 will expand into a sub-struct.
pub type RuntimeVersionHash = Hash32;

/// The execution-context root: everything the commitment binds to.
///
/// If a field is not in this struct, it is not committed to, which means
/// the worker can change it without breaking the commitment. Every field
/// below must therefore be one of: (a) required for determinism, (b)
/// required for settlement-relevant contract compliance, or (c) an
/// attack-surface vector documented in the literature.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionContextRoot {
    /// Merkle hash of the model weights at commit time.
    pub weights_hash: Hash32,
    /// Identity and version of the tokenizer.
    pub tokenizer_hash: Hash32,
    /// System prompt used in the inference session.
    pub system_prompt_hash: Hash32,
    /// Sampling parameters (temperature, top-k, top-p, seed).
    pub sampling_params: SamplingParams,
    /// Runtime identity hash.
    pub runtime_version: RuntimeVersionHash,
    /// Attention implementation (TOPLOC-attributed attack vector).
    pub attention_impl_id: AttentionImpl,
    /// Precision mode (TOPLOC-attributed attack vector).
    pub precision_mode: PrecisionMode,
    /// Inference config (max_tokens, stop sequences, penalties).
    pub inference_config: InferenceConfig,
    /// Root over input-world sources: oracle IDs, RAG corpus version,
    /// tool-call bindings. This is the channel through which `f_i`
    /// (input freshness) is anchored.
    pub input_manifest_root: Hash32,
    /// KV-cache root (mode C4 from the paper). `None` when the inference
    /// does not use a persistent cache.
    pub kv_cache_root: Option<Hash32>,
}

impl ExecutionContextRoot {
    /// Compute the Merkle root over all fields.
    ///
    /// Phase 1 stub. Phase 2 will implement a concrete Merkle scheme
    /// (likely binary SHA-256 Merkle with the field order defined in
    /// §8 of the paper).
    pub fn merkle_root(&self) -> Hash32 {
        unimplemented!(
            "Phase 2: SHA-256 Merkle over (weights_hash, tokenizer_hash, system_prompt_hash, \
             serialize(sampling_params), runtime_version, attention_impl_id as u8, \
             precision_mode as u8, serialize(inference_config), input_manifest_root, \
             kv_cache_root.unwrap_or([0u8; 32])). Field order is protocol-defined and must not change."
        )
    }
}
