//! The execution-context root: Merkle commitment over everything that
//! affects computation output, as defined in §8 of the paper.
//!
//! Getting the scope of this root right is load-bearing: any component
//! that affects output but is *not* in the root is a trivial evasion
//! vector. The fields below are the minimum scope; future work will
//! formalize proofs of sufficiency for specific inference runtimes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// 32-byte cryptographic digest.
pub type Hash32 = [u8; 32];

/// Sampling parameters that affect inference output.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

impl SamplingParams {
    /// Serialize the sampling params into a stable byte layout for Merkle
    /// hashing. IEEE-754 float bytes are used directly (bit-exact).
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 4 + 4 + 8);
        out.extend_from_slice(&self.temperature.to_le_bytes());
        out.extend_from_slice(&self.top_k.to_le_bytes());
        out.extend_from_slice(&self.top_p.to_le_bytes());
        out.extend_from_slice(&self.seed.to_le_bytes());
        out
    }
}

/// Attention kernel identity. Attribution: identified as an attack-surface
/// vector by Prime Intellect's TOPLOC paper (Ong et al., arXiv:2501.16007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl AttentionImpl {
    fn discriminant(&self) -> u8 {
        match self {
            Self::FlashAttention2 => 1,
            Self::Sdpa => 2,
            Self::FlexAttention => 3,
            Self::Other(tag) => 0x80 | (tag & 0x7F),
        }
    }
}

/// Floating-point precision mode. Attribution: identified as an
/// attack-surface vector by Prime Intellect's TOPLOC paper
/// (Ong et al., arXiv:2501.16007).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

impl PrecisionMode {
    fn discriminant(&self) -> u8 {
        match self {
            Self::Bf16 => 1,
            Self::Fp16 => 2,
            Self::Fp32 => 3,
            Self::Fp8 => 4,
        }
    }
}

/// Inference configuration parameters that affect output deterministically.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceConfig {
    /// Maximum tokens generated.
    pub max_tokens: u32,
    /// Stop sequences encoded as a single Merkle root.
    pub stop_sequences_root: Hash32,
    /// Repetition penalty, frequency penalty, presence penalty — folded
    /// into one root for compactness.
    pub penalty_params_root: Hash32,
}

impl InferenceConfig {
    fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 32 + 32);
        out.extend_from_slice(&self.max_tokens.to_le_bytes());
        out.extend_from_slice(&self.stop_sequences_root);
        out.extend_from_slice(&self.penalty_params_root);
        out
    }
}

/// Runtime identity (CUDA version, driver version, inference engine).
pub type RuntimeVersionHash = Hash32;

/// The execution-context root: everything the commitment binds to.
///
/// If a field is not in this struct, it is not committed to, which means
/// the worker can change it without breaking the commitment. Every field
/// below must therefore be one of: (a) required for determinism, (b)
/// required for settlement-relevant contract compliance, or (c) an
/// attack-surface vector documented in the literature.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// This is a canonical serialization: every field is written in the
    /// protocol-defined order, with fixed-length encodings where
    /// applicable. The output is the SHA-256 of the concatenation.
    ///
    /// **Changing field order is a breaking protocol change.** The order
    /// here must match the order enforced off-chain by any verifier
    /// recomputing the root.
    pub fn merkle_root(&self) -> Hash32 {
        let mut h = Sha256::new();
        h.update(&self.weights_hash);
        h.update(&self.tokenizer_hash);
        h.update(&self.system_prompt_hash);
        h.update(&self.sampling_params.to_bytes());
        h.update(&self.runtime_version);
        h.update(&[self.attention_impl_id.discriminant()]);
        h.update(&[self.precision_mode.discriminant()]);
        h.update(&self.inference_config.to_bytes());
        h.update(&self.input_manifest_root);
        match self.kv_cache_root {
            Some(root) => {
                h.update(&[1u8]);
                h.update(&root);
            }
            None => {
                h.update(&[0u8]);
            }
        }
        h.finalize().into()
    }
}
