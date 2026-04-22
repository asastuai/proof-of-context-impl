//! Proof-of-context commitment and the committer trait.
//!
//! A commitment is the artifact a worker produces at the end of a
//! computation. It binds (a) the execution-context root, (b) the triple
//! anchor at commit time, (c) the output hash, and (d) a TEE attestation
//! chain into a single signed package.
//!
//! The commitment is what a settlement gate consumes when deciding
//! whether to clear payment.

use crate::anchor::TripleAnchor;
use crate::attestation::AttestationChain;
use crate::context::{ExecutionContextRoot, Hash32};
use crate::error::PocError;

/// A signed proof-of-context commitment.
#[derive(Debug, Clone)]
pub struct FreshnessCommitment {
    /// Merkle root of the execution context (see [`ExecutionContextRoot`]).
    pub context_root: Hash32,
    /// The three clocks at commit time.
    pub anchor: TripleAnchor,
    /// Hash of the computation output (inference tokens, gradient blob, etc.).
    pub output_hash: Hash32,
    /// Signature over `(context_root || anchor || output_hash)` by the
    /// TEE-provisioned key. Phase 1 uses raw bytes; Phase 2 introduces
    /// a typed signature (planned: Ed25519 via `ed25519-dalek`).
    pub signature: Vec<u8>,
    /// TEE attestation chain (e.g., TDX quote + H100 attestation report)
    /// that anchors the signing key identity.
    pub attestation_chain: AttestationChain,
}

/// A producer of commitments.
///
/// Implementations will typically wrap an enclave (TDX + H100) and
/// produce the signature / attestation chain from hardware. A mock
/// implementation may sign with a software key — useful for tests,
/// not for economic settlement.
pub trait ContextCommitter {
    /// Build and sign a commitment binding the given context root and
    /// output hash against the current anchor.
    fn commit(
        &self,
        root: ExecutionContextRoot,
        output_hash: Hash32,
        anchor: TripleAnchor,
    ) -> Result<FreshnessCommitment, PocError>;

    /// Return a human-readable identifier for this committer (for logs).
    fn identity(&self) -> &str;
}

/// A verifier that checks signature and attestation chain on a
/// commitment, independently of settlement-gating.
pub trait CommitmentVerifier {
    /// Return `Ok(())` if the commitment's signature chains back to a
    /// valid TEE attestation for a known-good enclave measurement.
    fn verify(&self, commitment: &FreshnessCommitment) -> Result<(), PocError>;
}
