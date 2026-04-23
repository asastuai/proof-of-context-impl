//! Mock backend — software-only implementations of the proof-of-context
//! traits, suitable for tests and development. **Not** suitable for
//! economic settlement: the attestation chain is a `MockSoftware` vendor
//! tag with no hardware trust root, and the signing key is a plain
//! Ed25519 keypair held in memory.
//!
//! The Phase 3 backend replaces this module with TDX + H100 attestation
//! and hardware-held keys.

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::anchor::TripleAnchor;
use crate::attestation::{AttestationChain, AttestationVendor, AttestationVerifier};
use crate::commitment::{CommitmentVerifier, ContextCommitter, FreshnessCommitment};
use crate::context::{ExecutionContextRoot, Hash32};
use crate::error::PocError;
use crate::freshness::{FreshnessThresholds, FreshnessType};
use crate::settle::{SettlementGate, SettlementResult};

/// Software-only commitment producer — signs with an in-memory Ed25519 key.
pub struct MockCommitter {
    signing_key: SigningKey,
    identity: String,
}

impl MockCommitter {
    /// Construct a committer from an existing signing key.  Key generation
    /// is the caller's responsibility — the library deliberately does not
    /// depend on a randomness crate so that tests and integration stacks
    /// can choose their own RNG policy.
    pub fn new(signing_key: SigningKey, identity: impl Into<String>) -> Self {
        Self { signing_key, identity: identity.into() }
    }

    /// Return the committer's public verifying key (32 bytes).
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
}

impl ContextCommitter for MockCommitter {
    fn commit(
        &self,
        root: ExecutionContextRoot,
        output_hash: Hash32,
        anchor: TripleAnchor,
    ) -> Result<FreshnessCommitment, PocError> {
        let context_root = root.merkle_root();

        // Build the canonical signing digest.
        let mut h = Sha256::new();
        h.update(&context_root);
        h.update(&anchor.block_height.to_le_bytes());
        h.update(&anchor.tee_timestamp.to_le_bytes());
        h.update(&anchor.drand_round.to_le_bytes());
        h.update(&output_hash);
        let digest: [u8; 32] = h.finalize().into();

        // Sign the digest.
        let sig = self.signing_key.sign(&digest);
        let sig_bytes: [u8; 64] = sig.to_bytes();
        let pk_bytes: [u8; 32] = self.signing_key.verifying_key().to_bytes();

        Ok(FreshnessCommitment {
            context_root,
            anchor,
            output_hash,
            signature: sig_bytes,
            public_key: pk_bytes,
            attestation_chain: AttestationChain {
                payload: b"mock-software-attestation".to_vec(),
                vendor: AttestationVendor::MockSoftware,
            },
        })
    }

    fn identity(&self) -> &str {
        &self.identity
    }
}

/// Software-only commitment verifier — checks the Ed25519 signature and
/// accepts `MockSoftware` attestations unconditionally.  The production
/// verifier would replace the attestation check with TDX / H100 quote
/// validation against a known-good measurement registry.
pub struct MockVerifier;

impl MockVerifier {
    pub fn new() -> Self { Self }
}

impl Default for MockVerifier {
    fn default() -> Self { Self::new() }
}

impl CommitmentVerifier for MockVerifier {
    fn verify(&self, commitment: &FreshnessCommitment) -> Result<(), PocError> {
        // Reconstruct the canonical signing digest.
        let digest = commitment.signing_digest();

        let vk = VerifyingKey::from_bytes(&commitment.public_key)
            .map_err(|_| PocError::InvalidSignature)?;
        let sig = ed25519_dalek::Signature::from_bytes(&commitment.signature);

        vk.verify(&digest, &sig).map_err(|_| PocError::InvalidSignature)?;

        // Attestation chain: accept MockSoftware; reject anything else
        // in the mock verifier (because the mock does not know how to
        // parse hardware vendor formats).
        AttestationVerifier::verify(self, &commitment.attestation_chain)
    }
}

impl AttestationVerifier for MockVerifier {
    fn verify(&self, chain: &AttestationChain) -> Result<(), PocError> {
        if chain.vendor == AttestationVendor::MockSoftware {
            Ok(())
        } else {
            Err(PocError::InvalidAttestation)
        }
    }
}

/// Software-only settlement gate.  Combines signature verification with
/// triple-anchor freshness checks.
pub struct MockSettlementGate<V: CommitmentVerifier> {
    verifier: V,
}

impl<V: CommitmentVerifier> MockSettlementGate<V> {
    pub fn new(verifier: V) -> Self {
        Self { verifier }
    }
}

impl<V: CommitmentVerifier> SettlementGate for MockSettlementGate<V> {
    fn verify_and_settle(
        &self,
        commitment: &FreshnessCommitment,
        now: &TripleAnchor,
        thresholds: &FreshnessThresholds,
    ) -> Result<SettlementResult, PocError> {
        // 1. Signature + attestation verification.
        self.verifier.verify(commitment)?;

        // 2. Triple-anchor divergence check — detects accidental skew and
        //    single-clock failure under the assumption of valid attestation.
        //    This covers the f_c (commit latency) and f_m (timing-anchored
        //    model freshness) axes indirectly via the anchor comparison.
        let mut violations = Vec::new();

        if commitment.anchor.diverges_beyond(now, thresholds) {
            // Attribute to Computational freshness since the anchor is the
            // commit-time clock.  A stronger implementation could inspect
            // which axis (block / tee / drand) diverged and assign more
            // specific freshness types.
            violations.push(FreshnessType::Computational);
        }

        // 3. Settlement-window (f_s) check: commit must be settled within
        //    max_fs_blocks of the commit block height.
        let block_delta = if now.block_height >= commitment.anchor.block_height {
            now.block_height - commitment.anchor.block_height
        } else {
            // Clock went backwards — treat as divergence.
            return Ok(SettlementResult::Rejected(vec![FreshnessType::Settlement]));
        };
        if block_delta > thresholds.max_fs_blocks {
            violations.push(FreshnessType::Settlement);
        }

        // Future Phase 3 work: verify f_m (model freshness) against an
        // external "current canonical root" oracle, and f_i (input
        // freshness) against the commitment's input_manifest_root. The
        // mock gate deliberately does not cover those.

        if violations.is_empty() {
            Ok(SettlementResult::Clear)
        } else {
            Ok(SettlementResult::Rejected(violations))
        }
    }
}
