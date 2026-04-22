//! TEE attestation chain verification.
//!
//! As established in §9 of the paper, the triple-anchor defense operates
//! under a *valid TEE attestation chain*. Defense against enclave
//! compromise (TDXdown-class attacks) is this attestation chain, not
//! the three clocks.
//!
//! Phase 1 defines the shape; Phase 2 will implement TDX quote + H100
//! attestation verification against known-good measurement values.

/// A raw TEE attestation chain. Phase 1 carries bytes opaquely; Phase 2
/// introduces a typed struct distinguishing TDX quote, platform
/// certificate chain, and H100 attestation report.
#[derive(Debug, Clone)]
pub struct AttestationChain {
    /// Opaque attestation bytes (vendor-specific format).
    pub payload: Vec<u8>,
    /// Vendor identifier to help verifiers dispatch to the right parser.
    pub vendor: AttestationVendor,
}

/// Supported attestation vendors / formats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestationVendor {
    /// Intel TDX quote with platform certificate chain.
    IntelTdx,
    /// AMD SEV-SNP attestation report.
    AmdSevSnp,
    /// Nvidia H100 confidential compute attestation.
    NvidiaH100,
    /// Software-only attestation. Not suitable for economic settlement;
    /// provided for test / development use.
    MockSoftware,
}

/// A verifier that validates the attestation chain against a set of
/// known-good enclave measurements.
pub trait AttestationVerifier {
    /// Return `Ok(())` if the attestation is valid AND the enclave
    /// measurement is on the known-good list. Any other outcome returns
    /// the appropriate [`crate::PocError`] variant.
    fn verify(&self, chain: &AttestationChain) -> Result<(), crate::PocError>;
}
