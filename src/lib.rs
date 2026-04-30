//! # proof-of-context
//!
//! Reference implementation of the proof-of-context primitive: an
//! attestation-as-settlement layer for decentralized machine learning.
//!
//! See the position paper at <https://github.com/asastuai/proof-of-context>
//! for the conceptual framework. This crate translates that framework into
//! Rust traits and types.
//!
//! **Status:** scaffold. All primitive implementations are `unimplemented!()`
//! stubs. The goal of the 0.1.0-scaffold release is that the structure
//! compiles and that readers can see the architecture without needing to
//! read any implementation logic.
//!
//! ## One-sentence framing
//!
//! > PAL\*M attests that a computation happened correctly; proof-of-context
//! > makes those attestations economically perishable — binding freshness to
//! > settlement so that stale inferences cannot clear payment.
//!
//! ## Top-level crate layout
//!
//! - [`anchor`] — the three clocks (block height, TEE timestamp, Drand round).
//! - [`context`] — the execution-context root (what the commitment binds to).
//! - [`freshness`] — the four freshness types (`f_c`, `f_m`, `f_i`, `f_s`) and threshold parameters.
//! - [`commitment`] — a proof-of-context commitment and the [`ContextCommitter`] trait.
//! - [`settle`] — the [`SettlementGate`] trait that refuses to clear stale commitments.
//! - [`renewal`] — the [`Renewal`] trait implementing prospective-only root bumps.
//! - [`attestation`] — TEE attestation chain verification hooks.
//! - [`error`] — shared error types.
//!
//! ## Minimal usage sketch (aspirational, not yet functional)
//!
//! ```ignore
//! use proof_of_context::{
//!     anchor::TripleAnchor,
//!     context::ExecutionContextRoot,
//!     commitment::ContextCommitter,
//!     settle::SettlementGate,
//!     freshness::FreshnessThresholds,
//! };
//!
//! // 1. Worker runs the inference and builds the context root.
//! let root: ExecutionContextRoot = /* build from runtime state */ todo!();
//!
//! // 2. Worker commits, anchoring against the three clocks.
//! let committer: Box<dyn ContextCommitter> = /* TEE-backed committer */ todo!();
//! let commitment = committer.commit(root, /* output bytes */ &[]).unwrap();
//!
//! // 3. At settlement time, the gate checks freshness against current clocks.
//! let gate: Box<dyn SettlementGate> = /* protocol-configured */ todo!();
//! let now: TripleAnchor = /* read current state */ todo!();
//! let thresholds = FreshnessThresholds::default_base_mainnet();
//! if gate.is_settlement_eligible(&commitment, &now, &thresholds).unwrap() {
//!     // Release payment.
//! }
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod anchor;
pub mod attestation;
pub mod commitment;
pub mod context;
pub mod error;
pub mod freshness;
pub mod mock;
pub mod renewal;
pub mod settle;

/// Real-anchor clients (Drand + EVM RPC). Opt in with `--features real-anchors`.
#[cfg(feature = "real-anchors")]
pub mod clients;

pub use anchor::TripleAnchor;
pub use commitment::{ContextCommitter, FreshnessCommitment};
pub use context::ExecutionContextRoot;
pub use error::PocError;
pub use freshness::{FreshnessThresholds, FreshnessType};
pub use renewal::Renewal;
pub use settle::{SettlementGate, SettlementResult};
