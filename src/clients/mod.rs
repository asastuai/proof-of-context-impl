//! Real-anchor clients: Drand round + EVM block-RPC fetchers.
//!
//! Compiled only with `--features real-anchors`. The default build of the
//! crate stays pure crypto + types so consumers that do not need to fetch
//! against live mainnet sources do not pay for the HTTP dependency.
//!
//! # What this gives you
//!
//! - [`DrandClient`] — fetches the latest Drand round from the public
//!   Cloudflare mirror (or any mirror you point it at).
//! - [`BaseRpcClient`] — fetches the latest block height from a JSON-RPC
//!   endpoint compatible with `eth_blockNumber` (Base, Ethereum, any EVM L2).
//! - [`RealAnchorBuilder`] — composes both into a [`TripleAnchor`] with the
//!   TEE clock filled by best-effort wall time (a real TEE attestation is
//!   Phase 4 work — see [`crate::attestation`]).
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(feature = "real-anchors")]
//! # fn run() -> Result<(), proof_of_context::clients::ClientError> {
//! use proof_of_context::clients::{
//!     BaseRpcClient, DrandHttpClient, RealAnchorBuilder,
//! };
//!
//! let drand = DrandHttpClient::cloudflare();
//! let rpc = BaseRpcClient::new("https://mainnet.base.org");
//! let builder = RealAnchorBuilder::new(drand, rpc);
//!
//! let anchor = builder.build()?;
//! println!("anchor: {:?}", anchor);
//! # Ok(())
//! # }
//! ```
//!
//! # Honest scope
//!
//! These clients fetch live data over the public internet. Their honesty
//! depends on the network path:
//!
//! - The Drand mirror could lie about the round (mitigated: Drand is a
//!   threshold-BLS signature, and the round timestamp is deterministic
//!   from the mainnet genesis — verify the signature for stronger guarantees,
//!   not done in this client).
//! - The EVM RPC could lie about the block height (mitigated: use a node
//!   you operate, or compose multiple RPC providers and quorum).
//! - The TEE timestamp here is *just system time*. It is NOT attested by
//!   real hardware. That is Phase 4. The current builder fills it as a
//!   placeholder so consumers get a full `TripleAnchor`, not a hole.

pub mod block;
pub mod drand;

pub use block::{BaseRpcClient, BlockClient};
pub use drand::{DrandClient, DrandHttpClient, DrandInfo};

use crate::anchor::TripleAnchor;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Compose a real [`TripleAnchor`] from live Drand + EVM RPC fetches.
///
/// The TEE component is filled with the local system clock as a
/// placeholder until Phase 4 adds real hardware attestation.
pub struct RealAnchorBuilder<D, B>
where
    D: DrandClient,
    B: BlockClient,
{
    drand: D,
    block: B,
}

impl<D, B> RealAnchorBuilder<D, B>
where
    D: DrandClient,
    B: BlockClient,
{
    /// Construct a builder from any Drand and block clients.
    pub fn new(drand: D, block: B) -> Self {
        Self { drand, block }
    }

    /// Fetch all three clocks and assemble a `TripleAnchor`.
    pub fn build(&self) -> Result<TripleAnchor, ClientError> {
        let drand_round = self.drand.latest_round()?;
        let block_height = self.block.latest_block_number()?;
        let tee_timestamp = system_time_unix_nanos();

        Ok(TripleAnchor::new(block_height, tee_timestamp, drand_round))
    }
}

fn system_time_unix_nanos() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Errors produced by the real-anchor clients.
#[derive(Debug, Error)]
pub enum ClientError {
    /// HTTP transport failure (timeout, DNS, TLS, non-2xx response).
    #[error("HTTP request failed: {0}")]
    Http(String),
    /// Response body could not be parsed as the expected JSON shape.
    #[error("response parse failed: {0}")]
    Parse(String),
    /// Response was structurally valid JSON but logically wrong (missing
    /// required fields, RPC-level error, hex parsing failure, etc.).
    #[error("upstream returned an unexpected shape: {0}")]
    UnexpectedShape(String),
}
