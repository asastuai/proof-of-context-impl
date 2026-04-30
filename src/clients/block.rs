//! EVM JSON-RPC block-height fetcher.
//!
//! Returns the latest block number from any RPC endpoint that speaks
//! `eth_blockNumber`. Default target is Base mainnet (`https://mainnet.base.org`)
//! but the same client works against Ethereum, Arbitrum, Optimism, or any
//! private node.

use super::ClientError;
use crate::anchor::BlockHeight;
use serde::{Deserialize, Serialize};

/// Trait for fetching a chain's latest block height.
pub trait BlockClient {
    /// Fetch the latest block height from the upstream RPC.
    fn latest_block_number(&self) -> Result<BlockHeight, ClientError>;
}

/// JSON-RPC client targeting an EVM endpoint.
///
/// Wraps a single endpoint URL. For redundancy in production, compose multiple
/// `BaseRpcClient`s and quorum at the call site, or front the RPC with a
/// load-balancer.
pub struct BaseRpcClient {
    rpc_url: String,
    timeout_secs: u64,
}

impl BaseRpcClient {
    /// Construct a client against the given RPC URL.
    pub fn new(rpc_url: impl Into<String>) -> Self {
        Self {
            rpc_url: rpc_url.into(),
            timeout_secs: 10,
        }
    }

    /// Convenience: target the Base public RPC.
    pub fn base_mainnet() -> Self {
        Self::new("https://mainnet.base.org")
    }

    /// Convenience: target the Base Sepolia testnet.
    pub fn base_sepolia() -> Self {
        Self::new("https://sepolia.base.org")
    }

    /// Override the request timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: [&'a str; 0],
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    result: Option<String>,
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

impl BlockClient for BaseRpcClient {
    fn latest_block_number(&self) -> Result<BlockHeight, ClientError> {
        let req = JsonRpcRequest {
            jsonrpc: "2.0",
            id: 1,
            method: "eth_blockNumber",
            params: [],
        };

        let resp = ureq::AgentBuilder::new()
            .timeout_read(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .post(&self.rpc_url)
            .set("Content-Type", "application/json")
            .send_json(serde_json::to_value(&req).map_err(|e| {
                ClientError::Parse(format!("serialize request: {e}"))
            })?)
            .map_err(|e| ClientError::Http(format!("POST {}: {e}", self.rpc_url)))?;

        let body: JsonRpcResponse = resp
            .into_json()
            .map_err(|e| ClientError::Parse(format!("eth_blockNumber JSON: {e}")))?;

        if let Some(err) = body.error {
            return Err(ClientError::UnexpectedShape(format!(
                "RPC error code {}: {}",
                err.code, err.message
            )));
        }

        let hex_height = body.result.ok_or_else(|| {
            ClientError::UnexpectedShape("missing result field".into())
        })?;

        // eth_blockNumber returns "0x<hex>". Strip prefix and parse.
        let trimmed = hex_height
            .strip_prefix("0x")
            .ok_or_else(|| {
                ClientError::UnexpectedShape(format!("missing 0x prefix: {hex_height}"))
            })?;

        u64::from_str_radix(trimmed, 16).map_err(|e| {
            ClientError::Parse(format!(
                "block number hex parse failed for {hex_height}: {e}"
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub client that returns a fixed block number.
    pub(crate) struct StubBlock(pub BlockHeight);
    impl BlockClient for StubBlock {
        fn latest_block_number(&self) -> Result<BlockHeight, ClientError> {
            Ok(self.0)
        }
    }

    #[test]
    fn stub_returns_what_it_was_constructed_with() {
        let stub = StubBlock(42);
        assert_eq!(stub.latest_block_number().unwrap(), 42);
    }

    /// Live test, opt-in. Run with:
    ///   cargo test --features real-anchors -- --ignored
    #[test]
    #[ignore]
    fn live_base_returns_a_plausible_block_height() {
        let client = BaseRpcClient::base_mainnet();
        let height = client
            .latest_block_number()
            .expect("Base RPC reachable");
        // Base launched in mid-2023. By 2026 the chain is well past 10M blocks.
        assert!(
            height > 10_000_000,
            "block height {} suspiciously small",
            height
        );
    }
}
