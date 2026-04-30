//! Drand mainnet round fetcher.
//!
//! Drand is a threshold-BLS randomness beacon emitting a new round every 30s.
//! This module provides a minimal HTTP client that hits a public mirror and
//! returns the most recent round number. The round is the external clock used
//! by the third anchor of the [`crate::anchor::TripleAnchor`].
//!
//! Mainnet chain hash (pedersen-bls-chained):
//! `8990e7a9aaed2ffed73dbd7092123d6f289930540d7651336225dc172e51b2ce`.

use super::ClientError;
use crate::anchor::DrandRound;
use serde::Deserialize;

/// A client capable of returning the latest Drand round number.
///
/// Trait abstraction lets tests substitute a stub. The real implementation is
/// [`DrandHttpClient`] in this module.
pub trait DrandClient {
    /// Fetch the latest emitted round number from the upstream beacon.
    fn latest_round(&self) -> Result<DrandRound, ClientError>;
}

/// Public chain info returned by `/info` on any Drand mirror.
#[derive(Debug, Clone, Deserialize)]
pub struct DrandInfo {
    /// Scheme identifier, e.g. `"pedersen-bls-chained"` for mainnet.
    #[serde(rename = "schemeID")]
    pub scheme_id: String,
    /// Mainnet chain hash (32 bytes hex). Lets clients identify which
    /// Drand chain the beacon is part of.
    #[serde(rename = "hash")]
    pub chain_hash: String,
    /// Round period in seconds. Mainnet emits one round every 30s.
    #[serde(rename = "period")]
    pub period_secs: u64,
    /// Unix timestamp of mainnet genesis (round 0 emission target time).
    #[serde(rename = "genesis_time")]
    pub genesis_time_unix: u64,
}

/// HTTP client that talks to a public Drand mirror.
///
/// Defaults to the Cloudflare-hosted mirror at `https://drand.cloudflare.com`.
/// The primary `https://api.drand.sh` endpoint has been observed returning 502
/// from some networks (see paper §9 measurement notes), so the Cloudflare
/// mirror is the more reliable default for South American clients.
pub struct DrandHttpClient {
    base_url: String,
    timeout_secs: u64,
}

impl DrandHttpClient {
    /// Construct a client targeting the given mirror base URL (no trailing slash).
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout_secs: 10,
        }
    }

    /// Convenience: target the Cloudflare mirror.
    pub fn cloudflare() -> Self {
        Self::new("https://drand.cloudflare.com")
    }

    /// Override the request timeout.
    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Fetch the chain info (genesis, period, scheme). Useful sanity check.
    pub fn info(&self) -> Result<DrandInfo, ClientError> {
        let url = format!("{}/info", self.base_url);
        let resp = ureq::AgentBuilder::new()
            .timeout_read(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .get(&url)
            .call()
            .map_err(|e| ClientError::Http(format!("GET {url}: {e}")))?;
        let info: DrandInfo = resp
            .into_json()
            .map_err(|e| ClientError::Parse(format!("/info JSON: {e}")))?;
        Ok(info)
    }
}

#[derive(Debug, Deserialize)]
struct DrandPublicLatest {
    round: u64,
}

impl DrandClient for DrandHttpClient {
    fn latest_round(&self) -> Result<DrandRound, ClientError> {
        let url = format!("{}/public/latest", self.base_url);
        let resp = ureq::AgentBuilder::new()
            .timeout_read(std::time::Duration::from_secs(self.timeout_secs))
            .build()
            .get(&url)
            .call()
            .map_err(|e| ClientError::Http(format!("GET {url}: {e}")))?;

        let body: DrandPublicLatest = resp
            .into_json()
            .map_err(|e| ClientError::Parse(format!("/public/latest JSON: {e}")))?;

        Ok(body.round)
    }
}

/// Concrete public alias that mirrors what consumers reach for first.
pub type DrandClientCloudflare = DrandHttpClient;

#[cfg(test)]
mod tests {
    use super::*;

    /// Stub client that returns a fixed round, used by other tests.
    pub(crate) struct StubDrand(pub DrandRound);
    impl DrandClient for StubDrand {
        fn latest_round(&self) -> Result<DrandRound, ClientError> {
            Ok(self.0)
        }
    }

    #[test]
    fn stub_returns_what_it_was_constructed_with() {
        let stub = StubDrand(123_456);
        assert_eq!(stub.latest_round().unwrap(), 123_456);
    }

    /// Live test, opt-in. Run with `cargo test --features real-anchors -- --ignored`.
    #[test]
    #[ignore]
    fn live_drand_returns_a_plausible_round() {
        let client = DrandHttpClient::cloudflare();
        let round = client.latest_round().expect("Drand mirror reachable");
        // Drand mainnet has been emitting rounds since 2020-07-22. By 2026
        // the round number is well above 5 million.
        assert!(round > 5_000_000, "round {} suspiciously small", round);
    }

    #[test]
    #[ignore]
    fn live_drand_info_is_self_consistent() {
        let client = DrandHttpClient::cloudflare();
        let info = client.info().expect("Drand /info reachable");
        assert_eq!(info.period_secs, 30);
        assert_eq!(info.genesis_time_unix, 1_595_431_050);
    }
}
