//! Seconds-based input-freshness (`f_i`) witness for a unix-seconds venue.
//!
//! The SUR Solana dark pool settles in unix seconds (`Clock::unix_timestamp`),
//! and the canonical input-world state an agent quotes against is the market
//! price-as-of (`perp_engine::Market.last_price_update`, unix seconds, keyed by
//! `market_id`). This module is the Solana analogue of [`crate::input_freshness`]:
//! witness-presented (no network at settlement), the caller presents a signed
//! [`PriceAttestation`] for each market; the oracle verifies it and answers
//! "how many seconds old is the price this agent reasoned over".
//!
//! Unlike [`crate::oracle::CanonicalStateOracle`] (which is block-denominated),
//! this is a seconds-native path — the dark pool has no canonical block→time
//! mapping the way Base does. It is consumed by [`crate::darkpool`].

use std::collections::HashMap;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde_json::Value;

use crate::canonical::canonical_json;
use crate::error::PocError;

/// A signed market-price attestation: the price record an agent observed when
/// forming its quote, witness-presented at settlement. In SUR v0.2 prices are
/// operator-pushed (`oracle_router::push_price`), so the operator key signs this.
#[derive(Debug, Clone)]
pub struct PriceAttestation {
    /// The market this price is for (`[u8; 32]`, as SUR keys feeds/markets).
    pub market_id: [u8; 32],
    /// The attested price (venue precision; opaque to freshness gating).
    pub price: u64,
    /// Unix seconds the price was published / last updated
    /// (`Market.last_price_update`). This is the freshness fact.
    pub price_as_of_secs: u64,
    /// Ed25519 signature over [`Self::signing_message`], or `None` if unsigned.
    pub signature: Option<[u8; 64]>,
    /// Ed25519 public key (the operator) that signed, or `None`.
    pub public_key: Option<[u8; 32]>,
}

impl PriceAttestation {
    /// The canonical signing message: a domain-tagged, key-sorted canonical-JSON
    /// object binding `market_id`, `price`, and `price_as_of_secs`. Uses the
    /// shared [`canonical_json`] scheme so it is reproducible cross-language.
    pub fn signing_message(&self) -> String {
        let value: Value = serde_json::json!({
            "domain": "poc/price/0.1",
            "market_id": hex::encode(self.market_id),
            "price": self.price,
            "price_as_of_secs": self.price_as_of_secs,
        });
        canonical_json(&value)
    }

    /// Verify the Ed25519 signature over the canonical signing message.
    /// `Err(InvalidSignature)` if unsigned, malformed, or it does not verify.
    pub fn verify_signature(&self) -> Result<(), PocError> {
        let sig_bytes = self.signature.ok_or(PocError::InvalidSignature)?;
        let pk_bytes = self.public_key.ok_or(PocError::InvalidSignature)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| PocError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        vk.verify(self.signing_message().as_bytes(), &sig)
            .map_err(|_| PocError::InvalidSignature)
    }
}

/// A seconds-native `f_i` oracle over presented price attestations, indexed by
/// `market_id`. Optionally pins a single trusted operator public key.
#[derive(Debug, Default)]
pub struct PriceFreshnessOracle {
    by_market: HashMap<[u8; 32], PriceAttestation>,
    expected_pubkey: Option<[u8; 32]>,
}

impl PriceFreshnessOracle {
    /// Construct an oracle. Pass `expected_pubkey` to pin a single trusted
    /// price operator (`None` accepts any well-signed attestation).
    pub fn new(expected_pubkey: Option<[u8; 32]>) -> Self {
        Self { by_market: HashMap::new(), expected_pubkey }
    }

    /// Verify a price attestation's signature (and operator pin, if set), then
    /// index it by `market_id`. A later attestation for the same market wins.
    pub fn present_price(&mut self, attestation: PriceAttestation) -> Result<(), PocError> {
        attestation.verify_signature()?;
        if let Some(expected) = self.expected_pubkey {
            if attestation.public_key != Some(expected) {
                return Err(PocError::InvalidSignature);
            }
        }
        self.by_market.insert(attestation.market_id, attestation);
        Ok(())
    }

    /// Age in seconds of the presented price for `market_id` at `now_secs`
    /// (`now_secs − price_as_of_secs`, saturating). `Err(OracleUnavailable)` if
    /// no price was presented for that market — the gate treats that as stale.
    pub fn price_age_secs(&self, market_id: &[u8; 32], now_secs: u64) -> Result<u64, PocError> {
        let att = self.by_market.get(market_id).ok_or(PocError::OracleUnavailable)?;
        Ok(now_secs.saturating_sub(att.price_as_of_secs))
    }
}
