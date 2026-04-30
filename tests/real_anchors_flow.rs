//! Integration test for the `real-anchors` feature.
//!
//! Uses in-process stub clients to assemble a `TripleAnchor` without hitting
//! live Drand or EVM RPC. Live tests live as `#[ignore]` units inside the
//! respective client modules and are run with:
//!
//! ```sh
//! cargo test --features real-anchors -- --ignored
//! ```

#![cfg(feature = "real-anchors")]

use proof_of_context::anchor::{BlockHeight, DrandRound, TripleAnchor};
use proof_of_context::clients::{
    BlockClient, ClientError, DrandClient, RealAnchorBuilder,
};

struct FixedDrand(DrandRound);
impl DrandClient for FixedDrand {
    fn latest_round(&self) -> Result<DrandRound, ClientError> {
        Ok(self.0)
    }
}

struct FixedBlock(BlockHeight);
impl BlockClient for FixedBlock {
    fn latest_block_number(&self) -> Result<BlockHeight, ClientError> {
        Ok(self.0)
    }
}

#[test]
fn real_anchor_builder_composes_three_clocks_from_stubs() {
    let drand = FixedDrand(7_000_000);
    let block = FixedBlock(20_000_000);
    let builder = RealAnchorBuilder::new(drand, block);

    let anchor: TripleAnchor = builder.build().expect("stubs always succeed");

    assert_eq!(anchor.drand_round, 7_000_000);
    assert_eq!(anchor.block_height, 20_000_000);
    // TEE timestamp is the local wall clock — assert it is non-zero and
    // recent enough to be plausible (after 2025).
    let after_2025_ns: u128 = 1_735_689_600_u128 * 1_000_000_000;
    assert!(
        anchor.tee_timestamp > after_2025_ns,
        "tee_timestamp {} is implausibly old; system clock broken?",
        anchor.tee_timestamp
    );
}

#[test]
fn real_anchor_drand_wall_time_matches_paper_genesis() {
    // Drand mainnet round 1_000_000 should map to a specific wall time.
    let anchor = TripleAnchor::new(0, 0, 1_000_000);
    let wall = anchor.drand_wall_time_secs();
    // genesis 1595431050 + 1_000_000 * 30 = 1625431050 (Tue Jul 04 2021)
    assert_eq!(wall, 1_625_431_050);
}

#[test]
fn real_anchor_skew_detects_a_diverged_block_clock() {
    let now = TripleAnchor::new(20_000_010, 1_000, 7_000_001);
    let then = TripleAnchor::new(20_000_000, 1_000, 7_000_001);
    let skew = now.skew_vs(&then);
    assert_eq!(skew.block_delta, 10);
    assert_eq!(skew.drand_delta, 0);
}
