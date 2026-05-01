# Quickstart

A 5-minute orientation for the proof-of-context Rust crate.

## What this crate is, today

The Rust crate is the **typed reference architecture** for the proof-of-context primitive. It defines the execution-context root, the triple-anchor, the freshness types, and the `ContextCommitter` / `SettlementGate` traits the position paper describes. At the current scaffold stage many primitive methods are `unimplemented!()` — the goal of the 0.1.0-scaffold release is that the architecture compiles and reads cleanly, not that you can run a TEE-backed commit against mainnet today.

## What it is not, today

It is **not** the on-the-wire JSON canonical-hash + Ed25519 signature flow you see in the four JS/TS implementations (BaseOracle, TrustLayer, Vigil, PayClaw). Those four use SHA-256 over canonical JSON and an Ed25519 signature over the attested fields. The Rust crate uses typed Merkle hashing because it targets the protocol-level architecture (TEE-bound execution-context roots), not HTTP responses.

If you want to read a working `attest` + `verify` today, look at one of the JS/TS repos. If you want to read the typed architecture and understand where the protocol is heading, this crate is where to start.

## Build it

```bash
git clone https://github.com/asastuai/proof-of-context-impl
cd proof-of-context-impl
cargo build
cargo test
```

Tests pass. They exercise the type machinery, not a TEE.

## Read the architecture in 30 lines

```bash
cargo run --example sketch
```

That example walks you through the four moving parts you need to understand:

1. **`FreshnessThresholds`** — the protocol-level skew bounds for block height, TEE timestamp, and Drand round.
2. **`ExecutionContextRoot`** — what a commitment binds to: weights, tokenizer, sampling params, runtime, attention impl, precision, input manifest, optional KV-cache root.
3. **`TripleAnchor`** — the three clocks the commitment is anchored against at commit time.
4. **`ContextCommitter` + `SettlementGate`** — the two trait surfaces a real implementation must fill: how to commit, and how to refuse to clear stale commitments at payment time.

Read `src/lib.rs` next. It is short and intentionally readable.

## Wire format vs typed architecture

The wire format (what you would send over an HTTP `_poc` block) is specified at:

> github.com/asastuai/proof-of-context/blob/main/SPEC-WIRE-FORMAT-v0.1.md

The cross-language test vectors that pin the canonical-hash construction live at:

> github.com/asastuai/proof-of-context/blob/main/test-vectors/v0.1.json

The four JS/TS implementations all hash the same payloads to the same bytes. The Rust crate does not, because it is not on the wire path — it is the type reference for the protocol layer.

## What to read after this file

- `ARCHITECTURE.md` — module layout and what each piece is for.
- `ROADMAP.md` — what the scaffold becomes at Phase 2, Phase 3, Phase 5.
- `examples/multi_agent_orchestrator.rs` — a longer aspirational sketch.
- `examples/eigencompute_freshness_receipt.rs` — what a freshness receipt looks like in this model.

## Honest scope

This crate proves the architecture compiles and reads. It does not yet prove TEE-backed inference. Phase 2 fills the committer; Phase 3 fills the real-anchor clients; Phase 5 wires the TEE attestation chain. Each of those is its own milestone.
