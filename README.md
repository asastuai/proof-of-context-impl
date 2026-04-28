# proof-of-context

> *PAL\*M attests that a computation happened correctly; Proof-of-Context makes those attestations economically perishable — binding freshness to settlement so stale inferences cannot clear payment.*

Reference implementation of the **proof-of-context** primitive: an *attestation-as-settlement* layer for decentralized machine learning.

**Position paper:** [github.com/asastuai/proof-of-context](https://github.com/asastuai/proof-of-context) — v0.6 (22 April 2026). Read the paper first; this crate encodes the architecture it names.

**Status:** `v0.1.0-scaffold`. Traits and types are in place, all primitive implementations are `unimplemented!()` stubs. The crate compiles and the smoke tests pass. No cryptographic claim is enforced yet.

---

## What this crate is for

Existing verification primitives in decentralized ML (proof-of-learning, zkML, TEE attestations, refereed delegation, inference-activation LSH) answer the question *"was the computation correct?"* They do not answer *"is it still worth settling on?"*

Proof-of-context sits on top of those primitives and gates payment against a *freshness commitment*: a signed bundle of `(execution_context_root, triple_anchor, output_hash)` that expires. If a worker's commitment has aged beyond the protocol-defined horizon when settlement is attempted, payment does not clear — regardless of whether the underlying math was correct.

This crate provides the Rust types and traits for building such a protocol layer.

## Architecture at a glance

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full mapping from paper sections to crate modules.

| Paper section | Module | Core type / trait |
|---|---|---|
| §6 — Four Freshness Types | `freshness` | `FreshnessType`, `FreshnessThresholds` |
| §7 constraint 6 — Triple Anchor | `anchor` | `TripleAnchor` |
| §8 — Execution-Context Root | `context` | `ExecutionContextRoot`, `merkle_root()` |
| §7 constraint 5 + §8 | `commitment` | `FreshnessCommitment`, `ContextCommitter` |
| §3.6 + §6 — Settlement gating | `settle` | `SettlementGate`, `SettlementResult` |
| §7 constraint 5 — Prospective-only bumps | `renewal` | `Renewal`, `RenewalOutcome` |
| §7 constraint 6 + §9 | `attestation` | `AttestationChain`, `AttestationVerifier` |

## Scaffold-stage design

Per the project's working-bible, the current phase is **Phase 2: Scaffold** — structure compiles, nothing does anything useful. Implementations will arrive in subsequent phases.

```rust
use proof_of_context::{
    ExecutionContextRoot, TripleAnchor, FreshnessThresholds,
    context::{SamplingParams, AttentionImpl, PrecisionMode, InferenceConfig},
};

// All types are constructible.
let thresh = FreshnessThresholds::default_base_mainnet();
let anchor = TripleAnchor::new(/*block*/ 100, /*tee_ns*/ 0, /*drand*/ 50_000);

// Calling unimplemented methods panics with "Phase 2: ..." messages
// that tell the reader exactly what is yet to be built.
```

Every `unimplemented!()` body in the crate includes a brief description of what the future implementation must do.

## Build and test

```bash
cargo build
cargo test
```

Both should succeed on a stock Rust toolchain (2021 edition). No external dependencies at scaffold stage.

## Roadmap

See [`ROADMAP.md`](./ROADMAP.md) for phased plans. Rough order:

1. **Scaffold (this release).** Traits, types, architectural bones.
2. **Primitives.** SHA-256 Merkle root for execution context; Ed25519 signing; in-process triple-anchor check.
3. **Mock backend.** Software-only committer + settlement gate that exercises the full flow end-to-end in tests.
4. **TEE backend.** TDX + H100 attestation chain verification hooked into the committer.
5. **Drand client.** Real fetch of Drand mainnet rounds; block-RPC client for anchor construction.
6. **SUR Protocol integration.** First deployment — wire proof-of-context into the SUR settlement rail (see [github.com/asastuai/sur-protocol](https://github.com/asastuai/sur-protocol)).

## License

Licensed under either of:

- MIT License ([LICENSE-MIT](./LICENSE-MIT))
- Apache License, Version 2.0 ([LICENSE-APACHE](./LICENSE-APACHE))

at your option. The position paper is released under CC BY 4.0; the code in this repository is released under the dual MIT / Apache-2.0 license that is standard for the Rust ecosystem.

## Author and contact

Juan Cruz Maisu — `juancmaisu@outlook.com` — [github.com/asastuai](https://github.com/asastuai).

---

## Body of work

This crate is part of an evolving body of work by Juan Cruz Maisu, independent researcher in Buenos Aires, Argentina:

- [Proof of Context (papers)](https://github.com/asastuai/proof-of-context) — v0.6 framework + v0.1 applied to verifiable inference
- [Proof of Context — reference implementation](https://github.com/asastuai/proof-of-context-impl) — this crate
- [SUR Protocol](https://github.com/asastuai/sur-protocol) — perp DEX with agent-native execution layer
- [Hermetic Computing](https://github.com/asastuai/kybalion) — Rust framework formalizing hermetic principles as computational primitives
- [intent-cipher](https://crates.io/crates/intent-cipher) — published crate, stream cipher with intent-keyed schedule

**Status:** open to research-engineering and applied-research roles in inference attestation, decentralized ML infrastructure, and agent-native systems. Remote, full-time, any timezone.
