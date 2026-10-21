# Armillary

Host-neutral execution mechanics and independent bounded observation infrastructure.

This repository preserves the implementation history promoted from Mere on 2026-10-19. The initial extraction preserved crate names, APIs, licenses and selectable features. The execution/shutdown continuation adds fallible actor completion and optional async task scopes; see the crate documentation.

Canonical migration: `mere/design_docs/mere_docs/implementation_strategy/2026-10-19_family_promotion_plan.md`.

| Crate | Source |
|---|---|
| `armillary` | [crates/armillary](crates/armillary) |
| `apparatus-core` | [crates/apparatus-core](crates/apparatus-core) |

Run `cargo test --workspace` for default library coverage. Optional network, GPU, external model and host acceptance have separate gates. No registry release is implied by this source promotion.

`apparatus-core` is a sibling library with no dependency on the actor runtime.
Its default library uses only `std`, with optional Serde. Mere retains its
Registry collector and accessibility adapters behind the existing
`mere-apparatus` API. Producers retain redaction, outcome and persistence
authority; moving observation storage does not install a global collector.
