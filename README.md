# Armillary

Host-neutral execution mechanics, bounded observation, and independent application residency.

This repository preserves the implementation history promoted from Mere on 2026-10-19. The initial extraction preserved crate names, APIs, licenses and selectable features. The execution/shutdown continuation adds fallible actor completion and optional async task scopes; see the crate documentation.

Canonical migration: `mere/design_docs/mere_docs/implementation_strategy/2026-10-19_family_promotion_plan.md`.

| Crate | Source |
|---|---|
| `armillary` | [crates/armillary](crates/armillary) |
| `apparatus-core` | [crates/apparatus-core](crates/apparatus-core) |
| `djinn` | [crates/djinn](crates/djinn) |

Run `cargo test --workspace` for default library coverage. Optional network, GPU, external model and host acceptance have separate gates. No registry release is implied by this source promotion.

`apparatus-core` is a sibling library with no dependency on the actor runtime.
Its default library uses only `std`, with optional Serde. Mere retains its
Registry collector and accessibility adapters behind the existing
`mere-apparatus` API. Producers retain redaction, outcome and persistence
authority; moving observation storage does not install a global collector.


## Demand admission

`armillary::demand::{DemandActor, DemandUpdates, Admission}` layers deferred
admission over the existing actor harness. Hosts authorize and classify their
own commands. Replaceable passive configuration waits without starting an
actor; first demand consumes the configured factory once and forwards that
configuration before the command. A missing factory can publish a typed refusal.

Command ports may be cloned. Dropping the final port closes the actor's command
channel with the harness's existing nonblocking drop behavior, while the inbox
can still drain. An unused factory and its pending configuration are released
without opening resources. This gate adds no worker pool, renderer, transport
or product identity types. Once-only resource initialization can use the
standard library's `LazyLock` directly.

Djinn owns the finite application door, selected native custody clients, and
resident service/task lifetimes. Mere supplies concrete product composition in
`mere-resident`, retaining the `djinn` executable names. Armillary itself has no
Djinn or product dependency. See [Djinn features and authority boundaries](crates/djinn/README.md)
and the [qualification receipt](support/receipts/djinn-ownership-20261030.json).
