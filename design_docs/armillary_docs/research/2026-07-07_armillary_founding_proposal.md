# armillary Founding Proposal

**Date:** 2026-07-07
**Status:** founding proposal. This repo's first doc. Promotes mere's
`crates/armillary` to a standalone crate. Unlike the vates and sibylla foundings
(a seam plus a stub, with backends as roadmap), this is a **complete port**: the
whole runtime, all four modules, ported and green in this commit. There is no
backend roadmap; the work below is reconciliation and adoption.

## 1. What armillary is

armillary is a host-neutral actor-kernel runtime. A single-threaded *host kernel*
owns all canonical state; a constellation of *actors* runs off-thread and talks
to it only by message. Four pieces:

- **The typed boundary** (`boundary::KernelThread`). A zero-size `!Send` marker
  embedded in the host's kernel context, so the compiler refuses to move kernel
  authority onto an actor thread. Boundary drift is a compile error, not a
  code-review catch. This is GPUI's `ForegroundExecutor` discipline distilled to
  a marker, and it is verified by a `compile_fail` doctest.
- **The actor harness** (`actor`). `spawn` runs a subsystem on its own thread,
  driven by `Send` commands and drained of `Send` updates through an `Emitter`
  plus a `Wake` callback the host supplies. The actor's internals may be `!Send`
  (a JS engine, a DOM, a layout engine) because they are built *on* the actor
  thread, never moved across the boundary. Each run is wrapped in a `tracing`
  lifecycle span so a host diagnostics bridge sees actors spawn, live, and die.
- **The worker pool** (`pool`). `spawn_on` runs an actor on a growable, reusing
  worker pool instead of a fresh thread, bounding the OS-thread count (and any
  leaked per-thread state, such as a layout engine's leaked sharing cache) to
  *peak concurrent* actors rather than total spawns. Lock-plus-condvar, no
  `crossbeam`.
- **Generations** (`message`). Monotonic counters the kernel stamps outgoing work
  with, so a result from a superseded state is dropped rather than applied.

The concrete `Command` / `Update` taxonomy and the kernel inbox belong to the
host; the runtime is generic over them.

## 2. Why a standalone crate

`crates/armillary` was built host-neutral from the start: its module docs say so,
and its dependency list is a single external crate (`tracing`), zero mere-internal
deps. It already earns its place as a shared spine; it was simply living inside
the mere workspace. Two forces pull it out now:

- **vates needs it.** The vates founding proposal
(`repos/vates/design_docs/2026-07-07_vates_founding_proposal.md` *(historical citation)* <!-- doc-audit: historical-path -->, sections 5 and
  8) flagged armillary as vates's *one* mere coupling: vates's streaming
  inference actor (roadmap P2) rides this harness. That proposal recommended
  reimplementing a thin thread-actor primitive inside vates specifically because
  armillary had not yet been read and might be a heavy mere-internal harness.
  **This founding resolves that open question in favour of promotion (that
  proposal's option 2).** armillary is 732 LOC with one external dependency and a
  clean host-neutral surface, so vates depending on it is cheaper and better than
  reimplementing an actor loop, and it gives every consumer streaming-off-the-main-
  thread for free.
- **Isometry wants the shape.** Isometry's serval host is exactly armillary's
  form: a single-threaded winit host owning GPU and the document model, with
  off-thread actors (net sessions, optional inference via vates, world
  simulation) messaging in. It consumes serval and netrender, not mere, so it
  cannot reach armillary through mere.

That makes three consumers (mere/meerkat, vates's actor, Isometry's host), which
clears the "wait for a second consumer" threshold cleanly. armillary is the
one-way shared dependency, the same pattern as the wgpu-sibling libs, vates, and
sibylla.

## 3. Origin and what is ported

Promoted from `mere/crates/armillary`. This is a complete port, MPL headers
intact, all tests included, 8 unit tests plus the `compile_fail` boundary doctest
green:

- `boundary.rs` (the `!Send` marker) ported verbatim; its doctest already imports
  `armillary::KernelThread`, so it moves unchanged.
- `actor.rs`, `pool.rs`, `message.rs`, `lib.rs`: code and tests verbatim. Only
  doc prose changed, and only to genericize references that named mere internals:
  - the crate doc dropped a concrete meerkat message-taxonomy aside and a
    mere-internal design-doc link;
  - `actor.rs` reworded illustrative references to meerkat's `fetch` / `sync`
    modules and internal plan tags into generic "a network fetcher or a sync
    host" prose, keeping the public-crate examples (winit, a JS engine);
  - `pool.rs` and `message.rs` neutralised meerkat's "tile" / "tab" vocabulary to
    "surface" and generalised a Stylo-specific aside to "a layout engine".

No code, signature, or test changed. The port is behaviour-identical to mere's.

## 4. Roadmap

Done-conditions, not time estimates. Because the port is complete, the roadmap is
adoption, not construction.

- **P0 (this commit): the port.** All four modules ported; the crate compiles and
  its tests pass with `tracing` only. **Done when** `cargo test` is green (it is).
- **P1: vates depends on armillary.** vates's actor (its own roadmap P2) is built
  on this crate rather than a reimplemented primitive. **Done when** vates streams
  inference fragments as actor updates through `armillary::spawn`, with no
  mere dependency. This retires vates open question 1.
- **P2: mere adopts the standalone crate.** mere switches `crates/armillary` to a
  git dependency on this repo (or deletes the in-tree copy per no-legacy-friction),
  so there is one armillary. **Done when** mere builds against the promoted crate
  and meerkat's kernel is unchanged behaviourally.
- **P3: Isometry adopts the harness.** Isometry's serval host moves its off-thread
  work (net, optional inference, simulation) onto armillary's kernel/actor
  boundary. This is a horizon, gated behind Isometry's own keystones exactly like
  vates and sibylla, not a blocker. **Done when** an Isometry actor emits updates
  to the host kernel through this crate.

**P3 landed 2026-07-11.** Isometry's network authority runs as an Armillary
actor. Its generated-campaign commit path also supplied the first non-browser
correlation requirement: `RequestId`/`RequestIds` and `Correlated<T>` now pair a
host command with its eventual typed outcome. The primitive is deliberately
outcome-neutral so Strophe project I/O and Turnstone action/effect execution can
reuse it without moving their command taxonomies into Armillary.

P2 and P3 are independent. P1 is the immediate motivation and the reason this
crate exists as a repo today.

## 5. The generation-vocabulary question

One corner of the port is not fully host-neutral: `message.rs` ships
`NavGeneration` and `ViewportGeneration`, named for browser navigation and
viewport. A generic actor runtime does not inherently have either. The port kept
the names and mechanism verbatim (neutralising only the surrounding "tile" prose)
for two reasons: renaming is an API change rather than a port, and it would
diverge this crate from mere's copy before the P2 reconciliation that unifies
them. Three options, to settle during P2:

1. **Keep the concrete names.** They are two useful concrete generation kinds a
   windowed host will often want, and any host is free to ignore them and stamp
   its own counters. Cost: two browser-flavoured names in a host-neutral crate.
2. **Generalise to a parametric generation.** A `Generation<Kind>` or a small set
   of host-defined generation lanes, with nav/viewport as one host's instantiation.
   Cost: a modest API change and a migration in meerkat's kernel.
3. **Move generations out of armillary entirely.** The actor harness and pool do
   not use `message` at all; it is an independent backpressure helper that rides
   along. It could live host-side (meerkat) or in a separate tiny crate. Cost: one
   more move; benefit: the runtime spine carries nothing app-flavoured.

**Recommendation: option 1 for now, revisit at P2.** The names cost nothing at
runtime and callers can ignore them; generalising is worth doing only if a second
consumer wants different generation kinds. Isometry is the natural test (it has
camera and turn generations, not navigation), so let its adoption (P3) inform the
choice rather than pre-deciding it.

## 6. Consumers, scope, licensing

- **Consumers and direction.** mere/meerkat, vates, and Isometry consume
  armillary; the flow is one-way (they depend on it, it depends on none of them).
  This mirrors the wgpu-sibling libs, vates, and sibylla.
- **Scope: the runtime spine only.** armillary is the kernel/actor boundary, the
  harness, the pool, generation counters, and request correlation. It is not an async runtime (no
  tokio, no executor), not a message bus, and names no host. A host brings its own
  event loop, its own command/update types, and its own kernel state; armillary
  supplies the discipline that keeps that state on one thread and the work off it.
- **Licensing.** Resolved after founding: the repository, manifest, and license
  files use `MIT OR Apache-2.0`, matching Isometry, Serval, and the promoted
  sibling libraries.

## 7. Open questions

1. **Generation vocabulary** (section 5): keep the concrete names (recommended
   now), parametrise, or move generations out of the crate. Settle at P2.
2. **mere reconciliation mechanism** (P2): git-dep the standalone crate, or delete
   the in-tree copy and depend outright. The latter fits no-legacy-friction; the
   former is reversible during the transition.
3. **Publish vs git-dep:** publish to crates.io (like wgpu-scry) or consume as a
   git dep first. `publish` stays off until this and the license settle, decided
   alongside the sibling crates.

## Provenance

Grounded in a read of `mere/crates/armillary` (lib, boundary, message, actor,
pool, Cargo.toml) 2026-07-07, and in the vates founding proposal that flagged the
armillary coupling. The sibling crates vates (generation) and sibylla (embedding
and retrieval) were founded the same day; this crate is the runtime spine beneath
vates's streaming actor. The name and the promotion decision are recorded in the
workspace memory.


## Execution/shutdown consolidation, 2026-10-19

Implementation follows the accepted boundary scope at
`mere/design_docs/mere_docs/implementation_strategy/2026-10-19_family_promotion_plan.md`.
The existing crate now owns ordered-close mechanics and optional Tokio task
scopes. Hosts supply policy, order and domain outcomes. Dedicated and pooled
actor handles expose fallible completion; pooled completion is distinct from
worker lifetime. Reusable draining and terminal close are separate operations.
Q112/Q113 pool scheduling/retirement remain explicit; the Mere receiving pass
must qualify actual domain close behavior and inference-disconnection Q217.

Validation so far: the pooled cleanup control fails against the previous source;
the same control and dedicated/pooled panic tests pass after the change. Shared
close tests preserve capture release order and multiple errors. Task tests cover
nested release, reaped panic reporting, reusable drain and terminal refusal.
Git-only receiving and Mere integration gates are recorded in the owning plan.


Execution/shutdown receiving qualification (2026-10-19): the final implementation
at `e67c5def1c735be047492a867bcdc8b41fba22b8` preserves Send/Sync actor handles
and cumulative terminal-close failures. Nineteen unit/integration/doc tests pass.
The qualified Mere receiving gates cover Distillery actor loss and resident close,
Graphshell doors, Djinn tasks, Fleece and an independent synchronous Git consumer;
its browser target compiles. Exact consumer pins and scope limits are in
`mere/design_docs/mere_docs/implementation_strategy/2026-10-19_family_promotion_plan.md`.
The ordered-close helper collects returned Result errors; it does not convert
arbitrary resource-close panics into Result failures. Pool Q112/Q113 and the
later observation/custody boundaries remain separate gates.


## Pool admission and retirement repair, 2026-10-21

Q112 and Q113 are now repaired in the execution package. Admission compares the
queued demand with waiting and starting workers under one mutex, so a notified
worker cannot be promised to multiple long-lived jobs. Public pool ownership is
separate from worker state. The final public handle wakes all waiters; accepted
jobs finish and workers then exit, releasing shared pool state.

Drop remains nonblocking. It neither cancels jobs nor joins OS threads, and a
job retaining a pool clone keeps the pool open. Actor completion remains its
own observation. `workers()` counts all threads spawned, not current liveness.

Both selected regression controls fail on the old source at the intended
assertions and pass after repair. The default workspace has 38 passing tests;
all features have 43, including the unchanged 18 Apparatus tests. All 43 also
pass on Rust 1.97.1. Formatting and focused pool Clippy pass; broader strict
Clippy encounters two unchanged actor/task lint findings, recorded with exact
commands in [the repair receipt](../../../support/receipts/pool-lifetime-20261021.json).
The synchronous normal dependency tree still excludes Tokio. Consumer intake
is qualified separately in Mere's existing family-promotion plan.


## Demand admission consolidation, 2026-10-29

**Status: landed, supplier-qualified.** Turnstone's place and optional protocol adapters need
one deferred admission rule over this crate's existing actor harness. Product
commands, configuration keys, refusal updates and authorization remain with
the host. The runtime owns the once-only actor factory, coalesced passive
configuration and the update inbox; it does not add a pool or another loop.

The ownership target is demand admission without eager workers. Its validation
covers first demand, replacement/withdrawal of pending configuration, honest
absence and command-channel closure when the final sender drops while an inbox
is still retained. Receiving adoption removes the product's local copy.

Generic resource initialization uses the standard library's `LazyLock` rather
than another Armillary synchronization type. Initialization of native engines,
media, device readers and publishing resources remains with their owners.


Qualification (2026-10-29): 18 default-feature tests and 18 all-feature tests
pass. The retained negative control failed when the inbox prolonged command
ownership. The shared gate now closes the actor after its last sender, permits
inbox draining, releases unstarted configuration and preserves queued refusals.
The six demand controls cover concurrent first use, coalescing, withdrawal,
absence and both started and unstarted close paths. Existing actor and pool
controls remain green. No product, device or platform presentation is qualified
by this supplier gate.
