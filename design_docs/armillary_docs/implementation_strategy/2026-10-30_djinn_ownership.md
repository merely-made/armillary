# Djinn ownership extraction implementation plan

> For agentic workers: use subagent-driven-development, with focused source review and bounded qualification for each boundary.

**Status:** 2026-10-30, implementation and qualification in progress.

**Goal:** Put independent Djinn application protocol and resident lifetime ownership beside Armillary, leaving concrete Mere assembly in `mere-resident`.

**Architecture:** Djinn owns the finite application door, selected native/custody clients, common application handshake and resident task/shutdown sequence. Graphshell owns projection adaptation; Mere constructs and supplies product services and protected custody authority. Armillary mechanics remain independent.

**Tech stack:** Rust 1.97.1, Cargo features, Tokio, existing Armillary tasks/lifecycle, Serde guarded frames.

**Spec:** Mark's explicit 2026-10-30 ownership-cut authorization in this conversation. This records its implementation boundaries; it adds no approval checkpoint.

## Global constraints

- Preserve provider-offer delivery and its policy, lease generations, work ordering, cancellation and disconnect behavior. Publish that baseline first; new supplier edits are isolated.
- One `djinn` package in Armillary; Mere package becomes `mere-resident` at its existing path with executable names unchanged. No extra client/broker crates.
- Default features empty. Portable `door`; native `door-native`, `door-serve`, `custody`, `custody-client`; native `resident` enables Armillary lifecycle/task orchestration. No Chirograph/scenes/Mere/Knot/Distillery dependencies in independent Djinn.
- Identity domain types stay Dramatis/Personae. Remove convenience identity re-export and migrate every live receiver directly to `dramatis::view`.
- Same endpoint/env/schema strings, native-endian 1 MiB framing, safe JSON category/line/column errors, guarded owned buffers, session/nonces/request IDs, locked custody, host grants and mandatory projection validators.
- Custodian/Castellan and custody-wire remain protected separate authority. Mere supplies custody dispatch, not a newly generalized authority framework.
- Heavy builds: shared machine-heavy.lock, 3 GiB, zero swap, 150% CPU, one Cargo job/test thread, 600-second cap. Retain failures and exact log hashes. Immediate migration and supplier-before-consumer pins/publication.

## Review focus

- Dynamic provider permission must preserve explicit route denial and lease cancellation after shared admission moves.
- Locked custody must enter after app handshake without projection admission or door keys.
- Browser and application transcript binding must share one nonce implementation without changing domain bytes.
- Listener termination must fence and join tracked children before product close actions, preserving run and shutdown failures.
- Isolated feature fixtures must prove absence of product imports and APIs without dev/workspace feature unification; portable Wasm stays portable.

## Task 1: Independent client/protocol owner

Files: new `crates/djinn/{Cargo.toml,src/lib.rs,src/door/*}`; workspace membership; endpoint adapter manifest/modules in Mere.

- [ ] Copy existing neutral app_admission, route, wire, frame, local_endpoint, app_client, custody, custody_client, custody_identity, custody_payload, quarantine implementation into Djinn. Preserve wire/security tests. Route retains host route ID/cadence only; it has no Graphshell dependency.
- [ ] Keep projection, provider offer/runner, resident_mere_proxy and application profile adapters with Graphshell. Move projection-specific tests to their adapter owner; remove identity convenience module.
- [ ] Give each dependency explicit feature/target ownership. Native methods remain unavailable on Wasm. Use supplier-local Armillary dependency; pin domain suppliers to audited current revisions.
- [ ] Verify moved native unit tests, safe malformed/unexpected secret payload tests, exact wire fixtures, portable build and negative API consumer fixtures.

## Task 2: Application admission and resident lifetime

Files: new Djinn `door/server.rs`, `door/link.rs`, `resident.rs`; Mere app_broker/browser_carrier and bin/djinn.rs adapters.

- [ ] Move shared hello read/validation and application challenge/connect into narrow server functions with host-supplied route resolution. Preserve dynamic provider grant augmentation and explicit deny precedence in Mere adapter.
- [ ] Move LocalLink binding and nonce checks unchanged into Djinn; browser adapter owns browser message validation then calls shared bind.
- [ ] Move application listener/session ownership into Djinn using existing LocalListener/Armillary tracking. Product adapter supplies the admitted service continuation, not raw generic JSON.
- [ ] Implement resident orchestration owning the existing task scope and executing child drain before supplied product shutdown. Preserve stop/works release sequence and combined failures; keep concrete refresh/lock callbacks in Mere.
- [ ] Run nonce/transcript, host admission, locked custody, offer revoke/disconnect/close and bounded lifecycle regressions.

## Task 3: Immediate consumers and composition identity

- [ ] Rename existing Cargo package/library to mere-resident; keep executable names. Migrate all internal tests/examples/binaries.
- [ ] Move neutral imports to Djinn and identity views to Dramatis across Mere and current external consumers, preserving application GraphshellIdentity/profile choices.
- [ ] Replace endpoint neutral features with direct Djinn feature requests; projection adapters depend downward on Djinn. No compatibility module/re-export period.
- [ ] Use temporary local supplier overrides only for qualification; remove them before supplier-first publication and receiving git pins. Audit lock package identities and dependency edges, preserving unrelated versions.

## Task 4: Qualification, review and publication

- [ ] External fixture cones: portable/native connection/custody DTO/client/resident and Graphshell projection/provider/combined Mere; nonzero tests and forbidden API checks, portable Wasm.
- [ ] Run real consuming targets including binaries/examples/tests, host mandatory validator regressions, existing frame/error/wipe/custody invalidation suites and provider integration.
- [ ] Independent source/diff review; resolve findings, preserve receipts and limitations. Windows stays unqualified absent executor receipts.
- [ ] Fetch/reconcile, publish Armillary supplier then Mere and live receivers with exact staged files and pins; report published hashes, cone evidence and receipt paths.

## Findings and progress

2026-10-30: Provider offers published in Mere46e339b11 and Knot63ba1b9c, receipts Mere4e75bd4b. Independent review found and corrected maintenance-action cancellation and surface-snapshot ordering in the extraction. Supplier native tests and initial isolated fixtures passed; integrated consumer gates remain pending.
