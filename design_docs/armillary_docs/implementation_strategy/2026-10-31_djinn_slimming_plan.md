# Djinn slimming plan

**Status:** 2026-11-02, done: S0 to S5 (D1 to D24).
Consumers outside Armillary and Dramatis still pin Djinn revisions from
before the cut and move in S4. Findings were measured against Armillary `019d1e5` (Djinn's sources
unchanged since `104b8d4`) and Mere `23bb596e2`.

**For:** Mere's distillery extraction D18 ("Publish the djinn chain, but also,
aren't we supposed to be moving those services so djinn isn't a god crate and
can just be execution?", then "Slim, then publish"), whose fork F4 this plan
answers. `graphshell-endpoint` 0.0.3 cannot publish while it depends on
`djinn`, because Djinn links the identity services and the unpublished
`peer-facts`. Producers should depend on the door's wire contract, not on the
runner.

**Not here:**
- `mere-resident`, the 47,632-line composition still built as the `djinn`
  binary, is the larger god crate. Its lanes (`resident_distillery`,
  `resident_inference`, `resident_knot`, the sites, sync, the identity UI)
  move to their producers in the next plan, under the producer/host/runner
  survey (`mere:distillery-extraction` D10) and the store-lifetime fork
  (`mere:distillery-extraction` F1).
- The custodian and `custody-wire` moved from Mere to Dramatis on 2026-11-03
  (`dramatis/design_docs/2026-10-28_custody_plan.md`, D14). Castellan stayed in Mere here
  (the archived Dramatis plan's ruling D6, 2026-10-06) and moved to Dramatis on
  2026-11-03 (its current repo plan, D11 to D13), with the pandect wallet store as
  `sporran` and gazette's directory domain. This plan moves the application side
  of the custody route only.
- WIT contracts and OS channels (capability door C0, D1, D3).

## Decisions

- **D1. The library first, the resident next (Mark, 2026-10-31):** "Library
  now, resident next (Recommended)", over slimming both in one plan or only
  `mere-resident`. This plan takes the custody half out of Armillary's `djinn`
  so the publish chain unblocks; `mere-resident`'s services move in their own
  plan.

  Links: area Stack · draws on mere:stack.3 · plans mere:distillery-extraction D18 · summary Slim the Djinn library now; mere-resident's lanes move to their producers in the next plan.

- **D2. The custody client goes to Dramatis (Mark, 2026-10-31):** "New crate
  in Dramatis (Recommended)", over keeping it in Djinn behind a feature or
  moving it into Mere beside Castellan. Dramatis owns identity and ruled this
  route (its repo plan's D5, D11, DR-C). The new crate depends on the door
  contract (D3), never on Djinn. Its name goes through a naming round.

  Links: area Stack · draws on mere:stack.3 · amends djinn-ownership "one djinn package, no extra client crates" · summary The custody route's application side becomes a Dramatis crate over the door contract.

- **D3. A separate door contract crate (Mark, 2026-10-31):** "Separate
  contract crate (Recommended)", over Djinn's `door` feature serving as the
  contract. Djinn landed ten commits in two days, and each 0.0.x bump breaks
  every producer's `[patch]` match, as it did for Knot on 2026-10-31. The
  contract changes only when the wire does. It holds the wire, frame, route,
  declaration and admission types, plus the client half (`app_client`, the
  `local_endpoint` dialer). Djinn keeps the server, link, launch, grant logic
  and resident. Its name goes through a naming round.

  Links: area Stack · draws on mere:stack.1, mere:stack.3 · amends djinn-ownership "one djinn package" · plans mere:distillery-extraction D18 · summary Producers depend on a small door contract crate in Armillary; Djinn keeps the serving half.

- **D4. Cut after capability-door I1 (Mark, 2026-10-31):** "Plan now, cut
  after I1 lands (Recommended)", over starting now and rebasing over I1, or
  asking the door lane to schedule it. Armillary took door commits at 17:30
  and 22:40 that day (launch handles, Windows peer identity). Mere's
  distillery P2 stays paused until this plan lands.

  Links: summary Execution waits for capability-door I1 to land; the plan is written now.

- **D5. The door contract crate is `ostiary` (Mark, 2026-11-01):** "ostiary",
  over `djinn-door` (recommended), `djinn-wire` and `doorward`. The ostiary is
  the doorkeeper, a minor order. Its lean toward the serving side, which
  stays in Djinn, and its obscurity were stated when it was offered. On
  2026-11-01 crates.io had it free; postern, wicket, lintel, threshold and
  porter were taken.

  Links: plans djinn-slimming D3 · summary The door contract crate is named ostiary.

- **D6. The custody crate is `castellan-client` (Mark, 2026-11-01):** Asked
  for a name, Mark wrote "Why don't we repurpose castellan? If it is no longer
  necessary…". It is still necessary: Castellan is the custody authority
  (27,573 lines: the vault, the unlock ladder, the SSH agent, wallet seeds),
  linked only by Djinn's custodian, and `castellan` 0.0.3 on crates.io is
  ours. Put back with that finding, he chose "castellan-client
  (Recommended)", over `suppliant`, `claviger` and `petitioner`. The client is
  the app's side of Castellan's "gate petition". It lives in Dramatis, and
  Castellan stayed in Mere (the archived Dramatis plan's D6) until it moved there
  too on 2026-11-03.

  Links: plans djinn-slimming D2 · summary The custody client crate is named castellan-client, the petitioning side of Castellan.

- **D7. Claim the names by publishing real code (Mark, 2026-11-01):** "Real
  publish at S5", over 0.0.1 reservation stubs now. Both names stay exposed
  until S5 (the ledger's heddle risk, stated when offered).

  Links: summary ostiary and castellan-client are claimed by S5's real publish, not by stubs.

- **D8. The socket fallback is inlined and pinned (Mark, 2026-11-01):**
  "Inline + pin (Recommended)", over keeping a native `personae` dependency or
  giving the door its own directory. Off Windows, without `XDG_RUNTIME_DIR`,
  the endpoint is `personae::default_vault_dir()` joined with
  `graphshell-app.sock`: `$XDG_DATA_HOME` or `~/.local/share`, then
  `personae/vault`. macOS never sets `XDG_RUNTIME_DIR`, so that is the macOS
  default. Ostiary copies the derivation, and a test pins the path, so no
  installed client or resident moves and the contract never reaches Dramatis.

  Links: closes djinn-slimming F1 · summary ostiary inlines the vault-directory socket fallback with a test pinning its path; no personae dependency.

- **D9. Ostiary reserves the byte path W1 needs (Mark, 2026-11-01):**
  "Reserve byte path now (Recommended)", over moving the JSON wire unchanged
  and letting W1 change ostiary later, or doing W1's door step first.
  Capability-door D21 and W1 (Mere `23bb596e2`) move the projection
  session's door path onto the generated WIT calls as it is next touched, and
  after the hello today's door speaks only JSON frames. In S2 ostiary hands
  out the admitted stream after the hello, so W1 binds script-wire's
  transport to it in `graphshell-endpoint`. Ostiary never depends on
  script-wire. Custody, MCP and overmap stay on the JSON wire, which W1 does
  not cover.

  Links: draws on mere:capability-door D21, W1 · closes djinn-slimming F3 · summary ostiary exposes the admitted stream after the hello so W1 can carry the WIT calls over the door; script-wire stays above it.

- **D10. Moved tests open over a stream (Mark, 2026-11-01):** "open_over(stream)
  (Recommended)", over a `testkit` feature exposing a handshake-free
  constructor or rewriting the custody tests with neutral payloads. Two
  custody tests built an `AppConnection` from its private fields;
  `AppConnection::open_over(stream, hello)` runs the real handshake over a
  stream the caller holds (D9's `into_stream` is its inverse), and the moved
  tests drive a host's side of it.

  Links: plans djinn-slimming S2 · summary ostiary's AppConnection::open_over runs the handshake over a given stream; the moved custody tests use it.

- **D11. Ostiary keeps the module names, flat (Mark, 2026-11-01):** "Same
  names, flat (Recommended)", over shorter names or keeping a `door::` level.
  `djinn::door::{app_admission, app_client, declaration, frame, launch,
  local_endpoint, route, wire}` become `ostiary::…`, so S4 is a path rewrite.

  Links: plans djinn-slimming S2, S4 · summary ostiary's modules keep Djinn's door module names at the crate root.

- **D12. Djinn keeps its feature names (Mark, 2026-11-01):** "Keep the names
  (Recommended)", over collapsing to `door-serve`. `door` is ostiary plus the
  owner's grants, `door-native` turns on `ostiary/native`, and `door-serve`
  is unchanged, so no consumer's feature list changes in S4.

  Links: plans djinn-slimming S2, S4 · summary Djinn's door, door-native and door-serve features keep their names over ostiary.

- **D13. Custody admission is a method on the call (Mark, 2026-11-01):**
  "Method on CustodyCall (Recommended)", over an extension trait or a free
  function. `impl AppAuthority { admit_custody }` in custody could not stay
  once `AppAuthority` moved to ostiary; `CustodyCall::admitted_by(&authority)`
  moves to castellan-client in S3 with the call type. mere-resident's one
  caller (`ports/mere-resident/src/custody.rs:279`) changes in S4.

  Links: plans djinn-slimming S3, S4 · summary authority.admit_custody(&call) becomes call.admitted_by(&authority).

- **D14. M1 lands first, and S4 carries its Mere side (Mark, 2026-11-01):**
  "M1 lands, then S3, S4 carries it (Recommended)", over the M1 lane adopting
  in Mere after S4 or before it. Capability-door M1's Armillary change
  (`m1/manifests`, `bd77d60`, on S2) edits `custody_identity.rs`, which S3
  moves, so it lands on Armillary main before S3 starts. S4 repoints Mere to
  a revision that includes it and takes M1's Mere branch (`f427b6466`) in the
  same change: `admitted_by` in `custody.rs`, the broker's consent refusal,
  and the payload seal scope from `AppAuthority::payload_scope`. Because M1
  refuses undeclared hellos, the repin changes behaviour as well as paths.

  Links: draws on mere:capability-door M1 · plans djinn-slimming S3, S4 · summary M1's Armillary commit lands before S3; S4's Mere repin carries M1's Mere branch in one change.

- **D15. castellan-client's types are its default; `client` adds the clients
  (Mark, 2026-11-01):** "Types default, `client` feature (Recommended)", over
  no features or Djinn's feature names. Djinn's `custody` becomes
  castellan-client's default features and `custody-client` becomes `client`,
  which keeps the custody-types fixture's split.

  Links: plans djinn-slimming S3, S4 · summary castellan-client defaults to the custody types; its client feature adds the clients.

- **D16. castellan-client keeps the module names, flat (Mark, 2026-11-01):**
  "Same names, flat (Recommended)", over dropping the `custody_` prefix, as
  D11 did for ostiary: `castellan_client::{custody, custody_client,
  custody_identity, custody_payload, quarantine}`.

  Links: plans djinn-slimming S3, S4 · summary castellan-client's modules keep Djinn's custody module names.

- **D17. The custody fixtures move to Dramatis (Mark, 2026-11-01):** "Move to
  Dramatis (Recommended)", over dropping them. Armillary's
  `support/fixtures/djinn/{custody-types,custody}` became Dramatis's
  `support/fixtures/castellan-client/{types,client}`, with a check script that
  forbids Djinn, Armillary's serving crates, castellan and product crates.

  Links: plans djinn-slimming S3 · summary The custody fixtures and their check move to Dramatis with castellan-client.

- **D18. Dramatis repins ostiary in step with the consumers (Mark,
  2026-11-02):** "Bump Dramatis in step", over each consumer patching ostiary
  (recommended). castellan-client pinned ostiary at Armillary `0ccfe7a`; the
  consumers pin Djinn at `08ebbc4`, whose ostiary is byte-identical but a
  different source, so a lock would hold two. Dramatis repins first, and the
  consumers name the same revision. Until S5 publishes, an Armillary repin in
  the consumers takes a Dramatis repin with it. Mere still lists ostiary in
  its `[patch."…armillary.git"]` table, because that table moves every
  Armillary crate to the `www.` source.

  Links: plans djinn-slimming S4 · summary castellan-client's ostiary pin moves with the consumers' Armillary revision; Mere also patches ostiary.

- **D19. M1's Mere branch merges as it is, S4 on top (Mark, 2026-11-02):**
  "Merge it, S4 on top (Recommended)", over squashing M1 and S4 into one
  commit. `m1/manifests` (`f427b6466`, three commits) still pins Djinn
  `104b8d4`, so its commits do not build alone; Mere main builds at the
  merge.

  Links: plans djinn-slimming D14, S4 · summary S4's Mere change merges m1/manifests with its commits, then repoints.

- **D20. S4 carries M1's Cleromancy branch too (Mark, 2026-11-02):** "S4
  carries it too (Recommended)", over the M1 lane rebasing after S4.
  `m1/declarations` (`e1da5b1`) declares Cleromancy's door routes, which a
  resident under M1 requires, so it lands with Cleromancy's repoint, as D14
  does for Mere.

  Links: draws on mere:capability-door M1 · plans djinn-slimming S4 · summary Cleromancy's repoint merges m1/declarations in the same landing.

- **D21. Knot drops Djinn (Mark, 2026-11-02):** "Drop Djinn entirely
  (Recommended)", over keeping its `door-serve` dev-dependency. Knot names
  nothing that stays in Djinn, so it depends on `ostiary` (`native`) and
  `castellan-client` (`client`) alone. A test that needs the serving side
  comes back as a fork.

  Links: plans djinn-slimming S4 · summary knot-editor depends on ostiary and castellan-client, not Djinn.

- **D22. The seal scope is declared, with the label table as fallback (Mark,
  2026-11-02):** "2 and make removing the fallback part of the m1 lane", over
  keeping the label table (recommended) or switching outright. D14 had S4
  carry the seal scope, but M1's Mere branch still chose it by label, and
  neither Turnstone nor Graphshell declared one; grants on disk pin none.
  Mere's `custody/payload.rs` seals under `AppAuthority::payload_scope` when
  the scope is declared and granted, and under the label's scope otherwise,
  so nothing is refused. Graphshell declares its existing string. Removing
  the fallback, after Turnstone declares, is the M1 lane's (capability door
  D30).

  Links: amends djinn-slimming D14 · draws on mere:capability-door D30 · summary Retained content seals under the declared, granted scope, falling back to the label's; the M1 lane removes the fallback.

- **D23. Dramatis releases personae 0.3.1 and dramatis 0.0.4 first (Mark,
  2026-11-02):** "personae 0.3.1, dramatis 0.0.4 (Recommended)", over 0.4.0 and
  0.1.0 or stopping at ostiary and peer-facts. castellan-client uses
  `personae::carry::RemoteAuthRevocationOutcome` and `dramatis::authentication`,
  which the published 0.3.0 and 0.0.3 lack; the repo's changes are additive.
  The drift check also found `insigne` 0.0.2 and `chatelaine` 0.0.3 identical
  to their published crates.

  Links: plans djinn-slimming S5 · summary personae 0.3.1 and dramatis 0.0.4 release the additive Dramatis changes castellan-client needs.

- **D24. Armillary 0.1.2, then Djinn (Mark, 2026-11-02):** "Publish armillary
  0.1.2, then Djinn", over deferring Djinn. Djinn's `resident` and `door-serve`
  need armillary's `tokio` feature, which 0.1.1 lacks; the repo's changes since
  (the `demand` module, `actor`, `boundary`) are additive.

  Links: plans djinn-slimming S5 · summary armillary 0.1.2 releases the additive actor changes so Djinn 0.0.3 can publish.

## Open forks

None. F1 was closed by D8, F2 by D5 to D7 and F3 by D9.

## Findings

2026-11-01 (S0), against Armillary `019d1e5` and Mere `23bb596e2`:

- **Djinn is unchanged since `104b8d4`.** The sizes below hold (8,039 lines);
  the local manifest reads 0.0.3, and crates.io has 0.0.2.
- **What I1 added, by side of the seam:**
  - `launch.rs` splits. `LAUNCH_FD_ENV`, `LAUNCH_FD`, `inherited()` and
    `claim()` (lines 25-76, std only) are the launched child's side, and
    `app_client` calls `inherited()` on every route hello: contract.
    `Launched`, `launch`, `launch_command`, `end` and `end_process`
    (`door-serve`, `libc`, `peer-facts`) stay in Djinn.
  - `LaunchHandle` and the hello's `launched` field, with
    `AppAdmissionError::InvalidLaunch`: contract.
  - `declaration.rs` gained `AppIdentity`, `SignedAppIdentity`,
    `WindowsAppIdentity`, `LinuxLaunch`, `IdentityBasis`, `AppGrant` and
    `AppAuthority`. None uses `peer-facts`, so the whole file stays in the
    contract as grant vocabulary.
  - `AllowedAppRoutes::identify`, `begin_process` and `end_process` take
    `peer_facts` types: Djinn, with the rest of the grant logic.
  - `local_endpoint`'s listener and `server` now hand `peer_facts::Connected`:
    Djinn. The dialer is still free of peer facts.
- **The new `wit` feature does not touch the door.** `graphshell-endpoint`'s
  `src/wit` names no `djinn` path. Its door carrier (`src/door/projection.rs`)
  is the one W1 moves, which D9 makes room for.
- **Consumers the table missed:** isocosm's `isocosm-genet` (`custody-client`,
  `CustodyIdentity::connect_as`, pinned to Armillary `7eebeeb`), and
  Armillary's own `support/fixtures/djinn` (`portable`, `native`, `custody`,
  `custody-types`, `resident`, and `check.sh`). Both are added to the table.
- **crates.io, 2026-11-01:** `ostiary`, `castellan-client`, `peer-facts`,
  `script-wire` and `script-witgen` are free. `chirograph` is at 0.0.3, and
  its source has changed since then (capability-door D20). `sceno` is at
  0.0.7. Because `graphshell-endpoint`'s optional `wit` dependencies must be
  published too, the D17 chain gains `script-wire` and `script-witgen` and
  needs a fresh `chirograph`.

2026-10-31, against Armillary `104b8d4`:

- **Size.** `crates/djinn` is 8,039 lines:
  - the door core: `app_admission` 1,173, `declaration` 779, `frame` 495,
    `wire` 201, `route` 80;
  - native: `local_endpoint` 838, `app_client` 524, `launch` 280;
  - serving: `server` 117, `link` 81;
  - custody, about 2,850: `custody_identity` 1,137, `custody_client` 811,
    `custody` 674, `custody_payload` 166, `quarantine` 60;
  - `resident` 556.
- **The heavy dependencies are custody's.** `dramatis`, `chatelaine`,
  `insigne`, `eidetic` and `uuid` appear only in the custody modules.
  `personae` appears there, in tests, and in F1's fallback.
  `peer-facts` and `armillary` belong to the serving half (`door-serve`,
  `resident`).
- **One-way coupling.** The custody modules use `app_admission`,
  `app_client`, `declaration` and `frame`. The door uses custody only in
  tests: `app_client.rs:359-428` and `wire.rs:130-147` build custody answers
  as sample payloads. Those tests move with custody or switch to neutral
  payloads.
- **Grant vocabulary stays in the door.** `declaration` holds `CustodyUse`,
  `EpochUse`, `CustodyOperation` and `SaltSource` as grant terms (capability
  door D9 and I1). They are plain types with no service dependencies, so they
  stay in the contract.
- **The dialer needs no peer facts.** `connect_local`
  (`local_endpoint.rs:121`) uses none; the listener, Windows client
  verification and Unix endpoint checks are all `door-serve`. The contract
  takes the dialer, and Djinn keeps the listener.
- **`app_admission` mixes types and logic.** Its public types (`AppId`,
  `AppRouteId`, `AppHello`, `AppRequest`, `LaunchHandle`, `AppAdmissionError`,
  the endpoint functions) are contract. `AllowedAppRoutes` and
  `AppRouteGrants` with their process map are admission logic and stay in
  Djinn. S2 splits the file along that seam.
- **crates.io.** `djinn` 0.0.1 and 0.0.2, `armillary` 0.1.1 (current),
  `dramatis` 0.0.3, `chatelaine` 0.0.3, `insigne` 0.0.2, `personae` 0.3.0 and
  `eidetic` 0.0.2 are published. `peer-facts` and `apparatus-core` are not.
  Before publishing, check the Dramatis crates' crates.io source against
  their git pins; the contract crates had drifted (distillery-extraction
  D17).
- **Consumers.** Library uses of `djinn::` paths, by crate:

  | Consumer | Uses | Moves to |
  | --- | --- | --- |
  | `graphshell-endpoint` (`projection-door`, `-offer`, `-provider`) | admission types, `app_client`, `declaration`, `wire`, `frame` | contract |
  | `graphshell-endpoint` (`profile`) | `custody`, `custody_client` | custody crate |
  | `graphshell-host` | `route` | contract |
  | `graphshell-mcp`, `mere-overmap` | admission types | contract |
  | `station-custody` (Signalman) | `custody`, `custody_client`, admission | custody crate + contract |
  | Mere `ports/dramatis` | `custody_client`, `quarantine` | custody crate |
  | Mere `ports/graphshell`, `ports/graphshell/mere` | admission, `frame`, `wire`, `custody-client` | both |
  | `mere-resident` | everything, `door-serve`, `resident` | Djinn + both |
  | `support/fixtures/custody-projection` (6 crates) | per feature | per feature |
  | Knot (`knot-editor`) | admission, `declaration`, `wire`, `frame`, `custody`, `custody_client` | both |
  | Cleromancy | admission types | contract |
  | isocosm `isocosm-genet` | `custody_identity` | custody crate |
  | Armillary `support/fixtures/djinn` (5 crates) | per feature | per feature |

- **C0 is a layer above.** Capability door D13 and D14 (Mere `39a3a8afd`)
  put the projection session's WIT interface in `mere:script`, probed under
  Mere's `crates/probes/projection-session-c0/`. The door contract here
  carries today's JSON wire, which C0 leaves working unchanged. When C0
  promotes, `graphshell-endpoint`'s projection features may move onto it,
  but that is C0's business.

  Receipt directories that name `djinn` (Turnstone, Knot, Mere
  `support/receipts`) are history and stay as written.

## Phases

### S0. The tip after I1

Done 2026-11-01: see the first findings entry.

I1 was built on 2026-10-30 (Armillary `b6578ee`). Its Windows remainder
(capability door D11) was landing on 2026-10-31 (`7eebeeb`, `104b8d4`).

- Done when: capability-door I1, Windows remainder included, is recorded as
  landed in its plan, this plan's
  findings are re-measured against that Armillary tip, and anything I1 added
  to the door is placed on one side of the seam in an amended findings entry.

### S1. Names

Chosen and recorded in the naming ledger: `ostiary` (D5) and
`castellan-client` (D6). They are claimed in S5 (D7).

- Done when: both names are still free when S2 starts. If either has been
  taken, it goes back to Mark before any code is named.

### S2. The door contract crate (Armillary)

Done 2026-11-01. `crates/ostiary` holds `wire`, `frame`, `route`,
`declaration`, the admission types and endpoint functions, `app_client`, the
dialer and the child's side of `launch`; Djinn keeps the grants, launcher,
listener, server, link, custody and `resident`, and depends on ostiary.
- D8: `unix_app_endpoint` copies the fallback; `the_socket_path_is_pinned`
  pins it, macOS case included, and runs on every platform.
- D9, D10: `AppConnection::open_over` and `into_stream`;
  `an_admitted_connection_hands_its_stream_to_another_protocol` carries raw
  bytes after the handshake.
- Tests: Djinn had 82 on Windows with all features. Every one survives by
  name, 49 in Djinn and 33 in ostiary, plus the two above. The custody tests
  from `wire` and `app_client` wait in Djinn's `custody` and
  `custody_client` for S3. Of `app_admission`'s 21 tests (19 run on
  Windows), the eight about the hello, the launch handle and the endpoint
  moved; the thirteen about grants stayed.
- `cargo tree -p ostiary`: serde, serde_json, thiserror and zeroize; with
  `native`, also tokio, base64 and rand_core; no Dramatis crate, Armillary,
  peer-facts or Djinn. The portable tier checks for `wasm32-unknown-unknown`.
- Each Djinn feature (`door`, `door-native`, `door-serve`, `custody`,
  `custody-client`, `resident`) checks alone without warnings. Djinn has no
  re-export of ostiary.
- Fixtures: `support/fixtures/{portable,native}` became
  `support/fixtures/ostiary/`, and `support/fixtures/check.sh` runs all five,
  forbidding Dramatis, Armillary, peer-facts and Djinn in ostiary's cone.
- Linux and macOS (2026-11-01, `bc12b23` cloned fresh, rustc 1.99.1): on
  Fedora 44 (T-PC) and macOS 15.8.1 Intel (Q-PC), every Djinn feature and
  ostiary's portable tier check, with no warnings beyond the workspace's
  `unsafe_code` lint on moved code and one existing deprecation. Ostiary's
  35 tests pass on both. Djinn's 59 pass on Linux. On macOS, the first full
  run failed one test, `launch::tests::a_launched_process_reads_its_handle_once_from_the_named_descriptor`
  (the child exited non-zero), and the next eight full runs passed. Eight
  full runs of the pre-cut tree (`1145443`, 92 tests) also passed, so 1 in 17
  after the cut against 0 in 8 before, on a host at load 11 to 14. S2
  changed only that test's imports. A suspect, not proven: `launch_command`
  opens its pipe without close-on-exec, so a child spawned concurrently by
  another test inherits its descriptors.


The contract crate is a new Armillary workspace member. It holds `wire`,
`frame`, `route`, `declaration`, the admission types, `app_client`, the
dialer and the launched child's side of `launch` (`inherited`, `claim`), with
the same endpoint, environment and schema strings and the same 1 MiB
native-endian framing. Djinn depends on it and keeps `server`, `link`, the
launcher, the grant logic, the listener and `resident`.

- Done when:
  - the socket fallback is inlined, with a test pinning its path (D8);
  - an admitted connection can hand out its stream after the hello, with a
    test that carries raw bytes over it (D9);
  - the contract's portable tier builds for `wasm32-unknown-unknown`, and its
    dependency tree holds serde, serde_json, thiserror and zeroize, plus
    tokio, base64 and rand_core on native, and nothing from Dramatis,
    Armillary or `peer-facts` (`cargo tree` recorded);
  - each moved test passes in its new home, with the same count as before;
  - Djinn's own tests pass;
  - no compatibility re-export is left in Djinn (djinn-ownership's "no
    compatibility module" rule).

### S3. The custody crate (Dramatis)

Done 2026-11-01, after M1 landed (D14). Dramatis's
`crates/castellan-client` holds `custody`, `custody_payload` and
`quarantine` by default and `custody_client` and `custody_identity` under
`client` (D15, D16), over `ostiary` pinned to Armillary `0ccfe7a`. Djinn's
`custody` and `custody-client` features and its Dramatis, eidetic and uuid
dependencies are gone.
- Tests: Djinn had 52 on Windows with all features at `0ccfe7a`. The 22
  custody tests pass in castellan-client under the same names, and Djinn's
  remaining 30 pass.
- `cargo tree -p djinn --all-features` names no `dramatis`, `chatelaine`,
  `insigne`, `personae` or `eidetic`, and Armillary's lock lists none of them.
- Dramatis's lock holds one copy of each family crate, and `cargo deny check
  bans` passes. castellan-client is empty on `wasm32-unknown-unknown`.
- Fixtures (D17): `support/fixtures/castellan-client/check.sh` passes for
  `types` (117 packages) and `client` (128); the types fixture cannot name
  `custody_client`. Armillary's `check.sh` passes its remaining three.
- The Dramatis repo plan has its DR-C line.
- Cross-check 2026-11-02, fresh clones of Armillary `bf86882` and Dramatis
  `baa4ed2` on Linux (T-PC) and macOS (Q-PC, x86_64): every feature set
  checks, `cargo tree -p djinn` names no Dramatis crate, ostiary's 38 tests
  pass, and both fixture tiers pass. On Linux, Djinn's lib tests number 62
  at `0ccfe7a` and 38 at `bf86882`; the 24 that left are by name the 24 that
  castellan-client runs there, its 22 plus two `cfg(unix)` tests carried
  from Djinn. On macOS, one of ten full Djinn runs failed
  `local_endpoint::unix_tests::a_stale_same_user_socket_is_removed`
  (`prepare_unix_endpoint` refused the stale socket, line 625). S3 did not
  touch that file. Repeated on Q-PC: 0 of 300 alone, as was the S2 launch
  test, and 1 of 100 full runs. A suspect, not proven, shared with the S2
  flake: the launcher's test forks through `pre_exec`, so for a moment the
  child holds every descriptor in the test process, including another
  test's just-dropped listener, which then still answers the probe; its
  pipe also lacks close-on-exec.


The new Dramatis crate holds `custody`, `custody_client`, `custody_identity`,
`custody_payload` and `quarantine`, plus the custody-payload tests from
`app_client` and `wire`. It depends on the door contract and the Dramatis
crates in the same workspace.

- Done when:
  - Djinn has no `custody` or `custody-client` feature;
  - `cargo tree -p djinn` shows no `dramatis`, `chatelaine`, `insigne`,
    `personae` or `eidetic`;
  - the custody tests pass in Dramatis with the same count;
  - the Dramatis repo plan gains a line under DR-C saying where the route's
    client now lives.

### S4. Consumers

Done 2026-11-02, in the order below (D18 to D22). Dramatis `9d6e77e`
(ostiary repinned), Knot `57ce57c` then `3eac0b0` (repin), Mere `d1055540d`
(merge of `m1/manifests`, M1's keys renumbered D24 to D30 there because Mere
main already held D22 and D23, then the repoint), Cleromancy `e5b392d`
(merge of `m1/declarations`), isocosm `952d05c4` (the whole wing's 202 Mere
pins, 16 manifests, four locks).
- Checks: Knot's workspace and the nine touched Mere packages check with
  `--locked`, all targets, against the pushed Knot; every changed feature set
  and the two `wasm32-unknown-unknown` fixtures build. Cleromancy checks with
  `--locked`. isocosm's four locks resolve under `--locked`; the isocosm
  wing is not built, and its lanes fix what the new rev breaks.
- Locks: each moves only Mere, Dramatis, Armillary and Knot packages, and
  Knot's, Mere's and Cleromancy's hold one ostiary, one Djinn and one
  castellan-client. `cargo update -p knot-editor` sweeps floating genet,
  murm and retinue revisions; each repin reverted them.
- Fixtures: the seven `custody-projection` fixtures pass with their forbidden
  checks naming `custody_client` and `app_client` from the new crates, and the
  combined resident fixture's audit shows one copy of each. Mere's
  unused-patch warnings equal the base's (nine crates, same counts).
- Tests: the two broker tests hung because M1's declaration-only admission
  refuses a bare hello and `serve_app_connection` writes no frame, so the
  client waits for a challenge forever; seven tests now declare. The rest
  pass except six known Windows failures and one load-sensitive
  `published_replay_regression` test, unverified on Mere main.
- The M1 lane has the new API forms and its follow-up (removing D22's label
  fallback).

The table above is the list. Suppliers go first: the contract and Djinn in
Armillary, then the custody crate in Dramatis. Knot goes before Mere, since a
breaking change lands in Knot first and is briefly red (lockstep rule).
Cleromancy comes last. `graphshell-endpoint`'s `profile` feature depends on
the custody crate; its projection features depend on the contract.

Order, from the 2026-11-02 survey: Dramatis repins ostiary (D18); Knot drops
Djinn (D21) and is red until Mere lands, by the lockstep procedure; Mere
merges `m1/manifests` (D19), repoints and pins that Knot commit; Knot repins
Mere. Cleromancy (with `m1/declarations`, D20) and isocosm follow Mere,
because both reach Djinn through Mere crates as well (`mere-resident`,
`mere-overmap`; `graphshell-host`'s `custody-client`). Cleromancy's tests
still name `AllowedAppRoutes` and `AppRouteGrants`, so it keeps Djinn as a
dev-dependency.

- Done when:
  - every consumer in the table checks with its features on;
  - the fixtures' forbidden-API checks name the new crates;
  - each lock holds one copy of the contract, Djinn and the custody crate;
  - the Mere lock's unused-patch warnings match the base revision;
  - the M1 lane is told when S4 is on Mere main, naming the new forms of
    `connect_declared_as` and `open_declared_route` if S4 renames them (D14).

### S5. Publish and resume

Done 2026-11-02. Published, each after a registry dry-run and a name
recheck (D7): `ostiary` 0.0.1, `peer-facts` 0.0.1, `personae` 0.3.1, `dramatis` 0.0.4
(D23), `castellan-client` 0.0.1 (both feature sets verified against the registry),
`armillary` 0.1.2 and `djinn` 0.0.3 (D24), then Mere's chain: `script-wire` 0.0.1 and
`script-witgen` 0.0.1 (their `publish = false` removed, since `graphshell-endpoint`'s
optional `wit` dependencies must be on the registry), `chirograph` 0.0.4 (the `wit`
feature needs `CarrierError::Lapsed`; Knot's requirement moved first, `62aff7b`),
`graphshell-endpoint` 0.0.3 (every feature verified; its `wit/world.wit` is a copy of
the workspace's, held equal by `tests/wit_copy.rs`), `workbench` 0.1.1, `incipit` 0.2.1,
`scenograph` 0.0.6, `scenomise` 0.0.7, `mere-surface-api` 0.1.1, and `cambium` 0.6.1 after
`genet-events` 0.0.1 (Genet `ad3627231`; its `publish = false` came off at Mark's instruction,
and it is 0.0.1 because the event-dispatch API is unsettled).
- Commits: Armillary `0b05362`, Dramatis `7308142`, Mere `5f618efaf`, `db4a8d447`,
  `6576edf7f`, `328709104`, Knot `62aff7b`.
- Mere `e14dd68cf` requires `genet-events` 0.0.1 and takes Genet's release commit in the
  lock (the Genet family moves, 34 packages); the whole workspace checks under `--locked`.
- Consumers lock Dramatis, Armillary and Mere by revision, so none moves until its next
  update; then `dramatis` rows reading 0.0.3 need 0.0.4 and Knot's `chirograph` row is
  already 0.0.4.
- `mere:distillery-extraction` D17 resumed and F4 closed in Mere's plan.

## Progress

- 2026-11-02: ported device-pairing D9/D11's channel opening exchange from `door/channel-route` into Ostiary after S2's
  extraction. The admitted session's opening call and answer precede raw bytes; Djinn serves the same door contract.
  This unblocks D3's consumer repin onto the slimmed packages without restoring the custody dependency in Djinn.

- 2026-10-31: plan written; D1 to D4 answered.
- 2026-11-01: naming round, D5 to D7; F2 closed.
- 2026-11-01: S0 done. I1's additions placed, two missed consumers added,
  both names still free (S1); D8 and D9 answered, closing F1 and F3.
- 2026-11-01: S2 done: ostiary cut, D10 to D13 answered on the way.
- 2026-11-01: D14 orders M1 before S3 and folds M1's Mere side into S4.
- 2026-11-01: S3 done: castellan-client in Dramatis, D15 to D17 answered.
- 2026-11-02: S3 cross-checked on Linux and macOS; one macOS flake in
  Djinn's listener tests, untouched by S3.
- 2026-11-02: S4 surveyed; D18 to D21 answered, then D22 (the seal scope).
- 2026-11-02: S4 done: Dramatis, Knot, Mere, Cleromancy and isocosm landed.
- 2026-11-02: S5 done: eighteen crates published (genet-events and cambium 0.6.1 last); D23 and D24 answered; F4 closed.
