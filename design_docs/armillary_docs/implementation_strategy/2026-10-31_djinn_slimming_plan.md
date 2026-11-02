# Djinn slimming plan

**Status:** 2026-11-01, S2 done (ostiary in Armillary); S3 next. Consumers
outside Armillary still pin Djinn revisions from before the cut and move in
S4. Findings were measured against Armillary `019d1e5` (Djinn's sources
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
- Castellan, the custodian and `custody-wire` stay in Mere (Dramatis repo
  plan D6). This plan moves the application side of the custody route only.
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
  Castellan stays in Mere (Dramatis D6).

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

Starts once capability-door M1's Armillary commit is on main (D14).

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

The table above is the list. Suppliers go first: the contract and Djinn in
Armillary, then the custody crate in Dramatis. Knot goes before Mere, since a
breaking change lands in Knot first and is briefly red (lockstep rule).
Cleromancy comes last. `graphshell-endpoint`'s `profile` feature depends on
the custody crate; its projection features depend on the contract.

- Done when:
  - every consumer in the table checks with its features on;
  - the fixtures' forbidden-API checks name the new crates;
  - each lock holds one copy of the contract, Djinn and the custody crate;
  - the Mere lock's unused-patch warnings match the base revision;
  - the M1 lane is told when S4 is on Mere main, naming the new forms of
    `connect_declared_as` and `open_declared_route` if S4 renames them (D14).

### S5. Publish and resume

- Done when:
  - published, in order: `ostiary`, `castellan-client` (after the Dramatis
    drift check), `peer-facts` and Djinn, each name rechecked just before
    its upload (D7);
  - `mere:distillery-extraction` D17 resumes: `graphshell-endpoint` 0.0.3
    and the crates behind it are published, now including `script-wire`,
    `script-witgen` and a `chirograph` bump past 0.0.3 (S0 findings);
  - `mere:distillery-extraction` F4 is closed, citing this plan.

## Progress

- 2026-10-31: plan written; D1 to D4 answered.
- 2026-11-01: naming round, D5 to D7; F2 closed.
- 2026-11-01: S0 done. I1's additions placed, two missed consumers added,
  both names still free (S1); D8 and D9 answered, closing F1 and F3.
- 2026-11-01: S2 done: ostiary cut, D10 to D13 answered on the way.
- 2026-11-01: D14 orders M1 before S3 and folds M1's Mere side into S4.
