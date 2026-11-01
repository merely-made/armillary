# Djinn slimming plan

**Status:** 2026-11-01, plan; names chosen (D5, D6). No code moves until capability-door I1 is recorded as
landed (D4); the cut is then made against that tip. Measured against Armillary
`104b8d4`, Mere `5431b896c` and Dramatis `2d9ddc0`; no build was run for these
findings.

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

## Open forks

- **F1. The socket-path fallback.** `default_app_endpoint` falls back to
  `personae::default_vault_dir()` when `XDG_RUNTIME_DIR` is unset
  (`door/app_admission.rs:769`). That is the door's only `personae` use
  outside tests and custody. The contract can inline the same ten-line
  derivation, with a test pinning the resulting path, or keep a `personae`
  dependency on native targets. Put this to Mark at S2's start.
- **F2.** Closed by D5 to D7.

## Findings

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

- **Channel routes (2026-11-01).** `door/channel.rs` came in after these
  measurements, for Mere's device-pairing D11 (SSH by key): a route whose
  session, after one opening `Call` and its `ChannelOpened` answer, carries
  raw bytes, the host proxying them (capability door N1's proxied channel).
  On the seam: `ChannelOpened` and `AppConnection::open_channel` are
  contract; `read_channel_open`, `answer_channel_open` and
  `refuse_channel_open` serve, beside `server`, in Djinn.
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

The contract crate is a new Armillary workspace member. It holds `wire`,
`frame`, `route`, `declaration`, the admission types, `app_client` and the
dialer, with the same endpoint, environment and schema strings and the same
1 MiB native-endian framing. Djinn depends on it and keeps `server`, `link`,
`launch`, the grant logic, the listener and `resident`.

- Done when:
  - F1 is answered;
  - the contract's portable tier builds for `wasm32-unknown-unknown`, and its
    dependency tree holds serde, serde_json, thiserror and zeroize, plus
    tokio, base64 and rand_core on native, and nothing from Dramatis,
    Armillary or `peer-facts` (`cargo tree` recorded);
  - each moved test passes in its new home, with the same count as before;
  - Djinn's own tests pass;
  - no compatibility re-export is left in Djinn (djinn-ownership's "no
    compatibility module" rule).

### S3. The custody crate (Dramatis)

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
  - the Mere lock's unused-patch warnings match the base revision.

### S5. Publish and resume

- Done when:
  - published, in order: `ostiary`, `castellan-client` (after the Dramatis
    drift check), `peer-facts` and Djinn, each name rechecked just before
    its upload (D7);
  - `mere:distillery-extraction` D17 resumes: `graphshell-endpoint` 0.0.3
    and the six crates behind it are published;
  - `mere:distillery-extraction` F4 is closed, citing this plan.

## Progress

- 2026-10-31: plan written; D1 to D4 answered.
- 2026-11-01: naming round, D5 to D7; F2 closed.
