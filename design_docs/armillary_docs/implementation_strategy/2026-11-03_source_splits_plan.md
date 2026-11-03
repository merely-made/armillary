# Source splits plan

**Status (2026-11-03):** landed. S1-S3 complete. Two ceiling exceptions retired.
**Scope:** Ostiary declarations and OS peer facts, following Mere stack.7.
Keep public entry points, wire formats, authority rules and crate features.
This pass changes module ownership inside the existing crates.

## Phases

- **S1. Declaration and authority.** Keep declaration/grant data and
  validation at `ostiary::declaration`; move the connection's permission
  intersection into its private `authority` module, re-exporting the public
  types. Keep regression fixtures in the same test module path.
  Done when the existing native Ostiary tests pass and every resulting file
  is at most 600 lines, with the obsolete ceiling exception removed.
- **S2. OS observations.** Keep portable observed facts and connected-peer
  state at `peer_facts`; place Windows, Unix and macOS observation code in
  private platform modules under the original cfg conditions.
  Done when native peer tests pass, existing exports remain available and
  the obsolete ceiling exception is removed.
- **S3. Qualification and publication.** Compare the existing tests before
  and after; run the full local gate and relevant feature checks, regenerate
  decisions from staged source records, then commit and push main.
  Done when the receipt states the verified platform scope and the two
  exceptions have been retired without replacement exemptions.

## Decisions

No new design ruling. Mark requested useful splits after the house-style
rollout; these are internal responsibility boundaries under Mere stack.1
and stack.7. Platform acceptance remains with its original owner plans.

## Findings

- 2026-11-03: `ostiary/src/declaration.rs` combines wire data and its
  validation with the declaration/grant intersection (`AppAuthority`).
  Its existing tests pin distinct undeclared/not-granted refusals, binary
  salt prefixes, epoch scope, compact serialization and malformed inputs.
- 2026-11-03: `peer-facts/src/lib.rs` already has cfg-isolated inline
  Windows and macOS modules, plus Unix socket observation functions.
  Their bodies can move as units while the portable public surface stays.
- Required evidence: before/after existing tests, source-move review,
  ceiling pass and full local gate. Retained-byte cap: 100 MB; compact
  receipts only, appended to
  `archive_docs/receipts/2026-11-03_source_splits_plan_receipts.md`.

## Progress

- 2026-11-03: selected the two existing responsibility boundaries and began
  the native baseline. The repository was clean before this pass.
- 2026-11-03: S1 and S2 are implemented. Ostiary's declaration and grant
  shapes remain at their existing paths; `AppAuthority` and `AuthorityRefusal`
  are re-exported from the private authority module. Platform modules keep
  their original cfgs, unsafe blocks and parent visibility.
- 2026-11-03: the same 41 Ostiary and one portable peer-facts test pass
  before and after. Workspace all-feature tests (including Djinn's native
  door consumer) and the no-default-feature wasm checks pass. S3's full
  local gate and source-record publication are next.
- 2026-11-03: S3 passed the full local gate (ceiling, Clippy, current
  decisions manifest), all-feature workspace tests, portable wasm checks and
  public documentation with broken intra-doc links denied. All resulting
  source files are below 600 lines. Both obsolete exceptions are retired;
  Armillary retains only its two Djinn server-file exceptions. Publication
  is the commit carrying this source record and its appended receipt.
