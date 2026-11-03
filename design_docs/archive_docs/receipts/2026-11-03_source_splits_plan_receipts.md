# Source splits receipts

## 2026-11-03: Armillary declarations and OS observations

Baseline: Armillary main `e970050`, clean before this pass. Owner: chat
`01a19f86-cb71-7820-a6ac-aaec39d8bfd4`. Retained cap: 100 MB, compact text.

- Before and after: `cargo test -p ostiary -p peer-facts --features
  ostiary/native --locked`, 41 Ostiary tests and one peer-facts test pass.
  Their test module paths and fixtures are preserved.
- `cargo test --workspace --all-features --locked`: 120 unit/integration
  tests and one doctest pass, including the native Djinn door consumer.
- `cargo check -p ostiary -p peer-facts --no-default-features --target
  wasm32-unknown-unknown --locked`: pass. This exercises the portable public
  types separately from the native implementation.
- `rustfmt --edition 2024` on the two roots and their new child modules:
  pass. Only those source families were formatted.

| Source | Before lines | After lines |
|---|---:|---:|
| ostiary/src/declaration.rs | 847 | 543 |
| ostiary/src/declaration/authority.rs | new | 174 |
| ostiary/src/declaration/tests.rs | moved inline fixtures | 304 |
| peer-facts/src/lib.rs | 683 | 298 |
| peer-facts/src/windows.rs | moved inline module | 320 |
| peer-facts/src/macos.rs | moved inline module | 124 |
| peer-facts/src/unix.rs | moved Unix observation functions | 85 |

The authority intersection and its refusals move together; declaration and
grant data/validation retain their public paths. The OS modules remain
private, with their former cfgs and root exports. Existing OS calls, unsafe
blocks and authority/serialization assertions are preserved. Both obsolete
ceiling exceptions are removed; no new exception is added. The two Djinn
server-file exceptions remain outside this pass.

Executed platform: Windows native and wasm32 compilation. Unix/macOS
observation bodies were moved as units and parsed by rustfmt; their native
OS branches were not executed here. No new platform-security acceptance is
claimed. Cargo manifests and lock are unchanged. Build output reuses
`C:/t/cargo-targets/armillary` and its `build` directory, with two jobs;
no isolated target, Cargo home or worktree was created.

### Final local qualification

- `prek run --all-files`: line ceiling, Clippy and Responsa check all pass.
- `cargo doc -p ostiary -p peer-facts --all-features --no-deps --locked`,
  with `RUSTDOCFLAGS=-D rustdoc::broken_intra_doc_links`: pass. Public
  re-exports and their documentation resolve in their original API homes.
- `responsa regen --stage` then `responsa check`: manifest current, with
  the declared cross-repository link checked. Regeneration reports existing
  unsupported link syntax in the older Djinn slimming plan; this pass keeps
  those records intact. Armillary has no staged doctrine budget to check.
- Scoped diff review: source bodies move into private modules; remaining
  differences are imports, re-exports and rustfmt layout. Existing private
  fields remain private. Cargo manifests/lock, wire data and OS calls are
  unchanged. The original 42 focused tests retain their names and results.
- Seven resulting source files range from 85 to 543 lines. The exception
  list shrinks from four entries to two without replacement exclusions.

The source plan and this receipt are committed with the implementation.
No isolated targets, Cargo homes, worktrees, temporary source helpers or
full diagnostic logs were retained. The stable Armillary target remains
available for the repository's ordinary builds.
