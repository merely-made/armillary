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

## 2026-11-03: remaining door splits (S4-S5)

Baseline: Armillary `f519c1ab96b5340ac4560c876af898a09484621e`, clean before
this continuation. `cargo test -p djinn --all-features --locked` passes all
30 native tests before the move. The same lane owner and 100 MB compact
receipt cap continue.

The route-policy state and live policy snapshots stay in app_admission;
live launch/OS identity methods move into a private child impl. Method
names, state fields and their visibility are preserved. Listener startup
and its public surface stay at local_endpoint; private Windows/Unix modules
hold platform enforcement and their existing tests. The new parent-only
helper visibility matches the original private parent scope.

| Source | Before lines | After lines |
|---|---:|---:|
| djinn/src/door/app_admission.rs | 765 | 329 |
| djinn/src/door/app_admission/identity.rs | moved methods | 125 |
| djinn/src/door/app_admission/tests.rs | moved fixtures | 458 |
| djinn/src/door/local_endpoint.rs | 793 | 131 |
| djinn/src/door/local_endpoint/windows.rs | moved enforcement/fixtures | 283 |
| djinn/src/door/local_endpoint/unix.rs | moved enforcement/fixtures | 475 |

- `cargo test --workspace --all-features --locked`: 120 tests plus one
  doctest pass. This includes the unchanged 30-test Djinn native suite,
  owner-only pipe ACL checks, connect readiness, process-reuse refusal and
  declaration/owner grant/identity tests.
- Static fixture review compares all test function names across every cfg
  branch before and after; all are retained. Platform test module prefixes
  now include their private implementation module; assertions are preserved.
- `cargo check -p djinn --no-default-features --features door --target
  wasm32-unknown-unknown --locked`: pass, isolating the portable door API.
- Rustfmt parses all moved platform files. Public paths, cfg/feature
  conditions, listener readiness, spawned-task ownership and OS/security
  calls retain their behavior. Cargo manifests and lock are unchanged.

Executed native scope is Windows. Ubuntu WSL is installed but has no Cargo
or rustc available, so native Unix/macOS cases were not run. No toolchain or
shell-profile changes were made for this pass. Existing platform bodies and
fixtures were retained for their owner runs. The final full gate and
public API documentation results follow below.

### S4-S5 final gates

- `prek run --all-files`: ceiling, Clippy and Responsa check pass.
- `cargo clippy -p djinn --all-features --all-targets --locked`: pass,
  explicitly selecting the native server code excluded by default features.
  Existing advisory warnings remain warnings.
- `cargo doc -p djinn --all-features --no-deps --locked` with broken
  intra-doc links denied: pass after qualifying the existing `LAUNCH_FD`
  documentation link as `ostiary::launch::LAUNCH_FD`. The old import was
  cfg-unix and did not resolve in Windows docs; the constant's Ostiary home
  is portable. Only that link changes in launch.rs.
- Source review preserves public method/type paths and scopes. Each platform
  retains its access checks, probe ordering, failure paths and tracked-task
  lifecycle. The shared listener is bound before readiness is reported.
- The last two exceptions are removed. `line-ceiling.toml` now contains only
  the 600-line ceiling, with no exception or exclusion. Cargo manifests and
  lock retain their original contents. The full local gate covers the new
  staged modules, and the real commit runs the installed hooks again.

This continuation retains only this compact appended receipt. It reuses the
stable Armillary Cargo target/build directory with two jobs. No isolated
Cargo home, target, worktree or helper files were created.
