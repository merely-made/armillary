# Apparatus core

Bounded observations and read-only inspection data, extracted from Mere
`8942e30503f2fa91fdefe879ec5268ee42a5241a`. The observation implementation and
its original tests are unchanged. Portable inspection retains its original
implementation/tests; accessibility projection remains in `mere-apparatus`.

`ObservationStore<P>` retains producer-redacted values under caller-selected
record, accounted encoded-byte, and age limits. Independent readers report
unavailable ranges, source/run boundaries and explicit loss. Products supply
monotonic receipt times and actual known dropped counts. The encoded-byte
contract is not an allocator-memory bound. Missing instrumentation is unknown.

The default library uses only `std`. Optional `serde` serializes observation
values and opaque inspection cursors; cursors cannot be deserialized into a new
store. There is no dependency on Armillary, Tokio, Mere, a renderer or Registry.
Host authorization, command outcomes, redaction, persistence, export, scheduling
and UI remain with their owners. This store is an observation copy, not a durable
audit journal or operation authority.

`inspect_batch` provides bounded read-only text rows using product-supplied
labels. Display limits do not change retained history or loss. Mere retains its
Registry collector, AccessKit/UxTree projection and existing facade API.

Run `cargo test -p apparatus-core --all-features` from the repository root.
