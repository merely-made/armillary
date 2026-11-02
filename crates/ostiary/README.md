# Ostiary

The application door's contract: what an application says at Djinn's door
and how it says it. Applications depend on this crate; Djinn serves the other
side.

Default features are empty and build for Wasm.

| Feature | API | Native | Wasm |
| --- | --- | --- | --- |
| (none) | The hello and admission types, application declarations and grant vocabulary, route keys, generic wire envelopes and bounded synchronous framing | Yes | Yes |
| `native` | Endpoint discovery, the dialer, `AppConnection` and a launched application's handle (`launch::claim`) | Yes | Gated out |

`AppConnection::open_over` runs the handshake over a stream the caller
already holds, and `into_stream` hands the admitted stream to another
protocol, such as the projection session's generated calls.

Without `XDG_RUNTIME_DIR`, the Unix socket sits in personae's vault directory
(`$XDG_DATA_HOME` or `~/.local/share`, then `personae/vault`), the macOS
default; the path is copied here and pinned by a test, so this crate depends
on nothing from Dramatis. An `AppId` label and a declaration are statements
within the same-user boundary, not executable authentication.
