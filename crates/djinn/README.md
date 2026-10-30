# Djinn

Djinn provides a shared application door protocol and resident lifetime
mechanics. Hosts supply route policy, application services and custody
authority. Identity domain types belong to Dramatis and Personae; custody
wire operations do not themselves grant authority.

Default features are empty. Native APIs are available on Unix and Windows and
are gated out on Wasm.

| Feature | API | Native | Wasm |
| --- | --- | --- | --- |
| `door` | Admission, route policy types, generic wire envelopes and bounded synchronous framing | Yes | Yes |
| `door-native` | Local endpoint discovery and application connections | Yes | Gated out |
| `door-serve` | Listener, shared handshake and link binding | Yes | Gated out |
| `custody` | Custody, payload and quarantine types | Yes | Gated out |
| `custody-client` | Custody and identity clients | Yes | Gated out |
| `resident` | Task and shutdown orchestration | Yes | Gated out |

`door-native` currently depends on Personae for default vault-directory
endpoint discovery. `custody-client` adds the client side of the protected
custody boundary; the host retains custody dispatch, grants and secrets.
`resident` orchestrates supplied services and shutdown actions, while the host
chooses those services and their policy.
