# Djinn

Djinn provides a shared application door protocol and resident lifetime
mechanics. Hosts supply route policy, application services and custody
authority. Identity domain types belong to Dramatis and Personae; custody
wire operations do not themselves grant authority.

Default features are empty. Native APIs are available on Unix and Windows and
are gated out on Wasm.

| Feature | API | Native | Wasm |
| --- | --- | --- | --- |
| `door` | Admission, application declarations and owner grants, route policy types, generic wire envelopes and bounded synchronous framing | Yes | Yes |
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

An application may carry an `AppDeclaration` on its route hello: the routes it
opens, the projections it offers and the custody operations, epoch
derivations and salt namespaces it needs (released, or only signed and
attested with). Salts are named as UTF-8 text matched against their bytes, or
by delegation domain for insigne's binary-framed delegation signing keys. The host's `AppGrant` states what the owner lets it have.
A declared connection receives only what both name; an application the owner
grants by declaration must declare, and other applications keep label route
grants. `AllowedAppRoutes::default()` admits no application; hosts name their
own. Declarations, like `AppId` labels, are statements within the same-user
boundary, not executable authentication.

The door records what the OS says about each connection's peer
(`peer-facts`). An owner's `AppGrant` may pin the label to an OS identity per
platform: a macOS code signature (team and identifier, checked against the
peer's audit token), a Windows executable image (the same-user posture of a
path), or a Linux launch, where Djinn starts the application
(`door::launch`) with a one-time handle on descriptor 3 that its door client
carries on every route hello. A pinned label without that identity is
refused; an unpinned one is admitted as development mode, and
`AdmittedApp::basis` says which.
