# Djinn

Djinn serves the application door and provides resident lifetime mechanics.
The door's contract, what applications speak, is [`ostiary`](../ostiary):
the hello and admission types, declarations, framing, envelopes and the
native client. The custody route's application side, its calls and clients,
is Dramatis's `castellan-client`. Hosts supply route policy, application
services and custody authority.

Default features are empty. Native APIs are available on Unix and Windows and
are gated out on Wasm.

| Feature | API | Native | Wasm |
| --- | --- | --- | --- |
| `door` | Owner grants and route policy (`AllowedAppRoutes`, `AppRouteGrants`) over `ostiary` | Yes | Yes |
| `door-native` | `ostiary`'s native client | Yes | Gated out |
| `door-serve` | Listener, launcher, shared handshake and link binding | Yes | Gated out |
| `resident` | Task and shutdown orchestration | Yes | Gated out |

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
path, read by process id at connect rather than bound to the connection), or
a Linux launch, where Djinn starts the application (`door::launch`) with a
one-time handle on descriptor 3. The application calls `ostiary::launch::claim()`
first in `main`, which reads the handle, closes the descriptor and clears its
variable before anything is spawned; its door client carries the handle on
every route hello. A pinned label without that identity is
refused; an unpinned one is admitted as development mode, and
`AdmittedApp::basis` says which.
