// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The custody route's wire: what an application asks djinn for, and what it
//! hears back (dramatis repo plan, rulings D5, D11, D12, D17).
//!
//! Every application reaches identity and secrets by calling djinn on the
//! first-party door, never by opening a vault, storage or wallet (D5). The
//! route is [`CUSTODY_ROUTE`]; the server half is the resident's
//! `ResidentIdentity::custody` (in Graphshell's `native::resident_identity`),
//! the client half [`super::custody_client`]. Both name these types, so they
//! cannot drift.
//!
//! The split follows D11 ("Mixed"): root-level acts ([`CustodyCall::Attest`],
//! [`CustodyCall::Sign`], [`CustodyCall::IssueStationGrant`],
//! [`CustodyCall::RevokeDevice`]) happen inside djinn and only their results
//! cross. The one thing that crosses as a secret is a namespaced derived key
//! an application needs continuously ([`CustodyCall::Release`]): djinn checks
//! the salt against its release policy, never releases the master, and a lock
//! revokes what it released ([`CustodyCall::WatchLock`]).

use std::path::PathBuf;

use dramatis::roster::Roster;
use dramatis::view::{VaultLockView, VaultProtectionView};
use insigne::DerivedKeyAttestation;
use personae::ProfileId;
use personae::carry::{DeviceGrantSet, RemoteAuthRevocationOutcome};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::door::declaration::{AppAuthority, AuthorityRefusal, CustodyOperation, SaltSource};

/// The resident route custody is served on.
pub const CUSTODY_ROUTE: &str = "custody";

/// Which root a derived key, attestation or signature comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// The vault persona in use: transport and sealing keys, mesh authors,
    /// session keys.
    Persona,
    /// The wallet's identity seed: device grants and the stations they
    /// commission (D8, D17).
    Wallet,
}

/// One request on the custody route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "call", rename_all = "snake_case")]
pub enum CustodyCall {
    /// Retained-content encryption through the current profile's custodian.
    /// No epoch key is released. The resident checks app and profile binding.
    Payload(super::custody_payload::PayloadRequest),
    /// Ask the resident to render its own native unlock prompt.
    UnlockNative,
    /// Local Dramatis authentication update; credentials are collected by Djinn.
    ChangePassphraseNative(dramatis::authentication::ChangePassphraseIntentV1),
    /// Older imports requiring an explicit profile association.
    UnassignedImports,
    /// Djinn asks the owner to associate one exact older import namespace.
    AssignImport(crate::door::quarantine::AssignImportRequest),
    /// Lock authority without supplying a secret.
    LockVault,
    /// Public cards belonging to a named identity profile.
    Quarantine { profile: ProfileId },
    /// Request one action; Djinn obtains its own consent.
    ReviewQuarantine(crate::door::quarantine::ReviewRequest),
    /// The lock, the protection and the public roots. Answered Locked or
    /// not; an application uses it to decide whether to show the identity
    /// as pending (D12).
    Status,
    /// The vault's personas, as a picker shows them.
    Roster,
    /// Terminal vault operations run inside djinn. Only public output crosses.
    VaultCommand {
        profile: ProfileId,
        command: String,
        args: Vec<String>,
    },
    /// Switch the persona in use.
    ChooseProfile { profile: ProfileId },
    /// Mint a persona and switch to it.
    CreateProfile {
        profile: ProfileId,
        display_name: String,
    },
    /// Release the derived keys for `salts`, with an attestation for each
    /// (D11). Refused for any salt outside djinn's release policy.
    Release {
        source: KeySource,
        #[serde(with = "b64_list")]
        salts: Vec<Vec<u8>>,
    },
    /// The master's attestation of the key `salt` derives. Signed inside
    /// djinn; no key crosses.
    Attest {
        source: KeySource,
        #[serde(with = "b64")]
        salt: Vec<u8>,
    },
    /// Sign `message` with the key `salt` derives, inside djinn.
    Sign {
        source: KeySource,
        #[serde(with = "b64")]
        salt: Vec<u8>,
        #[serde(with = "b64")]
        message: Vec<u8>,
    },
    /// Issue a sited station's narrow RemoteAuth grant with the wallet's
    /// seed (D17). `issuer_public_key` is the root the station's material
    /// was derived under, checked against the wallet.
    IssueStationGrant {
        request: StationGrantRequest,
        #[serde(with = "b64_32")]
        issuer_public_key: [u8; 32],
    },
    /// Revoke one delegated device in the wallet.
    RevokeDevice { device_id: Uuid },
    /// Wait until the lock leaves `seen`, then answer the new state. An
    /// application holding released keys drops them when this answers
    /// Locked.
    WatchLock { seen: VaultLockView },
    /// Release keys derived from a persona wallet's current private epoch
    /// (D11), for a store whose keys must match on every device of the
    /// persona. The epoch itself never crosses. Refused for any derivation
    /// outside djinn's release policy.
    ReleaseEpochKeys {
        persona: Uuid,
        /// Mint this device's identity under this label if it has none.
        /// Absent, a device-bound key with no device identity is refused.
        device_label: Option<String>,
        keys: Vec<EpochKeyRequest>,
    },
    /// Answer `call` as persona `profile` without switching to it: for an
    /// application whose own identity djinn adopted as a persona apart from
    /// the one in use (D13). Only a status, or a persona release,
    /// attestation or signature, answers this way.
    AsProfile {
        profile: ProfileId,
        inner: Box<CustodyCall>,
    },
}

impl CustodyCall {
    /// The call a named-persona wrapper carries, or this call.
    pub fn unwrapped(&self) -> &Self {
        match self {
            Self::AsProfile { inner, .. } => inner.unwrapped(),
            call => call,
        }
    }

    /// Which operation this call is, for declarations and grants.
    pub fn operation(&self) -> CustodyOperation {
        match self.unwrapped() {
            Self::Payload(_) => CustodyOperation::Payload,
            Self::UnlockNative => CustodyOperation::UnlockNative,
            Self::ChangePassphraseNative(_) => CustodyOperation::ChangePassphraseNative,
            Self::UnassignedImports => CustodyOperation::UnassignedImports,
            Self::AssignImport(_) => CustodyOperation::AssignImport,
            Self::LockVault => CustodyOperation::LockVault,
            Self::Quarantine { .. } => CustodyOperation::Quarantine,
            Self::ReviewQuarantine(_) => CustodyOperation::ReviewQuarantine,
            Self::Status => CustodyOperation::Status,
            Self::Roster => CustodyOperation::Roster,
            Self::VaultCommand { .. } => CustodyOperation::VaultCommand,
            Self::ChooseProfile { .. } => CustodyOperation::ChooseProfile,
            Self::CreateProfile { .. } => CustodyOperation::CreateProfile,
            Self::Release { .. } => CustodyOperation::Release,
            Self::Attest { .. } => CustodyOperation::Attest,
            Self::Sign { .. } => CustodyOperation::Sign,
            Self::IssueStationGrant { .. } => CustodyOperation::IssueStationGrant,
            Self::RevokeDevice { .. } => CustodyOperation::RevokeDevice,
            Self::WatchLock { .. } => CustodyOperation::WatchLock,
            Self::ReleaseEpochKeys { .. } => CustodyOperation::ReleaseEpochKeys,
            Self::AsProfile { .. } => unreachable!("unwrapped above"),
        }
    }

    /// Whether this call can be answered as a named persona
    /// ([`CustodyCall::AsProfile`]).
    pub fn answers_as_profile(&self) -> bool {
        matches!(
            self,
            Self::Status
                | Self::Release {
                    source: KeySource::Persona,
                    ..
                }
                | Self::Attest {
                    source: KeySource::Persona,
                    ..
                }
                | Self::Sign {
                    source: KeySource::Persona,
                    ..
                }
        )
    }
}

/// One key derived from a persona's current private epoch: blake3's
/// `derive_key` under `context`, over the epoch secret followed by this
/// device's public root when `device_bound`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochKeyRequest {
    pub context: String,
    pub device_bound: bool,
    /// Answer only the Ed25519 public key the derived bytes seed.
    pub public_only: bool,
}

impl EpochKeyRequest {
    /// A secret derivation.
    pub fn secret(context: impl Into<String>, device_bound: bool) -> Self {
        Self {
            context: context.into(),
            device_bound,
            public_only: false,
        }
    }

    /// The Ed25519 public half of a derivation.
    pub fn public(context: impl Into<String>, device_bound: bool) -> Self {
        Self {
            context: context.into(),
            device_bound,
            public_only: true,
        }
    }
}

/// One released epoch key, answering the request it echoes.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedEpochKey {
    pub request: EpochKeyRequest,
    /// The derived secret, or its Ed25519 public key when the request was
    /// `public_only`.
    #[serde(with = "b64_32")]
    pub key: [u8; 32],
}

impl std::fmt::Debug for ReleasedEpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasedEpochKey")
            .field("request", &self.request)
            .finish_non_exhaustive()
    }
}

impl Drop for ReleasedEpochKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.key);
    }
}

/// A sited station's grant request, as plain fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StationGrantRequest {
    pub device_id: Uuid,
    #[serde(with = "b64_32")]
    pub station_ed25519_public_key: [u8; 32],
    pub label: String,
    pub issued_at_ms: u64,
    pub expires_at_ms: u64,
}

/// What the resident knows about its identity, public parts only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResidentStatus {
    pub lock: VaultLockView,
    pub protection: VaultProtectionView,
    /// The persona in use, absent before the vault has one.
    pub profile: Option<ProfileId>,
    /// The persona's master public key, absent while Locked.
    #[serde(default, with = "b64_32_opt")]
    pub persona_public_key: Option<[u8; 32]>,
    /// The wallet root's public key, absent with no wallet or while Locked.
    #[serde(default, with = "b64_32_opt")]
    pub wallet_public_key: Option<[u8; 32]>,
    /// Where the wallet's public records live, for an application that reads
    /// already-public state (grant sets, the device roster) itself.
    pub wallet_root: Option<PathBuf>,
    /// Authoritative transition evidence when supplied by a separate custodian.
    /// Absence is a legacy capability, never a synthetic generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_epoch: Option<CustodyEpoch>,
}

/// Authoritative custodian lifetime and invalidation generation. It is public
/// transition evidence, not a key, grant or proof of a completed effect.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyEpoch {
    pub instance: String,
    pub generation: u64,
}

impl CustodyEpoch {
    pub fn valid(&self) -> bool {
        !self.instance.is_empty() && self.instance.len() <= 256
    }
}

/// One released key: its salt, the derived seed and the master's attestation.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedKey {
    #[serde(with = "b64")]
    pub salt: Vec<u8>,
    #[serde(with = "b64_32")]
    pub seed: [u8; 32],
    pub attestation: DerivedKeyAttestation,
}

impl std::fmt::Debug for ReleasedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReleasedKey")
            .field("salt_len", &self.salt.len())
            .finish_non_exhaustive()
    }
}

impl Drop for ReleasedKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.seed);
    }
}

/// djinn's answer to one call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum CustodyAnswer {
    PassphraseChange {
        receipt: dramatis::authentication::PassphraseChangeReceiptV1,
    },
    Payload {
        result: super::custody_payload::PayloadResult,
    },
    Quarantine {
        cards: Vec<crate::door::quarantine::QuarantineCard>,
    },
    UnassignedImports {
        imports: Vec<crate::door::quarantine::UnassignedImport>,
    },
    /// Public CA installation material. The terminal executes SSH after the
    /// keeper releases its mutex, allowing the resident agent to authenticate.
    VaultEnrollment {
        target: String,
        script: String,
        confirmation: String,
    },
    /// Public terminal text produced by a keeper-owned command.
    VaultOutput {
        text: String,
    },
    Status(ResidentStatus),
    Roster(Roster),
    /// The call changed state and has nothing to report.
    Done,
    Released {
        #[serde(with = "b64_32")]
        master: [u8; 32],
        keys: Vec<ReleasedKey>,
    },
    Attestation(DerivedKeyAttestation),
    Signature {
        #[serde(with = "b64_32")]
        public_key: [u8; 32],
        #[serde(with = "b64")]
        signature: Vec<u8>,
    },
    StationGrant(DeviceGrantSet),
    Revoked(RemoteAuthRevocationOutcome),
    Lock(VaultLockView),
    /// The epoch keys asked for, in request order.
    /// A struct variant: the internal `answer` tag cannot sit beside a bare
    /// sequence.
    EpochKeys {
        keys: Vec<ReleasedEpochKey>,
    },
}

/// Why djinn did not answer a call.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CustodyRefusal {
    /// This host serves no custody route.
    #[error("this host does not serve custody")]
    NotServed,
    /// The vault (or the wallet) is locked: the identity is pending (D12).
    #[error("the identity is locked")]
    Locked,
    /// The salt is outside the release policy; the key stays in djinn.
    #[error("djinn does not release this key")]
    NotReleasable,
    /// The resident has no wallet to act with.
    #[error("the resident has no wallet")]
    NoWallet,
    /// The wallet holds no such persona.
    #[error("the wallet holds no such persona")]
    NoPersona,
    /// The request itself was refused, with the reason.
    #[error("refused: {reason}")]
    Refused { reason: String },
    /// The act failed inside djinn.
    #[error("failed: {reason}")]
    Failed { reason: String },
    /// The application's declaration does not name this; nothing was tried.
    #[error("undeclared: {what}")]
    Undeclared { what: String },
    /// The application declared this, and its owner has not granted it.
    #[error("not granted: {what}")]
    NotGranted { what: String },
}

impl From<AuthorityRefusal> for CustodyRefusal {
    fn from(refusal: AuthorityRefusal) -> Self {
        match refusal {
            AuthorityRefusal::Undeclared { what, .. } => Self::Undeclared { what },
            AuthorityRefusal::NotGranted { what, .. } => Self::NotGranted { what },
        }
    }
}

impl AppAuthority {
    /// Whether this connection may make `call`: its operation, each epoch
    /// derivation it asks for, and each salt it releases, attests or signs
    /// with, declared and granted. The resident's floors (never the master,
    /// its own special scopes) still apply after this.
    pub fn admit_custody(&self, call: &CustodyCall) -> Result<(), CustodyRefusal> {
        self.custody_operation(call.operation())?;
        match call.unwrapped() {
            CustodyCall::ReleaseEpochKeys { keys, .. } => {
                for key in keys {
                    self.epoch(&key.context, key.device_bound, key.public_only)?;
                }
            }
            CustodyCall::Release { source, salts } => {
                for salt in salts {
                    self.salt((*source).into(), salt, true)?;
                }
            }
            CustodyCall::Attest { source, salt } | CustodyCall::Sign { source, salt, .. } => {
                self.salt((*source).into(), salt, false)?;
            }
            _ => {}
        }
        Ok(())
    }
}

impl From<KeySource> for SaltSource {
    fn from(source: KeySource) -> Self {
        match source {
            KeySource::Persona => Self::Persona,
            KeySource::Wallet => Self::Wallet,
        }
    }
}

pub(super) mod b64 {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let text = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)
    }
}

mod b64_list {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(list: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(list.iter().map(|bytes| URL_SAFE_NO_PAD.encode(bytes)))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|text| {
                URL_SAFE_NO_PAD
                    .decode(text)
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

mod b64_32 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        super::b64::serialize(bytes, serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let bytes = super::b64::deserialize(deserializer)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

mod b64_32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(
        bytes: &Option<[u8; 32]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => super::b64_32::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<[u8; 32]>, D::Error> {
        use base64::Engine;
        let Some(text) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(text)
            .map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map(Some)
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_and_its_answer_round_trip_as_json() {
        let call = CustodyCall::Release {
            source: KeySource::Persona,
            salts: vec![b"mesh-author".to_vec()],
        };
        let text = serde_json::to_string(&call).unwrap();
        assert_eq!(serde_json::from_str::<CustodyCall>(&text).unwrap(), call);

        let status = CustodyAnswer::Status(ResidentStatus {
            custody_epoch: None,
            lock: VaultLockView::Locked,
            protection: VaultProtectionView::Ephemeral,
            profile: Some(ProfileId("default".into())),
            persona_public_key: None,
            wallet_public_key: Some([3; 32]),
            wallet_root: None,
        });
        let text = serde_json::to_string(&status).unwrap();
        assert_eq!(
            serde_json::from_str::<CustodyAnswer>(&text).unwrap(),
            status
        );
    }

    #[test]
    fn a_released_seed_never_prints() {
        let provider = personae::InMemoryProvider::from_seed([9; 32]);
        let key = ReleasedKey {
            salt: b"mesh-author".to_vec(),
            seed: [0x5a; 32],
            attestation: personae::IdentityProvider::attest_derived_key(&provider, b"mesh-author")
                .unwrap(),
        };
        assert!(!format!("{key:?}").contains("90"));
    }

    #[test]
    fn an_epoch_release_round_trips_and_never_prints_its_key() {
        let call = CustodyCall::ReleaseEpochKeys {
            persona: Uuid::from_u128(7),
            device_label: Some("study".into()),
            keys: vec![EpochKeyRequest::secret("ctx", true)],
        };
        let text = serde_json::to_string(&call).unwrap();
        assert_eq!(serde_json::from_str::<CustodyCall>(&text).unwrap(), call);
        let answer = CustodyAnswer::EpochKeys {
            keys: vec![ReleasedEpochKey {
                request: EpochKeyRequest::public("ctx", false),
                key: [0x5a; 32],
            }],
        };
        let text = serde_json::to_string(&answer).unwrap();
        assert_eq!(
            serde_json::from_str::<CustodyAnswer>(&text).unwrap(),
            answer
        );
        assert!(!format!("{answer:?}").contains("90"));
    }

    #[test]
    fn a_declared_app_is_refused_what_it_did_not_declare_or_was_not_granted() {
        use crate::door::app_admission::AppId;
        use crate::door::declaration::{AppDeclaration, AppGrant, CustodyUse, EpochUse, NamePattern};
        let declaration = AppDeclaration {
            custody: CustodyUse {
                operations: [CustodyOperation::Status, CustodyOperation::ReleaseEpochKeys].into(),
                epoch: vec![EpochUse::secret("app.vault", false)],
                ..CustodyUse::default()
            },
            ..AppDeclaration::default()
        };
        let mut grant = AppGrant::new(AppId::new("app"));
        grant.custody.operations = [CustodyOperation::Status, CustodyOperation::ReleaseEpochKeys, CustodyOperation::LockVault].into();
        grant.custody.epoch = vec![NamePattern::prefix("app.")];
        let authority = AppAuthority::new(declaration, grant);
        let release = |context: &str| CustodyCall::ReleaseEpochKeys {
            persona: Uuid::from_u128(7),
            device_label: None,
            keys: vec![EpochKeyRequest::secret(context, false)],
        };
        assert!(authority.admit_custody(&CustodyCall::Status).is_ok());
        assert!(authority.admit_custody(&CustodyCall::AsProfile {
            profile: ProfileId("p".into()),
            inner: Box::new(CustodyCall::Status),
        }).is_ok());
        assert!(authority.admit_custody(&release("app.vault")).is_ok());
        assert!(matches!(authority.admit_custody(&CustodyCall::LockVault), Err(CustodyRefusal::Undeclared { .. })));
        assert!(matches!(authority.admit_custody(&release("app.other")), Err(CustodyRefusal::Undeclared { .. })));
        let mut salted = AppDeclaration::default();
        salted.custody.operations = [CustodyOperation::Release, CustodyOperation::Sign].into();
        salted.custody.salts = vec![crate::door::declaration::SaltUse::persona(crate::door::declaration::SaltPattern::Prefix("app.place.".into()))];
        let mut salt_grant = AppGrant::new(AppId::new("app"));
        salt_grant.custody.operations = salted.custody.operations.clone();
        salt_grant.custody.salts = salted.custody.salts.clone();
        let salted = AppAuthority::new(salted, salt_grant);
        let release = |salt: &[u8]| CustodyCall::Release { source: KeySource::Persona, salts: vec![b"app.place.a".to_vec(), salt.to_vec()] };
        assert!(salted.admit_custody(&release(b"app.place.b")).is_ok());
        assert!(matches!(salted.admit_custody(&release(b"other")), Err(CustodyRefusal::Undeclared { .. })), "every salt in a release is checked");
        assert!(salted.admit_custody(&CustodyCall::Sign { source: KeySource::Persona, salt: b"app.place.a".to_vec(), message: vec![] }).is_ok());
        assert!(matches!(
            salted.admit_custody(&CustodyCall::Sign { source: KeySource::Wallet, salt: b"app.place.a".to_vec(), message: vec![] }),
            Err(CustodyRefusal::Undeclared { .. })
        ));
        let refusal = authority.admit_custody(&CustodyCall::Roster).unwrap_err();
        assert_eq!(refusal, CustodyRefusal::Undeclared { what: "the custody operation roster".into() });
        let text = serde_json::to_string(&refusal).unwrap();
        assert_eq!(serde_json::from_str::<CustodyRefusal>(&text).unwrap(), refusal);
    }

    #[test]
    fn the_delegation_scope_prefix_is_insignes() {
        for domain in ["moot", "mere.knot", "mere.graphshell", ""] {
            assert_eq!(
                crate::door::declaration::delegation_scope_prefix(domain),
                insigne::delegation::delegation_signing_prefix(domain)
            );
        }
    }
}
