// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The application side of the custody route: how an app reaches identity
//! and secrets by calling djinn (dramatis repo plan, D5).
//!
//! [`CustodyClient`] is async, for an app that already runs tokio;
//! [`BlockingCustodyClient`] owns a current-thread runtime, for a CLI or a
//! synchronous seam, and must not be used from inside a runtime.
//!
//! **Pending (D12).** When djinn is absent or Locked an app shows the identity
//! as pending: it never falls back to a key of its own and never writes
//! unsealed, and it may still read already-public state.
//! [`CustodyClientError::is_pending`] is the one test for that.
//!
//! **Releases (D11).** [`CustodyClient::release`] returns a
//! [`RetainedKeys`] that answers exactly the salts asked for, every other salt
//! being Locked, with each attestation checked against the released master.
//! An app holding one watches [`CustodyClient::watch_lock`] and drops it
//! when the vault locks.

use dramatis::roster::Roster;
use dramatis::view::VaultLockView;
use insigne::DerivedKeyAttestation;
use personae::carry::{DeviceGrantSet, DeviceId, RemoteAuthRevocationOutcome};
use personae::{Ed25519Keypair, Ed25519PublicKey, IdentityError, ProfileId, RetainedKeys};

use crate::door::app_admission::{AppId, AppRouteId, configured_app_endpoint};
use crate::door::app_client::{AppClientError, AppConnection};
use crate::door::declaration::AppDeclaration;
use crate::door::custody::{
    CUSTODY_ROUTE, CustodyAnswer, CustodyCall, CustodyRefusal, EpochKeyRequest, KeySource,
    ReleasedEpochKey, ResidentStatus, StationGrantRequest,
};

/// Why a custody call did not answer.
#[derive(Debug, thiserror::Error)]
pub enum CustodyClientError {
    /// djinn's door could not be reached: the resident is not running, or
    /// this app is not admitted to the custody route.
    #[error("djinn is not reachable: {0}")]
    Absent(AppClientError),
    /// djinn answered with a refusal.
    #[error(transparent)]
    Refused(#[from] CustodyRefusal),
    /// The conversation broke after it opened.
    #[error(transparent)]
    Transport(#[from] AppClientError),
    /// djinn answered a different question.
    #[error("djinn answered {got} to a {asked} call")]
    UnexpectedAnswer {
        asked: &'static str,
        got: &'static str,
    },
    /// A release did not check out against its own attestations.
    #[error("the released keys did not verify: {0}")]
    Release(IdentityError),
}

impl CustodyClientError {
    /// Whether the app must show its identity as pending (D12): djinn is
    /// absent, or the vault is Locked. Every other error is a real failure.
    pub fn is_pending(&self) -> bool {
        matches!(
            self,
            Self::Absent(_) | Self::Refused(CustodyRefusal::Locked)
        )
    }
}

/// An open custody session against djinn, as one application.
pub struct CustodyClient {
    inner: AppConnection,
    profile: Option<ProfileId>,
}

impl CustodyClient {
    /// Connect to the configured first-party endpoint as `app`.
    pub async fn open(app: AppId) -> Result<Self, CustodyClientError> {
        Self::open_at(&configured_app_endpoint(), app).await
    }

    /// The same, at an explicit endpoint. Tests and receipts use this.
    pub async fn open_at(endpoint: &str, app: AppId) -> Result<Self, CustodyClientError> {
        let route = AppRouteId::new(CUSTODY_ROUTE).expect("the custody route id is valid");
        let inner = AppConnection::open_route_at(endpoint, app, route)
            .await
            .map_err(CustodyClientError::Absent)?;
        Ok(Self {
            inner,
            profile: None,
        })
    }

    /// Connect to the configured endpoint as `app`, carrying its declaration.
    /// Djinn then answers only the custody the declaration names and the
    /// owner grants.
    pub async fn open_declared(
        app: AppId,
        declaration: AppDeclaration,
    ) -> Result<Self, CustodyClientError> {
        Self::open_declared_at(&configured_app_endpoint(), app, declaration).await
    }

    /// The same, at an explicit endpoint.
    pub async fn open_declared_at(
        endpoint: &str,
        app: AppId,
        declaration: AppDeclaration,
    ) -> Result<Self, CustodyClientError> {
        let route = AppRouteId::new(CUSTODY_ROUTE).expect("the custody route id is valid");
        let inner = AppConnection::open_declared_route_at(endpoint, app, route, declaration)
            .await
            .map_err(CustodyClientError::Absent)?;
        Ok(Self {
            inner,
            profile: None,
        })
    }

    /// One raw call. The typed calls below are what an app normally uses.
    pub async fn call(&mut self, call: CustodyCall) -> Result<CustodyAnswer, CustodyClientError> {
        let call = match &self.profile {
            Some(profile) if call.answers_as_profile() => CustodyCall::AsProfile {
                profile: profile.clone(),
                inner: Box::new(call),
            },
            _ => call,
        };
        Ok(self
            .inner
            .call::<_, Result<CustodyAnswer, CustodyRefusal>>(call)
            .await??)
    }

    /// Speak as persona `profile` from now on, without switching djinn to
    /// it: status, releases, attestations and signatures answer for that
    /// persona (D13). `None` returns to the persona in use.
    pub fn speak_as(&mut self, profile: Option<ProfileId>) {
        self.profile = profile;
    }

    /// The lock, the protection and the public roots.
    pub async fn status(&mut self) -> Result<ResidentStatus, CustodyClientError> {
        expect_status(self.call(CustodyCall::Status).await?)
    }

    /// The resident's secret-free quarantine cards.
    pub async fn unassigned_imports(
        &mut self,
    ) -> Result<Vec<crate::door::quarantine::UnassignedImport>, CustodyClientError> {
        match self.call(CustodyCall::UnassignedImports).await? {
            CustodyAnswer::UnassignedImports { imports } => Ok(imports),
            other => Err(mismatch("unassigned_imports", &other)),
        }
    }
    pub async fn assign_import(
        &mut self,
        request: crate::door::quarantine::AssignImportRequest,
    ) -> Result<(), CustodyClientError> {
        expect_done(self.call(CustodyCall::AssignImport(request)).await?)
    }
    pub async fn quarantine(
        &mut self,
        profile: ProfileId,
    ) -> Result<Vec<crate::door::quarantine::QuarantineCard>, CustodyClientError> {
        match self.call(CustodyCall::Quarantine { profile }).await? {
            CustodyAnswer::Quarantine { cards } => Ok(cards),
            other => Err(mismatch("quarantine", &other)),
        }
    }
    /// Request a decision, approved only by the resident's own native UI.
    pub async fn review_quarantine(
        &mut self,
        request: crate::door::quarantine::ReviewRequest,
    ) -> Result<(), CustodyClientError> {
        expect_done(self.call(CustodyCall::ReviewQuarantine(request)).await?)
    }
    pub async fn unlock_native(&mut self) -> Result<(), CustodyClientError> {
        expect_done(self.call(CustodyCall::UnlockNative).await?)
    }
    pub async fn change_passphrase_native(
        &mut self,
    ) -> Result<dramatis::authentication::PassphraseChangeReceiptV1, CustodyClientError> {
        match self
            .call(CustodyCall::ChangePassphraseNative(Default::default()))
            .await?
        {
            CustodyAnswer::PassphraseChange { receipt } => Ok(receipt),
            other => Err(mismatch("passphrase change", &other)),
        }
    }
    pub async fn lock_vault(&mut self) -> Result<(), CustodyClientError> {
        expect_done(self.call(CustodyCall::LockVault).await?)
    }
    /// The vault's personas, for a picker.
    pub async fn roster(&mut self) -> Result<Roster, CustodyClientError> {
        expect_roster(self.call(CustodyCall::Roster).await?)
    }

    /// Switch the persona in use.
    pub async fn choose_profile(&mut self, profile: ProfileId) -> Result<(), CustodyClientError> {
        expect_done(self.call(CustodyCall::ChooseProfile { profile }).await?)
    }

    /// Mint a persona and switch to it.
    pub async fn create_profile(
        &mut self,
        profile: ProfileId,
        display_name: impl Into<String>,
    ) -> Result<(), CustodyClientError> {
        let display_name = display_name.into();
        expect_done(
            self.call(CustodyCall::CreateProfile {
                profile,
                display_name,
            })
            .await?,
        )
    }

    /// The derived keys for `salts`, released under djinn's policy (D11).
    pub async fn release(
        &mut self,
        source: KeySource,
        salts: Vec<Vec<u8>>,
    ) -> Result<RetainedKeys, CustodyClientError> {
        expect_released(self.call(CustodyCall::Release { source, salts }).await?)
    }

    /// The master's attestation for the key `salt` derives.
    pub async fn attest(
        &mut self,
        source: KeySource,
        salt: Vec<u8>,
    ) -> Result<DerivedKeyAttestation, CustodyClientError> {
        expect_attestation(self.call(CustodyCall::Attest { source, salt }).await?)
    }

    /// Sign `message` inside djinn with the key `salt` derives: the signing
    /// key's public half and the signature.
    pub async fn sign(
        &mut self,
        source: KeySource,
        salt: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<([u8; 32], Vec<u8>), CustodyClientError> {
        expect_signature(
            self.call(CustodyCall::Sign {
                source,
                salt,
                message,
            })
            .await?,
        )
    }

    /// Issue a sited station's grant with the wallet (D17).
    pub async fn issue_station_grant(
        &mut self,
        request: StationGrantRequest,
        issuer_public_key: [u8; 32],
    ) -> Result<DeviceGrantSet, CustodyClientError> {
        expect_grant(
            self.call(CustodyCall::IssueStationGrant {
                request,
                issuer_public_key,
            })
            .await?,
        )
    }

    /// Revoke one delegated device in the wallet.
    pub async fn revoke_device(
        &mut self,
        device_id: DeviceId,
    ) -> Result<RemoteAuthRevocationOutcome, CustodyClientError> {
        expect_revoked(
            self.call(CustodyCall::RevokeDevice {
                device_id: *device_id.as_uuid(),
            })
            .await?,
        )
    }

    /// Keys derived from `persona`'s current private epoch, released under
    /// djinn's policy (D11), in request order.
    pub async fn release_epoch_keys(
        &mut self,
        persona: uuid::Uuid,
        device_label: Option<String>,
        keys: Vec<EpochKeyRequest>,
    ) -> Result<Vec<ReleasedEpochKey>, CustodyClientError> {
        expect_epoch_keys(
            self.call(CustodyCall::ReleaseEpochKeys {
                persona,
                device_label,
                keys,
            })
            .await?,
        )
    }

    /// Wait until the lock leaves `seen`; the new state.
    pub async fn watch_lock(
        &mut self,
        seen: VaultLockView,
    ) -> Result<VaultLockView, CustodyClientError> {
        expect_lock(self.call(CustodyCall::WatchLock { seen }).await?)
    }
}

/// [`CustodyClient`] on its own current-thread runtime, for synchronous
/// callers. Never call it from inside a tokio runtime.
pub struct BlockingCustodyClient {
    runtime: tokio::runtime::Runtime,
    client: CustodyClient,
    timeout: Option<std::time::Duration>,
}

fn deadline_error() -> CustodyClientError {
    CustodyClientError::Transport(AppClientError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "custody operation deadline elapsed",
    )))
}

impl BlockingCustodyClient {
    /// Bound connection, handshake and one read-only status operation together.
    /// The client is dropped on timeout so a late frame can never answer a later
    /// request on a reused sequential connection. Call outside a Tokio runtime.
    pub fn status_at_timeout(
        endpoint: &str,
        app: AppId,
        profile: Option<ProfileId>,
        timeout: std::time::Duration,
    ) -> Result<ResidentStatus, CustodyClientError> {
        expect_status(Self::call_at_timeout(
            endpoint,
            app,
            profile,
            CustodyCall::Status,
            timeout,
        )?)
    }

    /// One bounded independent conversation. Timeout discards its transport;
    /// callers decide uncertainty/reconciliation and this never retries a call.
    pub fn call_at_timeout(
        endpoint: &str,
        app: AppId,
        profile: Option<ProfileId>,
        call: CustodyCall,
        timeout: std::time::Duration,
    ) -> Result<CustodyAnswer, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        runtime.block_on(async {
            tokio::time::timeout(timeout, async {
                let mut client = CustodyClient::open_at(endpoint, app).await?;
                client.speak_as(profile);
                client.call(call).await
            })
            .await
            .map_err(|_| {
                CustodyClientError::Transport(AppClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "custody status deadline elapsed",
                )))
            })?
        })
    }

    /// Connect to the configured first-party endpoint as `app`.
    pub fn open(app: AppId) -> Result<Self, CustodyClientError> {
        Self::open_at(&configured_app_endpoint(), app)
    }

    /// The same, at an explicit endpoint.
    pub fn open_at(endpoint: &str, app: AppId) -> Result<Self, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let client = runtime.block_on(CustodyClient::open_at(endpoint, app))?;
        Ok(Self {
            runtime,
            client,
            timeout: None,
        })
    }

    /// Connect to the configured endpoint as `app`, carrying its declaration.
    pub fn open_declared(app: AppId, declaration: AppDeclaration) -> Result<Self, CustodyClientError> {
        Self::open_declared_at(&configured_app_endpoint(), app, declaration)
    }

    /// The same, at an explicit endpoint.
    pub fn open_declared_at(
        endpoint: &str,
        app: AppId,
        declaration: AppDeclaration,
    ) -> Result<Self, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let client = runtime.block_on(CustodyClient::open_declared_at(endpoint, app, declaration))?;
        Ok(Self {
            runtime,
            client,
            timeout: None,
        })
    }

    /// Bounded transport for a provider whose actor must be joinable. Every
    /// later call also has this deadline; a transport timeout retires the client.
    pub fn open_at_timeout(
        endpoint: &str,
        app: AppId,
        timeout: std::time::Duration,
    ) -> Result<Self, CustodyClientError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let client = runtime.block_on(async {
            tokio::time::timeout(timeout, CustodyClient::open_at(endpoint, app))
                .await
                .map_err(|_| deadline_error())?
        })?;
        Ok(Self {
            runtime,
            client,
            timeout: Some(timeout),
        })
    }

    pub(crate) fn set_call_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.timeout = timeout;
    }

    /// See [`CustodyClient::speak_as`].
    pub fn speak_as(&mut self, profile: Option<ProfileId>) {
        self.client.speak_as(profile);
    }

    /// One raw call.
    pub fn call(&mut self, call: CustodyCall) -> Result<CustodyAnswer, CustodyClientError> {
        match self.timeout {
            Some(timeout) => self.runtime.block_on(async {
                tokio::time::timeout(timeout, self.client.call(call))
                    .await
                    .map_err(|_| deadline_error())?
            }),
            None => self.runtime.block_on(self.client.call(call)),
        }
    }

    /// See [`CustodyClient::status`].
    pub fn status(&mut self) -> Result<ResidentStatus, CustodyClientError> {
        expect_status(self.call(CustodyCall::Status)?)
    }

    /// See [`CustodyClient::roster`].
    pub fn roster(&mut self) -> Result<Roster, CustodyClientError> {
        expect_roster(self.call(CustodyCall::Roster)?)
    }

    /// See [`CustodyClient::release`].
    pub fn release(
        &mut self,
        source: KeySource,
        salts: Vec<Vec<u8>>,
    ) -> Result<RetainedKeys, CustodyClientError> {
        expect_released(self.call(CustodyCall::Release { source, salts })?)
    }

    /// See [`CustodyClient::attest`].
    pub fn attest(
        &mut self,
        source: KeySource,
        salt: Vec<u8>,
    ) -> Result<DerivedKeyAttestation, CustodyClientError> {
        expect_attestation(self.call(CustodyCall::Attest { source, salt })?)
    }

    /// See [`CustodyClient::sign`].
    pub fn sign(
        &mut self,
        source: KeySource,
        salt: Vec<u8>,
        message: Vec<u8>,
    ) -> Result<([u8; 32], Vec<u8>), CustodyClientError> {
        expect_signature(self.call(CustodyCall::Sign {
            source,
            salt,
            message,
        })?)
    }

    /// See [`CustodyClient::issue_station_grant`].
    pub fn issue_station_grant(
        &mut self,
        request: StationGrantRequest,
        issuer_public_key: [u8; 32],
    ) -> Result<DeviceGrantSet, CustodyClientError> {
        expect_grant(self.call(CustodyCall::IssueStationGrant {
            request,
            issuer_public_key,
        })?)
    }

    /// See [`CustodyClient::release_epoch_keys`].
    pub fn release_epoch_keys(
        &mut self,
        persona: uuid::Uuid,
        device_label: Option<String>,
        keys: Vec<EpochKeyRequest>,
    ) -> Result<Vec<ReleasedEpochKey>, CustodyClientError> {
        expect_epoch_keys(self.call(CustodyCall::ReleaseEpochKeys {
            persona,
            device_label,
            keys,
        })?)
    }

    /// See [`CustodyClient::revoke_device`].
    pub fn revoke_device(
        &mut self,
        device_id: DeviceId,
    ) -> Result<RemoteAuthRevocationOutcome, CustodyClientError> {
        expect_revoked(self.call(CustodyCall::RevokeDevice {
            device_id: *device_id.as_uuid(),
        })?)
    }
}

fn answer_name(answer: &CustodyAnswer) -> &'static str {
    match answer {
        CustodyAnswer::PassphraseChange { .. } => "a passphrase change receipt",
        CustodyAnswer::Payload { .. } => "a retained payload",
        CustodyAnswer::VaultOutput { .. } => "vault output",
        CustodyAnswer::VaultEnrollment { .. } => "vault enrollment",
        CustodyAnswer::Quarantine { .. } => "quarantine cards",
        CustodyAnswer::UnassignedImports { .. } => "unassigned imports",
        CustodyAnswer::Status(_) => "a status",
        CustodyAnswer::Roster(_) => "a roster",
        CustodyAnswer::Done => "done",
        CustodyAnswer::Released { .. } => "a release",
        CustodyAnswer::Attestation(_) => "an attestation",
        CustodyAnswer::Signature { .. } => "a signature",
        CustodyAnswer::StationGrant(_) => "a station grant",
        CustodyAnswer::Revoked(_) => "a revocation",
        CustodyAnswer::Lock(_) => "a lock state",
        CustodyAnswer::EpochKeys { .. } => "epoch keys",
    }
}

fn mismatch(asked: &'static str, got: &CustodyAnswer) -> CustodyClientError {
    CustodyClientError::UnexpectedAnswer {
        asked,
        got: answer_name(got),
    }
}

fn expect_status(answer: CustodyAnswer) -> Result<ResidentStatus, CustodyClientError> {
    match answer {
        CustodyAnswer::Status(status) => Ok(status),
        other => Err(mismatch("status", &other)),
    }
}

fn expect_roster(answer: CustodyAnswer) -> Result<Roster, CustodyClientError> {
    match answer {
        CustodyAnswer::Roster(roster) => Ok(roster),
        other => Err(mismatch("roster", &other)),
    }
}

fn expect_done(answer: CustodyAnswer) -> Result<(), CustodyClientError> {
    match answer {
        CustodyAnswer::Done => Ok(()),
        other => Err(mismatch("profile", &other)),
    }
}

fn expect_released(answer: CustodyAnswer) -> Result<RetainedKeys, CustodyClientError> {
    let (master, keys) = match answer {
        CustodyAnswer::Released { master, keys } => (master, keys),
        other => return Err(mismatch("release", &other)),
    };
    let master = Ed25519PublicKey::from_bytes(&master).map_err(CustodyClientError::Release)?;
    RetainedKeys::from_released(
        master,
        keys.iter().map(|key| {
            (
                key.salt.clone(),
                Ed25519Keypair::from_seed(key.seed),
                key.attestation.clone(),
            )
        }),
    )
    .map_err(CustodyClientError::Release)
}

fn expect_attestation(answer: CustodyAnswer) -> Result<DerivedKeyAttestation, CustodyClientError> {
    match answer {
        CustodyAnswer::Attestation(attestation) => Ok(attestation),
        other => Err(mismatch("attest", &other)),
    }
}

fn expect_signature(answer: CustodyAnswer) -> Result<([u8; 32], Vec<u8>), CustodyClientError> {
    match answer {
        CustodyAnswer::Signature {
            public_key,
            signature,
        } => Ok((public_key, signature)),
        other => Err(mismatch("sign", &other)),
    }
}

fn expect_grant(answer: CustodyAnswer) -> Result<DeviceGrantSet, CustodyClientError> {
    match answer {
        CustodyAnswer::StationGrant(grant) => Ok(grant),
        other => Err(mismatch("station grant", &other)),
    }
}

fn expect_revoked(
    answer: CustodyAnswer,
) -> Result<RemoteAuthRevocationOutcome, CustodyClientError> {
    match answer {
        CustodyAnswer::Revoked(outcome) => Ok(outcome),
        other => Err(mismatch("revoke", &other)),
    }
}

fn expect_epoch_keys(answer: CustodyAnswer) -> Result<Vec<ReleasedEpochKey>, CustodyClientError> {
    match answer {
        CustodyAnswer::EpochKeys { keys } => Ok(keys),
        other => Err(mismatch("release epoch keys", &other)),
    }
}

fn expect_lock(answer: CustodyAnswer) -> Result<VaultLockView, CustodyClientError> {
    match answer {
        CustodyAnswer::Lock(lock) => Ok(lock),
        other => Err(mismatch("watch lock", &other)),
    }
}

#[cfg(test)]
mod tests {
    use personae::{IdentityProvider, InMemoryProvider};

    use super::*;
    use crate::door::custody::ReleasedKey;

    #[cfg(unix)]
    #[test]
    fn bounded_custody_status_times_out_a_stalled_handshake() {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        use std::time::{Duration, Instant};
        let path = std::path::PathBuf::from(format!(
            "/tmp/alembic-status-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let (stop, stopped) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline && stopped.try_recv().is_err() {
                match listener.accept() {
                    Ok((_stream, _)) => {
                        let _ = stopped.recv_timeout(Duration::from_secs(3));
                        break;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });
        let start = Instant::now();
        let result = BlockingCustodyClient::status_at_timeout(
            path.to_str().unwrap(),
            AppId::new("turnstone"),
            None,
            Duration::from_millis(150),
        );
        let elapsed = start.elapsed();
        let _ = stop.send(());
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
        assert!(
            matches!(result, Err(CustodyClientError::Transport(AppClientError::Io(ref error)))
            if error.kind() == std::io::ErrorKind::TimedOut)
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "status must not wait for the stalled resident"
        );
    }

    fn release_of(provider: &InMemoryProvider, salts: &[&[u8]]) -> CustodyAnswer {
        CustodyAnswer::Released {
            master: provider.master_public_key().to_bytes(),
            keys: salts
                .iter()
                .map(|salt| ReleasedKey {
                    salt: salt.to_vec(),
                    seed: provider.derive_keypair(salt).unwrap().to_seed(),
                    attestation: provider.attest_derived_key(salt).unwrap(),
                })
                .collect(),
        }
    }

    #[test]
    fn a_release_answers_its_salts_and_locks_the_rest() {
        let provider = InMemoryProvider::from_seed([0x41; 32]);
        let keys = expect_released(release_of(&provider, &[b"mesh-author"])).unwrap();
        assert_eq!(
            keys.derive_keypair(b"mesh-author").unwrap().to_seed(),
            provider.derive_keypair(b"mesh-author").unwrap().to_seed()
        );
        assert!(matches!(
            keys.derive_keypair(b"anything-else"),
            Err(IdentityError::Locked)
        ));
    }

    #[test]
    fn a_release_whose_key_is_not_its_attestations_is_refused() {
        let provider = InMemoryProvider::from_seed([0x42; 32]);
        let CustodyAnswer::Released { master, mut keys } = release_of(&provider, &[b"mesh-author"])
        else {
            unreachable!()
        };
        keys[0].seed = [0x13; 32];
        let forged = CustodyAnswer::Released { master, keys };
        assert!(matches!(
            expect_released(forged),
            Err(CustodyClientError::Release(_))
        ));
    }

    #[test]
    fn absent_and_locked_are_pending_and_nothing_else_is() {
        let absent = CustodyClientError::Absent(AppClientError::Closed);
        assert!(absent.is_pending());
        assert!(CustodyClientError::Refused(CustodyRefusal::Locked).is_pending());
        assert!(!CustodyClientError::Refused(CustodyRefusal::NotReleasable).is_pending());
    }
}
