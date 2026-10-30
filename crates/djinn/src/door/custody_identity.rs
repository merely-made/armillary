// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A synchronous [`IdentityProvider`] over the custody route, for an
//! application whose code derives keys through a provider (dramatis repo
//! plan, DR-C; D11, D12).
//!
//! [`CustodyIdentity`] answers `derive_keypair` with a release djinn makes
//! under its policy, one salt at a time, and holds what it was given until
//! the vault locks: a watcher on the lock broadcast drops every held key the
//! moment djinn reports Locked or goes away. Attestations and signatures for
//! salts djinn will not release (root-level acts, D11) are made inside djinn
//! through [`CustodyIdentity::attest_derived_key`],
//! [`CustodyIdentity::sign`] and [`CustodyIdentity::issue_certificate`].
//!
//! Calls run on the provider's own thread, so the provider can be used from
//! inside or outside a tokio runtime. With djinn absent or Locked,
//! [`CustodyIdentity::connect`] fails with an error whose
//! [`is_pending`](CustodyClientError::is_pending) is true and every key
//! request answers [`IdentityError::Locked`]: the identity is pending, never
//! replaced by a key of the application's own (D12).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

use dramatis::roster::Roster;
use dramatis::view::VaultLockView;
use insigne::DerivedKeyAttestation;
use insigne::delegation::{
    DelegationCertificate, DelegationRevocation, SignedDelegationCertificate,
    SignedDelegationRevocation, delegation_signing_salt,
};
use personae::delegation::DelegationError;
use personae::{
    Ed25519Keypair, Ed25519PublicKey, IdentityError, IdentityProvider, ProfileId, RetainedKeys,
};

use crate::door::app_admission::{AppId, configured_app_endpoint};
use crate::door::app_client::AppClientError;
use crate::door::custody::{CustodyAnswer, CustodyCall, KeySource, ResidentStatus};
use crate::door::custody_client::{BlockingCustodyClient, CustodyClient, CustodyClientError};

type JobCall = Box<dyn FnOnce(Option<&mut BlockingCustodyClient>) -> bool + Send>;
struct Job {
    deadline: Option<Instant>,
    cancelled: Arc<AtomicBool>,
    call: JobCall,
}
impl Job {
    fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }
    fn expired(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
            || self
                .remaining()
                .is_some_and(|remaining| remaining.is_zero())
    }
    fn run(self, client: Option<&mut BlockingCustodyClient>) -> bool {
        if self.expired() {
            return true;
        }
        (self.call)(client)
    }
}

/// Own the initializing actor until every fallible constructor step succeeds.
struct StartingActor {
    sender: Option<mpsc::Sender<Job>>,
    thread: Option<std::thread::JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}
impl Drop for StartingActor {
    fn drop(&mut self) {
        if self.thread.is_none() {
            return;
        }
        self.stop.store(true, Ordering::SeqCst);
        self.sender.take();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The persona djinn speaks as, reached through the custody route.
pub struct CustodyIdentity {
    endpoint: String,
    app: AppId,
    requested_profile: Option<ProfileId>,
    master: Ed25519PublicKey,
    status: ResidentStatus,
    jobs: Mutex<Option<mpsc::Sender<Job>>>,
    job_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    watch_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
    call_timeout: Option<Duration>,
    held: Arc<Mutex<HashMap<Vec<u8>, RetainedKeys>>>,
    locked: Arc<AtomicBool>,
    epoch: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
}

impl CustodyIdentity {
    /// Connect to djinn at the configured first-party endpoint as `app`.
    /// Pending (see [`CustodyClientError::is_pending`]) when djinn is absent
    /// or Locked.
    pub fn connect(app: &str) -> Result<Self, CustodyClientError> {
        Self::connect_at(&configured_app_endpoint(), app)
    }

    /// A provider with bounded connection/status stages and bounded actor RPCs.
    /// Intended for cancellable off-thread setup; it never retries an operation.
    pub fn connect_timeout(app: &str, timeout: Duration) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(&configured_app_endpoint(), app, None, Some(timeout))
    }

    pub fn connect_at_timeout(
        endpoint: &str,
        app: &str,
        timeout: Duration,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(endpoint, app, None, Some(timeout))
    }

    /// The same, at an explicit endpoint.
    pub fn connect_at(endpoint: &str, app: &str) -> Result<Self, CustodyClientError> {
        Self::connect_as_at(endpoint, app, None)
    }

    /// Connect as `app` speaking as persona `profile` without switching djinn
    /// to it (D13); `None` is the persona in use.
    pub fn connect_as(app: &str, profile: Option<ProfileId>) -> Result<Self, CustodyClientError> {
        Self::connect_as_at(&configured_app_endpoint(), app, profile)
    }

    /// [`Self::connect_as`] at an explicit endpoint.
    pub fn connect_as_at(
        endpoint: &str,
        app: &str,
        profile: Option<ProfileId>,
    ) -> Result<Self, CustodyClientError> {
        Self::connect_as_at_bounded(endpoint, app, profile, None)
    }

    fn connect_as_at_bounded(
        endpoint: &str,
        app: &str,
        profile: Option<ProfileId>,
        timeout: Option<Duration>,
    ) -> Result<Self, CustodyClientError> {
        let deadline = timeout
            .map(|duration| Instant::now().checked_add(duration).ok_or_else(timed_out))
            .transpose()?;
        let remaining = || deadline.map(|end| end.saturating_duration_since(Instant::now()));
        let app = AppId::new(app);
        let requested_profile = profile.clone();
        let open = move |endpoint: &str, app: AppId, limit: Option<Duration>| {
            let opened = match limit {
                Some(timeout) => BlockingCustodyClient::open_at_timeout(endpoint, app, timeout),
                None => BlockingCustodyClient::open_at(endpoint, app),
            };
            opened.map(|mut client| {
                client.speak_as(profile.clone());
                client
            })
        };
        let (jobs, received) = mpsc::channel::<Job>();
        let (ready, opened) = mpsc::channel();
        let actor_endpoint = endpoint.to_string();
        let actor_app = app.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let actor_stop = stop.clone();
        let job_thread = std::thread::Builder::new()
            .name(format!("custody-{app}"))
            .spawn(move || {
                let initial_timeout =
                    deadline.map(|end| end.saturating_duration_since(Instant::now()));
                let mut client = match open(&actor_endpoint, actor_app.clone(), initial_timeout) {
                    Ok(client) => {
                        let _ = ready.send(Ok(()));
                        Some(client)
                    }
                    Err(error) => {
                        let _ = ready.send(Err(error));
                        return;
                    }
                };
                while let Ok(job) = received.recv() {
                    if actor_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if job.expired() {
                        continue;
                    }
                    if client.is_none() {
                        client = open(&actor_endpoint, actor_app.clone(), job.remaining()).ok();
                    }
                    if actor_stop.load(Ordering::SeqCst) {
                        break;
                    }
                    if job.expired() {
                        continue;
                    }
                    if let Some(client) = client.as_mut() {
                        client.set_call_timeout(job.remaining());
                    }
                    if !job.run(client.as_mut()) {
                        client = None;
                    }
                }
            })
            .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
        let mut starting = StartingActor {
            sender: Some(jobs),
            thread: Some(job_thread),
            stop: stop.clone(),
        };
        match timeout {
            Some(_) => opened
                .recv_timeout(remaining().expect("bounded startup"))
                .map_err(|error| match error {
                    mpsc::RecvTimeoutError::Timeout => timed_out(),
                    mpsc::RecvTimeoutError::Disconnected => closed(),
                })??,
            None => opened.recv().map_err(|_| closed())??,
        }

        let status = ask_on_bounded(
            starting.sender.as_ref().expect("startup sender"),
            remaining(),
            |client| client.status(),
        )?;
        let Some(master) = status
            .persona_public_key
            .filter(|_| status.lock == VaultLockView::Unlocked)
        else {
            return Err(CustodyClientError::Refused(
                crate::door::custody::CustodyRefusal::Locked,
            ));
        };
        let master = Ed25519PublicKey::from_bytes(&master).map_err(CustodyClientError::Release)?;
        let this = Self {
            endpoint: endpoint.to_owned(),
            app: app.clone(),
            requested_profile,
            master,
            status,
            jobs: Mutex::new(starting.sender.take()),
            job_thread: Mutex::new(starting.thread.take()),
            watch_thread: Mutex::new(None),
            call_timeout: timeout,
            held: Arc::default(),
            locked: Arc::new(AtomicBool::new(false)),
            epoch: Arc::new(AtomicU64::new(1)),
            stop,
        };
        this.watch(endpoint.to_string(), app);
        Ok(this)
    }

    /// The status djinn answered when this connected.
    pub fn connected_status(&self) -> &ResidentStatus {
        &self.status
    }

    /// The persona in use when this connected.
    pub fn profile(&self) -> Option<&ProfileId> {
        self.status.profile.as_ref()
    }

    /// What protects the vault, as djinn reports it.
    pub fn protection(&self) -> String {
        format!("{:?} (held by djinn)", self.status.protection)
    }

    /// Whether djinn has reported the vault Locked (or gone) since this
    /// connected: every key request is pending until it unlocks.
    pub fn is_locked(&self) -> bool {
        self.locked.load(Ordering::SeqCst)
    }

    /// Monotonic local binding generation, including lock/loss followed by
    /// unlock between UI turns. It is not a wallet epoch or an authorization.
    pub fn custody_epoch(&self) -> Option<u64> {
        let epoch = self.epoch.load(Ordering::SeqCst);
        (!self.is_locked() && epoch != 0 && self.epoch.load(Ordering::SeqCst) == epoch)
            .then_some(epoch)
    }

    /// The lock, the protection and the public roots, now.
    pub fn status(&self) -> Result<ResidentStatus, CustodyClientError> {
        self.ask(|client| client.status())
    }

    /// A bounded, read-only status check independent of the provider job queue.
    /// Timeout drops this fresh conversation; no consequential call is retried.
    pub fn status_timeout(&self, timeout: Duration) -> Result<ResidentStatus, CustodyClientError> {
        let endpoint = self.endpoint.clone();
        let app = self.app.clone();
        let profile = self.requested_profile.clone();
        let result = bounded_worker(move || {
            BlockingCustodyClient::status_at_timeout(&endpoint, app, profile, timeout)
        });
        if self.status.custody_epoch.is_some()
            && !result
                .as_ref()
                .is_ok_and(|status| self.status_matches_binding(status))
        {
            self.invalidate_binding();
        }
        result
    }

    /// The vault's personas, for a picker. Answered while Locked too.
    pub fn roster(&self) -> Result<Roster, CustodyClientError> {
        self.ask(|client| client.roster())
    }

    /// Switch the persona djinn speaks as. Keys held for the old one are
    /// dropped; this provider keeps answering for the persona it connected
    /// as, so reconnect to speak as the new one.
    pub fn choose_profile(&self, profile: ProfileId) -> Result<(), CustodyClientError> {
        self.forget();
        self.ask(move |client| done(client.call(CustodyCall::ChooseProfile { profile })?))
    }

    /// Mint a persona in djinn's vault and switch to it.
    pub fn create_profile(
        &self,
        profile: ProfileId,
        display_name: impl Into<String>,
    ) -> Result<(), CustodyClientError> {
        let display_name = display_name.into();
        self.forget();
        self.ask(move |client| {
            done(client.call(CustodyCall::CreateProfile {
                profile,
                display_name,
            })?)
        })
    }

    /// Sign `message` inside djinn with the key `salt` derives: the signing
    /// key's public half and the signature (D11).
    pub fn sign(&self, salt: &[u8], message: &[u8]) -> Result<([u8; 32], Vec<u8>), IdentityError> {
        self.pending()?;
        let (salt, message) = (salt.to_vec(), message.to_vec());
        self.ask(move |client| client.sign(KeySource::Persona, salt, message))
            .map_err(identity_error)
    }

    /// Issue a delegation certificate as this persona, signed inside djinn:
    /// the scope's signing key never leaves it.
    pub fn issue_certificate(
        &self,
        certificate: DelegationCertificate,
    ) -> Result<SignedDelegationCertificate, DelegationError> {
        if !certificate.is_well_formed() {
            return Err(DelegationError::MalformedCertificate);
        }
        if certificate.issuer != self.master.to_bytes() {
            return Err(DelegationError::WrongIssuer);
        }
        let (signer, signature) = self.sign_scoped(
            &delegation_signing_salt(&certificate.scope),
            &certificate.signing_bytes(),
        )?;
        Ok(SignedDelegationCertificate::from_parts(
            certificate,
            signer,
            signature,
        ))
    }

    /// Issue a delegation revocation as this persona, signed inside djinn.
    pub fn issue_revocation(
        &self,
        revocation: DelegationRevocation,
    ) -> Result<SignedDelegationRevocation, DelegationError> {
        if !revocation.is_well_formed() {
            return Err(DelegationError::MalformedRevocation);
        }
        if revocation.issuer != self.master.to_bytes() {
            return Err(DelegationError::WrongIssuer);
        }
        let (signer, signature) = self.sign_scoped(
            &delegation_signing_salt(&revocation.scope),
            &revocation.signing_bytes(),
        )?;
        Ok(SignedDelegationRevocation::from_parts(
            revocation, signer, signature,
        ))
    }

    /// Drop every key held so far.
    pub fn forget(&self) {
        advance_epoch(&self.epoch);
        self.held.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn sign_scoped(
        &self,
        salt: &[u8],
        message: &[u8],
    ) -> Result<(DerivedKeyAttestation, Vec<u8>), DelegationError> {
        let signer = self
            .attest_derived_key(salt)
            .map_err(|_| DelegationError::Identity)?;
        let (public_key, signature) = self
            .sign(salt, message)
            .map_err(|_| DelegationError::Identity)?;
        match signer.check(salt) {
            Ok(checked) if checked.derived() == &public_key => Ok((signer, signature)),
            _ => Err(DelegationError::Identity),
        }
    }

    fn pending(&self) -> Result<(), IdentityError> {
        match self.is_locked() {
            true => Err(IdentityError::Locked),
            false => Ok(()),
        }
    }

    fn ask<T: Send + 'static>(
        &self,
        call: impl FnOnce(&mut BlockingCustodyClient) -> Result<T, CustodyClientError> + Send + 'static,
    ) -> Result<T, CustodyClientError> {
        let jobs = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .cloned()
            .ok_or_else(closed)?;
        ask_on_bounded(&jobs, self.call_timeout, call)
    }

    /// Follow the lock broadcast on a second conversation: a Locked vault,
    /// or a djinn that went away, drops every held key (D11, D12).
    fn watch(&self, endpoint: String, app: AppId) {
        let held = Arc::clone(&self.held);
        let locked = Arc::clone(&self.locked);
        let epoch = Arc::clone(&self.epoch);
        let stop = Arc::clone(&self.stop);
        let spawned = std::thread::Builder::new()
            .name(format!("custody-lock-{app}"))
            .spawn(move || {
                let drop_all = || {
                    invalidate_epoch(&locked, &epoch);
                    held.lock().unwrap_or_else(|e| e.into_inner()).clear();
                };
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
                    drop_all(); return;
                };
                while !stop.load(Ordering::SeqCst) {
                    let opened = runtime.block_on(async {
                        tokio::select! {
                            _ = wait_stopped(&stop) => None,
                            result = tokio::time::timeout(Duration::from_secs(2), CustodyClient::open_at(&endpoint, app.clone())) => Some(result),
                        }
                    });
                    let mut client = match opened {
                        None => return,
                        Some(Ok(Ok(client))) => client,
                        Some(_) => {
                            drop_all();
                            runtime.block_on(async {
                                tokio::select! {
                                    _ = wait_stopped(&stop) => {},
                                    _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                                }
                            });
                            continue;
                        },
                    };
                    let mut seen = VaultLockView::Unlocked;
                    loop {
                        let changed = runtime.block_on(async {
                            tokio::select! {
                                _ = wait_stopped(&stop) => None,
                                result = client.watch_lock(seen) => Some(result),
                            }
                        });
                        match changed {
                            None => return,
                            Some(Ok(VaultLockView::Locked)) => {
                                drop_all(); seen = VaultLockView::Locked;
                            },
                            Some(Ok(VaultLockView::Unlocked)) => {
                                locked.store(false, Ordering::SeqCst); seen = VaultLockView::Unlocked;
                            },
                            Some(Err(_)) => { drop_all(); break; },
                        }
                    }
                }
            });
        match spawned {
            Ok(thread) => {
                *self.watch_thread.lock().unwrap_or_else(|e| e.into_inner()) = Some(thread)
            }
            Err(_) => {
                invalidate_epoch(&self.locked, &self.epoch);
                self.forget();
                tracing::warn!("custody lock watcher could not start; identity remains locked");
            }
        }
    }
}

fn advance_epoch(epoch: &AtomicU64) {
    // Exhaustion permanently closes the generation instead of reusing one.
    let _ = epoch.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |value| {
        Some(if value == 0 {
            0
        } else {
            value.checked_add(1).unwrap_or(0)
        })
    });
}

async fn wait_stopped(stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn timed_out() -> CustodyClientError {
    CustodyClientError::Transport(AppClientError::Io(std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "custody provider deadline elapsed",
    )))
}

fn invalidate_epoch(locked: &AtomicBool, epoch: &AtomicU64) {
    if !locked.swap(true, Ordering::SeqCst) {
        advance_epoch(epoch);
    }
}

#[cfg(test)]
mod epoch_tests {
    use super::*;

    fn actorless_fixture() -> (CustodyIdentity, mpsc::Receiver<Job>) {
        use personae::IdentityProvider as _;
        let root = personae::InMemoryProvider::from_seed([7; 32]);
        let master = root.master_public_key();
        let (jobs, receiver) = mpsc::channel();
        let identity = CustodyIdentity {
            endpoint: "/tmp/alembic-no-custody-runtime-test.sock".into(),
            app: AppId::new("turnstone"),
            requested_profile: None,
            master,
            status: ResidentStatus {
                lock: VaultLockView::Unlocked,
                protection: dramatis::view::VaultProtectionView::Ephemeral,
                profile: Some(ProfileId("test".into())),
                persona_public_key: Some(master.to_bytes()),
                wallet_public_key: None,
                wallet_root: None,
                custody_epoch: None,
            },
            jobs: Mutex::new(Some(jobs)),
            job_thread: Mutex::new(None),
            watch_thread: Mutex::new(None),
            call_timeout: Some(Duration::from_secs(2)),
            held: Arc::default(),
            locked: Arc::new(AtomicBool::new(false)),
            epoch: Arc::new(AtomicU64::new(1)),
            stop: Arc::new(AtomicBool::new(false)),
        };
        (identity, receiver)
    }

    #[test]
    fn bounded_payload_is_safe_inside_tokio_runtime() {
        const CHILD: &str = "MERE_CUSTODY_NESTED_RUNTIME_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "door::custody_identity::epoch_tests::bounded_payload_is_safe_inside_tokio_runtime"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                result.status.success(),
                "payload must not panic in Tokio: {}",
                String::from_utf8_lossy(&result.stderr)
            );
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("1 passed"),
                "child must execute the payload regression"
            );
            return;
        }
        let (identity, _receiver) = actorless_fixture();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let _ = eidetic::PayloadSealer::seal(&identity, &eidetic::Hash::of(b"test"), b"test");
        });
    }

    #[test]
    fn fresh_status_must_match_original_authoritative_epoch_profile_and_master() {
        let (mut identity, _receiver) = actorless_fixture();
        identity.status.custody_epoch = Some(crate::door::custody::CustodyEpoch {
            instance: "test-custodian".into(),
            generation: 4,
        });
        let original = identity.status.clone();
        assert!(identity.status_matches_binding(&original));
        let mut changed = original.clone();
        changed.custody_epoch.as_mut().unwrap().generation += 1;
        assert!(!identity.status_matches_binding(&changed));
        let mut changed = original.clone();
        changed.profile = Some(ProfileId("other".into()));
        assert!(!identity.status_matches_binding(&changed));
        let mut changed = original.clone();
        changed.persona_public_key = Some([0; 32]);
        assert!(!identity.status_matches_binding(&changed));
        let mut changed = original;
        changed.custody_epoch = None;
        assert!(!identity.status_matches_binding(&changed));
    }

    #[test]
    fn simultaneous_callers_can_enqueue_without_waiting_for_each_other() {
        let (identity, receiver) = actorless_fixture();
        let identity = Arc::new(identity);
        let first = identity.clone();
        let one = std::thread::spawn(move || first.status());
        let first_job = receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("first caller queued");
        let second = identity.clone();
        let two = std::thread::spawn(move || second.status());
        let second_job = receiver.recv_timeout(Duration::from_millis(500));
        assert!(
            second_job.is_ok(),
            "another caller must enqueue before the first answer"
        );
        first_job.run(None);
        second_job.unwrap().run(None);
        assert!(one.join().unwrap().is_err());
        assert!(two.join().unwrap().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn watcher_drop_joins_while_handshake_is_stalled() {
        use std::os::unix::{fs::PermissionsExt, net::UnixListener};
        use std::time::Instant;
        let path = std::path::PathBuf::from(format!(
            "/tmp/alembic-watch-{}.sock",
            uuid::Uuid::new_v4().simple()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let (accepted_tx, accepted_rx) = mpsc::channel();
        let (stop_tx, stop_rx) = mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            if let Ok((_stream, _)) = listener.accept() {
                let _ = accepted_tx.send(());
                let _ = stop_rx.recv_timeout(Duration::from_secs(3));
            }
        });
        let (identity, _receiver) = actorless_fixture();
        identity.watch(path.to_str().unwrap().into(), AppId::new("turnstone"));
        accepted_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("watcher connected");
        let start = Instant::now();
        drop(identity);
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "watcher stop must interrupt stalled handshake"
        );
        let _ = stop_tx.send(());
        server.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn failed_initialization_closes_and_joins_actor() {
        let (sender, receiver) = mpsc::channel::<Job>();
        let exited = Arc::new(AtomicBool::new(false));
        let observed = exited.clone();
        let worker = std::thread::spawn(move || {
            while receiver.recv().is_ok() {}
            observed.store(true, Ordering::SeqCst);
        });
        let result: Result<(), ()> = (|| {
            let _starting = StartingActor {
                sender: Some(sender),
                thread: Some(worker),
                stop: Arc::new(AtomicBool::new(false)),
            };
            Err(())
        })();
        assert!(result.is_err());
        assert!(
            exited.load(Ordering::SeqCst),
            "constructor failure must join its actor"
        );
    }

    #[test]
    fn caller_timeout_retires_a_queued_job_before_dispatch() {
        let (sender, receiver) = mpsc::channel();
        let caller = std::thread::spawn(move || {
            ask_on_bounded(&sender, Some(Duration::from_millis(30)), |_| Ok(()))
        });
        let job: Job = receiver.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            caller.join().unwrap(),
            Err(CustodyClientError::Transport(_))
        ));
        assert!(job.expired());
        assert!(job.run(None), "expired job must not touch a provider");
    }

    #[test]
    fn timed_out_or_cancelled_queued_job_never_dispatches() {
        let calls = Arc::new(AtomicU64::new(0));
        for (deadline, cancelled) in [
            (Some(Instant::now()), false),
            (Some(Instant::now() + Duration::from_secs(30)), true),
        ] {
            let observed = calls.clone();
            let job = Job {
                deadline,
                cancelled: Arc::new(AtomicBool::new(cancelled)),
                call: Box::new(move |_| {
                    observed.fetch_add(1, Ordering::SeqCst);
                    true
                }),
            };
            assert!(job.run(None));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let observed = calls.clone();
        let job = Job {
            deadline: None,
            cancelled: Arc::new(AtomicBool::new(false)),
            call: Box::new(move |_| {
                observed.fetch_add(1, Ordering::SeqCst);
                true
            }),
        };
        assert!(job.run(None));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn custody_epoch_remembers_lock_unlock_between_observations() {
        let locked = AtomicBool::new(false);
        let epoch = AtomicU64::new(1);
        let admitted = epoch.load(Ordering::SeqCst);
        invalidate_epoch(&locked, &epoch);
        invalidate_epoch(&locked, &epoch);
        locked.store(false, Ordering::SeqCst);
        assert!(!locked.load(Ordering::SeqCst));
        assert_ne!(epoch.load(Ordering::SeqCst), admitted);
        assert_eq!(epoch.load(Ordering::SeqCst), 2);
        invalidate_epoch(&locked, &epoch);
        assert_eq!(epoch.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn custody_epoch_exhaustion_does_not_reuse_an_old_generation() {
        let epoch = AtomicU64::new(u64::MAX);
        advance_epoch(&epoch);
        assert_eq!(epoch.load(Ordering::SeqCst), 0);
        advance_epoch(&epoch);
        assert_eq!(epoch.load(Ordering::SeqCst), 0);
    }
}

impl Drop for CustodyIdentity {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.forget();
        if let Some(thread) = self
            .watch_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = thread.join();
        }
        self.jobs.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(thread) = self
            .job_thread
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            let _ = thread.join();
        }
    }
}

impl std::fmt::Debug for CustodyIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustodyIdentity")
            .field("profile", &self.status.profile)
            .field("locked", &self.is_locked())
            .finish_non_exhaustive()
    }
}

impl IdentityProvider for CustodyIdentity {
    fn master_public_key(&self) -> Ed25519PublicKey {
        self.master
    }

    /// The key djinn releases for `salt` (D11); [`IdentityError::Locked`]
    /// while pending, and an error naming the refusal for a salt djinn keeps.
    fn derive_keypair(&self, salt: &[u8]) -> Result<Ed25519Keypair, IdentityError> {
        self.pending()?;
        if let Some(keys) = self
            .held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(salt)
        {
            return keys.derive_keypair(salt);
        }
        let asked = salt.to_vec();
        let keys = self
            .ask(move |client| client.release(KeySource::Persona, vec![asked]))
            .map_err(identity_error)?;
        if keys.master_public_key() != self.master {
            return Err(IdentityError::DerivationFailed(
                "djinn now speaks as a different persona; reconnect".into(),
            ));
        }
        let keypair = keys.derive_keypair(salt)?;
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        held.insert(salt.to_vec(), keys);
        if self.is_locked() {
            held.clear();
            return Err(IdentityError::Locked);
        }
        Ok(keypair)
    }

    /// The master's attestation for `salt`'s key, signed inside djinn.
    fn attest_derived_key(&self, salt: &[u8]) -> Result<DerivedKeyAttestation, IdentityError> {
        self.pending()?;
        if let Some(keys) = self
            .held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(salt)
        {
            return keys.attest_derived_key(salt);
        }
        let asked = salt.to_vec();
        let attestation = self
            .ask(move |client| client.attest(KeySource::Persona, asked))
            .map_err(identity_error)?;
        match attestation.check(salt) {
            Ok(checked) if checked.master() == &self.master.to_bytes() => Ok(attestation),
            _ => Err(IdentityError::DerivationFailed(
                "djinn's attestation does not name this persona".into(),
            )),
        }
    }
}

fn done(answer: CustodyAnswer) -> Result<(), CustodyClientError> {
    match answer {
        CustodyAnswer::Done => Ok(()),
        _ => Err(CustodyClientError::UnexpectedAnswer {
            asked: "profile",
            got: "another answer",
        }),
    }
}

fn closed() -> CustodyClientError {
    CustodyClientError::Transport(AppClientError::Closed)
}

impl eidetic::PayloadSealer for CustodyIdentity {
    fn seal(
        &self,
        hash: &eidetic::Hash,
        cleartext: &[u8],
    ) -> eidetic::Result<(Vec<u8>, eidetic::SealedBlobRef)> {
        use super::custody_payload::{PayloadBytes, PayloadOperation, PayloadResult};
        if cleartext.len() > super::custody_payload::MAX_PAYLOAD_BYTES {
            return Err(eidetic::Error::new(
                "retained payload exceeds custody budget",
            ));
        }
        match self.retained_payload(
            hash,
            PayloadOperation::Seal {
                bytes: PayloadBytes(cleartext.to_vec()),
            },
        )? {
            PayloadResult::Sealed { bytes, marker } => Ok((bytes.0, marker)),
            _ => Err(eidetic::Error::new(
                "custody returned a different retained-payload operation",
            )),
        }
    }

    fn unseal(
        &self,
        hash: &eidetic::Hash,
        marker: &eidetic::SealedBlobRef,
        sealed: &[u8],
    ) -> eidetic::Result<Vec<u8>> {
        use super::custody_payload::{PayloadBytes, PayloadOperation, PayloadResult};
        if sealed.len() > super::custody_payload::MAX_PAYLOAD_BYTES + 40 {
            return Err(eidetic::Error::new(
                "retained payload exceeds custody budget",
            ));
        }
        match self.retained_payload(
            hash,
            PayloadOperation::Unseal {
                bytes: PayloadBytes(sealed.to_vec()),
                marker: marker.clone(),
            },
        )? {
            PayloadResult::Clear { bytes } if eidetic::Hash::of(&bytes.0) == *hash => Ok(bytes.0),
            _ => Err(eidetic::Error::new(
                "custody returned invalid retained-payload bytes",
            )),
        }
    }
}

impl CustodyIdentity {
    fn invalidate_binding(&self) {
        invalidate_epoch(&self.locked, &self.epoch);
        self.held.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    fn status_matches_binding(&self, status: &ResidentStatus) -> bool {
        status.lock == VaultLockView::Unlocked
            && status.profile == self.status.profile
            && status.persona_public_key == Some(self.master.to_bytes())
            && status.custody_epoch == self.status.custody_epoch
    }

    fn check_fresh_payload_binding(&self, timeout: Duration) -> eidetic::Result<()> {
        let status = self.status_timeout(timeout);
        if status
            .as_ref()
            .is_ok_and(|status| self.status_matches_binding(status))
            && self.custody_epoch().is_some()
        {
            return Ok(());
        }
        self.invalidate_binding();
        Err(eidetic::Error::new(
            "custody binding unavailable or changed",
        ))
    }

    fn retained_payload(
        &self,
        hash: &eidetic::Hash,
        operation: super::custody_payload::PayloadOperation,
    ) -> eidetic::Result<super::custody_payload::PayloadResult> {
        self.pending()
            .map_err(|e| eidetic::Error::new(e.to_string()))?;
        let request = super::custody_payload::PayloadRequest {
            profile: self.profile().cloned().ok_or_else(|| {
                eidetic::Error::new("custody disclosed no retained-content profile")
            })?,
            master: self.master.to_bytes(),
            content_hash: *hash,
            custody_epoch: self.status.custody_epoch.clone(),
            operation,
        };
        request.validate().map_err(eidetic::Error::new)?;
        let timeout = self.call_timeout.unwrap_or(Duration::from_secs(5));
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| eidetic::Error::new("custody deadline invalid"))?;
        let local_epoch = self
            .custody_epoch()
            .ok_or_else(|| eidetic::Error::new("custody binding unavailable"))?;
        let remaining = || deadline.saturating_duration_since(Instant::now());
        if request.custody_epoch.is_some() {
            self.check_fresh_payload_binding(remaining())?;
        }
        let endpoint = self.endpoint.clone();
        let app = self.app.clone();
        let profile = self.requested_profile.clone();
        let payload_timeout = remaining();
        let result = bounded_worker(move || {
            match BlockingCustodyClient::call_at_timeout(
                &endpoint,
                app,
                profile,
                CustodyCall::Payload(request),
                payload_timeout,
            ) {
                Ok(CustodyAnswer::Payload { result }) => Ok(result),
                Ok(_) => Err(CustodyClientError::UnexpectedAnswer {
                    asked: "retained payload",
                    got: "another operation",
                }),
                Err(error) => Err(error),
            }
        });
        if self.status.custody_epoch.is_some() {
            self.check_fresh_payload_binding(remaining())?;
        }
        if self.custody_epoch() != Some(local_epoch) {
            return Err(eidetic::Error::new(
                "custody binding changed during payload",
            ));
        }
        result.map_err(|e| eidetic::Error::new(e.to_string()))
    }
}

/// Isolate synchronous one-shot Tokio runtimes from any caller runtime.
/// The one-shot transport has its own deadline and is never retried.
fn bounded_worker<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, CustodyClientError> + Send + 'static,
) -> Result<T, CustodyClientError> {
    let thread = std::thread::Builder::new()
        .name("custody-bounded-call".into())
        .spawn(operation)
        .map_err(|error| CustodyClientError::Absent(AppClientError::Io(error)))?;
    thread.join().map_err(|_| closed())?
}

/// A pending identity reads as Locked; anything else keeps its reason.
fn identity_error(error: CustodyClientError) -> IdentityError {
    match error {
        error if error.is_pending() => IdentityError::Locked,
        CustodyClientError::Release(error) => error,
        other => IdentityError::Backend(other.to_string()),
    }
}

/// Run `call` on the provider's own thread and wait for its answer.
fn ask_on_bounded<T: Send + 'static>(
    jobs: &mpsc::Sender<Job>,
    timeout: Option<Duration>,
    call: impl FnOnce(&mut BlockingCustodyClient) -> Result<T, CustodyClientError> + Send + 'static,
) -> Result<T, CustodyClientError> {
    let (reply, answer) = mpsc::channel();
    let deadline = timeout
        .map(|duration| Instant::now().checked_add(duration).ok_or_else(timed_out))
        .transpose()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let check = cancelled.clone();
    let job = Job {
        deadline,
        cancelled: check.clone(),
        call: Box::new(move |client| {
            if check.load(Ordering::SeqCst) || deadline.is_some_and(|end| Instant::now() >= end) {
                return true;
            }
            match client {
                Some(client) => {
                    let result = call(client);
                    let healthy = !matches!(
                        result,
                        Err(CustodyClientError::Transport(_) | CustodyClientError::Absent(_))
                    );
                    let _ = reply.send(result);
                    healthy
                }
                None => {
                    let _ = reply.send(Err(CustodyClientError::Absent(AppClientError::Closed)));
                    false
                }
            }
        }),
    };
    jobs.send(job).map_err(|_| closed())?;
    let result = match deadline {
        Some(deadline) => answer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => timed_out(),
                mpsc::RecvTimeoutError::Disconnected => closed(),
            }),
        None => answer.recv().map_err(|_| closed()),
    };
    cancelled.store(true, Ordering::SeqCst);
    result?
}
