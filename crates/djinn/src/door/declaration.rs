// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! What an application declares, and what its owner grants.
//!
//! **Declaration versus permission.** An application states the routes it
//! opens, the projections it offers and the custody it needs, in an
//! [`AppDeclaration`] carried on its hello. The owner's [`AppGrant`] states
//! what the host lets that application have. A connection receives only what
//! both name: an undeclared request is refused as undeclared, a declared but
//! ungranted one as not granted.
//!
//! The declaration is the application's own statement under a self-declared
//! [`AppId`]. Like the label, it is not executable authentication: it gives an
//! honest application least authority and makes its needs legible to the
//! owner, within the same-user boundary the endpoint already sets.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::door::app_admission::{AppId, AppRouteId};

/// Longest name a declaration or grant may carry.
pub const MAX_DECLARED_NAME: usize = 1024;
/// Most entries one declaration or grant list may carry.
pub const MAX_DECLARED_ENTRIES: usize = 64;

/// A route, context or other name, matched exactly or by prefix.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamePattern {
    /// Exactly this name.
    Exact(String),
    /// Any name beginning with this prefix and longer than it.
    Prefix(String),
}

impl NamePattern {
    pub fn exact(name: impl Into<String>) -> Self {
        Self::Exact(name.into())
    }

    pub fn prefix(prefix: impl Into<String>) -> Self {
        Self::Prefix(prefix.into())
    }

    /// Whether `name` falls under this pattern.
    pub fn matches(&self, name: &str) -> bool {
        self.matches_bytes(name.as_bytes())
    }

    /// Whether `bytes` fall under this pattern's UTF-8 text. A salt may carry
    /// a binary suffix (a scope hash) after a text prefix.
    pub fn matches_bytes(&self, bytes: &[u8]) -> bool {
        match self {
            Self::Exact(exact) => bytes == exact.as_bytes(),
            Self::Prefix(prefix) => {
                bytes.len() > prefix.len() && bytes.starts_with(prefix.as_bytes())
            }
        }
    }

    fn text(&self) -> &str {
        match self {
            Self::Exact(text) | Self::Prefix(text) => text,
        }
    }

    fn validate(&self) -> Result<(), DeclarationError> {
        let text = self.text();
        if text.is_empty() || text.len() > MAX_DECLARED_NAME || text.chars().any(char::is_whitespace) {
            return Err(DeclarationError::InvalidName(text.chars().take(64).collect()));
        }
        Ok(())
    }
}

/// A custody operation, one per custody call. A call made as a named persona
/// is the operation of the call it wraps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyOperation {
    Payload,
    VaultCommand,
    UnlockNative,
    ChangePassphraseNative,
    UnassignedImports,
    AssignImport,
    LockVault,
    Quarantine,
    ReviewQuarantine,
    Status,
    Roster,
    ChooseProfile,
    CreateProfile,
    Release,
    Attest,
    Sign,
    IssueStationGrant,
    RevokeDevice,
    WatchLock,
    ReleaseEpochKeys,
}

impl CustodyOperation {
    /// The operation's wire name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Payload => "payload",
            Self::VaultCommand => "vault_command",
            Self::UnlockNative => "unlock_native",
            Self::ChangePassphraseNative => "change_passphrase_native",
            Self::UnassignedImports => "unassigned_imports",
            Self::AssignImport => "assign_import",
            Self::LockVault => "lock_vault",
            Self::Quarantine => "quarantine",
            Self::ReviewQuarantine => "review_quarantine",
            Self::Status => "status",
            Self::Roster => "roster",
            Self::ChooseProfile => "choose_profile",
            Self::CreateProfile => "create_profile",
            Self::Release => "release",
            Self::Attest => "attest",
            Self::Sign => "sign",
            Self::IssueStationGrant => "issue_station_grant",
            Self::RevokeDevice => "revoke_device",
            Self::WatchLock => "watch_lock",
            Self::ReleaseEpochKeys => "release_epoch_keys",
        }
    }
}

/// Which root a salt derives from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaltSource {
    /// The vault persona in use.
    Persona,
    /// The wallet.
    Wallet,
}

/// How a namespace of salts is named.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaltPattern {
    /// Exactly this UTF-8 text.
    Exact(String),
    /// Any salt beginning with this UTF-8 text and longer than it. A salt may
    /// carry a binary suffix (a scope hash or id) after the text.
    Prefix(String),
    /// Every delegation signing key in this capability domain: the salts
    /// `insigne::delegation::delegation_signing_salt` derives for any resource
    /// in it. Their framing is binary, so they are named by domain.
    DelegationScope(String),
}

/// The bytes every delegation signing salt in `domain` begins with
/// (`insigne::delegation::delegation_signing_prefix`): length-prefixed
/// little-endian `u64` frames of the signing-key tag and the domain.
pub fn delegation_scope_prefix(domain: &str) -> Vec<u8> {
    const SIGNING_KEY_TAG: &[u8] = b"personae/delegation-signing-key/v1";
    let mut bytes = Vec::with_capacity(16 + SIGNING_KEY_TAG.len() + domain.len());
    bytes.extend_from_slice(&(SIGNING_KEY_TAG.len() as u64).to_le_bytes());
    bytes.extend_from_slice(SIGNING_KEY_TAG);
    bytes.extend_from_slice(&(domain.len() as u64).to_le_bytes());
    bytes.extend_from_slice(domain.as_bytes());
    bytes
}

impl SaltPattern {
    fn matches(&self, salt: &[u8]) -> bool {
        match self {
            Self::Exact(text) => NamePattern::Exact(text.clone()).matches_bytes(salt),
            Self::Prefix(text) => NamePattern::Prefix(text.clone()).matches_bytes(salt),
            Self::DelegationScope(domain) => {
                let prefix = delegation_scope_prefix(domain);
                salt.len() > prefix.len() && salt.starts_with(&prefix)
            }
        }
    }

    fn validate(&self) -> Result<(), DeclarationError> {
        match self {
            Self::Exact(text) => NamePattern::Exact(text.clone()).validate(),
            Self::Prefix(text) | Self::DelegationScope(text) => {
                NamePattern::Prefix(text.clone()).validate()
            }
        }
    }
}

/// A namespace of derived keys from one root.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SaltUse {
    pub source: SaltSource,
    pub name: SaltPattern,
}

impl SaltUse {
    pub fn persona(name: SaltPattern) -> Self {
        Self {
            source: SaltSource::Persona,
            name,
        }
    }

    pub fn wallet(name: SaltPattern) -> Self {
        Self {
            source: SaltSource::Wallet,
            name,
        }
    }

    fn covers(&self, source: SaltSource, salt: &[u8]) -> bool {
        self.source == source && self.name.matches(salt)
    }
}

fn salt_display(salt: &[u8]) -> String {
    let text = String::from_utf8_lossy(salt);
    let mut shown: String = text.chars().take(64).collect();
    if text.chars().count() > 64 {
        shown.push('…');
    }
    shown
}

/// One epoch derivation an application needs: its context, whether it mixes
/// in the device root, and whether its secret must leave or only its public
/// key.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EpochUse {
    pub context: String,
    pub device_bound: bool,
    pub secret: bool,
}

impl EpochUse {
    pub fn secret(context: impl Into<String>, device_bound: bool) -> Self {
        Self {
            context: context.into(),
            device_bound,
            secret: true,
        }
    }

    pub fn public(context: impl Into<String>, device_bound: bool) -> Self {
        Self {
            context: context.into(),
            device_bound,
            secret: false,
        }
    }

    /// Whether a request for `context` answers within this use. A secret use
    /// also covers a request for only its public key.
    pub fn covers(&self, context: &str, device_bound: bool, public_only: bool) -> bool {
        self.context == context && self.device_bound == device_bound && (self.secret || public_only)
    }
}

/// The custody an application needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustodyUse {
    /// The custody calls it makes.
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub operations: BTreeSet<CustodyOperation>,
    /// The epoch derivations it asks for.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub epoch: Vec<EpochUse>,
    /// The derived keys it asks to be released to it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub salts: Vec<SaltUse>,
    /// The derived keys it asks djinn to sign or attest with, never releasing
    /// them. A released namespace may also be signed or attested with.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acts: Vec<SaltUse>,
}

impl CustodyUse {
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
            && self.epoch.is_empty()
            && self.salts.is_empty()
            && self.acts.is_empty()
    }
}

/// A projection an application offers under its own route.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfferedProjection {
    pub route: AppRouteId,
    pub label: String,
}

/// What an application states it opens, offers and needs.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppDeclaration {
    /// The resident routes it opens.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<NamePattern>,
    /// The projections it offers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub offers: Vec<OfferedProjection>,
    /// The custody it needs.
    #[serde(skip_serializing_if = "CustodyUse::is_empty")]
    pub custody: CustodyUse,
}

impl AppDeclaration {
    /// Whether this declaration names `route` among those it opens.
    pub fn declares_route(&self, route: &AppRouteId) -> bool {
        self.routes.iter().any(|pattern| pattern.matches(route.as_str()))
    }

    /// The offer this declaration makes under `route`, if any.
    pub fn offer(&self, route: &AppRouteId) -> Option<&OfferedProjection> {
        self.offers.iter().find(|offer| &offer.route == route)
    }

    /// Bound the declaration before the host reads it.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        if self.routes.len() > MAX_DECLARED_ENTRIES
            || self.offers.len() > MAX_DECLARED_ENTRIES
            || self.custody.epoch.len() > MAX_DECLARED_ENTRIES
            || self.custody.salts.len() > MAX_DECLARED_ENTRIES
            || self.custody.acts.len() > MAX_DECLARED_ENTRIES
        {
            return Err(DeclarationError::TooLarge);
        }
        for pattern in &self.routes {
            pattern.validate()?;
        }
        for offer in &self.offers {
            AppRouteId::new(offer.route.as_str())
                .map_err(|_| DeclarationError::InvalidName(offer.route.as_str().chars().take(64).collect()))?;
            if offer.route.as_str().len() > MAX_DECLARED_NAME || offer.label.len() > MAX_DECLARED_NAME {
                return Err(DeclarationError::TooLarge);
            }
        }
        for epoch in &self.custody.epoch {
            NamePattern::Exact(epoch.context.clone()).validate()?;
        }
        self.custody
            .salts
            .iter()
            .chain(&self.custody.acts)
            .try_for_each(|used| used.name.validate())
    }
}

/// The custody an owner grants one application: which calls, which epoch
/// contexts, and which salts released or only signed and attested with, by
/// namespace.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CustodyGrant {
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub operations: BTreeSet<CustodyOperation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub epoch: Vec<NamePattern>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub salts: Vec<SaltUse>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub acts: Vec<SaltUse>,
}

/// The OS identity an owner pins an application's label to, per platform.
/// Where none is pinned for the platform the resident runs on, the label is
/// accepted as stated (development mode), and status says so.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AppIdentity {
    /// The code signature a macOS peer must satisfy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub macos: Option<SignedAppIdentity>,
    /// The executable a Windows peer must be: the same-user posture of an
    /// image path, not an OS-held identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub windows: Option<WindowsAppIdentity>,
    /// How Djinn launches the application on Linux; a connection is admitted
    /// under the label only with the handle that launch gave it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub linux: Option<LinuxLaunch>,
}

/// A macOS code signing team and identifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedAppIdentity {
    pub team: String,
    pub identifier: String,
}

/// A Windows executable, by its full image path.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsAppIdentity {
    pub image: String,
}

impl WindowsAppIdentity {
    /// Whether `image` names this executable. Windows paths compare without
    /// case; separators are normalized.
    pub fn matches(&self, image: &str) -> bool {
        let normal = |path: &str| path.replace('/', "\\").to_lowercase();
        normal(&self.image) == normal(image)
    }
}

/// A program Djinn launches for an application, with its arguments.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxLaunch {
    pub executable: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// What a connection's label rests on, for status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum IdentityBasis {
    /// The label as the application stated it; no identity is pinned for
    /// this platform.
    Development,
    /// A macOS code signature matched the pinned team and identifier.
    Signed { team: String, identifier: String },
    /// A Windows peer's executable matched the pinned image: the same-user
    /// posture of a path, not an OS-held identity.
    WindowsImage { image: String },
    /// A Linux connection carried the handle Djinn launched it with.
    Launched,
}

/// What the owner lets one declared application have.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppGrant {
    pub app: AppId,
    /// The resident routes it may open.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<NamePattern>,
    #[serde(default)]
    pub custody: CustodyGrant,
    /// The OS identity the label is pinned to; absent, development mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<AppIdentity>,
}

impl AppGrant {
    pub fn new(app: AppId) -> Self {
        Self {
            app,
            routes: Vec::new(),
            custody: CustodyGrant::default(),
            identity: None,
        }
    }

    /// Whether the owner lets this application open `route`.
    pub fn grants_route(&self, route: &AppRouteId) -> bool {
        self.routes.iter().any(|pattern| pattern.matches(route.as_str()))
    }

    /// Bound the grant before the host uses it.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        if self.app.as_str().is_empty() || self.app.as_str().len() > MAX_DECLARED_NAME {
            return Err(DeclarationError::InvalidName(self.app.as_str().chars().take(64).collect()));
        }
        if self.routes.len() > MAX_DECLARED_ENTRIES
            || self.custody.epoch.len() > MAX_DECLARED_ENTRIES
            || self.custody.salts.len() > MAX_DECLARED_ENTRIES
            || self.custody.acts.len() > MAX_DECLARED_ENTRIES
        {
            return Err(DeclarationError::TooLarge);
        }
        self.routes
            .iter()
            .chain(&self.custody.epoch)
            .try_for_each(NamePattern::validate)?;
        self.custody
            .salts
            .iter()
            .chain(&self.custody.acts)
            .try_for_each(|used| used.name.validate())
    }
}

/// Why a declaration or grant was rejected as malformed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DeclarationError {
    #[error("a declared name is empty, too long or contains whitespace: {0:?}")]
    InvalidName(String),
    #[error("a declaration or grant list exceeds its bound")]
    TooLarge,
}

/// Why a declared application was refused something.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityRefusal {
    #[error("{app} did not declare {what}")]
    Undeclared { app: AppId, what: String },
    #[error("{app} declared {what}, but the owner has not granted it")]
    NotGranted { app: AppId, what: String },
}

/// One connection's authority: what its declaration names and its owner's
/// grant allows, both.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppAuthority {
    declaration: AppDeclaration,
    grant: AppGrant,
}

impl AppAuthority {
    pub fn new(declaration: AppDeclaration, grant: AppGrant) -> Self {
        Self { declaration, grant }
    }

    pub fn app(&self) -> &AppId {
        &self.grant.app
    }

    pub fn declaration(&self) -> &AppDeclaration {
        &self.declaration
    }

    pub fn grant(&self) -> &AppGrant {
        &self.grant
    }

    /// Whether this connection may make custody calls of `operation`.
    pub fn custody_operation(&self, operation: CustodyOperation) -> Result<(), AuthorityRefusal> {
        let what = || format!("the custody operation {}", operation.name());
        if !self.declaration.custody.operations.contains(&operation) {
            return Err(self.undeclared(what()));
        }
        if !self.grant.custody.operations.contains(&operation) {
            return Err(self.not_granted(what()));
        }
        Ok(())
    }

    /// Whether one epoch derivation may leave for this connection.
    pub fn epoch(&self, context: &str, device_bound: bool, public_only: bool) -> Result<(), AuthorityRefusal> {
        let what = || {
            let half = if public_only { "public key" } else { "secret" };
            let bound = if device_bound { "device-bound " } else { "" };
            format!("the {bound}epoch {half} of {context}")
        };
        if !self
            .declaration
            .custody
            .epoch
            .iter()
            .any(|declared| declared.covers(context, device_bound, public_only))
        {
            return Err(self.undeclared(what()));
        }
        if !self.grant.custody.epoch.iter().any(|pattern| pattern.matches(context)) {
            return Err(self.not_granted(what()));
        }
        Ok(())
    }

    /// Whether the key `salt` derives from `source` may leave for this
    /// connection (`released`), or only be signed or attested with. A released
    /// namespace covers signing and attesting too.
    pub fn salt(&self, source: SaltSource, salt: &[u8], released: bool) -> Result<(), AuthorityRefusal> {
        let what = || {
            let root = match source {
                SaltSource::Persona => "persona",
                SaltSource::Wallet => "wallet",
            };
            let act = if released { "release of" } else { "signature with" };
            format!("the {act} {root} key {}", salt_display(salt))
        };
        let covered = |salts: &[SaltUse], acts: &[SaltUse]| {
            salts.iter().any(|used| used.covers(source, salt))
                || (!released && acts.iter().any(|used| used.covers(source, salt)))
        };
        if !covered(&self.declaration.custody.salts, &self.declaration.custody.acts) {
            return Err(self.undeclared(what()));
        }
        if !covered(&self.grant.custody.salts, &self.grant.custody.acts) {
            return Err(self.not_granted(what()));
        }
        Ok(())
    }

    /// The offer this connection declared under `route`, if any. Whether
    /// the owner lets it serve that offer is the host's projection policy.
    pub fn offer(&self, route: &AppRouteId) -> Result<&OfferedProjection, AuthorityRefusal> {
        self.declaration
            .offer(route)
            .ok_or_else(|| self.undeclared(format!("the offered projection {route}")))
    }

    fn undeclared(&self, what: String) -> AuthorityRefusal {
        AuthorityRefusal::Undeclared {
            app: self.grant.app.clone(),
            what,
        }
    }

    fn not_granted(&self, what: String) -> AuthorityRefusal {
        AuthorityRefusal::NotGranted {
            app: self.grant.app.clone(),
            what,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn declaration() -> AppDeclaration {
        AppDeclaration {
            routes: vec![NamePattern::exact("custody"), NamePattern::prefix("mere/")],
            offers: vec![OfferedProjection {
                route: AppRouteId::new("app-documents").unwrap(),
                label: "Documents".into(),
            }],
            custody: CustodyUse {
                operations: [CustodyOperation::Status, CustodyOperation::ReleaseEpochKeys].into(),
                epoch: vec![EpochUse::secret("app.vault.v1", false), EpochUse::public("app.writer.v1", false)],
                ..CustodyUse::default()
            },
        }
    }

    fn grant() -> AppGrant {
        AppGrant {
            app: AppId::new("app"),
            routes: vec![NamePattern::prefix("mere/"), NamePattern::exact("custody")],
            custody: CustodyGrant {
                operations: [CustodyOperation::Status, CustodyOperation::ReleaseEpochKeys, CustodyOperation::Sign].into(),
                epoch: vec![NamePattern::prefix("app.")],
                ..CustodyGrant::default()
            },
            identity: None,
        }
    }

    #[test]
    fn a_prefix_needs_a_name_beyond_it() {
        let mere = NamePattern::prefix("mere/");
        assert!(mere.matches("mere/notes"));
        assert!(!mere.matches("mere/"));
        assert!(!mere.matches("ambient/mere/notes"));
        assert!(NamePattern::exact("custody").matches("custody"));
        assert!(!NamePattern::exact("custody").matches("custody2"));
    }

    #[test]
    fn custody_needs_both_declaration_and_grant() {
        let authority = AppAuthority::new(declaration(), grant());
        assert!(authority.custody_operation(CustodyOperation::Status).is_ok());
        assert!(matches!(
            authority.custody_operation(CustodyOperation::Sign),
            Err(AuthorityRefusal::Undeclared { .. })
        ));
        let mut narrow = grant();
        narrow.custody.operations.remove(&CustodyOperation::ReleaseEpochKeys);
        assert!(matches!(
            AppAuthority::new(declaration(), narrow).custody_operation(CustodyOperation::ReleaseEpochKeys),
            Err(AuthorityRefusal::NotGranted { .. })
        ));
    }

    #[test]
    fn epoch_releases_match_the_declared_derivation_exactly() {
        let authority = AppAuthority::new(declaration(), grant());
        assert!(authority.epoch("app.vault.v1", false, false).is_ok());
        assert!(authority.epoch("app.vault.v1", false, true).is_ok(), "a secret use covers its public key");
        assert!(authority.epoch("app.writer.v1", false, true).is_ok());
        assert!(matches!(authority.epoch("app.writer.v1", false, false), Err(AuthorityRefusal::Undeclared { .. })));
        assert!(matches!(authority.epoch("app.vault.v1", true, false), Err(AuthorityRefusal::Undeclared { .. })));
        let mut other = grant();
        other.custody.epoch = vec![NamePattern::prefix("other.")];
        assert!(matches!(
            AppAuthority::new(declaration(), other).epoch("app.vault.v1", false, false),
            Err(AuthorityRefusal::NotGranted { .. })
        ));
    }

    #[test]
    fn salts_match_text_prefixes_over_bytes_and_acts_never_release() {
        let mut declaration = declaration();
        declaration.custody.salts = vec![SaltUse::persona(SaltPattern::Prefix("app.place.".into()))];
        declaration.custody.acts = vec![SaltUse::persona(SaltPattern::Prefix("app/delegation/".into()))];
        let mut wide = grant();
        wide.custody.salts = vec![SaltUse::persona(SaltPattern::Prefix("app.".into()))];
        wide.custody.acts = vec![SaltUse::persona(SaltPattern::Prefix("app/".into()))];
        let authority = AppAuthority::new(declaration, wide);
        assert!(authority.salt(SaltSource::Persona, b"app.place.p1", true).is_ok());
        assert!(authority.salt(SaltSource::Persona, b"app.place.p1", false).is_ok(), "released covers acts");
        let binary = [b"app/delegation/".as_slice(), &[0xff, 0x00, 0x9c]].concat();
        assert!(authority.salt(SaltSource::Persona, &binary, false).is_ok(), "a binary suffix after a text prefix");
        assert!(matches!(authority.salt(SaltSource::Persona, &binary, true), Err(AuthorityRefusal::Undeclared { .. })), "an act never releases");
        assert!(matches!(authority.salt(SaltSource::Wallet, b"app.place.p1", true), Err(AuthorityRefusal::Undeclared { .. })), "the root matters");
        assert!(matches!(authority.salt(SaltSource::Persona, b"app.place.", true), Err(AuthorityRefusal::Undeclared { .. })), "a prefix needs more");
        assert!(matches!(authority.salt(SaltSource::Persona, b"", false), Err(AuthorityRefusal::Undeclared { .. })), "never the master's place");

        let mut narrow = grant();
        narrow.custody.acts = vec![SaltUse::persona(SaltPattern::Prefix("app/".into()))];
        let mut declaration = super::tests::declaration();
        declaration.custody.salts = vec![SaltUse::persona(SaltPattern::Prefix("app.place.".into()))];
        let authority = AppAuthority::new(declaration, narrow);
        assert!(matches!(authority.salt(SaltSource::Persona, b"app.place.p1", true), Err(AuthorityRefusal::NotGranted { .. })));
    }

    #[test]
    fn a_delegation_scope_names_every_resource_in_its_domain() {
        let mut declaration = AppDeclaration::default();
        declaration.custody.salts = vec![SaltUse::persona(SaltPattern::DelegationScope("mere.knot".into()))];
        let mut wide = grant();
        wide.custody.salts = declaration.custody.salts.clone();
        assert!(declaration.validate().is_ok(), "the domain is text even though the salt is not");
        let authority = AppAuthority::new(declaration, wide);
        let salt = [delegation_scope_prefix("mere.knot"), vec![32, 0, 0, 0, 0, 0, 0, 0, 0xab]].concat();
        assert!(authority.salt(SaltSource::Persona, &salt, true).is_ok());
        let other = [delegation_scope_prefix("mere.knots"), vec![1]].concat();
        assert!(authority.salt(SaltSource::Persona, &other, true).is_err(), "the domain is length-framed");
        assert!(authority.salt(SaltSource::Persona, &delegation_scope_prefix("mere.knot"), true).is_err());
        let json = serde_json::to_value(SaltUse::persona(SaltPattern::DelegationScope("moot".into()))).unwrap();
        assert_eq!(json, serde_json::json!({"source": "persona", "name": {"delegation_scope": "moot"}}));
    }

    #[test]
    fn offers_are_named_by_route() {
        let authority = AppAuthority::new(declaration(), grant());
        assert_eq!(authority.offer(&AppRouteId::new("app-documents").unwrap()).unwrap().label, "Documents");
        assert!(authority.offer(&AppRouteId::new("app-other").unwrap()).is_err());
    }

    #[test]
    fn the_wire_shape_is_compact_and_strict() {
        let json = serde_json::to_value(declaration()).unwrap();
        assert_eq!(json["routes"][1], serde_json::json!({"prefix": "mere/"}));
        assert_eq!(json["custody"]["operations"], serde_json::json!(["status", "release_epoch_keys"]));
        assert_eq!(serde_json::to_string(&AppDeclaration::default()).unwrap(), "{}");
        assert!(serde_json::from_str::<AppDeclaration>(r#"{"routes":[],"extra":1}"#).is_err());
        let back: AppDeclaration = serde_json::from_value(json).unwrap();
        assert_eq!(back, declaration());
    }

    #[test]
    fn malformed_declarations_and_grants_are_rejected() {
        assert!(declaration().validate().is_ok());
        assert!(grant().validate().is_ok());
        let mut spaced = declaration();
        spaced.routes.push(NamePattern::prefix("mere /"));
        assert!(spaced.validate().is_err());
        let mut empty = grant();
        empty.routes.push(NamePattern::exact(""));
        assert!(empty.validate().is_err());
        let mut many = declaration();
        many.routes = (0..=MAX_DECLARED_ENTRIES).map(|i| NamePattern::exact(format!("r{i}"))).collect();
        assert_eq!(many.validate(), Err(DeclarationError::TooLarge));
    }
}
