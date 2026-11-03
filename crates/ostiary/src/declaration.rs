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

use crate::app_admission::{AppId, AppRouteId};

mod authority;
pub use authority::{AppAuthority, AuthorityRefusal};

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
        if text.is_empty()
            || text.len() > MAX_DECLARED_NAME
            || text.chars().any(char::is_whitespace)
        {
            return Err(DeclarationError::InvalidName(
                text.chars().take(64).collect(),
            ));
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
    /// The scope its retained-content payloads are sealed under. The scope
    /// is bound into every sealed payload, so it never changes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_scope: Option<String>,
}

impl CustodyUse {
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
            && self.epoch.is_empty()
            && self.salts.is_empty()
            && self.acts.is_empty()
            && self.payload_scope.is_none()
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
        self.routes
            .iter()
            .any(|pattern| pattern.matches(route.as_str()))
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
            AppRouteId::new(offer.route.as_str()).map_err(|_| {
                DeclarationError::InvalidName(offer.route.as_str().chars().take(64).collect())
            })?;
            if offer.route.as_str().len() > MAX_DECLARED_NAME
                || offer.label.len() > MAX_DECLARED_NAME
            {
                return Err(DeclarationError::TooLarge);
            }
        }
        for epoch in &self.custody.epoch {
            NamePattern::Exact(epoch.context.clone()).validate()?;
        }
        if let Some(scope) = &self.custody.payload_scope {
            NamePattern::Exact(scope.clone()).validate()?;
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
    /// The retained-content seal scope, as the application declared it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload_scope: Option<String>,
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
    /// The executable a Windows peer must be: the process Djinn launched from
    /// it, or else the same-user posture of an image path, not an OS-held
    /// identity.
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

/// A Windows executable, by its full image path: the program Djinn launches
/// for the application, and the image a connection it did not launch must be.
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
    /// posture of a path, not an OS-held identity. The image was read when
    /// the door saw the connect, from one handle to the process the pipe
    /// recorded, which was refused had it been created after the connect.
    WindowsImage { image: String },
    /// A process Djinn launched for the application: on Linux the connection
    /// carried the launch's handle; on Windows the pipe recorded the launched
    /// process itself, by id and creation time, while Djinn held its handle.
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
    /// The owner marks this application an agent: a route closed to agents
    /// refuses it whatever else the grant names (capability door D25).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub agent: bool,
}

impl AppGrant {
    pub fn new(app: AppId) -> Self {
        Self {
            app,
            routes: Vec::new(),
            custody: CustodyGrant::default(),
            identity: None,
            agent: false,
        }
    }

    /// Whether the owner lets this application open `route`.
    pub fn grants_route(&self, route: &AppRouteId) -> bool {
        self.routes
            .iter()
            .any(|pattern| pattern.matches(route.as_str()))
    }

    /// Bound the grant before the host uses it.
    pub fn validate(&self) -> Result<(), DeclarationError> {
        if self.app.as_str().is_empty() || self.app.as_str().len() > MAX_DECLARED_NAME {
            return Err(DeclarationError::InvalidName(
                self.app.as_str().chars().take(64).collect(),
            ));
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
        if let Some(scope) = &self.custody.payload_scope {
            NamePattern::Exact(scope.clone()).validate()?;
        }
        self.custody
            .salts
            .iter()
            .chain(&self.custody.acts)
            .try_for_each(|used| used.name.validate())
    }
}

/// Why a declaration or grant was rejected as malformed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationError {
    #[error("a declared name is empty, too long or contains whitespace: {0:?}")]
    InvalidName(String),
    #[error("a declaration or grant list exceeds its bound")]
    TooLarge,
}

#[cfg(test)]
mod tests;
