// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The intersection of an application declaration and its owner grant.

use super::{AppDeclaration, AppGrant, CustodyOperation, OfferedProjection, SaltSource, SaltUse};
use crate::app_admission::{AppId, AppRouteId};

fn salt_display(salt: &[u8]) -> String {
    let text = String::from_utf8_lossy(salt);
    let mut shown: String = text.chars().take(64).collect();
    if text.chars().count() > 64 {
        shown.push('…');
    }
    shown
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
    pub fn epoch(
        &self,
        context: &str,
        device_bound: bool,
        public_only: bool,
    ) -> Result<(), AuthorityRefusal> {
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
        if !self
            .grant
            .custody
            .epoch
            .iter()
            .any(|pattern| pattern.matches(context))
        {
            return Err(self.not_granted(what()));
        }
        Ok(())
    }

    /// Whether the key `salt` derives from `source` may leave for this
    /// connection (`released`), or only be signed or attested with. A released
    /// namespace covers signing and attesting too.
    pub fn salt(
        &self,
        source: SaltSource,
        salt: &[u8],
        released: bool,
    ) -> Result<(), AuthorityRefusal> {
        let what = || {
            let root = match source {
                SaltSource::Persona => "persona",
                SaltSource::Wallet => "wallet",
            };
            let act = if released {
                "release of"
            } else {
                "signature with"
            };
            format!("the {act} {root} key {}", salt_display(salt))
        };
        let covered = |salts: &[SaltUse], acts: &[SaltUse]| {
            salts.iter().any(|used| used.covers(source, salt))
                || (!released && acts.iter().any(|used| used.covers(source, salt)))
        };
        if !covered(
            &self.declaration.custody.salts,
            &self.declaration.custody.acts,
        ) {
            return Err(self.undeclared(what()));
        }
        if !covered(&self.grant.custody.salts, &self.grant.custody.acts) {
            return Err(self.not_granted(what()));
        }
        Ok(())
    }

    /// The scope this connection's retained-content payloads are sealed
    /// under: the one it declared, if the owner's grant names the same.
    pub fn payload_scope(&self) -> Result<&str, AuthorityRefusal> {
        let what = || "a retained-content seal scope".to_string();
        let declared = self
            .declaration
            .custody
            .payload_scope
            .as_deref()
            .ok_or_else(|| self.undeclared(what()))?;
        match self.grant.custody.payload_scope.as_deref() {
            Some(granted) if granted == declared => Ok(declared),
            _ => Err(self.not_granted(format!("the seal scope {declared}"))),
        }
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
