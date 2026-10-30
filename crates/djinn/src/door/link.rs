// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Shared local challenge and transcript binding. Labels are not credentials.
use base64::Engine;
use super::wire::{BrowserChallenge, BROWSER_CHALLENGE_SCHEMA};
const LINK_DOMAIN: &[u8] = b"mere.graphshell/native-messaging-link/v1";
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("local connect uses another schema")]
    WrongSchema,
    #[error("local challenge does not match this host process")]
    ChallengeMismatch,
    #[error("local nonce is not a 32-byte base64url value")]
    InvalidNonce,
}
/// A checked connect answer and its transcript link, for any local client.
///
/// The label is bound into the transcript, so a link minted for one client
/// cannot be replayed as another even on the same challenge. What the label
/// says is the caller's business: an extension origin for a browser, an
/// application name for a first-party app.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalLink {
    pub label: String,
    pub host_nonce: [u8; 32],
    pub client_nonce: [u8; 32],
    pub shared_link: [u8; 16],
}

impl LocalLink {
    /// Bind a client label and its answered nonces into a transcript link.
    ///
    /// Both browser and application adapters bind the same transcript.
    pub fn bind(
        label: String,
        challenge: &BrowserChallenge,
        host_nonce: &str,
        client_nonce: &str,
    ) -> Result<Self, LinkError> {
        let expected = challenge_nonce(challenge)?;
        let echoed = decode_nonce(host_nonce)?;
        if echoed != expected {
            return Err(LinkError::ChallengeMismatch);
        }
        let client_nonce = decode_nonce(client_nonce)?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(LINK_DOMAIN);
        hasher.update(&(label.len() as u64).to_le_bytes());
        hasher.update(label.as_bytes());
        hasher.update(&expected);
        hasher.update(&client_nonce);
        let mut shared_link = [0u8; 16];
        shared_link.copy_from_slice(&hasher.finalize().as_bytes()[..16]);
        Ok(Self {
            label,
            host_nonce: expected,
            client_nonce,
            shared_link,
        })
    }
}

fn challenge_nonce(challenge: &BrowserChallenge) -> Result<[u8; 32], LinkError> {
    if challenge.schema != BROWSER_CHALLENGE_SCHEMA {
        return Err(LinkError::WrongSchema);
    }
    decode_nonce(&challenge.host_nonce)
}

fn decode_nonce(value: &str) -> Result<[u8; 32], LinkError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| LinkError::InvalidNonce)?;
    bytes
        .try_into()
        .map_err(|_| LinkError::InvalidNonce)
}
