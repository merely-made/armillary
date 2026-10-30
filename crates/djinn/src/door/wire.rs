// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Typed envelopes shared by applications and the Djinn door broker.
//!
//! Each [`AppMessage`] or [`AppHostMessage`] occupies one native-messaging
//! frame. Payload slots are generic so custody and projection can use the same
//! envelope without depending on each other. The common handshake is carried
//! by `super::app_client` on native platforms; clients supply typed operations.

#[cfg(all(
    feature = "door-serve",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::door::app_admission::AppId;

/// Schema of the connect answer an application sends.
pub const APP_CONNECT_SCHEMA: &str = "mere.graphshell/app-connect/v1";

/// Schema of the host challenge. Named for the browser door, which defined
/// it first; the application door sends the same challenge.
pub const BROWSER_CHALLENGE_SCHEMA: &str = "mere.graphshell/browser-challenge/v1";

/// First host message on every native-messaging conversation, on either door.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserChallenge {
    pub schema: String,
    pub host_nonce: String,
}

impl BrowserChallenge {
    /// A challenge with a fresh 32-byte host nonce, base64url without padding.
    #[cfg(all(
        feature = "door-serve",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    pub fn fresh() -> Self {
        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);
        Self {
            schema: BROWSER_CHALLENGE_SCHEMA.to_string(),
            host_nonce: base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                nonce,
            ),
        }
    }
}

/// Application-to-host messages.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppMessage<Request, Call> {
    /// Answer the host challenge and open the session.
    Connect {
        schema: String,
        host_nonce: String,
        client_nonce: String,
    },
    /// One carrier request against the admitted endpoint.
    Request { request: Request },
    /// Poll for one available notice with bounded stream intake.
    TakeNotice,
    /// Wait until the admitted endpoint rings with a revision notice.
    WaitNotice,
    /// One typed call on the selected route (custody or a projection provider).
    Call { id: u64, call: Call },
}

/// Host-to-application messages.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AppHostMessage<Response, Notice, Answer> {
    Challenge {
        challenge: BrowserChallenge,
    },
    Connected {
        app: AppId,
        session: String,
    },
    Response {
        response: Response,
    },
    Notice {
        notice: Option<Notice>,
    },
    /// The answer to one typed route call, by its id.
    Answer {
        id: u64,
        answer: Answer,
    },
    Failure {
        message: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_envelope_keeps_the_existing_wire_shape() {
        let message: AppMessage<String, u32> = AppMessage::Call { id: 7, call: 42 };
        assert_eq!(
            serde_json::to_string(&message).unwrap(),
            r#"{"type":"call","id":7,"call":42}"#
        );
        let answer: AppHostMessage<String, u32, bool> =
            serde_json::from_str(r#"{"type":"answer","id":7,"answer":true}"#).unwrap();
        assert!(matches!(
            answer,
            AppHostMessage::Answer {
                id: 7,
                answer: true
            }
        ));
    }

    #[cfg(all(feature = "custody", any(unix, windows), not(target_arch = "wasm32")))]
    #[test]
    fn released_custody_answer_preserves_exact_wire_fixture() {
        use crate::door::custody::{CustodyAnswer, CustodyRefusal};
        type Outgoing = AppHostMessage<(), (), Result<CustodyAnswer, CustodyRefusal>>;
        let answer = Outgoing::Answer {
            id: 9,
            answer: Ok(CustodyAnswer::Released {
                master: [0x5a; 32],
                keys: vec![],
            }),
        };
        let fixture = r#"{"type":"answer","id":9,"answer":{"Ok":{"answer":"released","master":"WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo","keys":[]}}}"#;
        assert_eq!(serde_json::to_string(&answer).unwrap(), fixture);
        assert_eq!(serde_json::from_str::<Outgoing>(fixture).unwrap(), answer);
    }

    #[cfg(all(feature = "custody", any(unix, windows), not(target_arch = "wasm32")))]
    #[test]
    fn released_answer_round_trips_nonempty_key_material() {
        use crate::door::custody::{CustodyAnswer, CustodyRefusal, ReleasedKey};
        use personae::IdentityProvider;
        type Outgoing = AppHostMessage<(), (), Result<CustodyAnswer, CustodyRefusal>>;
        let salt = b"test-release-key".to_vec();
        let provider = personae::InMemoryProvider::from_seed([9; 32]);
        let attestation = provider.attest_derived_key(&salt).unwrap();
        let answer = Outgoing::Answer {
            id: 9,
            answer: Ok(CustodyAnswer::Released {
                master: [0x5a; 32],
                keys: vec![ReleasedKey {
                    salt,
                    seed: [0x6b; 32],
                    attestation,
                }],
            }),
        };
        let encoded = serde_json::to_string(&answer).unwrap();
        assert!(encoded.contains("WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo"));
        assert!(encoded.contains("a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s"));
        assert_eq!(serde_json::from_str::<Outgoing>(&encoded).unwrap(), answer);
    }

    #[cfg(all(
        feature = "door-serve",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    #[test]
    fn a_fresh_challenge_carries_a_32_byte_nonce_under_the_shared_schema() {
        let challenge = BrowserChallenge::fresh();
        assert_eq!(challenge.schema, BROWSER_CHALLENGE_SCHEMA);
        let nonce = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &challenge.host_nonce,
        )
        .unwrap();
        assert_eq!(nonce.len(), 32);
        assert_ne!(challenge, BrowserChallenge::fresh());
    }

    #[test]
    fn the_envelope_is_tagged_snake_case() {
        let json = serde_json::to_value(AppMessage::<(), ()>::TakeNotice).unwrap();
        assert_eq!(json, serde_json::json!({ "type": "take_notice" }));
        let json = serde_json::to_value(AppHostMessage::<(), (), ()>::Failure {
            message: "no".into(),
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({ "type": "failure", "message": "no" })
        );
    }
}
