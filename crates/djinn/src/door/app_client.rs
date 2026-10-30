// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Shared native connection to the first-party application door.
//!
//! [`AppConnection`] handles the hello, handshake, sequential typed exchanges,
//! and request IDs used by the custody and projection clients. Djinn serves
//! the other side; both use the envelopes in [`super::wire`] and frames in
//! [`super::frame`]. Projection operations live in `super::projection`.
//!
//! The local transport establishes a same-user boundary. The self-declared
//! application label is used by host route policy and is not executable
//! authentication. Exchanges use `&mut self`, with one outstanding call.

use rand_core::{OsRng, RngCore};

use crate::door::app_admission::{AppHello, AppId, AppRouteId, configured_app_endpoint};
use crate::door::declaration::AppDeclaration;
use crate::door::frame::{
    FrameError, JsonDiagnostic, read_native_message_async, write_native_message_async,
};
use crate::door::local_endpoint::{LocalStream, connect_local};
use crate::door::wire::{APP_CONNECT_SCHEMA, AppHostMessage, AppMessage};

#[derive(Debug, thiserror::Error)]
pub enum AppClientError {
    #[error(transparent)]
    Frame(#[from] FrameError),
    #[error("the resident host closed the stream mid-conversation")]
    Closed,
    #[error("the resident host refused: {0}")]
    Refused(String),
    #[error("expected {expected}, the host answered with {got}")]
    UnexpectedAnswer {
        expected: &'static str,
        got: &'static str,
    },
    #[error("resident response {got} does not answer request {expected}")]
    MismatchedResponse { expected: u64, got: u64 },
    #[error("JSON failed: {0}")]
    Json(JsonDiagnostic),
    #[error("the resident response is invalid: {0}")]
    InvalidResponse(String),
    #[error("transport failed: {0}")]
    Io(#[from] std::io::Error),
}

impl From<serde_json::Error> for AppClientError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(JsonDiagnostic {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        })
    }
}

/// An open session against the resident host, as `app`.
pub struct AppConnection {
    stream: Box<dyn LocalStream>,
    session: String,
    next_id: u64,
}

impl AppConnection {
    #[cfg(test)]
    pub(super) fn for_test(stream: Box<dyn LocalStream>) -> Self {
        Self {
            stream,
            session: "fixture".into(),
            next_id: 1,
        }
    }

    /// Connect to the configured endpoint and complete the whole handshake:
    /// hello, challenge, connect, connected.
    pub async fn open(app: AppId) -> Result<Self, AppClientError> {
        Self::open_at(&configured_app_endpoint(), app).await
    }

    /// Connect to the configured endpoint and request one granted resident
    /// route through the version-two hello.
    pub async fn open_route(app: AppId, route: AppRouteId) -> Result<Self, AppClientError> {
        Self::open_route_at(&configured_app_endpoint(), app, route).await
    }

    /// The same, at an explicit endpoint. Tests and receipts use this.
    pub async fn open_at(endpoint: &str, app: AppId) -> Result<Self, AppClientError> {
        Self::open_with_hello(endpoint, AppHello::new(app.clone()), app).await
    }

    /// Route-aware connection at an explicit endpoint.
    pub async fn open_route_at(
        endpoint: &str,
        app: AppId,
        route: AppRouteId,
    ) -> Result<Self, AppClientError> {
        Self::open_with_hello(endpoint, AppHello::for_route(app.clone(), route), app).await
    }

    /// Connect to the configured endpoint, request `route` and carry the
    /// application's declaration.
    pub async fn open_declared_route(
        app: AppId,
        route: AppRouteId,
        declaration: AppDeclaration,
    ) -> Result<Self, AppClientError> {
        Self::open_declared_route_at(&configured_app_endpoint(), app, route, declaration).await
    }

    /// Declared route-aware connection at an explicit endpoint.
    pub async fn open_declared_route_at(
        endpoint: &str,
        app: AppId,
        route: AppRouteId,
        declaration: AppDeclaration,
    ) -> Result<Self, AppClientError> {
        let hello = AppHello::for_route(app.clone(), route).declaring(declaration);
        Self::open_with_hello(endpoint, hello, app).await
    }

    async fn open_with_hello(
        endpoint: &str,
        hello: AppHello,
        app: AppId,
    ) -> Result<Self, AppClientError> {
        let mut stream = connect_local(endpoint).await?;
        write_native_message_async(&mut stream, &hello).await?;
        let challenge =
            match read_host::<serde::de::IgnoredAny, serde::de::IgnoredAny, serde::de::IgnoredAny>(
                &mut stream,
            )
            .await?
            {
                AppHostMessage::Challenge { challenge } => challenge,
                other => return Err(unexpected("a challenge", &other)),
            };
        let mut client_nonce = [0u8; 32];
        OsRng.fill_bytes(&mut client_nonce);
        write_native_message_async(
            &mut stream,
            &AppMessage::<(), ()>::Connect {
                schema: APP_CONNECT_SCHEMA.to_string(),
                host_nonce: challenge.host_nonce,
                client_nonce: base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    client_nonce,
                ),
            },
        )
        .await?;
        let session =
            match read_host::<serde::de::IgnoredAny, serde::de::IgnoredAny, serde::de::IgnoredAny>(
                &mut stream,
            )
            .await?
            {
                AppHostMessage::Connected {
                    app: connected_app,
                    session,
                } => {
                    if connected_app != app {
                        return Err(AppClientError::Refused(format!(
                            "resident host connected {connected_app}, expected {app}"
                        )));
                    }
                    session
                }
                other => return Err(unexpected("connected", &other)),
            };
        Ok(Self {
            stream,
            session,
            next_id: 1,
        })
    }

    /// The session id the host admitted.
    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
    pub async fn request<
        R: serde::Serialize,
        S: serde::de::DeserializeOwned,
        N: serde::de::DeserializeOwned,
    >(
        &mut self,
        request: R,
    ) -> Result<S, AppClientError> {
        write_native_message_async(&mut self.stream, &AppMessage::<R, ()>::Request { request })
            .await?;
        match read_host::<S, N, serde::de::IgnoredAny>(&mut self.stream).await? {
            AppHostMessage::Response { response } => Ok(response),
            other => Err(unexpected("a carrier response", &other)),
        }
    }
    pub async fn call<C: serde::Serialize, A: serde::de::DeserializeOwned>(
        &mut self,
        call: C,
    ) -> Result<A, AppClientError> {
        let id = self.next_id();
        write_native_message_async(&mut self.stream, &AppMessage::<(), C>::Call { id, call })
            .await?;
        match read_host::<serde::de::IgnoredAny, serde::de::IgnoredAny, A>(&mut self.stream).await?
        {
            AppHostMessage::Answer {
                id: answered,
                answer,
            } if id == answered => Ok(answer),
            AppHostMessage::Answer { id: got, .. } => {
                Err(AppClientError::MismatchedResponse { expected: id, got })
            }
            AppHostMessage::Failure { message } => Err(AppClientError::Refused(message)),
            other => Err(unexpected("a custody answer", &other)),
        }
    }
    pub async fn take_notice<N: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Result<Option<N>, AppClientError> {
        self.notice(false).await
    }
    pub async fn wait_for_notice<N: serde::de::DeserializeOwned>(
        &mut self,
    ) -> Result<N, AppClientError> {
        self.notice(true).await?.ok_or(AppClientError::Closed)
    }
    async fn notice<N: serde::de::DeserializeOwned>(
        &mut self,
        wait: bool,
    ) -> Result<Option<N>, AppClientError> {
        let message = if wait {
            AppMessage::<(), ()>::WaitNotice
        } else {
            AppMessage::<(), ()>::TakeNotice
        };
        write_native_message_async(&mut self.stream, &message).await?;
        match read_host::<serde::de::IgnoredAny, N, serde::de::IgnoredAny>(&mut self.stream).await?
        {
            AppHostMessage::Notice { notice } => Ok(notice),
            other => Err(unexpected("a carrier notice", &other)),
        }
    }
}

async fn read_host<
    R: serde::de::DeserializeOwned,
    N: serde::de::DeserializeOwned,
    A: serde::de::DeserializeOwned,
>(
    stream: &mut Box<dyn LocalStream>,
) -> Result<AppHostMessage<R, N, A>, AppClientError> {
    read_native_message_async(stream)
        .await?
        .ok_or(AppClientError::Closed)
}
fn unexpected<R, N, A>(expected: &'static str, got: &AppHostMessage<R, N, A>) -> AppClientError {
    let got = match got {
        AppHostMessage::Challenge { .. } => "a challenge",
        AppHostMessage::Connected { .. } => "connected",
        AppHostMessage::Response { .. } => "a carrier response",
        AppHostMessage::Notice { .. } => "a carrier notice",
        AppHostMessage::Answer { .. } => "a custody answer",
        AppHostMessage::Failure { .. } => "a failure",
    };
    AppClientError::UnexpectedAnswer { expected, got }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_conversion_keeps_only_redacted_diagnostic_metadata() {
        #[derive(Debug, serde::Deserialize)]
        #[allow(dead_code)]
        enum Expected {
            Allowed,
        }
        let sentinel = "private-app-json-variant";
        let input = format!("\"{sentinel}\"");
        let raw = serde_json::from_str::<Expected>(&input).unwrap_err();
        assert!(raw.to_string().contains(sentinel));
        let expected = (raw.classify(), raw.line(), raw.column());
        let error = AppClientError::from(raw);
        match &error {
            AppClientError::Json(diagnostic) => assert_eq!(
                (diagnostic.category, diagnostic.line, diagnostic.column),
                expected
            ),
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(!format!("{error:?} {error}").contains(sentinel));
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            assert!(!format!("{cause:?} {cause}").contains(sentinel));
            source = cause.source();
        }
    }

    #[tokio::test]
    async fn unexpected_released_answer_does_not_leak_payload_in_error() {
        let (client, mut server) = tokio::io::duplex(4096);
        let mut connection = AppConnection {
            stream: Box::new(client),
            session: "fixture".into(),
            next_id: 1,
        };
        #[derive(serde::Serialize)]
        struct Released<'a> {
            answer: &'static str,
            master: &'a str,
            keys: Vec<()>,
        }
        let server_task = tokio::spawn(async move {
            let _: Option<AppMessage<String, ()>> =
                read_native_message_async(&mut server).await.unwrap();
            let answer = AppHostMessage::<(), (), _>::Answer {
                id: 1,
                answer: Ok::<_, ()>(Released {
                    answer: "released",
                    master: "private-release-material",
                    keys: Vec::new(),
                }),
            };
            write_native_message_async(&mut server, &answer)
                .await
                .unwrap();
        });
        let error = connection
            .request::<_, String, ()>("request")
            .await
            .unwrap_err();
        assert!(matches!(error, AppClientError::UnexpectedAnswer { .. }));
        let sentinel = "private-release-material";
        assert!(!format!("{error:?} {error}").contains(sentinel));
        let mut source = std::error::Error::source(&error);
        while let Some(cause) = source {
            assert!(!format!("{cause:?} {cause}").contains(sentinel));
            source = cause.source();
        }
        server_task.await.unwrap();
    }

    #[cfg(feature = "custody")]
    fn released_answer() -> crate::door::custody::CustodyAnswer {
        use crate::door::custody::{CustodyAnswer, ReleasedKey};
        use personae::IdentityProvider;
        let salt = b"test-release-key".to_vec();
        let provider = personae::InMemoryProvider::from_seed([9; 32]);
        let attestation = provider.attest_derived_key(&salt).unwrap();
        CustodyAnswer::Released {
            master: [0x5a; 32],
            keys: vec![ReleasedKey {
                salt,
                seed: [0x6b; 32],
                attestation,
            }],
        }
    }

    #[cfg(feature = "custody")]
    fn assert_release_secrets_absent(error: &AppClientError) {
        let sentinels = [
            "WlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlo",
            "a2tra2tra2tra2tra2tra2tra2tra2tra2tra2tra2s",
            "107, 107, 107",
            "90, 90, 90",
        ];
        let mut errors: Vec<&dyn std::error::Error> = vec![error];
        while let Some(cause) = errors.pop() {
            let description = format!("{cause:?} {cause}");
            for sentinel in sentinels {
                assert!(!description.contains(sentinel));
            }
            if let Some(source) = cause.source() {
                errors.push(source);
            }
        }
    }

    #[cfg(feature = "custody")]
    #[tokio::test]
    async fn unexpected_real_custody_release_does_not_leak_in_error_chain() {
        use crate::door::custody::CustodyRefusal;
        let (client, mut server) = tokio::io::duplex(4096);
        let mut connection = AppConnection {
            stream: Box::new(client),
            session: "fixture".into(),
            next_id: 1,
        };
        let host = tokio::spawn(async move {
            let _: Option<AppMessage<String, ()>> =
                read_native_message_async(&mut server).await.unwrap();
            let answer = AppHostMessage::<(), (), _>::Answer {
                id: 1,
                answer: Ok::<_, CustodyRefusal>(released_answer()),
            };
            write_native_message_async(&mut server, &answer)
                .await
                .unwrap();
        });
        let error = connection
            .request::<_, String, ()>("request")
            .await
            .unwrap_err();
        assert!(matches!(error, AppClientError::UnexpectedAnswer { .. }));
        assert_release_secrets_absent(&error);
        host.await.unwrap();
    }

    #[cfg(feature = "custody")]
    #[tokio::test]
    async fn mismatched_custody_release_does_not_leak_key_material() {
        use crate::door::custody::{CustodyAnswer, CustodyRefusal};
        let (client, mut server) = tokio::io::duplex(4096);
        let mut connection = AppConnection {
            stream: Box::new(client),
            session: "fixture".into(),
            next_id: 1,
        };
        let host = tokio::spawn(async move {
            let call: AppMessage<(), String> = read_native_message_async(&mut server)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(call, AppMessage::Call { id: 1, .. }));
            let answer = AppHostMessage::<(), (), _>::Answer {
                id: 99,
                answer: Ok::<_, CustodyRefusal>(released_answer()),
            };
            write_native_message_async(&mut server, &answer)
                .await
                .unwrap();
        });
        let error = connection
            .call::<_, Result<CustodyAnswer, CustodyRefusal>>("release")
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AppClientError::MismatchedResponse {
                expected: 1,
                got: 99
            }
        ));
        assert_release_secrets_absent(&error);
        host.await.unwrap();
    }

    #[tokio::test]
    async fn request_and_call_share_ids_and_reject_a_mismatched_answer() {
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Request {
            id: u64,
        }
        let (client, mut server) = tokio::io::duplex(4096);
        let mut connection = AppConnection {
            stream: Box::new(client),
            session: "fixture".into(),
            next_id: 1,
        };
        let host = tokio::spawn(async move {
            let request: AppMessage<Request, ()> = read_native_message_async(&mut server)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(
                request,
                AppMessage::Request {
                    request: Request { id: 1 }
                }
            ));
            write_native_message_async(
                &mut server,
                &AppHostMessage::<_, (), ()>::Response { response: 1u64 },
            )
            .await
            .unwrap();
            let call: AppMessage<(), String> = read_native_message_async(&mut server)
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(call, AppMessage::Call { id: 2, .. }));
            write_native_message_async(
                &mut server,
                &AppHostMessage::<(), (), _>::Answer {
                    id: 99,
                    answer: "wrong",
                },
            )
            .await
            .unwrap();
        });
        let id = connection.next_id();
        let response = connection
            .request::<_, u64, ()>(Request { id })
            .await
            .unwrap();
        assert_eq!(response, id);
        let error = connection.call::<_, String>("status").await.unwrap_err();
        assert!(matches!(
            error,
            AppClientError::MismatchedResponse {
                expected: 2,
                got: 99
            }
        ));
        host.await.unwrap();
    }
}
