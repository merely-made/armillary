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

use crate::app_admission::{AppHello, AppId, AppRouteId, configured_app_endpoint};
use crate::declaration::AppDeclaration;
use crate::frame::{
    FrameError, JsonDiagnostic, read_native_message_async, write_native_message_async,
};
use crate::local_endpoint::{LocalStream, connect_local};
use crate::wire::{APP_CONNECT_SCHEMA, AppHostMessage, AppMessage};

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
        Self::open_with_hello(endpoint, AppHello::new(app)).await
    }

    /// Route-aware connection at an explicit endpoint.
    pub async fn open_route_at(
        endpoint: &str,
        app: AppId,
        route: AppRouteId,
    ) -> Result<Self, AppClientError> {
        Self::open_with_hello(endpoint, AppHello::for_route(app, route)).await
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
        let hello = AppHello::for_route(app, route).declaring(declaration);
        Self::open_with_hello(endpoint, hello).await
    }

    async fn open_with_hello(endpoint: &str, hello: AppHello) -> Result<Self, AppClientError> {
        Self::open_over(connect_local(endpoint).await?, hello).await
    }

    /// Complete the whole handshake over a stream the caller already holds,
    /// such as a channel a parent passed down, rather than dialing an
    /// endpoint. [`Self::into_stream`] is the inverse.
    pub async fn open_over(
        mut stream: Box<dyn LocalStream>,
        hello: AppHello,
    ) -> Result<Self, AppClientError> {
        let app = hello.app.clone();
        // A process Djinn launched carries its handle on every route hello.
        let hello = match (hello.route.is_some(), crate::launch::inherited()) {
            (true, Some(handle)) => hello.launched(handle),
            _ => hello,
        };
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

    /// The admitted stream, for a protocol other than this envelope to carry
    /// from here on: the projection session's generated calls (capability
    /// door W1, djinn-slimming D9). The host must hand its side over at the
    /// same point.
    pub fn into_stream(self) -> Box<dyn LocalStream> {
        self.stream
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

    #[tokio::test]
    async fn an_admitted_connection_hands_its_stream_to_another_protocol() {
        use crate::wire::BrowserChallenge;
        let (client, mut server) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let hello: AppHello = read_native_message_async(&mut server).await.unwrap().unwrap();
            let challenge = AppHostMessage::<(), (), ()>::Challenge { challenge: BrowserChallenge::fresh() };
            write_native_message_async(&mut server, &challenge).await.unwrap();
            let connect: AppMessage<(), ()> = read_native_message_async(&mut server).await.unwrap().unwrap();
            assert!(matches!(connect, AppMessage::Connect { .. }));
            let connected = AppHostMessage::<(), (), ()>::Connected { app: hello.app, session: "s1".into() };
            write_native_message_async(&mut server, &connected).await.unwrap();
            // From here the stream is no longer framed JSON.
            let mut bytes = [0u8; 4];
            server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(bytes, [0, 0xff, 0x0a, 7]);
            server.write_all(&[9, 8]).await.unwrap();
        });
        let hello = AppHello::for_route(AppId::new("knot"), AppRouteId::new("projection").unwrap());
        let connection = AppConnection::open_over(Box::new(client), hello).await.unwrap();
        assert_eq!(connection.session(), "s1");
        let mut stream = connection.into_stream();
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream.write_all(&[0, 0xff, 0x0a, 7]).await.unwrap();
            let mut answer = [0u8; 2];
            stream.read_exact(&mut answer).await.unwrap();
            assert_eq!(answer, [9, 8]);
        }
        host.await.unwrap();
    }
}
