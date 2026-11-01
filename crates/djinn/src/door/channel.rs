// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Channel routes: a route whose session becomes a byte stream.
//!
//! After `Connected`, the application sends exactly one `Call` naming what it
//! wants opened, in the route's own type. The host answers with
//! [`ChannelOpened`] or a `Failure`. From the byte after that answer's frame
//! the conversation carries the provider's raw bytes, in both directions,
//! until either side closes it. The host stays in the middle: it proxies the
//! bytes, so closing its side revokes the channel (Mere's capability door,
//! N1's proxied channel).
//!
//! Frames are read exactly, header then body, so no raw byte is consumed as
//! part of the opening exchange.

use serde::{Deserialize, Serialize};

/// Schema of the answer that opens a channel.
pub const CHANNEL_OPENED_SCHEMA: &str = "mere.djinn/channel-opened/v1";

/// The host's answer to a channel route's opening call. Raw bytes follow it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelOpened {
    pub schema: String,
}

impl ChannelOpened {
    pub fn new() -> Self {
        Self {
            schema: CHANNEL_OPENED_SCHEMA.to_string(),
        }
    }
}

impl Default for ChannelOpened {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(all(feature = "door-native", any(unix, windows), not(target_arch = "wasm32")))]
mod native {
    use super::{CHANNEL_OPENED_SCHEMA, ChannelOpened};
    use crate::door::app_client::{AppClientError, AppConnection};
    use crate::door::local_endpoint::LocalStream;

    impl AppConnection {
        /// Open this session's channel with the route's typed call and hand
        /// back the stream, which carries raw bytes from here on.
        pub async fn open_channel<C: serde::Serialize>(
            mut self,
            open: C,
        ) -> Result<Box<dyn LocalStream>, AppClientError> {
            let opened: ChannelOpened = self.call(open).await?;
            if opened.schema != CHANNEL_OPENED_SCHEMA {
                return Err(AppClientError::InvalidResponse(
                    "channel answer uses another schema".into(),
                ));
            }
            Ok(self.into_stream())
        }
    }
}

#[cfg(all(feature = "door-serve", any(unix, windows), not(target_arch = "wasm32")))]
mod serve {
    use super::ChannelOpened;
    use crate::door::frame::{FrameError, read_native_message_async, write_native_message_async};
    use crate::door::wire::{AppHostMessage, AppMessage};
    use tokio::io::{AsyncRead, AsyncWrite};

    /// Read a channel route's opening call. `None` when the application
    /// closed first; any other message is refused and ends the session.
    pub async fn read_channel_open<R, C>(reader: &mut R) -> Result<Option<(u64, C)>, ChannelError>
    where
        R: AsyncRead + Unpin,
        C: serde::de::DeserializeOwned,
    {
        match read_native_message_async::<_, AppMessage<serde::de::IgnoredAny, C>>(reader).await? {
            None => Ok(None),
            Some(AppMessage::Call { id, call }) => Ok(Some((id, call))),
            Some(_) => Err(ChannelError::OpenRequired),
        }
    }

    /// Answer the opening call; raw bytes follow on both halves.
    pub async fn answer_channel_open<W: AsyncWrite + Unpin>(
        writer: &mut W,
        id: u64,
    ) -> Result<(), FrameError> {
        write_native_message_async(
            writer,
            &AppHostMessage::<(), (), _>::Answer {
                id,
                answer: ChannelOpened::new(),
            },
        )
        .await
    }

    /// Refuse the opening call; the session ends.
    pub async fn refuse_channel_open<W: AsyncWrite + Unpin>(
        writer: &mut W,
        message: impl Into<String>,
    ) -> Result<(), FrameError> {
        write_native_message_async(
            writer,
            &AppHostMessage::<(), (), ()>::Failure {
                message: message.into(),
            },
        )
        .await
    }

    #[derive(Debug, thiserror::Error)]
    pub enum ChannelError {
        #[error(transparent)]
        Frame(#[from] FrameError),
        #[error("a channel route opens with one call")]
        OpenRequired,
    }
}

#[cfg(all(feature = "door-serve", any(unix, windows), not(target_arch = "wasm32")))]
pub use serve::{ChannelError, answer_channel_open, read_channel_open, refuse_channel_open};

#[cfg(all(test, feature = "door-serve", any(unix, windows), not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use crate::door::app_client::{AppClientError, AppConnection};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Open {
        target: String,
    }

    #[tokio::test]
    async fn opened_channel_carries_raw_bytes_both_ways() {
        let (client, server) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);
            let (id, open) = read_channel_open::<_, Open>(&mut reader).await.unwrap().unwrap();
            assert_eq!(open.target, "device");
            answer_channel_open(&mut writer, id).await.unwrap();
            // Written with the answer's frame still in flight: none of it may be
            // taken for framing.
            writer.write_all(b"host-first").await.unwrap();
            let mut got = [0u8; 9];
            reader.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"app-bytes");
        });
        let connection = AppConnection::for_test(Box::new(client));
        let mut stream = connection
            .open_channel(Open {
                target: "device".into(),
            })
            .await
            .unwrap();
        let mut got = [0u8; 10];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"host-first");
        stream.write_all(b"app-bytes").await.unwrap();
        host.await.unwrap();
    }

    #[tokio::test]
    async fn refused_channel_reports_the_hosts_reason() {
        let (client, server) = tokio::io::duplex(4096);
        let host = tokio::spawn(async move {
            let (mut reader, mut writer) = tokio::io::split(server);
            read_channel_open::<_, Open>(&mut reader).await.unwrap().unwrap();
            refuse_channel_open(&mut writer, "not paired").await.unwrap();
        });
        let error = AppConnection::for_test(Box::new(client))
            .open_channel(Open { target: "x".into() })
            .await
            .err()
            .unwrap();
        assert!(matches!(error, AppClientError::Refused(reason) if reason == "not paired"));
        host.await.unwrap();
    }

    #[tokio::test]
    async fn a_channel_route_opens_with_a_call_only() {
        let (mut client, server) = tokio::io::duplex(4096);
        crate::door::frame::write_native_message_async(
            &mut client,
            &crate::door::wire::AppMessage::<(), ()>::TakeNotice,
        )
        .await
        .unwrap();
        let (mut reader, _writer) = tokio::io::split(server);
        assert!(matches!(
            read_channel_open::<_, Open>(&mut reader).await,
            Err(ChannelError::OpenRequired)
        ));
    }
}
