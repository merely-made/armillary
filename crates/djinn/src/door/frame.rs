// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Native-messaging frames: one JSON message behind a native-endian 32-bit
//! byte length, the WebExtensions wire.
//!
//! Both local doors use it: the browser door, because a browser extension
//! speaks nothing else, and the first-party application door, so one
//! resident reads one framing. End-of-stream between messages is normal
//! completion; a partial prefix or body is an error.

use std::io::{Read, Write};

use serde::Serialize;
use serde::de::DeserializeOwned;
#[cfg(all(
    feature = "door-native",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

/// A tighter application bound than Chrome's 64 MiB extension-to-host limit.
pub const MAX_NATIVE_MESSAGE_BYTES: u32 = 1024 * 1024;

/// Why one frame could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("native messaging frame of {len} bytes exceeds the {max} byte bound")]
    TooLarge { len: u64, max: u32 },
    #[error("native messaging stream failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("native messaging JSON failed: {0}")]
    Json(JsonDiagnostic),
}

/// JSON failure metadata that cannot retain message contents or serde errors.
#[derive(Debug, thiserror::Error)]
#[error("{category:?} at line {line} column {column}")]
pub struct JsonDiagnostic {
    pub category: serde_json::error::Category,
    pub line: usize,
    pub column: usize,
}

impl From<serde_json::Error> for FrameError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(JsonDiagnostic {
            category: error.classify(),
            line: error.line(),
            column: error.column(),
        })
    }
}

// Wipe while the allocation is still owned, including on errors and cancellation.
struct Body(Zeroizing<Vec<u8>>);

impl Drop for Body {
    fn drop(&mut self) {
        #[cfg(test)]
        let before = (self.0.len(), self.0.iter().any(|byte| *byte != 0));
        self.0.as_mut_slice().zeroize();
        #[cfg(test)]
        WIPE_OBSERVER.with(|observer| {
            if let Some(observer) = observer.borrow().as_ref() {
                observer(before.0, before.1, &self.0);
            }
        });
    }
}

#[cfg(test)]
thread_local! {
    static WIPE_OBSERVER: std::cell::RefCell<Option<Box<dyn Fn(usize, bool, &[u8])>>> = std::cell::RefCell::new(None);
}

/// Read one native-messaging JSON frame.
pub fn read_native_message<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: Read,
    T: DeserializeOwned,
{
    let mut length = [0u8; 4];
    let mut read = 0usize;
    while read < length.len() {
        match reader.read(&mut length[read..])? {
            0 if read == 0 => return Ok(None),
            0 => return Err(truncated_prefix()),
            count => read += count,
        }
    }
    let length = bounded(u32::from_ne_bytes(length))?;
    let mut body = Body(Zeroizing::new(vec![0u8; length as usize]));
    reader.read_exact(&mut body.0)?;
    Ok(Some(serde_json::from_slice(&body.0)?))
}

/// Write one native-messaging JSON frame.
pub fn write_native_message<W, T>(writer: &mut W, message: &T) -> Result<(), FrameError>
where
    W: Write,
    T: Serialize,
{
    let mut body = Body(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut *body.0, message)?;
    let length = body_length(&body.0)?;
    writer.write_all(&length.to_ne_bytes())?;
    writer.write_all(&body.0)?;
    writer.flush()?;
    Ok(())
}

/// Read one native-messaging JSON frame from an asynchronous stream, with the
/// same size and truncation behavior as [`read_native_message`].
#[cfg(all(
    feature = "door-native",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
pub async fn read_native_message_async<R, T>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let mut length = [0u8; 4];
    let mut read = 0usize;
    while read < length.len() {
        match AsyncReadExt::read(reader, &mut length[read..]).await? {
            0 if read == 0 => return Ok(None),
            0 => return Err(truncated_prefix()),
            count => read += count,
        }
    }
    let length = bounded(u32::from_ne_bytes(length))?;
    let mut body = Body(Zeroizing::new(vec![0u8; length as usize]));
    AsyncReadExt::read_exact(reader, &mut body.0).await?;
    Ok(Some(serde_json::from_slice(&body.0)?))
}

/// Write one native-messaging JSON frame to an asynchronous stream.
#[cfg(all(
    feature = "door-native",
    any(unix, windows),
    not(target_arch = "wasm32")
))]
pub async fn write_native_message_async<W, T>(writer: &mut W, message: &T) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let mut body = Body(Zeroizing::new(Vec::new()));
    serde_json::to_writer(&mut *body.0, message)?;
    let length = body_length(&body.0)?;
    AsyncWriteExt::write_all(writer, &length.to_ne_bytes()).await?;
    AsyncWriteExt::write_all(writer, &body.0).await?;
    AsyncWriteExt::flush(writer).await?;
    Ok(())
}

fn truncated_prefix() -> FrameError {
    std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "native messaging length prefix was truncated",
    )
    .into()
}

fn bounded(length: u32) -> Result<u32, FrameError> {
    if length > MAX_NATIVE_MESSAGE_BYTES {
        return Err(FrameError::TooLarge {
            len: u64::from(length),
            max: MAX_NATIVE_MESSAGE_BYTES,
        });
    }
    Ok(length)
}

fn body_length(body: &[u8]) -> Result<u32, FrameError> {
    let length = u32::try_from(body.len()).map_err(|_| FrameError::TooLarge {
        len: body.len() as u64,
        max: MAX_NATIVE_MESSAGE_BYTES,
    })?;
    bounded(length)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[derive(Debug, serde::Deserialize)]
    enum Expected {
        Accepted,
    }

    struct FailsAfterWriting;
    impl Serialize for FailsAfterWriting {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeSeq;
            let mut seq = serializer.serialize_seq(Some(2))?;
            seq.serialize_element("secret-partial-body")?;
            Err(serde::ser::Error::custom("secret-serializer-error"))
        }
    }

    fn assert_redacted(error: FrameError) {
        use std::error::Error;
        let display = error.to_string();
        let debug = format!("{error:?}");
        assert!(!display.contains("secret-"), "{display}");
        assert!(!debug.contains("secret-"), "{debug}");
        assert!(error.source().is_none());
    }

    #[test]
    fn typed_json_and_partial_serialization_errors_are_redacted() {
        let body = b"\"secret-variant\"";
        let mut wire = (body.len() as u32).to_ne_bytes().to_vec();
        wire.extend_from_slice(body);
        let observations = observe_wipe();
        assert_redacted(read_native_message::<_, Expected>(&mut Cursor::new(wire)).unwrap_err());
        finish_wipe_observation(&observations, body.len());
        let mut output = Vec::new();
        assert_redacted(write_native_message(&mut output, &FailsAfterWriting).unwrap_err());
        assert!(output.is_empty());
    }

    #[cfg(all(
        feature = "door-native",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    #[tokio::test]
    async fn async_json_and_partial_serialization_errors_are_redacted() {
        let body = b"\"secret-variant\"";
        let mut wire = (body.len() as u32).to_ne_bytes().to_vec();
        wire.extend_from_slice(body);
        let observations = observe_wipe();
        assert_redacted(
            read_native_message_async::<_, Expected>(&mut Cursor::new(wire))
                .await
                .unwrap_err(),
        );
        finish_wipe_observation(&observations, body.len());
        let mut output = Vec::new();
        assert_redacted(
            write_native_message_async(&mut output, &FailsAfterWriting)
                .await
                .unwrap_err(),
        );
        assert!(output.is_empty());
    }

    fn observe_wipe() -> std::rc::Rc<std::cell::RefCell<Vec<(usize, bool, bool)>>> {
        let observations = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let result = observations.clone();
        WIPE_OBSERVER.with(|observer| {
            *observer.borrow_mut() = Some(Box::new(move |len, had_data, bytes| {
                result
                    .borrow_mut()
                    .push((len, had_data, bytes.iter().all(|byte| *byte == 0)));
            }));
        });
        observations
    }

    fn finish_wipe_observation(
        observations: &std::rc::Rc<std::cell::RefCell<Vec<(usize, bool, bool)>>>,
        min_len: usize,
    ) {
        WIPE_OBSERVER.with(|observer| *observer.borrow_mut() = None);
        let observations = observations.borrow();
        assert!(
            observations
                .iter()
                .any(|(len, had_data, wiped)| *len >= min_len && *had_data && *wiped),
            "{observations:?}"
        );
    }

    #[test]
    fn partial_read_and_serialization_failure_wipe_owned_buffers() {
        let observations = observe_wipe();
        let mut wire = 24u32.to_ne_bytes().to_vec();
        wire.extend_from_slice(b"secret-partial");
        struct PartialReader(Cursor<Vec<u8>>);
        impl Read for PartialReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                Read::read(&mut self.0, buf)
            }
        }
        assert!(
            read_native_message::<_, serde_json::Value>(&mut PartialReader(Cursor::new(wire)))
                .is_err()
        );
        finish_wipe_observation(&observations, 24);

        let observations = observe_wipe();
        assert!(write_native_message(&mut Vec::new(), &FailsAfterWriting).is_err());
        finish_wipe_observation(&observations, "secret-partial-body".len());
    }

    #[cfg(all(
        feature = "door-native",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    #[tokio::test]
    async fn cancelling_pending_read_and_write_wipes_owned_buffers() {
        use std::future::Future;
        use std::task::{Context, Poll, Waker};
        let observations = observe_wipe();
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&24u32.to_ne_bytes()).await.unwrap();
        writer.write_all(b"secret-partial").await.unwrap();
        let mut future = Box::pin(read_native_message_async::<_, serde_json::Value>(
            &mut reader,
        ));
        let mut context = Context::from_waker(Waker::noop());
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);
        finish_wipe_observation(&observations, 24);

        let observations = observe_wipe();
        let (mut writer, mut reader) = tokio::io::duplex(64);
        writer.write_all(&24u32.to_ne_bytes()).await.unwrap();
        writer.write_all(b"secret-partial").await.unwrap();
        drop(writer);
        assert!(
            read_native_message_async::<_, serde_json::Value>(&mut reader)
                .await
                .is_err()
        );
        finish_wipe_observation(&observations, 24);

        let observations = observe_wipe();
        let (mut writer, _reader) = tokio::io::duplex(4);
        let message = "secret-write-body";
        let mut future = Box::pin(write_native_message_async(&mut writer, &message));
        assert!(matches!(future.as_mut().poll(&mut context), Poll::Pending));
        drop(future);
        finish_wipe_observation(&observations, message.len());
    }

    struct FailAfterPrefix(Vec<u8>);

    impl Write for FailAfterPrefix {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.0.len() == 4 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "writer failed",
                ));
            }
            let count = bytes.len().min(4 - self.0.len());
            self.0.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn writer_failure_after_prefix_wipes_owned_buffer() {
        let observations = observe_wipe();
        let message = "secret-write-body";
        let mut writer = FailAfterPrefix(Vec::new());
        let error = write_native_message(&mut writer, &message).unwrap_err();
        assert!(
            matches!(error, FrameError::Io(ref error) if error.kind() == std::io::ErrorKind::BrokenPipe)
        );
        assert_eq!(writer.0, ((message.len() + 2) as u32).to_ne_bytes());
        finish_wipe_observation(&observations, message.len());
    }

    #[cfg(all(
        feature = "door-native",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    impl tokio::io::AsyncWrite for FailAfterPrefix {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            bytes: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Write::write(&mut *self, bytes))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[cfg(all(
        feature = "door-native",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    #[tokio::test]
    async fn async_writer_failure_after_prefix_wipes_owned_buffer() {
        let observations = observe_wipe();
        let message = "secret-write-body";
        let mut writer = FailAfterPrefix(Vec::new());
        let error = write_native_message_async(&mut writer, &message)
            .await
            .unwrap_err();
        assert!(
            matches!(error, FrameError::Io(ref error) if error.kind() == std::io::ErrorKind::BrokenPipe)
        );
        assert_eq!(writer.0, ((message.len() + 2) as u32).to_ne_bytes());
        finish_wipe_observation(&observations, message.len());
    }

    #[test]
    fn frames_json_with_a_native_endian_length() {
        let message = serde_json::json!({ "type": "take_notice" });
        let mut bytes = Vec::new();
        write_native_message(&mut bytes, &message).unwrap();
        let body = serde_json::to_vec(&message).unwrap();
        assert_eq!(&bytes[..4], &(body.len() as u32).to_ne_bytes());
        let decoded: serde_json::Value = read_native_message(&mut Cursor::new(bytes))
            .unwrap()
            .unwrap();
        assert_eq!(decoded, message);
    }

    #[test]
    fn end_of_stream_between_frames_is_none_and_mid_prefix_is_an_error() {
        let empty: Option<serde_json::Value> =
            read_native_message(&mut Cursor::new(Vec::new())).unwrap();
        assert!(empty.is_none());
        assert!(matches!(
            read_native_message::<_, serde_json::Value>(&mut Cursor::new(vec![1, 0])),
            Err(FrameError::Io(_))
        ));
    }

    #[test]
    fn an_oversized_length_is_refused_before_its_body_is_read() {
        let bytes = (MAX_NATIVE_MESSAGE_BYTES + 1).to_ne_bytes().to_vec();
        assert!(matches!(
            read_native_message::<_, serde_json::Value>(&mut Cursor::new(bytes)),
            Err(FrameError::TooLarge { .. })
        ));
    }

    #[cfg(all(
        feature = "door-native",
        any(unix, windows),
        not(target_arch = "wasm32")
    ))]
    #[tokio::test]
    async fn asynchronous_frames_match_the_synchronous_wire() {
        let message = serde_json::json!({ "type": "failure", "message": "no" });
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        write_native_message_async(&mut writer, &message)
            .await
            .unwrap();
        drop(writer);
        let decoded: serde_json::Value = read_native_message_async(&mut reader)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decoded, message);
        let mut sync = Vec::new();
        write_native_message(&mut sync, &message).unwrap();
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        write_native_message_async(&mut writer, &message)
            .await
            .unwrap();
        drop(writer);
        let mut wire = Vec::new();
        reader.read_to_end(&mut wire).await.unwrap();
        assert_eq!(wire, sync);
    }
}
