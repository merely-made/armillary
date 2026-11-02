// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The client side of the owner-only local transport: the stream type and
//! the dialer.
//!
//! On Unix the socket is created in the runtime directory at `0600`, so the
//! filesystem does the proving; on Windows the door's pipe carries an
//! owner-only access list and compares the client's token with its own user.
//! Both checks belong to the listener, which Djinn serves. Neither says
//! *which* application is speaking; that is the door's business, above this
//! layer.

use tokio::io::{AsyncRead, AsyncWrite};

/// A local connection, whatever the platform calls it.
///
/// Boxed rather than threaded through as a type parameter: the two platforms
/// have unrelated stream types, and a session is a human-paced conversation,
/// so one virtual call per read costs nothing worth naming.
pub trait LocalStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> LocalStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

/// How long a client waits out a busy pipe, and how often it tries again.
#[cfg(windows)]
const PIPE_BUSY_PATIENCE: std::time::Duration = std::time::Duration::from_secs(2);
#[cfg(windows)]
const PIPE_BUSY_STEP: std::time::Duration = std::time::Duration::from_millis(20);

/// Open a connection to a local endpoint.
///
/// On Windows the listener keeps one waiting pipe instance and makes the next
/// only after a connect, so a client arriving between the two gets
/// `ERROR_PIPE_BUSY` (231). It retries for a bounded time, as tokio's
/// named-pipe documentation advises (vault lock plan, ruling 84).
pub async fn connect_local(endpoint: &str) -> Result<Box<dyn LocalStream>, std::io::Error> {
    #[cfg(windows)]
    {
        const ERROR_PIPE_BUSY: i32 = 231;
        let deadline = tokio::time::Instant::now() + PIPE_BUSY_PATIENCE;
        loop {
            match tokio::net::windows::named_pipe::ClientOptions::new().open(endpoint) {
                Ok(client) => return Ok(Box::new(client)),
                Err(error)
                    if error.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(PIPE_BUSY_STEP).await;
                }
                Err(error) => return Err(error),
            }
        }
    }
    #[cfg(not(windows))]
    {
        Ok(Box::new(tokio::net::UnixStream::connect(endpoint).await?))
    }
}
