// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The owner-only local transport both resident doors are served over.
//!
//! Graphshell serves two kinds of local caller — a browser relay and a
//! first-party application — on two endpoints. What reaches either one is the
//! same fact: a process running as this user. That check is transport work,
//! not door work, so it lives here once. A second door written against its own
//! copy of the listener would be a second copy of a security check, and copies
//! drift.
//!
//! **What the transport proves.** On Unix the socket is created in the runtime
//! directory at `0600`, so the filesystem does the proving. A Windows named
//! pipe's default access list lets every account read it, so the door's pipe
//! carries its own (SYSTEM and this user, nothing inherited) and refuses
//! remote clients, and the client's token, read through the pipe, is compared
//! against this process's user before a byte is read. Neither says *which*
//! application is speaking; that is the door's business, above this layer.

#[cfg(feature = "door-serve")]
use std::future::Future;

use ostiary::local_endpoint::LocalStream;

#[cfg(all(feature = "door-serve", windows))]
mod windows;
#[cfg(all(feature = "door-serve", windows))]
use windows::{create_pipe_instance, serve_platform};

#[cfg(all(feature = "door-serve", unix))]
mod unix;
#[cfg(all(feature = "door-serve", unix))]
pub use unix::prepare_unix_endpoint;
#[cfg(all(feature = "door-serve", unix))]
use unix::serve_platform;

/// A bound local endpoint, ready to accept connections.
///
/// Keeping the platform listener here lets callers establish that their
/// endpoint is available before reporting readiness.
#[cfg(feature = "door-serve")]
pub struct LocalListener {
    #[cfg(windows)]
    endpoint: String,
    #[cfg(windows)]
    what: &'static str,
    #[cfg(windows)]
    user: String,
    #[cfg(windows)]
    listener: tokio::net::windows::named_pipe::NamedPipeServer,
    #[cfg(not(windows))]
    listener: tokio::net::UnixListener,
}

#[cfg(feature = "door-serve")]
impl LocalListener {
    /// Prepare and bind a local endpoint.
    pub async fn bind(endpoint: &str, what: &'static str) -> Result<Self, std::io::Error> {
        #[cfg(windows)]
        let user = peer_facts::current_user_sid()?;
        #[cfg(windows)]
        let listener = create_pipe_instance(endpoint, &user, true)?;

        #[cfg(not(windows))]
        let listener = {
            use std::os::unix::fs::PermissionsExt;

            prepare_unix_endpoint(std::path::Path::new(endpoint)).await?;
            let listener = tokio::net::UnixListener::bind(endpoint)?;
            std::fs::set_permissions(endpoint, std::fs::Permissions::from_mode(0o600))?;
            listener
        };

        tracing::info!(endpoint, door = what, "resident endpoint listening");

        Ok(Self {
            #[cfg(windows)]
            endpoint: endpoint.to_owned(),
            #[cfg(windows)]
            what,
            #[cfg(windows)]
            user,
            listener,
        })
    }

    /// Accept owner-only connections forever, handing each to `handle`.
    pub async fn serve<H, F>(self, handle: H) -> Result<(), std::io::Error>
    where
        H: Fn(Box<dyn LocalStream>) -> F + Clone + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        self.serve_with_peer(move |stream, _peer| handle(stream))
            .await
    }

    /// [`Self::serve`], handing each connection with what the OS says about
    /// its peer, kept for a later signature check. `None` where the OS would
    /// not say; Windows connections from another user are refused before this.
    pub async fn serve_with_peer<H, F>(self, handle: H) -> Result<(), std::io::Error>
    where
        H: Fn(Box<dyn LocalStream>, Option<peer_facts::Connected>) -> F + Clone + Send + 'static,
        F: Future<Output = ()> + Send + 'static,
    {
        serve_platform(self, handle).await
    }
}

/// Accept owner-only connections forever, handing each to `handle`.
///
/// `what` names the door in the log line, so an operator reading a startup log
/// can tell which endpoint came up.
#[cfg(feature = "door-serve")]
pub async fn serve_local<H, F>(
    endpoint: &str,
    what: &'static str,
    handle: H,
) -> Result<(), std::io::Error>
where
    H: Fn(Box<dyn LocalStream>) -> F + Clone + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    LocalListener::bind(endpoint, what)
        .await?
        .serve(handle)
        .await
}
