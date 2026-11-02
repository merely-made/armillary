// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! The launched application's side of a launch (capability door plan, I1).
//!
//! Linux has no code signature to read from a peer, so Djinn starts the
//! application itself and hands it a one-time [`LaunchHandle`] on descriptor
//! [`LAUNCH_FD`], named by [`LAUNCH_FD_ENV`]. The child calls [`claim`]
//! first in `main`, which reads it, closes the descriptor and clears the
//! variable before the child can spawn anything; its door client then carries
//! it on every route hello; the door admits the label
//! when the handle is live for that application. It is a secret within the
//! same-user boundary, like the endpoint itself: it shows a connection came
//! from the launched process or one it shared the handle with, not more.
//!
//! Windows needs no secret (capability door plan, D11): Djinn holds the
//! launched process's handle and knows its connections by the pipe. The
//! launcher is Djinn's.

use crate::app_admission::LaunchHandle;

/// The environment variable naming the descriptor the handle arrives on.
pub const LAUNCH_FD_ENV: &str = "DJINN_LAUNCH_FD";
/// The descriptor Djinn places the handle on in a process it launches.
pub const LAUNCH_FD: i32 = 3;

/// The handle this process was launched with, read once from the descriptor
/// [`LAUNCH_FD_ENV`] names. `None` for a process Djinn did not launch.
#[cfg(unix)]
pub fn inherited() -> Option<LaunchHandle> {
    static HANDLE: std::sync::OnceLock<Option<LaunchHandle>> = std::sync::OnceLock::new();
    *HANDLE.get_or_init(|| {
        use std::io::Read;
        use std::os::fd::FromRawFd;
        let fd: i32 = std::env::var(LAUNCH_FD_ENV).ok()?.parse().ok()?;
        if fd < 0 {
            return None;
        }
        // SAFETY: the launcher placed a pipe's read end at `fd` for this
        // process to read once; taking ownership closes it after the read.
        let mut pipe = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut bytes = [0u8; 32];
        pipe.read_exact(&mut bytes).ok()?;
        Some(LaunchHandle::from_bytes(bytes))
    })
}

/// The handle this process was launched with; never on this platform, where
/// the door knows a launched process by the pipe.
#[cfg(not(unix))]
pub fn inherited() -> Option<LaunchHandle> {
    None
}

/// Take the launch handle into this process before anything else runs: read
/// it, close its descriptor and remove [`LAUNCH_FD_ENV`], so no child this
/// process spawns inherits either. Call it first in `main`, before spawning
/// threads or processes; a launched application that waits until its first
/// route hello leaves the handle open to children started before then.
/// Returns the handle, which later [`inherited`] calls return too.
pub fn claim() -> Option<LaunchHandle> {
    let handle = inherited();
    #[cfg(unix)]
    // SAFETY: claim runs first in `main`, before any other thread reads or
    // writes the environment.
    unsafe {
        std::env::remove_var(LAUNCH_FD_ENV);
    }
    handle
}
