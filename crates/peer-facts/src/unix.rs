// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Unix socket credentials and effective account identity.

use super::Peer;

/// The peer of a connected Unix-domain socket.
#[cfg(unix)]
pub fn unix_peer(fd: std::os::fd::RawFd) -> std::io::Result<Peer> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` and `len` are valid for writes of the sizes given.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Peer::Unix {
            uid: cred.uid,
            gid: cred.gid,
            pid: Some(cred.pid),
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        let mut uid: libc::uid_t = 0;
        let mut gid: libc::gid_t = 0;
        // SAFETY: both out-pointers are valid for writes.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Peer::Unix {
            uid,
            gid,
            pid: peer_pid(fd),
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn peer_pid(fd: std::os::fd::RawFd) -> Option<i32> {
    // <sys/un.h>: SOL_LOCAL 0, LOCAL_PEERPID 2.
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    // SAFETY: `pid` and `len` are valid for writes of the sizes given.
    let rc = unsafe { libc::getsockopt(fd, 0, 2, (&mut pid as *mut libc::pid_t).cast(), &mut len) };
    (rc == 0).then_some(pid)
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))
))]
fn peer_pid(_fd: std::os::fd::RawFd) -> Option<i32> {
    None
}

/// This process's effective uid.
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}
