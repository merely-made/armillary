// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Who is on the other end of a local connection, as the OS says so:
//! `SO_PEERCRED` on Linux, `getpeereid` (and `LOCAL_PEERPID`) on macOS and
//! the BSDs, a Windows pipe client's token read through the pipe and its
//! process read from one handle, and a signed code identity where a macOS
//! peer's audit token satisfies a signing requirement.
//!
//! These are facts, not policy. Djinn's application door records them for
//! each connection; custody-wire's custodian selects a principal by them and
//! its client verifies the custodian. What a fact must be for a connection to
//! be admitted is each caller's own rule.

use serde::{Deserialize, Serialize};

/// An OS-established peer identity. Never read from a message.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Peer {
    /// A Unix-domain socket peer.
    Unix {
        uid: u32,
        gid: u32,
        pid: Option<i32>,
    },
    /// A Windows named-pipe peer, by its token's user SID. `image` is the
    /// peer's main executable path where the OS could say so: the fact a
    /// policy pins its consent helper on.
    Windows {
        sid: String,
        pid: u32,
        #[serde(default)]
        image: Option<String>,
    },
    /// A macOS XPC peer whose code signature the native host verified.
    Signed { team: String, identifier: String },
}

impl Peer {
    /// A stable account key for per-principal budgets.
    pub fn account(&self) -> String {
        match self {
            Self::Unix { uid, .. } => format!("uid:{uid}"),
            Self::Windows { sid, .. } => format!("sid:{sid}"),
            Self::Signed { team, identifier } => format!("signed:{team}:{identifier}"),
        }
    }
}

/// A team and code identifier a macOS peer's signature must satisfy.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedIdentity {
    pub team: String,
    pub identifier: String,
}

/// One Windows process: its id and creation time. An id is reused once its
/// process ends and its last handle closes; the pair is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    /// Creation time, in 100-nanosecond intervals since 1601 (a `FILETIME`).
    pub created: u64,
}

/// What a Windows pipe client's token says, read through the pipe rather
/// than by process id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipeToken {
    /// The token user's SID.
    pub user: String,
    /// The Remote Desktop session the client runs in.
    pub session: u32,
    /// The mandatory integrity level's RID: [`PipeToken::MEDIUM`] for an
    /// ordinary desktop process, lower for a sandboxed one.
    pub integrity: u32,
    /// The AppContainer's SID, for a client running in one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_container: Option<String>,
}

impl PipeToken {
    /// `SECURITY_MANDATORY_MEDIUM_RID`.
    pub const MEDIUM: u32 = 0x2000;
}

/// What the OS said about a peer when it connected, kept so a caller can
/// check a code signature afterwards against a requirement it learns later
/// (an owner's grant, say). On macOS this holds the peer's audit token, which
/// names the process exactly; a pid could be reused. On Windows it holds the
/// client's token, read through the pipe, and the process the pipe recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connected {
    pub peer: Peer,
    #[cfg(target_os = "macos")]
    audit_token: Option<[u8; 32]>,
    #[cfg(windows)]
    process: Option<ProcessKey>,
    #[cfg(windows)]
    token: Option<PipeToken>,
}

impl Connected {
    /// A peer whose signature cannot be checked later.
    pub fn from_peer(peer: Peer) -> Self {
        Self {
            peer,
            #[cfg(target_os = "macos")]
            audit_token: None,
            #[cfg(windows)]
            process: None,
            #[cfg(windows)]
            token: None,
        }
    }

    /// The client of a connected pipe instance, read for a connect the server
    /// saw complete at `connected_at` (from [`system_time`], taken as soon as
    /// the connect returned). Its token is read through the pipe; its
    /// process id, creation time and image come from one handle to the
    /// process the pipe recorded, refused if that process was created after
    /// `connected_at`, when its id must have been reused. Within the
    /// granularity of process creation times, a process id cannot then name
    /// another program. The peer's SID is the token's.
    #[cfg(windows)]
    pub fn pipe_client(handle: windows::HANDLE, connected_at: u64) -> std::io::Result<Self> {
        let (process, image) = windows::pipe_client_process(handle, connected_at)?;
        let token = windows::pipe_token(handle)?;
        Ok(Self {
            peer: Peer::Windows {
                sid: token.user.clone(),
                pid: process.pid,
                image,
            },
            process: Some(process),
            token: Some(token),
        })
    }

    /// A Windows client's token, where it was read through the pipe.
    pub fn token(&self) -> Option<&PipeToken> {
        #[cfg(windows)]
        {
            self.token.as_ref()
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    /// The Windows process the pipe recorded, where it was read for the
    /// connect.
    pub fn process(&self) -> Option<ProcessKey> {
        #[cfg(windows)]
        {
            self.process
        }
        #[cfg(not(windows))]
        {
            None
        }
    }

    /// The peer of a connected Unix-domain socket, with its audit token on
    /// macOS.
    #[cfg(unix)]
    pub fn unix(fd: std::os::fd::RawFd) -> std::io::Result<Self> {
        Ok(Self {
            peer: unix_peer(fd)?,
            #[cfg(target_os = "macos")]
            audit_token: macos::audit_token(fd),
        })
    }

    /// Whether the peer's code signature satisfies `team` and `identifier`.
    /// Only macOS can say; elsewhere this is false.
    pub fn signed_as(&self, team: &str, identifier: &str) -> bool {
        #[cfg(target_os = "macos")]
        {
            self.audit_token
                .as_ref()
                .is_some_and(|token| macos::satisfies(token, team, identifier))
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (team, identifier);
            false
        }
    }
}

/// The first of `candidates` whose signing requirement the macOS peer on
/// `fd` satisfies, checked against its audit token rather than a pid.
#[cfg(target_os = "macos")]
pub fn signed_peer(fd: std::os::fd::RawFd, candidates: &[SignedIdentity]) -> Option<Peer> {
    let token = macos::audit_token(fd)?;
    candidates
        .iter()
        .find(|c| macos::satisfies(&token, &c.team, &c.identifier))
        .map(|c| Peer::Signed {
            team: c.team.clone(),
            identifier: c.identifier.clone(),
        })
}

#[cfg(target_os = "macos")]
mod macos;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{effective_uid, unix_peer};

#[cfg(windows)]
pub use windows::{
    current_user_sid, pipe_client_peer, pipe_server_peer, process_image, process_key, service_sid,
    system_time,
};

#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_has_a_stable_account_and_wire_shape() {
        let unix = Peer::Unix {
            uid: 501,
            gid: 20,
            pid: Some(7),
        };
        assert_eq!(unix.account(), "uid:501");
        let signed = Peer::Signed {
            team: "T".into(),
            identifier: "i".into(),
        };
        assert_eq!(signed.account(), "signed:T:i");
        let json = serde_json::to_value(&unix).unwrap();
        assert_eq!(
            json,
            serde_json::json!({"kind": "unix", "uid": 501, "gid": 20, "pid": 7})
        );
        assert_eq!(serde_json::from_value::<Peer>(json).unwrap(), unix);
    }

    #[cfg(unix)]
    #[test]
    fn the_os_reports_the_peer_not_the_message() {
        use std::os::fd::AsRawFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        match unix_peer(a.as_raw_fd()).unwrap() {
            Peer::Unix { uid, pid, .. } => {
                assert_eq!(uid, effective_uid());
                if let Some(pid) = pid {
                    assert_eq!(pid as u32, std::process::id());
                }
            }
            other => panic!("unexpected peer {other:?}"),
        }
    }

    /// The negative control: this ad-hoc-signed test binary satisfies no
    /// team requirement, so it stays a plain uid peer.
    #[cfg(target_os = "macos")]
    #[test]
    fn an_unsigned_peer_never_passes_as_a_signed_identity() {
        use std::os::fd::AsRawFd;
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let connected = Connected::unix(a.as_raw_fd()).unwrap();
        assert!(!connected.signed_as("ABCDE12345", "com.merely.knot"));
        assert!(
            !Connected::from_peer(connected.peer.clone())
                .signed_as("ABCDE12345", "com.merely.knot")
        );
        let candidates = [SignedIdentity {
            team: "ABCDE12345".into(),
            identifier: "com.merely.djinn.custodian".into(),
        }];
        assert!(signed_peer(a.as_raw_fd(), &candidates).is_none());
        let injected = [SignedIdentity {
            team: "X\" or anchor apple".into(),
            identifier: "y".into(),
        }];
        assert!(
            signed_peer(a.as_raw_fd(), &injected).is_none(),
            "requirement text cannot be injected"
        );
    }
}
