// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Who is on the other end of a local connection, as the OS says so:
//! `SO_PEERCRED` on Linux, `getpeereid` (and `LOCAL_PEERPID`) on macOS and
//! the BSDs, the pipe client's token SID and image on Windows, and a signed
//! code identity where a macOS peer's audit token satisfies a signing
//! requirement.
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

/// What the OS said about a peer when it connected, kept so a caller can
/// check a code signature afterwards against a requirement it learns later
/// (an owner's grant, say). On macOS this holds the peer's audit token, which
/// names the process exactly; a pid could be reused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connected {
    pub peer: Peer,
    #[cfg(target_os = "macos")]
    audit_token: Option<[u8; 32]>,
}

impl Connected {
    /// A peer whose signature cannot be checked later.
    pub fn from_peer(peer: Peer) -> Self {
        Self {
            peer,
            #[cfg(target_os = "macos")]
            audit_token: None,
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
mod macos {
    use std::ffi::c_void;

    type CFTypeRef = *const c_void;
    type OSStatus = i32;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        static kCFTypeDictionaryKeyCallBacks: c_void;
        static kCFTypeDictionaryValueCallBacks: c_void;
        fn CFDataCreate(allocator: CFTypeRef, bytes: *const u8, length: isize) -> CFTypeRef;
        fn CFStringCreateWithBytes(allocator: CFTypeRef, bytes: *const u8, length: isize, encoding: u32, external: u8) -> CFTypeRef;
        fn CFDictionaryCreate(allocator: CFTypeRef, keys: *const CFTypeRef, values: *const CFTypeRef, count: isize, key_callbacks: *const c_void, value_callbacks: *const c_void) -> CFTypeRef;
        fn CFRelease(object: CFTypeRef);
    }

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecGuestAttributeAudit: CFTypeRef;
        fn SecCodeCopyGuestWithAttributes(host: CFTypeRef, attributes: CFTypeRef, flags: u32, guest: *mut CFTypeRef) -> OSStatus;
        fn SecRequirementCreateWithString(text: CFTypeRef, flags: u32, requirement: *mut CFTypeRef) -> OSStatus;
        fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
    }

    const UTF8: u32 = 0x0800_0100;

    struct Owned(CFTypeRef);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: a +1 reference this wrapper owns.
                unsafe { CFRelease(self.0) };
            }
        }
    }

    /// `LOCAL_PEERTOKEN` (6 under `SOL_LOCAL`): the peer's audit token.
    pub fn audit_token(fd: std::os::fd::RawFd) -> Option<[u8; 32]> {
        let mut token = [0u8; 32];
        let mut len = token.len() as libc::socklen_t;
        // SAFETY: `token` is valid for `len` bytes.
        let rc = unsafe { libc::getsockopt(fd, 0, 6, token.as_mut_ptr().cast(), &mut len) };
        (rc == 0 && len as usize == token.len()).then_some(token)
    }

    pub fn satisfies(token: &[u8; 32], team: &str, identifier: &str) -> bool {
        let valid = |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || ".-_".contains(c));
        if !valid(team) || !valid(identifier) {
            return false;
        }
        let text = format!("anchor apple generic and identifier \"{identifier}\" and certificate leaf[subject.OU] = \"{team}\"");
        // SAFETY: every CF object is created here, owned by `Owned` and
        // released on every path; the requirement text is validated ASCII.
        unsafe {
            let data = Owned(CFDataCreate(std::ptr::null(), token.as_ptr(), token.len() as isize));
            let key = kSecGuestAttributeAudit;
            let attributes = Owned(CFDictionaryCreate(std::ptr::null(), &key, &data.0, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks));
            let mut code: CFTypeRef = std::ptr::null();
            if SecCodeCopyGuestWithAttributes(std::ptr::null(), attributes.0, 0, &mut code) != 0 {
                return false;
            }
            let code = Owned(code);
            let string = Owned(CFStringCreateWithBytes(std::ptr::null(), text.as_ptr(), text.len() as isize, UTF8, 0));
            let mut requirement: CFTypeRef = std::ptr::null();
            if SecRequirementCreateWithString(string.0, 0, &mut requirement) != 0 {
                return false;
            }
            let requirement = Owned(requirement);
            SecCodeCheckValidity(code.0, 0, requirement.0) == 0
        }
    }
}

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

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android", target_os = "macos", target_os = "ios"))))]
fn peer_pid(_fd: std::os::fd::RawFd) -> Option<i32> {
    None
}

/// This process's effective uid.
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

#[cfg(windows)]
pub use windows::{current_user_sid, pipe_client_peer, pipe_server_peer, process_image, service_sid};

#[cfg(windows)]
mod windows {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{GetTokenInformation, LookupAccountNameW, PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};

    use super::Peer;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().chain(std::iter::once(0)).collect()
    }

    struct Owned(HANDLE);

    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
                // SAFETY: this wrapper owns the handle.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    /// The SID of a process's token user, as an SDDL string.
    fn process_sid(process: HANDLE) -> std::io::Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: valid out-pointer; the token is closed by `Owned`.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = Owned(token);
        let mut len = 0u32;
        // SAFETY: a size query with a null buffer.
        unsafe { GetTokenInformation(token.0, TokenUser, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buffer = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: `buffer` holds at least `len` bytes, suitably aligned.
        if unsafe { GetTokenInformation(token.0, TokenUser, buffer.as_mut_ptr().cast(), len, &mut len) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: TokenUser fills a TOKEN_USER at the start of the buffer.
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(user.User.Sid)
    }

    fn sid_string(sid: PSID) -> std::io::Result<String> {
        let mut text: *mut u16 = std::ptr::null_mut();
        // SAFETY: `sid` is valid; the returned string is freed below.
        if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a NUL-terminated wide string allocated by the system.
        let len = (0..).take_while(|&i| unsafe { *text.add(i) } != 0).count();
        let value = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(text, len) });
        unsafe { LocalFree(text.cast()) };
        Ok(value)
    }

    fn peer_sid(pid: u32) -> std::io::Result<String> {
        // SAFETY: an ordinary query-only open; closed by `Owned`.
        let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if process.0.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        process_sid(process.0)
    }

    /// The main executable of a process, as a Win32 path.
    pub fn process_image(pid: u32) -> std::io::Result<String> {
        // SAFETY: an ordinary query-only open; closed by `Owned`.
        let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if process.0.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let mut buffer = vec![0u16; 32 * 1024];
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` is valid for `len` UTF-16 units.
        if unsafe { QueryFullProcessImageNameW(process.0, 0, buffer.as_mut_ptr(), &mut len) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(String::from_utf16_lossy(&buffer[..len as usize]))
    }

    /// The peer on the client end of a connected pipe instance: its token
    /// SID, and its executable where the OS could say so.
    pub fn pipe_client_peer(handle: HANDLE) -> std::io::Result<Peer> {
        let mut pid = 0u32;
        // SAFETY: valid out-pointer on a connected pipe.
        if unsafe { GetNamedPipeClientProcessId(handle, &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sid = peer_sid(pid)?;
        let image = process_image(pid).ok();
        Ok(Peer::Windows { sid, pid, image })
    }

    /// The peer on the server end of a connected pipe: its token SID. The
    /// image is not read; a client pins the server by its SID.
    pub fn pipe_server_peer(handle: HANDLE) -> std::io::Result<Peer> {
        let mut pid = 0u32;
        // SAFETY: valid out-pointer on a connected pipe.
        if unsafe { GetNamedPipeServerProcessId(handle, &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let sid = peer_sid(pid)?;
        Ok(Peer::Windows { sid, pid, image: None })
    }

    /// This process's token user SID.
    pub fn current_user_sid() -> std::io::Result<String> {
        // SAFETY: the pseudo-handle needs no closing.
        process_sid(unsafe { GetCurrentProcess() })
    }

    /// The SID of a service's virtual account (`NT SERVICE\<name>`).
    pub fn service_sid(service: &str) -> std::io::Result<String> {
        let account = wide(&format!("NT SERVICE\\{service}"));
        let mut sid = vec![0u8; 68];
        let mut sid_len = sid.len() as u32;
        let mut domain = vec![0u16; 64];
        let mut domain_len = domain.len() as u32;
        let mut use_kind: SID_NAME_USE = 0;
        // SAFETY: every buffer is valid for the lengths passed.
        let ok = unsafe {
            LookupAccountNameW(std::ptr::null(), account.as_ptr(), sid.as_mut_ptr().cast(), &mut sid_len, domain.as_mut_ptr(), &mut domain_len, &mut use_kind)
        };
        if ok == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(ERROR_INSUFFICIENT_BUFFER as i32) {
                return Err(std::io::Error::other("service SID buffer too small"));
            }
            return Err(error);
        }
        sid_string(sid.as_mut_ptr().cast())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_has_a_stable_account_and_wire_shape() {
        let unix = Peer::Unix { uid: 501, gid: 20, pid: Some(7) };
        assert_eq!(unix.account(), "uid:501");
        let signed = Peer::Signed { team: "T".into(), identifier: "i".into() };
        assert_eq!(signed.account(), "signed:T:i");
        let json = serde_json::to_value(&unix).unwrap();
        assert_eq!(json, serde_json::json!({"kind": "unix", "uid": 501, "gid": 20, "pid": 7}));
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
        assert!(!Connected::from_peer(connected.peer.clone()).signed_as("ABCDE12345", "com.merely.knot"));
        let candidates = [SignedIdentity { team: "ABCDE12345".into(), identifier: "com.merely.djinn.custodian".into() }];
        assert!(signed_peer(a.as_raw_fd(), &candidates).is_none());
        let injected = [SignedIdentity { team: "X\" or anchor apple".into(), identifier: "y".into() }];
        assert!(signed_peer(a.as_raw_fd(), &injected).is_none(), "requirement text cannot be injected");
    }
}
