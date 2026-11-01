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
            peer: Peer::Windows { sid: token.user.clone(), pid: process.pid, image },
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
pub use windows::{current_user_sid, pipe_client_peer, pipe_server_peer, process_image, process_key, service_sid, system_time};

#[cfg(windows)]
mod windows {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, INVALID_HANDLE_VALUE, LocalFree};
    use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows_sys::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountNameW, PSID, RevertToSelf, SID_NAME_USE, TOKEN_APPCONTAINER_INFORMATION, TOKEN_INFORMATION_CLASS,
        TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid, TokenIntegrityLevel, TokenIsAppContainer, TokenSessionId, TokenUser,
    };
    use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient};
    use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
    use windows_sys::Win32::System::Threading::{
        GetCurrentProcess, GetCurrentThread, GetProcessTimes, OpenProcess, OpenProcessToken, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
    };

    pub use windows_sys::Win32::Foundation::HANDLE;

    use super::{Peer, PipeToken, ProcessKey};

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

    fn filetime(time: FILETIME) -> u64 {
        (u64::from(time.dwHighDateTime) << 32) | u64::from(time.dwLowDateTime)
    }

    /// The system time, precise, in the `FILETIME` units process creation
    /// times use. A connect stamped with it after the connect returns is never
    /// earlier than the creation time of the process that connected, unless
    /// the clock is set back in between.
    pub fn system_time() -> u64 {
        let mut now = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        // SAFETY: a valid out-pointer.
        unsafe { GetSystemTimePreciseAsFileTime(&mut now) };
        filetime(now)
    }

    fn open_process(pid: u32) -> std::io::Result<Owned> {
        // SAFETY: an ordinary query-only open; closed by `Owned`.
        let process = Owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) });
        if process.0.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        Ok(process)
    }

    fn creation_time(process: HANDLE) -> std::io::Result<u64> {
        let zero = FILETIME { dwLowDateTime: 0, dwHighDateTime: 0 };
        let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
        // SAFETY: four valid out-pointers.
        if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(filetime(created))
    }

    /// A process's id and creation time, from a handle the caller holds.
    pub fn process_key(process: HANDLE, pid: u32) -> std::io::Result<ProcessKey> {
        Ok(ProcessKey { pid, created: creation_time(process)? })
    }

    /// The process a connected pipe recorded as its client, opened once and
    /// refused if it was created after `connected_at`.
    fn open_pipe_client(pipe: HANDLE, connected_at: u64) -> std::io::Result<(u32, Owned, u64)> {
        let mut pid = 0u32;
        // SAFETY: valid out-pointer on a connected pipe.
        if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let process = open_process(pid)?;
        let created = creation_time(process.0)?;
        if created > connected_at {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the pipe client's process id names a process created after the connect",
            ));
        }
        Ok((pid, process, created))
    }

    /// A token information class, in a buffer aligned for the structure it
    /// holds.
    fn token_information(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> std::io::Result<Vec<usize>> {
        let mut len = 0u32;
        // SAFETY: a size query with a null buffer.
        unsafe { GetTokenInformation(token, class, std::ptr::null_mut(), 0, &mut len) };
        if len == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut buffer = vec![0usize; (len as usize).div_ceil(std::mem::size_of::<usize>())];
        // SAFETY: `buffer` holds at least `len` bytes, suitably aligned.
        if unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), len, &mut len) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(buffer)
    }

    fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> std::io::Result<u32> {
        let mut value = 0u32;
        let mut len = 0u32;
        // SAFETY: `value` is valid for the four bytes passed.
        if unsafe { GetTokenInformation(token, class, (&mut value as *mut u32).cast(), 4, &mut len) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(value)
    }

    fn token_user(token: HANDLE) -> std::io::Result<String> {
        let buffer = token_information(token, TokenUser)?;
        // SAFETY: TokenUser fills a TOKEN_USER at the start of the buffer.
        let user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        sid_string(user.User.Sid)
    }

    fn token_integrity(token: HANDLE) -> std::io::Result<u32> {
        let buffer = token_information(token, TokenIntegrityLevel)?;
        // SAFETY: TokenIntegrityLevel fills a TOKEN_MANDATORY_LABEL whose SID
        // lies within the buffer; its last subauthority is the level's RID.
        unsafe {
            let label = &*(buffer.as_ptr().cast::<TOKEN_MANDATORY_LABEL>());
            let count = *GetSidSubAuthorityCount(label.Label.Sid);
            if count == 0 {
                return Err(std::io::Error::other("an integrity label without a level"));
            }
            Ok(*GetSidSubAuthority(label.Label.Sid, u32::from(count) - 1))
        }
    }

    fn token_app_container(token: HANDLE) -> std::io::Result<Option<String>> {
        if token_u32(token, TokenIsAppContainer)? == 0 {
            return Ok(None);
        }
        let buffer = token_information(token, TokenAppContainerSid)?;
        // SAFETY: TokenAppContainerSid fills a TOKEN_APPCONTAINER_INFORMATION
        // whose SID lies within the buffer.
        let info = unsafe { &*(buffer.as_ptr().cast::<TOKEN_APPCONTAINER_INFORMATION>()) };
        sid_string(info.TokenAppContainer).map(Some)
    }

    /// The pipe client's token, read by impersonating it on this thread.
    /// Tokio's pipe client connects at identification level, so the thread
    /// can read its token but act as no one; at any level the impersonation
    /// is reverted before this returns, with nothing awaited in between.
    pub(crate) fn pipe_token(pipe: HANDLE) -> std::io::Result<PipeToken> {
        // SAFETY: changes only this thread's token, reverted below.
        if unsafe { ImpersonateNamedPipeClient(pipe) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: valid out-pointer; opened as this process, since an
        // identification-level token cannot open objects itself.
        let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) };
        let error = std::io::Error::last_os_error();
        // SAFETY: ends the impersonation begun above.
        if unsafe { RevertToSelf() } == 0 {
            // A thread left wearing the client's token must not run on.
            std::process::abort();
        }
        if opened == 0 {
            return Err(error);
        }
        let token = Owned(token);
        Ok(PipeToken {
            user: token_user(token.0)?,
            session: token_u32(token.0, TokenSessionId)?,
            integrity: token_integrity(token.0)?,
            app_container: token_app_container(token.0)?,
        })
    }

    /// The SID of a process's token user, as an SDDL string.
    fn process_sid(process: HANDLE) -> std::io::Result<String> {
        let mut token: HANDLE = std::ptr::null_mut();
        // SAFETY: valid out-pointer; the token is closed by `Owned`.
        if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let token = Owned(token);
        token_user(token.0)
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

    /// The pipe client's process and, where the OS could say, its image, both
    /// from one handle.
    pub(crate) fn pipe_client_process(pipe: HANDLE, connected_at: u64) -> std::io::Result<(ProcessKey, Option<String>)> {
        let (pid, process, created) = open_pipe_client(pipe, connected_at)?;
        Ok((ProcessKey { pid, created }, image_of(process.0).ok()))
    }

    fn image_of(process: HANDLE) -> std::io::Result<String> {
        let mut buffer = vec![0u16; 32 * 1024];
        let mut len = buffer.len() as u32;
        // SAFETY: `buffer` is valid for `len` UTF-16 units.
        if unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut len) } == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(String::from_utf16_lossy(&buffer[..len as usize]))
    }

    /// The main executable of a process, as a Win32 path.
    pub fn process_image(pid: u32) -> std::io::Result<String> {
        image_of(open_process(pid)?.0)
    }

    /// The peer on the client end of a connected pipe instance: its process
    /// token's SID, and its executable where the OS could say so. Both are
    /// read from one handle to the process the pipe recorded, refused if that
    /// process was created after this call began, so a process id reused in
    /// between cannot mix two programs. A caller that saw the connect earlier
    /// passes its own time, and reads the token through the pipe, with
    /// [`super::Connected::pipe_client`].
    pub fn pipe_client_peer(handle: HANDLE) -> std::io::Result<Peer> {
        let (pid, process, _) = open_pipe_client(handle, system_time())?;
        let sid = process_sid(process.0)?;
        let image = image_of(process.0).ok();
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
        let sid = process_sid(open_process(pid)?.0)?;
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
