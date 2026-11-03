// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Windows named-pipe, token and process observations.

use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INSUFFICIENT_BUFFER, FILETIME, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows_sys::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, LookupAccountNameW, PSID,
    RevertToSelf, SID_NAME_USE, TOKEN_APPCONTAINER_INFORMATION, TOKEN_INFORMATION_CLASS,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER, TokenAppContainerSid, TokenIntegrityLevel,
    TokenIsAppContainer, TokenSessionId, TokenUser,
};
use windows_sys::Win32::System::Pipes::{
    GetNamedPipeClientProcessId, GetNamedPipeServerProcessId, ImpersonateNamedPipeClient,
};
use windows_sys::Win32::System::SystemInformation::GetSystemTimePreciseAsFileTime;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetProcessTimes, OpenProcess, OpenProcessToken,
    OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW,
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
    let mut now = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
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
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: four valid out-pointers.
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(filetime(created))
}

/// A process's id and creation time, from a handle the caller holds.
pub fn process_key(process: HANDLE, pid: u32) -> std::io::Result<ProcessKey> {
    Ok(ProcessKey {
        pid,
        created: creation_time(process)?,
    })
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
    if unsafe { GetTokenInformation(token, class, buffer.as_mut_ptr().cast(), len, &mut len) } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(buffer)
}

fn token_u32(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> std::io::Result<u32> {
    let mut value = 0u32;
    let mut len = 0u32;
    // SAFETY: `value` is valid for the four bytes passed.
    if unsafe { GetTokenInformation(token, class, (&mut value as *mut u32).cast(), 4, &mut len) }
        == 0
    {
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
pub(crate) fn pipe_client_process(
    pipe: HANDLE,
    connected_at: u64,
) -> std::io::Result<(ProcessKey, Option<String>)> {
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
    Ok(Peer::Windows {
        sid,
        pid,
        image: None,
    })
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
        LookupAccountNameW(
            std::ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut sid_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_kind,
        )
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
