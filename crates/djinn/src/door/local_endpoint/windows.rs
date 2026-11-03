// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Windows pipe access lists and per-connection owner verification.

use std::future::Future;

use ostiary::local_endpoint::LocalStream;

use super::LocalListener;

#[cfg(feature = "door-serve")]
#[cfg(windows)]
pub(super) async fn serve_platform<H, F>(
    listener: LocalListener,
    handle: H,
) -> Result<(), std::io::Error>
where
    H: Fn(Box<dyn LocalStream>, Option<peer_facts::Connected>) -> F + Clone + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    let LocalListener {
        endpoint,
        what,
        user,
        listener,
    } = listener;
    let user = std::sync::Arc::new(user);
    let mut server = listener;
    loop {
        server.connect().await?;
        let connected_at = peer_facts::system_time();
        let connection = server;
        server = create_pipe_instance(&endpoint, &user, false)?;
        let (handle, user) = (handle.clone(), user.clone());
        armillary::tasks::spawn_tracked(async move {
            let peer = match verify_client(&connection, connected_at, &user) {
                Ok(peer) => peer,
                Err(error) => {
                    tracing::warn!(%error, door = what, "rejected a pipe client");
                    return;
                }
            };
            handle(Box::new(connection), Some(peer)).await;
        });
    }
}

/// The door pipe's access list: full control for SYSTEM and this user,
/// protected from inheritance. Without it a pipe lets every account read.
#[cfg(feature = "door-serve")]
#[cfg(windows)]
fn pipe_sddl(user: &str) -> String {
    format!("D:P(A;;GA;;;SY)(A;;GA;;;{user})")
}

/// Create an instance of the door's pipe with [`pipe_sddl`]'s access list,
/// refusing remote clients; `first` refuses a name another process holds.
#[cfg(feature = "door-serve")]
#[cfg(windows)]
pub(super) fn create_pipe_instance(
    endpoint: &str,
    user: &str,
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, std::io::Error> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let sddl: Vec<u16> = pipe_sddl(user).encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string; the descriptor is freed below.
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    // SAFETY: `attributes` points at a valid descriptor for the whole call.
    let created = unsafe {
        tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(first)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                endpoint,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    };
    // SAFETY: allocated by the system above and no longer referenced.
    unsafe { LocalFree(descriptor) };
    created
}

/// Read the client of a pipe connected at `connected_at` and admit it only
/// as `user`, outside any AppContainer, at medium integrity or above.
///
/// Unix gets the user from the socket's mode. The pipe's access list already
/// keeps out other users and AppContainers, and its default label keeps out
/// lower integrity writers; the token read through the pipe checks each
/// connection again.
#[cfg(feature = "door-serve")]
#[cfg(windows)]
fn verify_client(
    connection: &tokio::net::windows::named_pipe::NamedPipeServer,
    connected_at: u64,
    user: &str,
) -> Result<peer_facts::Connected, std::io::Error> {
    use std::os::windows::io::AsRawHandle;

    let refused = |why: &str| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("the client {why}"),
        )
    };
    let connected =
        peer_facts::Connected::pipe_client(connection.as_raw_handle() as _, connected_at)?;
    let token = connected
        .token()
        .ok_or_else(|| refused("token was not read"))?;
    if token.user != user {
        return Err(refused("belongs to another Windows user"));
    }
    if token.app_container.is_some() {
        return Err(refused("runs in an AppContainer"));
    }
    if token.integrity < peer_facts::PipeToken::MEDIUM {
        return Err(refused("runs below medium integrity"));
    }
    Ok(connected)
}

#[cfg(feature = "door-serve")]
#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use tokio::net::windows::named_pipe::ClientOptions;

    #[tokio::test]
    async fn a_local_endpoint_accepts_the_current_windows_user() {
        let endpoint = format!(r"\\.\pipe\graphshell-user-check-{}", uuid::Uuid::new_v4());
        let user = peer_facts::current_user_sid().unwrap();
        let server = create_pipe_instance(&endpoint, &user, true).unwrap();
        let _client = ClientOptions::new().open(&endpoint).unwrap();
        server.connect().await.unwrap();
        let connected_at = peer_facts::system_time();
        let connected = verify_client(&server, connected_at, &user).unwrap();
        let token = connected.token().unwrap();
        assert_eq!(token.user, user);
        assert!(token.integrity >= peer_facts::PipeToken::MEDIUM);
        assert_eq!(token.app_container, None);
        let process = connected.process().unwrap();
        assert_eq!(process.pid, std::process::id());
        match &connected.peer {
            peer_facts::Peer::Windows { sid, pid, image } => {
                assert_eq!((sid, *pid), (&user, std::process::id()));
                let exe = std::env::current_exe().unwrap();
                assert!(
                    image
                        .as_deref()
                        .is_some_and(|image| image.eq_ignore_ascii_case(&exe.to_string_lossy())),
                    "{image:?} vs {exe:?}"
                );
            }
            other => panic!("expected a Windows peer, got {other:?}"),
        }
        assert!(
            verify_client(&server, connected_at, "S-1-5-21-0-0-0-1001").is_err(),
            "another user"
        );
    }

    #[tokio::test]
    async fn a_client_process_created_after_the_connect_is_refused() {
        let endpoint = format!(r"\\.\pipe\graphshell-reuse-check-{}", uuid::Uuid::new_v4());
        let user = peer_facts::current_user_sid().unwrap();
        let server = create_pipe_instance(&endpoint, &user, true).unwrap();
        let _client = ClientOptions::new().open(&endpoint).unwrap();
        server.connect().await.unwrap();
        // This process was created long after 1601: as though the client
        // that connected then had exited and its id had been reused.
        let error = verify_client(&server, 0, &user).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn the_door_pipe_carries_a_protected_owner_only_access_list() {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
            SE_KERNEL_OBJECT,
        };
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

        let endpoint = format!(r"\\.\pipe\graphshell-acl-check-{}", uuid::Uuid::new_v4());
        let listener = LocalListener::bind(&endpoint, "test").await.unwrap();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: valid out-pointers; the descriptor is freed below.
        let status = unsafe {
            GetSecurityInfo(
                listener.listener.as_raw_handle() as _,
                SE_KERNEL_OBJECT,
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut descriptor,
            )
        };
        assert_eq!(status, 0);
        let mut text = std::ptr::null_mut();
        // SAFETY: a valid descriptor; the string is freed below.
        let ok = unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SDDL_REVISION_1,
                DACL_SECURITY_INFORMATION,
                &mut text,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(ok, 0);
        // SAFETY: a NUL-terminated wide string allocated by the system.
        let sddl = unsafe {
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            LocalFree(descriptor);
            sddl
        };
        let user = peer_facts::current_user_sid().unwrap();
        assert!(sddl.starts_with("D:P"), "protected: {sddl}");
        assert!(sddl.contains(&user), "this user: {sddl}");
        for other in [";WD)", ";AN)", ";AC)", ";BU)"] {
            assert!(!sddl.contains(other), "no {other} entry: {sddl}");
        }
    }

    #[tokio::test]
    async fn a_bound_local_endpoint_is_immediately_connectable() {
        let endpoint = format!(r"\\.\pipe\graphshell-ready-{}", uuid::Uuid::new_v4());
        let listener = LocalListener::bind(&endpoint, "test")
            .await
            .expect("bind local endpoint");

        let client = ClientOptions::new()
            .open(&endpoint)
            .expect("bound endpoint accepts connections immediately");
        listener.listener.connect().await.expect("accept client");

        drop((client, listener));
    }

    #[tokio::test]
    async fn a_live_named_pipe_cannot_be_bound_twice() {
        let endpoint = format!(r"\\.\pipe\graphshell-conflict-{}", uuid::Uuid::new_v4());
        let listener = LocalListener::bind(&endpoint, "test")
            .await
            .expect("bind initial local endpoint");

        let second = LocalListener::bind(&endpoint, "test").await;

        assert!(second.is_err(), "live pipe instance must not be replaced");
        drop(listener);
    }
}
