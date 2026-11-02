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
        self.serve_with_peer(move |stream, _peer| handle(stream)).await
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

#[cfg(feature = "door-serve")]
#[cfg(windows)]
async fn serve_platform<H, F>(listener: LocalListener, handle: H) -> Result<(), std::io::Error>
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
fn create_pipe_instance(
    endpoint: &str,
    user: &str,
    first: bool,
) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, std::io::Error> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    let sddl: Vec<u16> = pipe_sddl(user).encode_utf16().chain(Some(0)).collect();
    let mut descriptor = std::ptr::null_mut();
    // SAFETY: a NUL-terminated SDDL string; the descriptor is freed below.
    if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut descriptor, std::ptr::null_mut()) } == 0 {
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
            .create_with_security_attributes_raw(endpoint, (&mut attributes as *mut SECURITY_ATTRIBUTES).cast())
    };
    // SAFETY: allocated by the system above and no longer referenced.
    unsafe { LocalFree(descriptor) };
    created
}

#[cfg(feature = "door-serve")]
#[cfg(not(windows))]
async fn serve_platform<H, F>(listener: LocalListener, handle: H) -> Result<(), std::io::Error>
where
    H: Fn(Box<dyn LocalStream>, Option<peer_facts::Connected>) -> F + Clone + Send + 'static,
    F: Future<Output = ()> + Send + 'static,
{
    use std::os::fd::AsRawFd;

    let LocalListener { listener, .. } = listener;
    loop {
        let (connection, _) = listener.accept().await?;
        // The socket's mode already limits it to this user; record who.
        let peer = peer_facts::Connected::unix(connection.as_raw_fd()).ok();
        let handle = handle.clone();
        armillary::tasks::spawn_tracked(async move {
            handle(Box::new(connection), peer).await;
        });
    }
}

/// Remove a stale socket owned by this effective user, preserving every
/// other object at the endpoint path.
///
/// A second resident host must fail loudly rather than unlink the socket the
/// first one is serving: the first would keep running, answering nobody. The
/// device/inode recheck catches path replacement during the probe. The final
/// path-based unlink still has a small same-directory race between that check
/// and unlink; callers should place endpoints in a runtime directory whose
/// parent cannot be modified by other users.
#[cfg(feature = "door-serve")]
#[cfg(unix)]
pub async fn prepare_unix_endpoint(endpoint: &std::path::Path) -> Result<(), std::io::Error> {
    // SAFETY: geteuid has no pointer arguments or other preconditions.
    let effective_uid = unsafe { libc::geteuid() };
    prepare_with_probe(endpoint, effective_uid, || async {
        tokio::net::UnixStream::connect(endpoint).await.map(drop)
    })
    .await
}

#[cfg(feature = "door-serve")]
#[cfg(unix)]
async fn prepare_with_probe<P, ProbeFuture>(
    endpoint: &std::path::Path,
    effective_uid: u32,
    probe: P,
) -> Result<(), std::io::Error>
where
    P: FnOnce() -> ProbeFuture,
    ProbeFuture: Future<Output = Result<(), std::io::Error>>,
{
    use std::os::unix::fs::MetadataExt;

    let Some(before) = endpoint_metadata(endpoint)? else {
        return Ok(());
    };
    validate_endpoint_owner(&before, effective_uid)?;

    match probe().await {
        Ok(()) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                "another resident host owns this endpoint",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // A socket can disappear after the first lstat but before or
            // during connect. Treat only an actually absent path as success.
            if endpoint_metadata(endpoint)?.is_none() {
                return Ok(());
            }
            return Err(error);
        }
        Err(error) => return Err(error),
    }

    let Some(after) = endpoint_metadata(endpoint)? else {
        return Ok(());
    };
    if before.dev() != after.dev() || before.ino() != after.ino() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "endpoint path changed while checking for a stale socket",
        ));
    }
    validate_endpoint_owner(&after, effective_uid)?;

    match std::fs::remove_file(endpoint) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "door-serve")]
#[cfg(unix)]
fn endpoint_metadata(
    endpoint: &std::path::Path,
) -> Result<Option<std::fs::Metadata>, std::io::Error> {
    match std::fs::symlink_metadata(endpoint) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

#[cfg(feature = "door-serve")]
#[cfg(unix)]
fn validate_endpoint_owner(
    metadata: &std::fs::Metadata,
    effective_uid: u32,
) -> Result<(), std::io::Error> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    if !metadata.file_type().is_socket() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "endpoint path exists and is not a Unix socket",
        ));
    }
    if metadata.uid() != effective_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "endpoint socket is owned by another user",
        ));
    }
    Ok(())
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

    let refused = |why: &str| std::io::Error::new(std::io::ErrorKind::PermissionDenied, format!("the client {why}"));
    let connected = peer_facts::Connected::pipe_client(connection.as_raw_handle() as _, connected_at)?;
    let token = connected.token().ok_or_else(|| refused("token was not read"))?;
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
                assert!(image.as_deref().is_some_and(|image| image.eq_ignore_ascii_case(&exe.to_string_lossy())), "{image:?} vs {exe:?}");
            }
            other => panic!("expected a Windows peer, got {other:?}"),
        }
        assert!(verify_client(&server, connected_at, "S-1-5-21-0-0-0-1001").is_err(), "another user");
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
        use windows_sys::Win32::Security::Authorization::{ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT};
        use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

        let endpoint = format!(r"\\.\pipe\graphshell-acl-check-{}", uuid::Uuid::new_v4());
        let listener = LocalListener::bind(&endpoint, "test").await.unwrap();
        let mut descriptor = std::ptr::null_mut();
        // SAFETY: valid out-pointers; the descriptor is freed below.
        let status = unsafe {
            GetSecurityInfo(listener.listener.as_raw_handle() as _, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), &mut descriptor)
        };
        assert_eq!(status, 0);
        let mut text = std::ptr::null_mut();
        // SAFETY: a valid descriptor; the string is freed below.
        let ok = unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &mut text, std::ptr::null_mut()) };
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

#[cfg(feature = "door-serve")]
#[cfg(all(test, unix))]
mod unix_tests {
    use std::os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt, symlink},
        net::UnixListener,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn scratch(label: &str) -> std::path::PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::path::PathBuf::from("/tmp").join(format!("ge-{}-{label}-{nonce}", std::process::id()))
    }

    fn current_uid() -> u32 {
        // SAFETY: geteuid has no pointer arguments or other preconditions.
        unsafe { libc::geteuid() }
    }

    fn stale_socket(path: &std::path::Path) {
        drop(UnixListener::bind(path).expect("bind stale socket"));
    }

    #[tokio::test]
    async fn an_initially_missing_endpoint_is_safe() {
        let directory = scratch("missing");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");

        prepare_unix_endpoint(&endpoint)
            .await
            .expect("missing endpoint needs no cleanup");

        assert!(!endpoint.exists());
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn each_connection_arrives_with_what_the_os_says_about_its_peer() {
        let directory = scratch("peer");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        let listener = LocalListener::bind(endpoint.to_str().expect("endpoint path"), "test")
            .await
            .expect("bind local endpoint");
        let (seen, mut received) = tokio::sync::mpsc::unbounded_channel();
        let server = tokio::spawn(listener.serve_with_peer(move |_stream, peer| {
            let seen = seen.clone();
            async move {
                let _ = seen.send(peer);
            }
        }));
        let _client = tokio::net::UnixStream::connect(&endpoint).await.expect("connect");
        let peer = received.recv().await.expect("a connection");
        match peer.map(|connected| connected.peer) {
            Some(peer_facts::Peer::Unix { uid, pid, .. }) => {
                assert_eq!(uid, peer_facts::effective_uid());
                if let Some(pid) = pid {
                    assert_eq!(pid as u32, std::process::id());
                }
            }
            other => panic!("expected a Unix peer, got {other:?}"),
        }
        server.abort();
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn a_bound_listener_is_immediately_connectable_and_owner_only() {
        let directory = scratch("bound");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");

        let listener = LocalListener::bind(endpoint.to_str().expect("endpoint path"), "test")
            .await
            .expect("bind local endpoint");
        let client = tokio::net::UnixStream::connect(&endpoint)
            .await
            .expect("bound endpoint accepts connections immediately");
        let (server, _) = listener.listener.accept().await.expect("accept client");
        assert_eq!(
            std::fs::metadata(&endpoint)
                .expect("endpoint metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop((client, server, listener));
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn bind_error_preserves_a_live_endpoint_and_its_security() {
        let directory = scratch("bind-live");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        let listener = tokio::net::UnixListener::bind(&endpoint).expect("bind live socket");
        std::fs::set_permissions(&endpoint, std::fs::Permissions::from_mode(0o600))
            .expect("restrict live socket");
        let before = std::fs::metadata(&endpoint).expect("live endpoint metadata");

        let error =
            match LocalListener::bind(endpoint.to_str().expect("endpoint path"), "test").await {
                Err(error) => error,
                Ok(_) => panic!("live endpoint must not be replaced"),
            };

        let after = std::fs::metadata(&endpoint).expect("live endpoint remains");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert_eq!(before.dev(), after.dev());
        assert_eq!(before.ino(), after.ino());
        assert_eq!(after.permissions().mode() & 0o777, 0o600);
        let _client = tokio::net::UnixStream::connect(&endpoint)
            .await
            .expect("original listener still serves endpoint");
        let _accepted = listener.accept().await.expect("accept original connection");
        drop(listener);
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn a_live_socket_is_preserved() {
        let directory = scratch("live");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        let _listener = tokio::net::UnixListener::bind(&endpoint).expect("bind live socket");

        let error = prepare_unix_endpoint(&endpoint)
            .await
            .expect_err("live socket must remain owned by its listener");

        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
        assert!(
            std::fs::symlink_metadata(&endpoint)
                .expect("live socket remains")
                .file_type()
                .is_socket()
        );
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn a_stale_same_user_socket_is_removed() {
        let directory = scratch("stale");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        stale_socket(&endpoint);

        prepare_unix_endpoint(&endpoint)
            .await
            .expect("stale socket is safe to remove");

        assert!(!endpoint.exists());
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn regular_files_and_symlinks_are_preserved() {
        let directory = scratch("objects");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let regular = directory.join("regular.sock");
        std::fs::write(&regular, b"keep").expect("write regular file");
        let symlink_path = directory.join("symlink.sock");
        symlink(&regular, &symlink_path).expect("create symlink");

        for path in [&regular, &symlink_path] {
            let error = prepare_unix_endpoint(path)
                .await
                .expect_err("non-socket path must be preserved");
            assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        }

        assert_eq!(
            std::fs::read(&regular).expect("regular file remains"),
            b"keep"
        );
        assert!(
            std::fs::symlink_metadata(&symlink_path)
                .expect("symlink remains")
                .file_type()
                .is_symlink()
        );
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn a_socket_with_another_expected_owner_is_preserved() {
        let directory = scratch("owner");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        stale_socket(&endpoint);
        let uid = current_uid();
        let other_uid = if uid == u32::MAX { uid - 1 } else { uid + 1 };

        let error = prepare_with_probe(&endpoint, other_uid, || async { Ok(()) })
            .await
            .expect_err("different owner must be preserved");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            std::fs::symlink_metadata(&endpoint)
                .expect("socket remains")
                .file_type()
                .is_socket()
        );
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn replacement_file_and_socket_are_preserved_after_probe() {
        for replacement in ["file", "socket"] {
            let directory = scratch(&format!("replacement-{replacement}"));
            std::fs::create_dir_all(&directory).expect("create scratch");
            let endpoint = directory.join("resident.sock");
            stale_socket(&endpoint);
            let probe_path = endpoint.clone();
            let retained_old_socket = directory.join("old.sock");

            let error = prepare_with_probe(&endpoint, current_uid(), || async move {
                // Keep the old inode linked so the replacement cannot reuse it.
                std::fs::rename(&probe_path, retained_old_socket)
                    .expect("move original socket aside");
                if replacement == "file" {
                    std::fs::write(&probe_path, b"replacement").expect("replace with file");
                } else {
                    let _replacement_listener =
                        UnixListener::bind(&probe_path).expect("replace with socket");
                }
                Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "simulated stale probe",
                ))
            })
            .await
            .expect_err("changed endpoint identity must be preserved");

            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
            if replacement == "file" {
                assert_eq!(
                    std::fs::read(&endpoint).expect("replacement file remains"),
                    b"replacement"
                );
            } else {
                assert!(
                    std::fs::symlink_metadata(&endpoint)
                        .expect("replacement socket remains")
                        .file_type()
                        .is_socket()
                );
            }
            std::fs::remove_dir_all(directory).expect("remove scratch");
        }
    }

    #[tokio::test]
    async fn disappearance_during_probe_is_safe() {
        let directory = scratch("disappeared");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        stale_socket(&endpoint);
        let probe_path = endpoint.clone();

        prepare_with_probe(&endpoint, current_uid(), || async move {
            std::fs::remove_file(&probe_path).expect("remove socket during probe");
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "simulated disappeared endpoint",
            ))
        })
        .await
        .expect("an absent path needs no cleanup");

        assert!(!endpoint.exists());
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn a_refused_probe_followed_by_disappearance_is_safe() {
        let directory = scratch("refused-disappeared");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        stale_socket(&endpoint);
        let probe_path = endpoint.clone();

        prepare_with_probe(&endpoint, current_uid(), || async move {
            std::fs::remove_file(&probe_path).expect("remove socket during probe");
            Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                "simulated refused probe",
            ))
        })
        .await
        .expect("an absent path needs no cleanup");

        assert!(!endpoint.exists());
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }

    #[tokio::test]
    async fn unknown_probe_errors_preserve_the_socket() {
        let directory = scratch("probe-error");
        std::fs::create_dir_all(&directory).expect("create scratch");
        let endpoint = directory.join("resident.sock");
        stale_socket(&endpoint);

        let error = prepare_with_probe(&endpoint, current_uid(), || async {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "simulated unknown probe error",
            ))
        })
        .await
        .expect_err("unknown probe failures must be preserved");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(endpoint.exists());
        std::fs::remove_dir_all(directory).expect("remove scratch");
    }
}
