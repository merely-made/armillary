// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Unix listener service and stale-socket ownership checks.

use std::future::Future;

use ostiary::local_endpoint::LocalStream;

use super::LocalListener;

#[cfg(feature = "door-serve")]
#[cfg(not(windows))]
pub(super) async fn serve_platform<H, F>(
    listener: LocalListener,
    handle: H,
) -> Result<(), std::io::Error>
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
        let _client = tokio::net::UnixStream::connect(&endpoint)
            .await
            .expect("connect");
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
