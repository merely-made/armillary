// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::sync::{Arc, mpsc};
use std::time::Duration;

#[test]
fn pooled_join_waits_for_actor_cleanup() {
    let pool = armillary::Pool::new();
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (handle, _) =
        armillary::spawn_on::<(), (), _>(&pool, Arc::new(|| {}), move |commands, _| {
            while commands.recv().is_ok() {}
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
        });
    let (joined_tx, joined_rx) = mpsc::channel();
    let joiner = std::thread::spawn(move || {
        let _ = handle.join();
        joined_tx.send(()).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let premature = joined_rx.recv_timeout(Duration::from_millis(100)).is_ok();
    release_tx.send(()).unwrap();
    joiner.join().unwrap();
    assert!(
        !premature,
        "join returned while actor cleanup was still blocked"
    );
}

#[test]
fn panic_is_reported_by_dedicated_and_pooled_actors() {
    let (actor, _) =
        armillary::spawn::<(), (), _>(Arc::new(|| {}), |_, _| panic!("synthetic actor failure"));
    assert_eq!(actor.join(), Err(armillary::ActorError::Panicked));
    let pool = armillary::Pool::new();
    let (actor, _) = armillary::spawn_on::<(), (), _>(&pool, Arc::new(|| {}), |_, _| {
        panic!("synthetic pooled failure")
    });
    assert_eq!(actor.join(), Err(armillary::ActorError::Panicked));
    let (actor, _) = armillary::spawn_on::<(), (), _>(&pool, Arc::new(|| {}), |_, _| {});
    actor.join().unwrap();
}

#[tokio::test]
async fn ordered_close_releases_captures_and_retains_every_failure() {
    use armillary::lifecycle::{CloseAction, CloseFuture, close_all};
    let held = Arc::new(());
    let first = Arc::clone(&held);
    let later = Arc::clone(&held);
    let report = close_all(vec![
        (
            "first",
            Box::new(move || {
                Box::pin(async move {
                    drop(first);
                    Err("first refusal".into())
                }) as CloseFuture<'static>
            }) as CloseAction<'static>,
        ),
        (
            "later",
            Box::new(move || {
                Box::pin(async move {
                    assert_eq!(
                        Arc::strong_count(&later),
                        2,
                        "first capture released before second close"
                    );
                    Err("second refusal".into())
                }) as CloseFuture<'static>
            }) as CloseAction<'static>,
        ),
    ])
    .await;
    assert_eq!(report.failure("first"), Some("first refusal"));
    assert_eq!(report.failure("later"), Some("second refusal"));
    assert_eq!(Arc::strong_count(&held), 1);
}
