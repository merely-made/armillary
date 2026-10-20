// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

#![cfg(feature = "tokio")]
use armillary::tasks::{ResidentTasks, spawn_tracked, spawn_tracked_with_handle};
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn close_joins_nested_work_and_fences_admission() {
    let tasks = ResidentTasks::new();
    let held = Arc::new(());
    let outer = held.clone();
    let (ready, started) = tokio::sync::oneshot::channel();
    tasks
        .scope(async move {
            spawn_tracked(async move {
                let inner = outer.clone();
                spawn_tracked(async move {
                    let _held = inner;
                    std::future::pending::<()>().await;
                });
                let _held = outer;
                ready.send(()).unwrap();
                std::future::pending::<()>().await;
            });
        })
        .await;
    started.await.unwrap();
    let report = tasks.close_and_join().await;
    assert_eq!(report.joined(), 2);
    assert!(report.is_clean());
    assert_eq!(Arc::strong_count(&held), 1);
    assert!(!tasks.spawn(async { panic!("closed work must not execute") }));
    assert_eq!(tasks.close_and_join().await.rejected, 1);
}

#[tokio::test]
async fn reaped_panics_survive_until_report_and_drain_remains_reusable() {
    let tasks = ResidentTasks::new();
    let (ready, started) = tokio::sync::oneshot::channel();
    tasks.spawn(async {
        ready.send(()).unwrap();
        panic!("synthetic task failure")
    });
    started.await.unwrap();
    // Poll the completed task to force the next spawn's reap path.
    tokio::task::yield_now().await;
    tasks.spawn(async {});
    let report = tasks.cancel_and_join().await;
    assert_eq!(report.panicked, 1);
    assert!(!report.is_clean());
    assert!(!tasks.is_closed());
    assert!(tasks.spawn(async {}));
    assert!(tasks.close_and_join().await.is_clean());
}

#[tokio::test]
async fn closed_scope_rejects_awaited_work_with_a_closed_reply() {
    let tasks = ResidentTasks::new();
    tasks.close_and_join().await;
    let reply = tasks
        .scope(async { spawn_tracked_with_handle(async { 42 }) })
        .await;
    assert!(reply.await.is_err());
    assert_eq!(tasks.close_and_join().await.rejected, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn interrupted_close_preserves_task_ownership_and_outcome() {
    struct Held {
        entered: Option<tokio::sync::oneshot::Sender<()>>,
        release: std::sync::mpsc::Receiver<()>,
    }
    impl Drop for Held {
        fn drop(&mut self) {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(());
            }
            let _ = self.release.recv();
        }
    }
    let tasks = ResidentTasks::new();
    let (entered, dropping) = tokio::sync::oneshot::channel();
    let (release, wait) = std::sync::mpsc::channel();
    let held = Held {
        entered: Some(entered),
        release: wait,
    };
    let (ready, started) = tokio::sync::oneshot::channel();
    tasks.spawn(async move {
        let _held = held;
        ready.send(()).unwrap();
        std::future::pending::<()>().await;
    });
    started.await.unwrap();
    let closing = tasks.clone();
    let drain = tokio::spawn(async move { closing.close_and_join().await });
    dropping.await.unwrap();
    drain.abort();
    assert!(drain.await.unwrap_err().is_cancelled());
    assert!(!tasks.spawn(async {}));
    release.send(()).unwrap();
    let report = tasks.close_and_join().await;
    assert_eq!(report.cancelled, 1);
    assert_eq!(report.rejected, 1);
    assert!(tasks.is_empty());
}

#[tokio::test]
async fn terminal_close_cannot_erase_an_earlier_panic() {
    let tasks = ResidentTasks::new();
    let (ready, started) = tokio::sync::oneshot::channel();
    tasks.spawn(async {
        ready.send(()).unwrap();
        panic!("synthetic terminal failure")
    });
    started.await.unwrap();
    let first = tasks.close_and_join().await;
    assert_eq!(first.panicked, 1);
    assert_eq!(tasks.close_and_join().await, first);
    let (a, b) = tokio::join!(tasks.close_and_join(), tasks.close_and_join());
    assert_eq!(a, first);
    assert_eq!(b, first);
}
