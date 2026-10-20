// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Scoped async work. Draining is reusable; closing first refuses new work.
//! A cancelled drain future leaves task ownership and observed results in the scope.

use std::future::{Future, poll_fn};
use std::sync::{Arc, Mutex};
use tokio::task::{JoinError, JoinSet};

tokio::task_local! { static CURRENT: ResidentTasks; }

/// Actual joined outcomes, including tasks reaped before shutdown.
/// Open drains consume a report; terminal closes retain a cumulative report.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TaskReport {
    pub completed: usize,
    pub cancelled: usize,
    pub panicked: usize,
    pub rejected: usize,
}
impl TaskReport {
    pub fn joined(&self) -> usize {
        self.completed
            .saturating_add(self.cancelled)
            .saturating_add(self.panicked)
    }
    /// Cancellation was requested by the drain. Panics and rejected work remain failures.
    pub fn is_clean(&self) -> bool {
        self.panicked == 0 && self.rejected == 0
    }
    fn include(&mut self, other: Self) {
        self.completed = self.completed.saturating_add(other.completed);
        self.cancelled = self.cancelled.saturating_add(other.cancelled);
        self.panicked = self.panicked.saturating_add(other.panicked);
        self.rejected = self.rejected.saturating_add(other.rejected);
    }
    fn record(&mut self, result: Result<(), JoinError>) {
        let count = match result {
            Ok(()) => &mut self.completed,
            Err(error) if error.is_cancelled() => &mut self.cancelled,
            Err(_) => &mut self.panicked,
        };
        *count = count.saturating_add(1);
    }
}
struct State {
    tasks: JoinSet<()>,
    report: TaskReport,
    terminal_report: TaskReport,
    closed: bool,
}
impl Default for State {
    fn default() -> Self {
        Self {
            tasks: JoinSet::new(),
            report: TaskReport::default(),
            terminal_report: TaskReport::default(),
            closed: false,
        }
    }
}
#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    drain: tokio::sync::Mutex<()>,
}

/// Clones share admission, task ownership and unconsumed completion results.
#[derive(Clone, Default)]
pub struct ResidentTasks(Arc<Inner>);
impl ResidentTasks {
    pub fn new() -> Self {
        Self::default()
    }
    pub async fn scope<F: Future>(&self, future: F) -> F::Output {
        CURRENT.scope(self.clone(), future).await
    }
    /// Return false when terminal close has fenced admission. The future is dropped.
    pub fn spawn<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let mut state = self.0.state.lock().expect("task scope mutex poisoned");
        while let Some(result) = state.tasks.try_join_next() {
            state.report.record(result);
        }
        if state.closed {
            state.report.rejected = state.report.rejected.saturating_add(1);
            return false;
        }
        state.tasks.spawn(CURRENT.scope(self.clone(), future));
        true
    }
    pub fn len(&self) -> usize {
        self.0
            .state
            .lock()
            .expect("task scope mutex poisoned")
            .tasks
            .len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn is_closed(&self) -> bool {
        self.0
            .state
            .lock()
            .expect("task scope mutex poisoned")
            .closed
    }
    /// Fence concurrent admission, then cancel and join the admitted tasks.
    /// Repeated/concurrent terminal closes retain earlier terminal failures.
    pub async fn close_and_join(&self) -> TaskReport {
        self.0
            .state
            .lock()
            .expect("task scope mutex poisoned")
            .closed = true;
        self.cancel_and_join().await
    }
    /// Cancel and join current work without changing admission.
    /// Open scopes remain reusable; closed scopes retain their terminal report.
    /// Work submitted after an open empty drain belongs to the next drain.
    pub async fn cancel_and_join(&self) -> TaskReport {
        let _drain = self.0.drain.lock().await;
        loop {
            // Keep the JoinSet in the scope across await, so cancelling this future
            // cannot detach ownership or discard already observed outcomes.
            let next = poll_fn(|cx| {
                let mut state = self.0.state.lock().expect("task scope mutex poisoned");
                state.tasks.abort_all();
                match state.tasks.poll_join_next(cx) {
                    std::task::Poll::Ready(Some(result)) => {
                        state.report.record(result);
                        std::task::Poll::Ready(true)
                    }
                    std::task::Poll::Ready(None) => std::task::Poll::Ready(false),
                    std::task::Poll::Pending => std::task::Poll::Pending,
                }
            })
            .await;
            if !next {
                let mut state = self.0.state.lock().expect("task scope mutex poisoned");
                let report = std::mem::take(&mut state.report);
                if state.closed {
                    state.terminal_report.include(report);
                    return state.terminal_report;
                }
                return report;
            }
        }
    }
}
/// Track descendants inside a scope; outside a scope the caller chooses detached work.
pub fn spawn_tracked<F>(future: F) -> bool
where
    F: Future<Output = ()> + Send + 'static,
{
    match CURRENT.try_with(Clone::clone) {
        Ok(tasks) => tasks.spawn(future),
        Err(_) => {
            tokio::spawn(future);
            true
        }
    }
}
/// Rejection or cancellation closes the result channel; it never manufactures a result.
pub fn spawn_tracked_with_handle<F, T>(future: F) -> tokio::sync::oneshot::Receiver<T>
where
    F: Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let (send, receive) = tokio::sync::oneshot::channel();
    spawn_tracked(async move {
        let _ = send.send(future.await);
    });
    receive
}
