// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! Ownership of a resident run, its graceful work stop, and its task fence.
//!
//! Product code assembles services inside [`Resident::run`], including its
//! refresh and lock handling, and restores borrowed resources before `finish`.

use armillary::tasks::{ResidentTasks, TaskReport};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

/// A named run failure and any later failure while stopping product work.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunFailure {
    pub source: &'static str,
    pub error: String,
    pub additional: Vec<RunFailure>,
}
impl RunFailure {
    pub fn new(source: &'static str, error: impl Into<String>) -> Self {
        Self {
            source,
            error: error.into(),
            additional: Vec::new(),
        }
    }
}

impl std::fmt::Display for RunFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.source, self.error)?;
        for failure in &self.additional {
            write!(f, "; {failure}")?;
        }
        Ok(())
    }
}
impl std::error::Error for RunFailure {}

/// A service ending is unexpected, including an ordinary successful return.
pub struct Service<'a> {
    name: &'static str,
    future: Pin<Box<dyn Future<Output = Result<(), String>> + 'a>>,
}
impl<'a> Service<'a> {
    pub fn new(name: &'static str, future: impl Future<Output = Result<(), String>> + 'a) -> Self {
        Self {
            name,
            future: Box::pin(future),
        }
    }
}

/// Marks a selected product maintenance action until its awaited work finishes.
/// Idle event watchers do not hold a guard, so they never delay shutdown.
#[derive(Clone, Default)]
pub struct MaintenanceActivity(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl MaintenanceActivity {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn begin(&self) -> MaintenanceGuard {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        MaintenanceGuard(self.0.clone())
    }
    fn active(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst) != 0
    }
}
/// Held around the complete selected maintenance action, including its awaits.
pub struct MaintenanceGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl Drop for MaintenanceGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Run services and the product control loop until one ends. Then request
/// graceful work stop and wait for it, without polling a completed future again.
/// The control future owns product-specific refresh, lock and stop handling;
/// an `Ok` return means a requested stop. `works` is absent when disabled.
/// Futures may borrow product state and need not be `Send`.
pub async fn supervise<'a, C, W>(
    services: Vec<Service<'a>>,
    control: C,
    works: Option<W>,
    stop_work: impl FnOnce(),
) -> Result<(), RunFailure>
where
    C: Future<Output = Result<(), String>>,
    W: Future<Output = Result<(), String>>,
{
    supervise_with_maintenance(
        services,
        control,
        works,
        std::future::pending(),
        MaintenanceActivity::new(),
        stop_work,
    )
    .await
}

/// Like `supervise`, also polling product maintenance while work drains.
/// Once maintenance completes it is not polled again.
pub async fn supervise_with_maintenance<'a, C, W, M>(
    mut services: Vec<Service<'a>>,
    control: C,
    works: Option<W>,
    maintenance: M,
    activity: MaintenanceActivity,
    stop_work: impl FnOnce(),
) -> Result<(), RunFailure>
where
    C: Future<Output = Result<(), String>>,
    W: Future<Output = Result<(), String>>,
    M: Future<Output = ()>,
{
    let mut maintenance = Some(Box::pin(maintenance));
    let mut control = Box::pin(control);
    let mut works = works.map(Box::pin);
    enum End {
        Control(Result<(), String>),
        Service(&'static str, Result<(), String>),
        Works(Result<(), String>),
    }
    let ended = poll_fn(|cx| {
        // Once selected, a product action has the same atomicity as a branch
        // body in the original select loop: finish it before observing exits.
        if activity.active() {
            if let Some(active) = maintenance.as_mut() {
                if active.as_mut().poll(cx).is_ready() {
                    maintenance = None;
                }
            }
            if activity.active() {
                return Poll::Pending;
            }
        }
        if let Poll::Ready(result) = control.as_mut().poll(cx) {
            return Poll::Ready(End::Control(result));
        }
        if let Some(work) = works.as_mut() {
            if let Poll::Ready(result) = work.as_mut().poll(cx) {
                return Poll::Ready(End::Works(result));
            }
        }
        for service in &mut services {
            if let Poll::Ready(result) = service.future.as_mut().poll(cx) {
                return Poll::Ready(End::Service(service.name, result));
            }
        }
        if let Some(active) = maintenance.as_mut() {
            if active.as_mut().poll(cx).is_ready() {
                maintenance = None;
            }
        }
        Poll::Pending
    })
    .await;
    let (mut outcome, work_ended) = match ended {
        End::Control(result) => (
            result.map_err(|error| RunFailure::new("control", error)),
            false,
        ),
        End::Service(name, result) => (
            Err(RunFailure::new(
                name,
                result
                    .err()
                    .unwrap_or_else(|| "service ended unexpectedly".into()),
            )),
            false,
        ),
        End::Works(result) => (
            Err(RunFailure::new(
                "works",
                result
                    .err()
                    .unwrap_or_else(|| "works ended unexpectedly".into()),
            )),
            true,
        ),
    };
    if !work_ended {
        if let Some(work) = works {
            stop_work();
            let mut work = work;
            let result = poll_fn(|cx| {
                if activity.active() {
                    if let Some(active) = maintenance.as_mut() {
                        if active.as_mut().poll(cx).is_ready() {
                            maintenance = None;
                        }
                    }
                    if activity.active() {
                        return Poll::Pending;
                    }
                }
                if let Poll::Ready(result) = work.as_mut().poll(cx) {
                    return Poll::Ready(result);
                }
                if let Some(active) = maintenance.as_mut() {
                    if active.as_mut().poll(cx).is_ready() {
                        maintenance = None;
                    }
                }
                Poll::Pending
            })
            .await;
            if let Err(error) = result {
                let failure = RunFailure::new("works", error);
                match &mut outcome {
                    Ok(()) => outcome = Err(failure),
                    Err(primary) => primary.additional.push(failure),
                }
            }
        }
    }
    outcome
}

/// Owns the tracked task scope for one application run.
pub struct Resident {
    tasks: ResidentTasks,
}
impl Default for Resident {
    fn default() -> Self {
        Self::new()
    }
}
impl Resident {
    pub fn new() -> Self {
        Self {
            tasks: ResidentTasks::new(),
        }
    }

    /// Retain a join handle when the caller may cancel the run future.
    pub fn drain_handle(&self) -> ResidentDrain {
        ResidentDrain(self.tasks.clone())
    }

    /// Run startup and services inside the task scope, then fence and join all
    /// tracked children. If cancelled, a background drain fences the scope;
    /// the caller remains responsible for product shutdown on cancellation.
    pub async fn run<F>(self, run: F) -> DrainedResident
    where
        F: Future<Output = Result<(), RunFailure>>,
    {
        let mut guard = DrainOnDrop(Some(self.tasks.clone()));
        let outcome = self.tasks.scope(run).await;
        let tasks = self.tasks.close_and_join().await;
        guard.0 = None;
        DrainedResident { outcome, tasks }
    }
}
/// Allows a cancelled run's owner to wait for all children before product close.
#[derive(Clone)]
pub struct ResidentDrain(ResidentTasks);
impl ResidentDrain {
    pub async fn close_and_join(&self) -> TaskReport {
        self.0.close_and_join().await
    }
}

struct DrainOnDrop(Option<ResidentTasks>);
impl Drop for DrainOnDrop {
    fn drop(&mut self) {
        if let Some(tasks) = self.0.take() {
            // Poll once here so admission is fenced before the cancelled run
            // returns control to its owner; joining can then finish in the runtime.
            let mut drain = Box::pin(async move {
                tasks.close_and_join().await;
            });
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            if drain.as_mut().poll(&mut cx).is_pending() {
                if let Ok(runtime) = tokio::runtime::Handle::try_current() {
                    runtime.spawn(drain);
                }
            }
        }
    }
}

/// Run and child results remain available even if product shutdown fails.
pub struct DrainedResident {
    pub outcome: Result<(), RunFailure>,
    pub tasks: TaskReport,
}
pub struct ResidentReport<E> {
    pub outcome: Result<(), RunFailure>,
    pub tasks: TaskReport,
    pub shutdown: Result<(), E>,
}
impl DrainedResident {
    /// Invoke product shutdown after the caller has restored borrowed resources.
    pub async fn finish<F, Fut, E>(self, shutdown: F) -> ResidentReport<E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        ResidentReport {
            outcome: self.outcome,
            tasks: self.tasks,
            shutdown: shutdown().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        cell::RefCell,
        future::pending,
        rc::Rc,
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
    };

    #[tokio::test]
    async fn first_exit_requests_work_stop_and_waits_before_closing_children() {
        let stopped = Arc::new(tokio::sync::Notify::new());
        let work_done = Arc::new(AtomicBool::new(false));
        let done = work_done.clone();
        let notification = stopped.clone();
        let resident = Resident::new();
        let drained = resident
            .run(async {
                armillary::tasks::spawn_tracked(pending());
                supervise(
                    vec![Service::new("broker", async { Ok(()) })],
                    pending(),
                    Some(async move {
                        notification.notified().await;
                        done.store(true, Ordering::SeqCst);
                        Ok(())
                    }),
                    move || stopped.notify_one(),
                )
                .await
            })
            .await;
        assert!(work_done.load(Ordering::SeqCst));
        assert_eq!(drained.tasks.cancelled, 1);
        assert_eq!(drained.outcome.as_ref().unwrap_err().source, "broker");
    }

    #[tokio::test]
    async fn shutdown_runs_after_children_and_keeps_all_failures() {
        let dropped = Arc::new(AtomicBool::new(false));
        struct Holder(Arc<AtomicBool>);
        impl Drop for Holder {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let child_flag = dropped.clone();
        let resident = Resident::new();
        let drained = resident
            .run(async move {
                armillary::tasks::spawn_tracked(async move {
                    let _holder = Holder(child_flag);
                    pending::<()>().await
                });
                tokio::task::yield_now().await;
                Err(RunFailure::new("listener", "failed"))
            })
            .await;
        let result = drained
            .finish(|| async {
                assert!(dropped.load(Ordering::SeqCst));
                Err::<(), _>("close failed".to_owned())
            })
            .await;
        assert_eq!(result.outcome.unwrap_err().source, "listener");
        assert_eq!(result.shutdown.unwrap_err(), "close failed");
    }

    #[tokio::test]
    async fn borrowed_non_send_futures_and_work_failure_are_supported() {
        let value = Rc::new(RefCell::new(false));
        let borrowed = &value;
        let result = supervise(
            vec![Service::new("broker", pending())],
            pending(),
            Some(async move {
                *borrowed.borrow_mut() = true;
                Err("lease failure".to_owned())
            }),
            || {},
        )
        .await;
        assert!(*value.borrow());
        assert_eq!(
            result.unwrap_err(),
            RunFailure::new("works", "lease failure")
        );
    }
    #[tokio::test]
    async fn failure_during_graceful_stop_is_retained_with_trigger() {
        let signal = Arc::new(tokio::sync::Notify::new());
        let waiting = signal.clone();
        let result = supervise(
            vec![Service::new("broker", async { Err("broken".into()) })],
            pending(),
            Some(async move {
                waiting.notified().await;
                Err("release failed".into())
            }),
            move || signal.notify_one(),
        )
        .await
        .unwrap_err();
        assert_eq!(result.source, "broker");
        assert_eq!(
            result.additional,
            vec![RunFailure::new("works", "release failed")]
        );
    }

    #[tokio::test]
    async fn cancellation_fences_task_admission_before_returning() {
        let resident = Resident::new();
        let tasks = resident.tasks.clone();
        let mut run = Box::pin(resident.run(pending()));
        tokio::select! { _ = &mut run => panic!("pending run ended"), _ = tokio::task::yield_now() => {} }
        drop(run);
        assert!(tasks.is_closed());
        assert!(!tasks.spawn(async {}));
        tasks.close_and_join().await;
    }
    #[tokio::test]
    async fn maintenance_continues_while_work_releases() {
        let stop = Arc::new(tokio::sync::Notify::new());
        let stopped = stop.clone();
        let advanced = Arc::new(tokio::sync::Notify::new());
        let advanced_work = advanced.clone();
        let result = supervise_with_maintenance(
            vec![Service::new("broker", async { Err("broken".into()) })],
            pending(),
            Some(async move {
                stopped.notified().await;
                advanced_work.notified().await;
                Ok(())
            }),
            async move {
                tokio::task::yield_now().await;
                advanced.notify_one();
            },
            MaintenanceActivity::new(),
            move || stop.notify_one(),
        )
        .await;
        assert_eq!(result.unwrap_err().source, "broker");
    }
    #[tokio::test]
    async fn started_maintenance_finishes_before_shutdown_after_listener_exit() {
        let activity = MaintenanceActivity::new();
        let mark = activity.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let released = Arc::new(tokio::sync::Notify::new());
        let finished = Arc::new(AtomicBool::new(false));
        let maintenance_started = started.clone();
        let maintenance_release = released.clone();
        let maintenance_done = finished.clone();
        let listener_started = started.clone();
        let run = Resident::new().run(async move {
            supervise_with_maintenance(
                vec![Service::new("listener", async move {
                    listener_started.notified().await;
                    Err("closed".into())
                })],
                pending(),
                None::<std::future::Pending<Result<(), String>>>,
                async move {
                    let _action = mark.begin();
                    maintenance_started.notify_one();
                    maintenance_release.notified().await;
                    maintenance_done.store(true, Ordering::SeqCst);
                },
                activity,
                || {},
            )
            .await
        });
        let release = async move {
            tokio::task::yield_now().await;
            released.notify_one();
        };
        let (drained, ()) = tokio::join!(run, release);
        let report = drained
            .finish(|| async {
                assert!(finished.load(Ordering::SeqCst));
                Ok::<_, ()>(())
            })
            .await;
        assert_eq!(report.outcome.unwrap_err().source, "listener");
    }

    #[tokio::test]
    async fn started_maintenance_finishes_when_works_end_during_drain() {
        let activity = MaintenanceActivity::new();
        let mark = activity.clone();
        let stop = Arc::new(tokio::sync::Notify::new());
        let stopped = stop.clone();
        let started = Arc::new(tokio::sync::Notify::new());
        let work_started = started.clone();
        let release = Arc::new(tokio::sync::Notify::new());
        let release_action = release.clone();
        let finished = Arc::new(AtomicBool::new(false));
        let action_done = finished.clone();
        let run = Resident::new().run(async move {
            supervise_with_maintenance(
                vec![Service::new("listener", async { Err("closed".into()) })],
                pending(),
                Some(async move {
                    stopped.notified().await;
                    work_started.notified().await;
                    Ok(())
                }),
                async move {
                    let _action = mark.begin();
                    started.notify_one();
                    release_action.notified().await;
                    action_done.store(true, Ordering::SeqCst);
                },
                activity,
                move || stop.notify_one(),
            )
            .await
        });
        let release = async move {
            tokio::task::yield_now().await;
            tokio::task::yield_now().await;
            release.notify_one();
        };
        let (drained, ()) = tokio::join!(run, release);
        drained
            .finish(|| async {
                assert!(finished.load(Ordering::SeqCst));
                Ok::<_, ()>(())
            })
            .await;
    }
}
