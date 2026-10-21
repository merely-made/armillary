// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

//! A growable, reusing worker-thread pool.
//!
//! Why this exists: some actors are long-lived (a content actor lives as long as
//! its surface) and `thread::spawn`-per-actor leaks one OS thread's worth of
//! per-thread state on every spawn — notably a layout engine's *leaked* thread-local
//! sharing cache, which is never reclaimed. Opening / closing / respawning surfaces
//! would then leak unboundedly with churn.
//!
//! A pooled worker **loops**: it runs one job (an actor's whole lifetime), and when
//! that job returns (the actor's command channel closed) it waits for the next job
//! rather than dying. Workers are reused across sequential jobs, bounding churn
//! in leaked per-thread state. The pool grows when queued jobs exceed the capacity
//! of waiting workers and workers still starting.
//!
//! The queue and its capacity accounting share one mutex. Each waiting or starting
//! worker covers at most one queued job, including submissions made before a
//! notified worker can acquire the lock. Dropping the last public pool handle
//! wakes waiting workers: admitted jobs finish, then workers exit. Drop does not
//! wait for jobs or join threads; a job that never returns keeps its worker alive.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

/// A unit of work to run on a pooled worker. For an actor this is its whole run
/// loop, so it occupies a worker until the actor ends.
type Job = Box<dyn FnOnce() + Send + 'static>;

struct State {
    queue: VecDeque<Job>,
    /// Workers currently waiting for a job, including notified workers that have
    /// not yet reacquired the mutex. Queued jobs reserve this capacity.
    idle: usize,
    /// Spawned workers that have not acquired the state mutex for the first time.
    starting: usize,
    closing: bool,
}

struct Inner {
    state: Mutex<State>,
    available: Condvar,
    /// Total workers spawned over the pool's lifetime, including replacements
    /// after a raw job panics. This is not a count of live or joined workers.
    workers: AtomicUsize,
}

// Workers retain only Inner. Keeping the public-handle lifetime separate lets
// the final handle close admission without relying on Arc strong-count races.
struct Owner {
    inner: Arc<Inner>,
}

impl Drop for Owner {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        state.closing = true;
        drop(state);
        self.inner.available.notify_all();
    }
}

/// A growable, reusing worker-thread pool. Cheap to clone (a shared handle).
///
/// The last handle's drop is nonblocking: accepted jobs keep running, then all
/// workers retire. A clone held by a job also keeps the pool open. Use an actor's
/// completion handle when its cleanup must be observed before proceeding.
#[derive(Clone)]
pub struct Pool {
    owner: Arc<Owner>,
}

impl Default for Pool {
    fn default() -> Self {
        Self::new()
    }
}

impl Pool {
    fn inner(&self) -> &Arc<Inner> {
        &self.owner.inner
    }

    /// An empty pool. Workers are spawned lazily as queued demand exceeds waiting
    /// and starting capacity.
    pub fn new() -> Self {
        Self {
            owner: Arc::new(Owner {
                inner: Arc::new(Inner {
                    state: Mutex::new(State {
                        queue: VecDeque::new(),
                        idle: 0,
                        starting: 0,
                        closing: false,
                    }),
                    available: Condvar::new(),
                    workers: AtomicUsize::new(0),
                }),
            }),
        }
    }

    /// Run `job` on a pooled worker, growing the pool when no unreserved waiting
    /// or starting worker is available. A returning worker is reused for the next
    /// job. Dropping the pool does not cancel accepted jobs.
    pub fn submit(&self, job: Job) {
        let mut state = self.inner().state.lock().unwrap();
        self.submit_locked(&mut state, job);
        drop(state);
        self.inner().available.notify_one();
    }

    fn submit_locked(&self, state: &mut State, job: Job) {
        state.queue.push_back(job);
        // A notification does not remove an idle worker from the count until it
        // reacquires this lock. The queue reserves that capacity in the meantime.
        if state.queue.len() > state.idle + state.starting {
            state.starting += 1;
            self.spawn_worker();
        }
    }

    /// Total worker threads spawned over this pool's lifetime. Sequential jobs
    /// reuse idle workers; raw job panics may require replacement workers. This
    /// counter does not report current liveness or prove worker retirement.
    pub fn workers(&self) -> usize {
        self.inner().workers.load(Ordering::SeqCst)
    }

    fn spawn_worker(&self) {
        self.inner().workers.fetch_add(1, Ordering::SeqCst);
        let inner = Arc::clone(self.inner());
        thread::spawn(move || {
            let mut state = inner.state.lock().unwrap();
            state.starting -= 1;
            loop {
                if let Some(job) = state.queue.pop_front() {
                    drop(state);
                    job(); // the actor's whole lifetime, outside the state lock
                    state = inner.state.lock().unwrap();
                } else if state.closing {
                    return;
                } else {
                    state.idle += 1;
                    state = inner.available.wait(state).unwrap();
                    state.idle -= 1;
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;

    const WAIT: Duration = Duration::from_secs(5);

    #[derive(Default)]
    struct Release(Arc<(Mutex<bool>, Condvar)>);

    impl Release {
        fn job(&self, id: usize, started: mpsc::Sender<usize>) -> Job {
            let gate = Arc::clone(&self.0);
            Box::new(move || {
                started.send(id).unwrap();
                let (lock, changed) = &*gate;
                drop(
                    changed
                        .wait_while(lock.lock().unwrap(), |open| !*open)
                        .unwrap(),
                );
            })
        }
    }

    impl Drop for Release {
        fn drop(&mut self) {
            *self.0.0.lock().unwrap() = true;
            self.0.1.notify_all();
        }
    }

    fn wait_until_idle(pool: &Pool, count: usize) {
        let deadline = Instant::now() + WAIT;
        while pool.inner().state.lock().unwrap().idle != count {
            assert!(Instant::now() < deadline, "workers did not become idle");
            thread::yield_now();
        }
    }

    fn warm(pool: &Pool) {
        let (done, completed) = mpsc::channel();
        pool.submit(Box::new(move || done.send(()).unwrap()));
        completed.recv_timeout(WAIT).unwrap();
        wait_until_idle(pool, 1);
    }

    #[test]
    fn queued_jobs_do_not_share_one_idle_reservation() {
        let pool = Pool::new();
        warm(&pool);
        let release = Release::default();
        let (started, observed) = mpsc::channel();
        {
            // Schedule two submissions before the awakened worker can reacquire
            // the queue lock. Both use the production admission path, with a real
            // idle worker; no worker count or idle state is fabricated.
            let mut state = pool.inner().state.lock().unwrap();
            pool.submit_locked(&mut state, release.job(0, started.clone()));
            pool.submit_locked(&mut state, release.job(1, started));
        }
        pool.inner().available.notify_all();
        let first = observed.recv_timeout(WAIT);
        let second = observed.recv_timeout(WAIT);
        // Release all admitted work even when the regression assertion fails.
        drop(release);
        assert_ne!(
            first.unwrap(),
            second.expect("second job stranded behind a busy worker")
        );
        assert_eq!(pool.workers(), 2);
    }

    #[test]
    fn runs_all_jobs_and_grows_for_concurrency() {
        let pool = Pool::new();
        let release = Release::default();
        let (started, observed) = mpsc::channel();
        for id in 0..5 {
            pool.submit(release.job(id, started.clone()));
        }
        let results: Vec<_> = (0..5).map(|_| observed.recv_timeout(WAIT)).collect();
        drop(release);
        let mut ids: Vec<_> = results.into_iter().map(Result::unwrap).collect();
        ids.sort();
        assert_eq!(ids, vec![0, 1, 2, 3, 4]);
        assert_eq!(pool.workers(), 5);
    }

    #[test]
    fn reuses_a_worker_for_a_sequential_job() {
        let pool = Pool::new();
        warm(&pool);
        let (done, completed) = mpsc::channel();
        pool.submit(Box::new(move || done.send(()).unwrap()));
        completed.recv_timeout(WAIT).unwrap();
        assert_eq!(pool.workers(), 1, "the idle worker was reused");
    }

    #[test]
    fn last_drop_wakes_every_idle_worker_and_releases_shared_state() {
        let pool = Pool::new();
        let release = Release::default();
        let (started, observed) = mpsc::channel();
        for id in 0..8 {
            pool.submit(release.job(id, started.clone()));
        }
        let results: Vec<_> = (0..8).map(|_| observed.recv_timeout(WAIT)).collect();
        drop(release);
        for result in results {
            result.unwrap();
        }
        wait_until_idle(&pool, 8);
        let retained = Arc::downgrade(pool.inner());
        drop(pool);
        let deadline = Instant::now() + WAIT;
        while retained.upgrade().is_some() {
            assert!(
                Instant::now() < deadline,
                "worker retained shared pool state"
            );
            thread::yield_now();
        }
    }
}
