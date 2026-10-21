// Copyright 2026 Mark Alan Boykin
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
// SPDX-License-Identifier: MPL-2.0

use std::cell::RefCell;
use std::sync::{Arc, mpsc};
use std::time::Duration;

use armillary::Pool;

const WAIT: Duration = Duration::from_secs(5);

struct ExitProbe(mpsc::Sender<()>);

impl Drop for ExitProbe {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

thread_local! {
    // The notification comes from actual worker thread-local teardown, rather
    // than job completion or a drop on the submitting thread.
    static EXIT: RefCell<Option<ExitProbe>> = const { RefCell::new(None) };
}

fn install_probe(exited: mpsc::Sender<()>) {
    EXIT.with(|probe| {
        assert!(probe.borrow().is_none());
        *probe.borrow_mut() = Some(ExitProbe(exited));
    });
}

#[test]
fn workers_retire_after_the_last_pool_handle_drops() {
    let pool = Pool::new();
    let (exited, exit) = mpsc::channel();
    let (ready, started) = mpsc::channel();
    pool.submit(Box::new(move || {
        install_probe(exited);
        ready.send(()).unwrap();
    }));
    started.recv_timeout(WAIT).unwrap();
    drop(pool);
    exit.recv_timeout(WAIT).expect("pool worker did not retire");
}

#[test]
fn last_drop_is_nonblocking_and_admitted_actor_still_completes() {
    let pool = Pool::new();
    let (exited, exit) = mpsc::channel();
    let (ready, started) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (actor, updates) =
        armillary::spawn_on::<(), usize, _>(&pool, Arc::new(|| {}), move |commands, out| {
            install_probe(exited);
            ready.send(()).unwrap();
            while commands.recv().is_ok() {}
            released.recv().unwrap();
            out.emit(42);
        });
    started.recv_timeout(WAIT).unwrap();
    let (dropped, drop_done) = mpsc::channel();
    let dropper = std::thread::spawn(move || {
        drop(pool);
        dropped.send(()).unwrap();
    });
    let returned = drop_done.recv_timeout(WAIT);
    let retired_early = exit.try_recv().is_ok();
    // Unblock the actor even if a regression made pool drop wait for it.
    release.send(()).unwrap();
    actor.join().unwrap();
    dropper.join().unwrap();
    returned.expect("pool drop blocked on a running actor");
    assert!(!retired_early);
    assert_eq!(updates.into_iter().collect::<Vec<_>>(), vec![42]);
    exit.recv_timeout(WAIT).unwrap();
}

#[test]
fn clone_keeps_pool_open_and_last_handle_can_drop_inside_a_job() {
    let pool = Pool::new();
    let survivor = pool.clone();
    drop(pool);
    let last = survivor.clone();
    let (exited, exit) = mpsc::channel();
    let (done, completed) = mpsc::channel();
    let (release, released) = mpsc::channel();
    survivor.submit(Box::new(move || {
        install_probe(exited);
        released.recv().unwrap();
        drop(last);
        done.send(()).unwrap();
    }));
    drop(survivor);
    release.send(()).unwrap();
    completed.recv_timeout(WAIT).unwrap();
    exit.recv_timeout(WAIT).unwrap();
}

#[test]
fn all_admitted_jobs_run_even_if_the_pool_is_dropped_immediately() {
    let pool = Pool::new();
    let (done, completed) = mpsc::channel();
    for id in 0..32 {
        let done = done.clone();
        pool.submit(Box::new(move || done.send(id).unwrap()));
    }
    drop(pool);
    drop(done);
    let mut ids: Vec<_> = (0..32)
        .map(|_| completed.recv_timeout(WAIT).unwrap())
        .collect();
    ids.sort();
    assert_eq!(ids, (0..32).collect::<Vec<_>>());
}
