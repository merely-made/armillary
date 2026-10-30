// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

enum Command {
    Configure(u32),
    Invoke(u32),
    Retire,
}

fn admission(command: Command, _: bool) -> Admission<Command> {
    match command {
        Command::Configure(_) => Admission::Deferred("configuration", command),
        Command::Invoke(_) => Admission::Demand(command),
        Command::Retire => Admission::Withdraw,
    }
}

#[test]
fn configuration_is_coalesced_and_first_demand_starts_exactly_one_actor() {
    let starts = Arc::new(AtomicUsize::new(0));
    let observed = starts.clone();
    let wake: Wake = Arc::new(|| {});
    let worker_wake = wake.clone();
    let (port, updates) = DemandActor::configured(
        Some(Box::new(move || {
            observed.fetch_add(1, Ordering::SeqCst);
            crate::spawn_named("demand-control", worker_wake, |commands, out| {
                while let Ok(command) = commands.recv() {
                    if let Command::Configure(value) | Command::Invoke(value) = command {
                        out.emit(value);
                    }
                }
            })
        })),
        admission,
        |_| None,
        wake,
    );
    port.command(Command::Configure(1));
    port.command(Command::Configure(2));
    assert!(!port.has_started());
    assert_eq!(starts.load(Ordering::SeqCst), 0);
    port.command(Command::Invoke(3));
    port.command(Command::Invoke(4));
    assert!(port.has_started());
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut values = Vec::new();
    while values.len() < 3 && std::time::Instant::now() < deadline {
        values.extend(updates.try_iter());
        std::thread::yield_now();
    }
    assert_eq!(values, vec![2, 3, 4]);
}

#[test]
fn retirement_before_demand_does_not_replay_withdrawn_configuration() {
    let wake: Wake = Arc::new(|| {});
    let w = wake.clone();
    let (port, updates) = DemandActor::configured(
        Some(Box::new(move || {
            crate::spawn_named("retirement-control", w, |commands, out| {
                while let Ok(command) = commands.recv() {
                    if let Command::Configure(v) | Command::Invoke(v) = command {
                        out.emit(v);
                    }
                }
            })
        })),
        admission,
        |_| None,
        wake,
    );
    port.command(Command::Configure(1));
    port.command(Command::Retire);
    assert!(!port.has_started());
    port.command(Command::Invoke(2));
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let value = loop {
        if let Ok(value) = updates.try_recv() {
            break value;
        }
        assert!(std::time::Instant::now() < deadline);
        std::thread::yield_now();
    };
    assert_eq!(value, 2);
    assert!(updates.try_recv().is_err());
}

#[test]
fn an_uninstalled_service_publishes_a_refusal_without_an_actor() {
    let (port, updates) = DemandActor::configured(
        None,
        admission,
        |command| match command {
            Command::Invoke(v) => Some(v),
            _ => None,
        },
        Arc::new(|| {}),
    );
    port.command(Command::Configure(1));
    assert!(port.command(Command::Invoke(2)));
    assert_eq!(updates.try_recv(), Ok(2));
    assert!(!port.has_started());
}

#[test]
fn last_sender_drop_stops_the_actor_while_the_inbox_can_still_drain() {
    let wake: Wake = Arc::new(|| {});
    let worker_wake = wake.clone();
    let (port, updates) = DemandActor::configured(
        Some(Box::new(move || {
            crate::spawn_named("demand-close-control", worker_wake, |commands, out| {
                while commands.recv().is_ok() {}
                out.emit("stopped");
            })
        })),
        |command: u8, _| Admission::Demand(command),
        |_| None,
        wake,
    );
    assert!(port.command(1));
    let second = port.clone();
    drop(port);
    assert!(second.command(2));
    drop(second);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let value = loop {
        if let Ok(value) = updates.try_recv() {
            break value;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the inbox retained the actor's command sender"
        );
        std::thread::yield_now();
    };
    assert_eq!(value, "stopped");
}

#[test]
fn an_unstarted_inbox_closes_after_preserving_its_queued_refusal() {
    let (port, updates) = DemandActor::configured(
        None,
        admission,
        |command| match command {
            Command::Invoke(v) => Some(v),
            _ => None,
        },
        Arc::new(|| {}),
    );
    assert!(port.command(Command::Invoke(5)));
    drop(port);
    assert_eq!(updates.try_recv(), Ok(5));
    assert_eq!(
        updates.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Disconnected)
    );
}

#[test]
fn concurrent_demand_uses_one_existing_actor_harness() {
    let starts = Arc::new(AtomicUsize::new(0));
    let seen = starts.clone();
    let wake: Wake = Arc::new(|| {});
    let worker_wake = wake.clone();
    let (port, updates) = DemandActor::configured(
        Some(Box::new(move || {
            seen.fetch_add(1, Ordering::SeqCst);
            crate::spawn_named("concurrent-demand", worker_wake, |commands, out| {
                while let Ok(command) = commands.recv() {
                    out.emit(command);
                }
            })
        })),
        |command: u32, _| Admission::Demand(command),
        |_| None,
        wake,
    );
    let callers = (0..8)
        .map(|value| {
            let port = port.clone();
            std::thread::spawn(move || assert!(port.command(value)))
        })
        .collect::<Vec<_>>();
    for caller in callers {
        caller.join().unwrap();
    }
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut values = Vec::new();
    while values.len() < 8 && std::time::Instant::now() < deadline {
        values.extend(updates.try_iter());
        std::thread::yield_now();
    }
    values.sort();
    assert_eq!(values, (0..8).collect::<Vec<_>>());
}
