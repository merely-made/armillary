// Copyright 2026 Mark Alan Boykin
// SPDX-License-Identifier: MPL-2.0

//! Demand-driven admission over the existing actor harness.
//!
//! A host classifies its own commands as demand, replaceable configuration,
//! or completed lifecycle work. Configuration does not spawn an actor. A
//! factory is consumed by the first demand; an absent factory uses the host's
//! typed refusal. No renderer, transport, identity, or product policy lives here.

use crate::{ActorHandle, Wake};
use std::collections::VecDeque;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc::{Receiver, TryRecvError},
};

/// A host's classification of one command. Classification never opens resources.
pub enum Admission<C> {
    /// Start once if configured, then forward the command or publish its refusal.
    Demand(C),
    /// Replace passive configuration in this slot without starting a worker.
    Deferred(&'static str, C),
    /// The host completed the lifecycle request without requiring an actor.
    Complete,
    /// Withdraw configuration that must never be replayed after retirement.
    Withdraw,
}

/// Construct a handle with the existing spawn/spawn_on harness on first demand.
pub type ActorFactory<C, U> = Box<dyn FnOnce() -> (ActorHandle<C>, Receiver<U>) + Send>;
type Classifier<C> = Arc<dyn Fn(C, bool) -> Admission<C> + Send + Sync>;
type Refusal<C, U> = Box<dyn Fn(C) -> Option<U> + Send>;

struct State<C, U> {
    factory: Option<ActorFactory<C, U>>,
    actor: Option<ActorHandle<C>>,
    updates: Option<Receiver<U>>,
    deferred: Vec<(&'static str, C)>,
    refused: VecDeque<U>,
    refuse: Option<Refusal<C, U>>,
}

/// A clonable command port with one deferred actor factory.
///
/// Dropping the final command port closes the actor's command channel without
/// blocking, like ActorHandle. An inbox does not prolong the actor's lifetime.
pub struct DemandActor<C, U> {
    state: Arc<Mutex<State<C, U>>>,
    classify: Classifier<C>,
    wake: Wake,
    writers: Arc<AtomicUsize>,
}

/// The kernel's nonblocking inbox; it may outlive every command port and drain.
pub struct DemandUpdates<C, U> {
    state: Arc<Mutex<State<C, U>>>,
    writers: Arc<AtomicUsize>,
}

impl<C, U> Clone for DemandActor<C, U> {
    fn clone(&self) -> Self {
        self.writers.fetch_add(1, Ordering::Relaxed);
        Self {
            state: self.state.clone(),
            classify: self.classify.clone(),
            wake: self.wake.clone(),
            writers: self.writers.clone(),
        }
    }
}

impl<C, U> Drop for DemandActor<C, U> {
    fn drop(&mut self) {
        if self.writers.fetch_sub(1, Ordering::AcqRel) != 1 {
            return;
        }
        let owned = {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            (
                state.actor.take(),
                state.factory.take(),
                std::mem::take(&mut state.deferred),
                state.refuse.take(),
            )
        };
        // Captured host resources may have their own Drop code. Release them
        // outside the inbox mutex, preserving ActorHandle's nonblocking drop.
        drop(owned);
    }
}

impl<C: Send + 'static, U: Send + 'static> DemandActor<C, U> {
    /// Configure admission without invoking the factory. The classifier receives
    /// whether an actor was started; lifecycle semantics remain host policy.
    pub fn configured(
        factory: Option<ActorFactory<C, U>>,
        classify: impl Fn(C, bool) -> Admission<C> + Send + Sync + 'static,
        refuse: impl Fn(C) -> Option<U> + Send + 'static,
        wake: Wake,
    ) -> (Self, DemandUpdates<C, U>) {
        let state = Arc::new(Mutex::new(State {
            factory,
            actor: None,
            updates: None,
            deferred: Vec::new(),
            refused: VecDeque::new(),
            refuse: Some(Box::new(refuse)),
        }));
        let writers = Arc::new(AtomicUsize::new(1));
        (
            Self {
                state: state.clone(),
                classify: Arc::new(classify),
                wake,
                writers: writers.clone(),
            },
            DemandUpdates { state, writers },
        )
    }

    /// Classify and deliver a command. False means no actor or refusal accepted
    /// it. Passive configuration is coalesced before demand and forwarded after.
    pub fn command(&self, command: C) -> bool {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        match (self.classify)(command, state.actor.is_some()) {
            Admission::Complete => true,
            Admission::Withdraw => {
                state.deferred.clear();
                true
            }
            Admission::Deferred(key, command) => {
                if let Some(actor) = &state.actor {
                    return actor.command(command);
                }
                if state.factory.is_some() {
                    state.deferred.retain(|(previous, _)| *previous != key);
                    state.deferred.push((key, command));
                }
                true
            }
            Admission::Demand(command) => {
                if state.actor.is_none()
                    && let Some(factory) = state.factory.take()
                {
                    let (actor, updates) = factory();
                    for (_, passive) in std::mem::take(&mut state.deferred) {
                        actor.command(passive);
                    }
                    state.actor = Some(actor);
                    state.updates = Some(updates);
                }
                if let Some(actor) = &state.actor {
                    return actor.command(command);
                }
                let result = state.refuse.as_ref().and_then(|refuse| refuse(command));
                if let Some(update) = result {
                    state.refused.push_back(update);
                    drop(state);
                    (self.wake)();
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Whether the factory has produced an actor; this does not invoke it.
    pub fn has_started(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .actor
            .is_some()
    }

    /// Whether a started actor returned or unwound; dormant actors are false.
    pub fn is_finished(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .actor
            .as_ref()
            .is_some_and(ActorHandle::is_finished)
    }
}

impl<C, U> DemandUpdates<C, U> {
    /// Drain an update or refusal without starting an actor or blocking.
    pub fn try_recv(&self) -> Result<U, TryRecvError> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(update) = state.refused.pop_front() {
            return Ok(update);
        }
        match &state.updates {
            Some(updates) => updates.try_recv(),
            None if self.writers.load(Ordering::Acquire) == 0 => Err(TryRecvError::Disconnected),
            None => Err(TryRecvError::Empty),
        }
    }

    /// Drain currently available updates, stopping at empty or disconnected.
    pub fn try_iter(&self) -> impl Iterator<Item = U> + '_ {
        std::iter::from_fn(|| self.try_recv().ok())
    }
}

#[cfg(test)]
#[path = "demand/tests.rs"]
mod tests;
