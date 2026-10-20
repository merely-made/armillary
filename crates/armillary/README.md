# armillary

A host-neutral actor-kernel runtime. A single-threaded host kernel owns the
canonical state (the document model, the GPU device, the window); actors run
off-thread and talk to it only by `Send` message. The crate is the runtime spine
and carries nothing host-specific; its default runtime dependency is `tracing`; scoped async tasks use optional Tokio support.

```rust
use std::sync::Arc;
use armillary::{spawn, Wake};

let wake: Wake = Arc::new(|| { /* poke the kernel's event loop */ });
let (handle, updates) = spawn::<u32, u32, _>(wake, |commands, out| {
    let mut total = 0;                 // actor-thread-local; never crosses the boundary
    while let Ok(n) = commands.recv() {
        total += n;
        out.emit(total);
    }
});
handle.command(2);
handle.command(3);
handle.join().unwrap();
assert_eq!(updates.iter().collect::<Vec<_>>(), vec![2, 5]);
```

## Modules

| Module | Contents |
| --- | --- |
| `boundary` | `KernelThread`, a zero-size `!Send` + `!Sync` marker (`PhantomData<Rc<()>>`). Embed it in the host's kernel context and moving that context to another thread becomes a compile error. |
| `actor` | `spawn`, `spawn_named`, `spawn_on`, `spawn_named_on`; `ActorHandle<C>` (`command`, `is_finished`, fallible `join`), `Emitter<U>` (`emit`, `Clone` without requiring `U: Clone`), `Wake = Arc<dyn Fn() + Send + Sync>`. The `run` closure executes on the actor thread, so `!Send` internals are constructed there and never move across. Each run loop is wrapped in a `tracing` span on target `armillary` with `actor started` / `actor finished` (`lifetime_ms`) events. |
| `pool` | `Pool` (`new`, `submit`, `workers`), a growable worker pool built on `Mutex` + `Condvar`. A worker runs one job for that job's whole lifetime, then waits for the next instead of exiting, so the OS-thread count tracks peak concurrent actors rather than total spawns. |
| `message` | `Generations` (`nav`, `viewport`, `accepts`), `NavGeneration` and `ViewportGeneration` (`bump`), `RequestId`, `RequestIds::issue`, `Correlated<T>` (`new`, `map`). Stamp outgoing work, drop returning work whose stamp no longer matches. |

`spawn` returns an `ActorHandle<C>` plus a `Receiver<U>` the kernel drains.
Dropping the handle closes the command channel, which is how the actor loop ends.
`spawn_on` waits for actor completion through a separate completion channel;
it does not join or stop the reusable pool worker. Both spawn paths report actor
panics through `ActorError`, and panic traces are distinct from normal finish.

The concrete `Command` / `Update` taxonomy and the kernel inbox belong to the
host; this crate is generic over them. `Correlated<T>` pairs updates with the
command that caused them without defining the outcome vocabulary.

## Next

- `design_docs/armillary_docs/research/2026-07-07_armillary_founding_proposal.md`
- Consumers in this workspace: `crates/system/fetch`, `crates/fleece` (`crawl` feature),
  pictograph's `canvas` feature (`crates/canvas/pictograph`), and
  `crates/intel/esp` under its `actor` feature.

License: MPL-2.0 (see LICENSE).

## Shared lifecycle mechanics

`lifecycle::close_all` attempts caller-ordered close actions and retains every
reported error. The caller owns resource order and shutdown policy.

Feature `tokio` adds `tasks::ResidentTasks`. `cancel_and_join` is a reusable drain;
`close_and_join` fences new admissions before draining and retains earlier
terminal failures across repeated/concurrent closes. `TaskReport` distinguishes
completed, cancelled, panicked and rejected work, including outcomes reaped before
the drain. Cancelling the drain future preserves the scope's task ownership.
Detached work outside a scope remains outside its shutdown guarantee.

The known pool admission/retirement findings Q112 and Q113 remain separate gates;
actor completion does not establish that all pool workers have exited.
