//! A gated `EventWriter` for testing `close_session` failure and retry paths (Phase 8,
//! T19a Task 4), gated behind the non-default `test-util` Cargo feature — mirroring the
//! identical pattern already used for this exact purpose by `roundhouse-policy` and
//! `roundhouse-engine`'s own `test-util` features. `roundhouse-engine`'s tests activate it
//! through a self dev-dependency on this crate with `features = ["test-util"]`; `cfg(test)`
//! alone does not reach a different crate's integration tests.
//!
//! [`spawn_gated_writer`] behaves exactly like [`super::spawn_writer`] for `append`/
//! `append_batch` — both pass straight through to the real store, redaction, and per-session
//! tail guard — but routes every `close_session` call through a [`CloseGate`] first. This is
//! deliberately more than a one-shot fault injector: [`CloseGate::hold`]/[`CloseGate::
//! release`] let a caller pause a `close_session` call indefinitely and resume it later from
//! elsewhere, which is the same shape a later task (the socket server's own close-request
//! handling) is expected to reuse for gating a close until an external signal fires, not
//! just for simulating a failure.

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, Mutex, Notify};

use crate::pool::StorePool;
use crate::redact::Redactor;
use crate::StoreError;

use super::{append_batch, append_one, close_session, EventWriter, WriteCmd};

/// Controls how a [`spawn_gated_writer`]'d [`EventWriter`]'s `close_session` calls behave.
///
/// Two independent dispositions, set explicitly by a test (or a future caller) and consumed
/// exactly once per `close_session` call that observes them:
/// - [`Self::fail_next`]: the very next `close_session` call fails immediately with a
///   synthesized [`StoreError`], never reaching the store — proving a caller (`SessionActor::
///   close`) handles a failed append without ever publishing a terminator.
/// - [`Self::hold`] / [`Self::release`]: the next `close_session` call blocks until
///   `release` is called (from anywhere holding this same `Arc<CloseGate>`), then proceeds
///   against the real store exactly as an ungated writer would — useful for pinning down
///   what a caller observes *while* a close is genuinely in flight.
///
/// Reverts to letting calls through immediately (`GateState::Open`) once a set disposition
/// has been consumed once — call `fail_next`/`hold` again before each call that should be
/// affected.
pub struct CloseGate {
    state: Mutex<GateState>,
    notify: Notify,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GateState {
    /// Let `close_session` run immediately, against the real store.
    Open,
    /// Fail the next `close_session` call with a synthesized error, without ever touching
    /// the store.
    FailNext,
    /// Block the next `close_session` call until `release()` is called, then let it run
    /// against the real store.
    Waiting,
}

impl CloseGate {
    /// A gate that lets every `close_session` call through immediately, until told
    /// otherwise.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState::Open),
            notify: Notify::new(),
        })
    }

    /// The next `close_session` call fails immediately with a synthesized [`StoreError`],
    /// without the store or its tail guard ever being consulted.
    pub async fn fail_next(&self) {
        *self.state.lock().await = GateState::FailNext;
    }

    /// Blocks the next `close_session` call until [`Self::release`] is called, then lets it
    /// proceed against the real store.
    pub async fn hold(&self) {
        *self.state.lock().await = GateState::Waiting;
    }

    /// Releases a `close_session` call currently blocked by [`Self::hold`].
    ///
    /// A no-op unless a `hold()` is genuinely still outstanding (`*guard ==
    /// GateState::Waiting`) at the moment this runs: the state transition
    /// from `Waiting` to `Open` happens HERE, under the same lock `admit`
    /// reads, before `notify_one` is ever called — never inside `admit`
    /// itself. Fix round 1 (review finding M2): an earlier version left the
    /// `Waiting` -> `Open` transition to `admit`'s own Waiting arm, which
    /// meant a `release()` called with no `hold()` outstanding still called
    /// `notify_one` unconditionally — and `Notify::notify_one` stores a
    /// permit for the next `notified().await` when nobody is waiting yet, so
    /// that stray permit would silently satisfy the NEXT, unrelated
    /// `hold()`/`admit()` pair instead of making it actually wait. Gating the
    /// notification on "is a hold genuinely active right now" closes that:
    /// a `release()` with nothing to release touches neither `*guard` nor
    /// `notify`, so no permit is ever manufactured for a future hold.
    ///
    /// Uses `Notify::notify_one`, not `notify_waiters`, for the same reason
    /// as before this fix round: a caller has no way to know whether the
    /// gated `close_session` call has already reached its own
    /// `notified().await` by the time `release` runs (in practice it
    /// usually hasn't — a caller typically observes some OTHER signal, like
    /// this session's state watch flipping to `Cancelling`, and calls
    /// `release` right after, well before the gated task's own executor
    /// turn). `notify_waiters` only wakes tasks ALREADY waiting and stores
    /// nothing for a future one, so calling it before that turn would be a
    /// genuine lost wakeup — the held call would then never wake.
    /// `notify_one` stores a permit for exactly the next `notified()` call
    /// when nothing is waiting yet, which is what makes `release` safe to
    /// call before, concurrently with, or after the corresponding
    /// `hold`ing call actually starts waiting. This gate supports exactly
    /// one outstanding `hold`/`release` pair at a time — a second `hold()`
    /// racing an unconsumed first one is not a case any current caller
    /// needs, and isn't specially handled here.
    pub async fn release(&self) {
        let mut guard = self.state.lock().await;
        if *guard == GateState::Waiting {
            *guard = GateState::Open;
            drop(guard);
            self.notify.notify_one();
        }
    }

    /// Applies this gate's current disposition to one `close_session` call: `Err`
    /// synthesizes a failure without touching the store; `Ok(())` means it is safe for the
    /// caller to run the real close now.
    async fn admit(&self) -> Result<(), StoreError> {
        let mut guard = self.state.lock().await;
        match *guard {
            GateState::Open => Ok(()),
            GateState::FailNext => {
                *guard = GateState::Open;
                Err(StoreError::Interact(
                    "close_session failed: CloseGate injected a test failure".to_string(),
                ))
            }
            GateState::Waiting => {
                // Drop the lock and wait — `release()` (not this method) is what
                // transitions `*guard` back to `Open`, and it does so BEFORE calling
                // `notify_one`, so by the time this `notified().await` resolves the
                // state is already consistent for whoever reads it next.
                drop(guard);
                self.notify.notified().await;
                Ok(())
            }
        }
    }
}

/// Spawns an [`EventWriter`] that behaves exactly like [`super::spawn_writer`]'s: one
/// dedicated task processes every command from its channel strictly in arrival order,
/// `append`/`append_batch` forwarded unmodified, and now `close_session` is no exception —
/// but `close_session` also routes through `gate` first — see [`CloseGate`]'s own doc
/// comment for what a caller can make it do. Whatever `gate` lets through runs the real
/// [`close_session`], against the real `store`, with the real redaction and tail-guard
/// behavior — this is a gate in front of a real close, never a fake one.
///
/// **Fix round 1 (review finding M1):** an earlier version of this function spawned each
/// `close_session` call off onto its own task rather than awaiting `gate.admit()` inline in
/// this loop, so that a `CloseGate::hold`-paused close could not stall this task's ability
/// to keep servicing ordinary `Append`/`AppendBatch` commands meanwhile. That let a gated
/// `close_session` run CONCURRENTLY with a later `append`/`append_batch` sent to this same
/// writer — a real, structural violation of the single-writer discipline `spawn_writer`'s
/// own doc comment describes, and a departure from what this function's own doc comment
/// claimed ("the same single-writer order"). `close_session` is now awaited inline like
/// every other command; every current caller only ever holds the gate with nothing else
/// in flight against the same writer, so this costs nothing today. A future caller that
/// genuinely needs a held `close_session` not to block unrelated appends on the SAME
/// writer will need a real design for that (e.g. a writer per session), not a silent
/// concurrency escape hatch here.
pub async fn spawn_gated_writer(store: StorePool, gate: Arc<CloseGate>) -> EventWriter {
    let (tx, mut rx) = mpsc::channel::<WriteCmd>(1024);
    // Empty-pattern automaton by default, matching `spawn_writer`'s own default — redaction
    // is always structurally "on," never simply absent because this test writer forgot to
    // configure one.
    let redactor = Arc::new(ArcSwap::from_pointee(Redactor::build(&[])));
    let redactor_for_task = Arc::clone(&redactor);

    tokio::spawn(async move {
        while let Some(cmd) = rx.recv().await {
            match cmd {
                WriteCmd::Append { event, reply } => {
                    let redactor = redactor_for_task.load_full();
                    let result = append_one(&store, *event, &redactor).await;
                    let _ = reply.send(result);
                }
                WriteCmd::AppendBatch { events, reply } => {
                    let redactor = redactor_for_task.load_full();
                    let result = append_batch(&store, events, &redactor).await;
                    let _ = reply.send(result);
                }
                WriteCmd::CloseSession {
                    runner,
                    session_id,
                    ts,
                    outcome,
                    reply,
                } => {
                    // Awaited inline, same as `Append`/`AppendBatch` above — see this
                    // function's own doc comment (fix round 1, M1) for why a held gate is
                    // allowed to stall this loop rather than being spawned off.
                    let redactor = redactor_for_task.load_full();
                    let result = match gate.admit().await {
                        Ok(()) => {
                            close_session(&store, runner, session_id, ts, outcome, redactor).await
                        }
                        Err(err) => Err(err),
                    };
                    let _ = reply.send(result);
                }
            }
        }
    });

    EventWriter { tx, redactor }
}
