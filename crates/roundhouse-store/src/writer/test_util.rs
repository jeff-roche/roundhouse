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
use tokio::sync::{mpsc, oneshot, Mutex};

use crate::pool::StorePool;
use crate::redact::Redactor;
use crate::StoreError;

use super::{
    append_batch, append_batch_with_blobs, append_one, close_session, EventWriter, WriteCmd,
};

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
    /// The sender paired with whichever [`oneshot::Receiver`] the CURRENT `GateState::
    /// Waiting` carries, if any. Deliberately a separate `Mutex` from `state`: `admit` takes
    /// the receiver out of `state` (and flips `state` back to `Open`) before it has actually
    /// been fired, so `release` — which only ever needs `tx`, never `state` — must still be
    /// able to reach it after that happens. See [`Self::hold`]/[`Self::release`] for why a
    /// fresh generation per hold, rather than `Notify`, is what closes the stray-wakeup
    /// hazard.
    tx: Mutex<Option<oneshot::Sender<()>>>,
}

enum GateState {
    /// Let `close_session` run immediately, against the real store.
    Open,
    /// Fail the next `close_session` call with a synthesized error, without ever touching
    /// the store.
    FailNext,
    /// Block the next `close_session` call until [`CloseGate::release`] fires this
    /// receiver's paired sender (held in `CloseGate::tx`), then let it run against the real
    /// store.
    Waiting(oneshot::Receiver<()>),
}

impl CloseGate {
    /// A gate that lets every `close_session` call through immediately, until told
    /// otherwise.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(GateState::Open),
            tx: Mutex::new(None),
        })
    }

    /// The next `close_session` call fails immediately with a synthesized [`StoreError`],
    /// without the store or its tail guard ever being consulted.
    pub async fn fail_next(&self) {
        *self.state.lock().await = GateState::FailNext;
        *self.tx.lock().await = None;
    }

    /// Blocks the next `close_session` call until [`Self::release`] is called, then lets it
    /// proceed against the real store.
    ///
    /// Creates a brand-new `oneshot` pair every call, unconditionally overwriting both
    /// `state` (the receiver half) and `tx` (the sender half) — dropping whatever pair, if
    /// any, was already there. That unconditional replacement is what makes re-arming safe:
    /// a channel with nothing sent to it carries nothing across the swap, so a later
    /// `admit()` can only ever be satisfied by a `release()` that runs after THIS `hold()`,
    /// never by one left over from an earlier generation.
    pub async fn hold(&self) {
        let (tx, rx) = oneshot::channel();
        *self.tx.lock().await = Some(tx);
        *self.state.lock().await = GateState::Waiting(rx);
    }

    /// Releases a `close_session` call currently blocked by [`Self::hold`].
    ///
    /// An earlier `Notify`-based version gated
    /// `notify_one` on "is a hold genuinely active right now," but `Notify::notify_one`
    /// still stores a permit for the next `notified().await` even when that check passes
    /// only because nothing is *currently* waiting — so a `release()` racing ahead of the
    /// `close_session` call it was meant for could leave a stray permit that a LATER,
    /// unrelated `hold()`/`admit()` pair would consume instead of genuinely waiting. A
    /// `oneshot::Sender` has no such stored-permit behavior: `send` either reaches the one
    /// receiver it was created with, or the receiver was already dropped and `send` is a
    /// true no-op — there is no shared "permit" slot for an unrelated future receiver to
    /// observe. Combined with [`Self::hold`] replacing `tx` wholesale on every call, a
    /// `release()` can only ever wake the `hold()` it is paired with (or nothing, if that
    /// pairing has already been consumed or superseded).
    ///
    /// Locks `tx` — not `state` — so this works whether `admit` has already taken the
    /// receiver out of `state` (the common case: `admit` starts waiting first, `release`
    /// runs later) or not yet (a `release` racing ahead of `admit` still finds `tx` in
    /// place and the eventual `admit` still recovers the same paired receiver from `state`
    /// unless a later `hold()` supersedes it first).
    pub async fn release(&self) {
        if let Some(tx) = self.tx.lock().await.take() {
            let _ = tx.send(());
        }
    }

    /// Applies this gate's current disposition to one `close_session` call: `Err`
    /// synthesizes a failure without touching the store; `Ok(())` means it is safe for the
    /// caller to run the real close now.
    async fn admit(&self) -> Result<(), StoreError> {
        let mut guard = self.state.lock().await;
        match &mut *guard {
            GateState::Open => Ok(()),
            GateState::FailNext => {
                *guard = GateState::Open;
                Err(StoreError::Interact(
                    "close_session failed: CloseGate injected a test failure".to_string(),
                ))
            }
            GateState::Waiting(_) => {
                // Take the receiver and flip back to `Open` before waiting on it: `tx`
                // lives in its own `Mutex`, independent of `state`, so `release` can still
                // reach and fire the paired sender no matter what `state` has moved on to
                // by the time it runs.
                let GateState::Waiting(rx) = std::mem::replace(&mut *guard, GateState::Open) else {
                    unreachable!("matched Waiting above");
                };
                drop(guard);
                // A dropped sender (e.g. superseded by a later `hold()` before this one was
                // ever released) closes the channel rather than hanging forever — either
                // way it is safe to proceed once this resolves.
                let _ = rx.await;
                Ok(())
            }
        }
    }
}

/// Spawns an [`EventWriter`] that behaves exactly like [`super::spawn_writer`]'s: one
/// dedicated task processes every command from its channel strictly in arrival order,
/// `append`/`append_batch`/`append_batch_with_blobs` forwarded unmodified (the last of
/// those is the streaming-delta flush path, so a gated writer streams exactly as an
/// ungated one does), and now `close_session` is no exception —
/// but `close_session` also routes through `gate` first — see [`CloseGate`]'s own doc
/// comment for what a caller can make it do. Whatever `gate` lets through runs the real
/// [`close_session`], against the real `store`, with the real redaction and tail-guard
/// behavior — this is a gate in front of a real close, never a fake one.
///
/// **Why a gated close stalls this loop:** an earlier version of this function spawned each
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
                WriteCmd::AppendBatchWithBlobs {
                    events,
                    state_dir,
                    reply,
                } => {
                    let redactor = redactor_for_task.load_full();
                    let result = append_batch_with_blobs(&store, events, state_dir, redactor).await;
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
                    // function's own doc comment for why a held gate is
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
