//! Phase 8 Task 21 (#40): committed events reach UDS clients from the store.
//!
//! Every test here runs the real daemon over a real Unix socket (`accept_loop`,
//! `create_real_session`, the real `run_agent_loop` and the real store) and asserts on the
//! frames a client actually receives, never on a poll of the database. The one scripted
//! piece is the provider, which can hold its stream at a gate the test releases, so every
//! ordering here comes from an explicit signal rather than a sleep. `tokio::time::timeout`
//! appears only as a failure bound.
//!
//! The frames are read with a raw NDJSON client ([`Conn`]) rather than
//! `roundhouse_tui::DaemonClient`, so these tests pin the daemon's wire behaviour on its
//! own terms.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use roundhouse_core::{EventPayload, SessionId, SessionOutcome, TaskId};
use roundhouse_daemon::socket_server::{drive_established_session, SessionLink};
use roundhouse_proto::{ClientEvent, ClientRequest, TurnOutcome};
use roundhouse_provider::{
    BlockDelta, BlockKind, BoxFut, Capabilities, ChatRequest, ChatStream, ModelId, ModelInfo, Plan,
    Provider, ProviderError, RequestCtx, StreamEvent, TokenCount,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::UnixStream;
use tokio::sync::{mpsc, Semaphore};

/// The failure bound on every single wait in this file. Never the thing being asserted.
const BOUND: Duration = Duration::from_secs(20);

/// What [`GatedProvider`] streams once its gate lets it continue.
#[derive(Clone, Copy)]
enum Script {
    /// A short text reply.
    Text,
    /// `stream_chat` itself fails with a fatal provider error.
    Fail,
    /// A text reply of [`BULK_DELTAS`] deltas of [`BULK_DELTA_BYTES`] bytes each: far more
    /// than one socket buffer plus one connection's event channel can hold, so a client
    /// that never reads really does stall its own connection.
    Bulk,
}

const BULK_DELTAS: usize = 100;
const BULK_DELTA_BYTES: usize = 8 * 1024;

/// A provider whose stream stops at a gate after its first two events. Each call signals
/// `entered` when it reaches the gate, then consumes one permit of `gate` before it
/// continues. A test that wants no gating opens the gate up front.
struct GatedProvider {
    script: Script,
    gate: Arc<Semaphore>,
    entered: mpsc::UnboundedSender<()>,
}

/// The test's side of a [`GatedProvider`].
struct Gate {
    permits: Arc<Semaphore>,
    entered: mpsc::UnboundedReceiver<()>,
}

impl Gate {
    /// Waits until one provider call has reached the gate.
    async fn entered(&mut self) {
        tokio::time::timeout(BOUND, self.entered.recv())
            .await
            .expect("the provider must reach its gate")
            .expect("the provider is still alive");
    }

    /// Lets one waiting (or future) provider call continue.
    fn release(&self) {
        self.permits.add_permits(1);
    }
}

fn gated_provider(script: Script, open: bool) -> (Arc<GatedProvider>, Gate) {
    let permits = Arc::new(Semaphore::new(if open { 1024 } else { 0 }));
    let (entered_tx, entered_rx) = mpsc::unbounded_channel();
    (
        Arc::new(GatedProvider {
            script,
            gate: permits.clone(),
            entered: entered_tx,
        }),
        Gate {
            permits,
            entered: entered_rx,
        },
    )
}

impl Provider for GatedProvider {
    fn capabilities(&self, _model: &ModelId) -> Capabilities {
        Capabilities::default()
    }
    fn resolve(&self, _req: &ChatRequest) -> Result<Plan, ProviderError> {
        Ok(Plan {
            endpoint: "fake".into(),
        })
    }
    fn stream_chat<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<ChatStream, ProviderError>> {
        let gate = self.gate.clone();
        let entered = self.entered.clone();
        let script = self.script;
        Box::pin(async move {
            if let Script::Fail = script {
                let _ = entered.send(());
                gate.acquire().await.unwrap().forget();
                return Err(ProviderError::QuotaExhausted);
            }
            let head = vec![
                StreamEvent::BlockStart {
                    index: 0,
                    kind: BlockKind::Text,
                },
                StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("partial ".into()),
                },
            ];
            let mut tail: Vec<StreamEvent> = match script {
                Script::Bulk => (0..BULK_DELTAS)
                    .map(|_| StreamEvent::BlockDelta {
                        index: 0,
                        delta: BlockDelta::Text("x".repeat(BULK_DELTA_BYTES)),
                    })
                    .collect(),
                _ => vec![StreamEvent::BlockDelta {
                    index: 0,
                    delta: BlockDelta::Text("done".into()),
                }],
            };
            tail.push(StreamEvent::BlockStop { index: 0 });
            tail.push(StreamEvent::MessageStop);
            let rest = async move {
                let _ = entered.send(());
                gate.acquire().await.unwrap().forget();
                futures::stream::iter(tail.into_iter().map(Ok))
            };
            Ok(ChatStream(Box::pin(
                futures::stream::iter(head.into_iter().map(Ok))
                    .chain(futures::stream::once(rest).flatten()),
            )))
        })
    }
    fn count_tokens<'a>(
        &'a self,
        _req: &'a ChatRequest,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<TokenCount, ProviderError>> {
        Box::pin(async { Ok(TokenCount::default()) })
    }
    fn list_models<'a>(
        &'a self,
        _ctx: &'a RequestCtx,
    ) -> BoxFut<'a, Result<Vec<ModelInfo>, ProviderError>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

/// A live daemon on a real socket.
struct Daemon {
    _dir: tempfile::TempDir,
    socket_path: PathBuf,
    db_path: PathBuf,
    /// The registry `accept_loop` was handed, so a test can reap a session the
    /// way `spawn_session_reaper` does, without waiting on the reaper.
    registry: Arc<roundhouse_daemon::session_registry::SessionRegistry>,
}

async fn start_daemon(provider: Arc<dyn Provider>) -> Daemon {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let db_path = dir.path().join("events.db");
    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let listener = roundhouse_daemon::socket_server::bind_socket(&socket_path).unwrap();
    let resources = common::resources_with_provider(dir.path(), provider).await;
    tokio::spawn(roundhouse_daemon::socket_server::accept_loop(
        listener,
        registry.clone(),
        resources,
    ));
    Daemon {
        _dir: dir,
        socket_path,
        db_path,
        registry,
    }
}

/// A raw NDJSON client: one request per line out, one `ClientEvent` per line in.
struct Conn {
    reader: BufReader<OwnedReadHalf>,
    writer: OwnedWriteHalf,
}

impl Conn {
    async fn open(socket_path: &Path, first: &ClientRequest) -> Conn {
        let stream = UnixStream::connect(socket_path).await.unwrap();
        let (read_half, write_half) = stream.into_split();
        let mut conn = Conn {
            reader: BufReader::new(read_half),
            writer: write_half,
        };
        conn.send(first).await;
        conn
    }

    async fn send(&mut self, request: &ClientRequest) {
        let line = serde_json::to_string(request).unwrap();
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.write_all(b"\n").await.unwrap();
    }

    /// The next frame, or `None` once the daemon closes the connection.
    async fn recv(&mut self) -> Option<ClientEvent> {
        let mut line = String::new();
        let n = tokio::time::timeout(BOUND, self.reader.read_line(&mut line))
            .await
            .expect("the daemon must send the next frame or close the connection")
            .unwrap();
        if n == 0 {
            return None;
        }
        Some(serde_json::from_str(line.trim_end()).unwrap())
    }
}

/// One `Committed` frame, flattened.
#[derive(Debug, Clone)]
struct Frame {
    seq: u64,
    task_id: Option<TaskId>,
    payload: EventPayload,
}

impl Frame {
    /// Payload equality through serde, since `EventPayload` has no `PartialEq`.
    fn same_as(&self, other: &Frame) -> bool {
        self.seq == other.seq
            && self.task_id == other.task_id
            && serde_json::to_value(&self.payload).unwrap()
                == serde_json::to_value(&other.payload).unwrap()
    }
}

fn committed(event: ClientEvent, expected_session: SessionId) -> Option<Frame> {
    match event {
        ClientEvent::Committed {
            session_id,
            seq,
            task_id,
            payload,
        } => {
            assert_eq!(session_id, expected_session, "a frame for another session");
            Some(Frame {
                seq,
                task_id,
                payload: *payload,
            })
        }
        _ => None,
    }
}

/// Creates a session and returns the connection plus the first frame it received,
/// which must be the durable `SessionCreated`.
async fn create(daemon: &Daemon) -> (Conn, SessionId, Frame) {
    let mut conn = Conn::open(
        &daemon.socket_path,
        &ClientRequest::CreateSession {
            workspace_name: "default".into(),
        },
    )
    .await;
    let first = conn
        .recv()
        .await
        .expect("the daemon must answer CreateSession");
    let ClientEvent::Committed {
        session_id,
        seq,
        task_id,
        payload,
    } = first
    else {
        panic!("the first frame after CreateSession must be a Committed event, got {first:?}");
    };
    (
        conn,
        session_id,
        Frame {
            seq,
            task_id,
            payload: *payload,
        },
    )
}

/// Reads frames until this connection's `TurnFinished`, returning every `Committed`
/// frame seen on the way plus the outcome and its `through_seq`.
async fn until_turn_finished(
    conn: &mut Conn,
    session_id: SessionId,
) -> (Vec<Frame>, TurnOutcome, Option<u64>) {
    let mut frames = Vec::new();
    loop {
        let event = conn
            .recv()
            .await
            .expect("the connection must stay open until TurnFinished");
        match event {
            ClientEvent::TurnFinished {
                session_id: finished,
                outcome,
                through_seq,
            } => {
                assert_eq!(finished, session_id);
                return (frames, outcome, through_seq);
            }
            other => {
                if let Some(frame) = committed(other, session_id) {
                    frames.push(frame);
                }
            }
        }
    }
}

/// Reads `Committed` frames until one with `seq == last`, failing on any other frame.
async fn until_seq(conn: &mut Conn, session_id: SessionId, last: u64) -> Vec<Frame> {
    let mut frames = Vec::new();
    loop {
        let event = conn
            .recv()
            .await
            .expect("the connection must stay open until the expected seq");
        let frame = committed(event.clone(), session_id)
            .unwrap_or_else(|| panic!("expected a Committed frame, got {event:?}"));
        let seq = frame.seq;
        frames.push(frame);
        if seq == last {
            return frames;
        }
    }
}

fn seqs(frames: &[Frame]) -> Vec<u64> {
    frames.iter().map(|f| f.seq).collect()
}

fn submit(session_id: SessionId, text: &str) -> ClientRequest {
    ClientRequest::SubmitTurn {
        session_id,
        text: text.into(),
    }
}

/// Runs one complete, ungated text turn on a fresh session and returns the creator's
/// connection plus every frame it received (SessionCreated first).
async fn session_with_one_turn(daemon: &Daemon) -> (Conn, SessionId, Vec<Frame>) {
    let (mut creator, session_id, created) = create(daemon).await;
    creator.send(&submit(session_id, "hello")).await;
    let (mut frames, outcome, _) = until_turn_finished(&mut creator, session_id).await;
    assert!(matches!(outcome, TurnOutcome::Completed), "{outcome:?}");
    frames.insert(0, created);
    (creator, session_id, frames)
}

#[tokio::test]
async fn create_streams_the_durable_session_created_as_seq_0() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;

    let (_conn, session_id, first) = create(&daemon).await;
    assert_eq!(first.seq, 0);
    assert!(
        matches!(first.payload, EventPayload::SessionCreated { .. }),
        "seq 0 must be SessionCreated, got {:?}",
        first.payload
    );

    // The frame is the stored row, not something made up for the handshake.
    let store = roundhouse_store::open(&daemon.db_path).await.unwrap();
    let stored = roundhouse_store::session_events(&store, session_id)
        .await
        .unwrap();
    let row = stored
        .first()
        .expect("the store must hold the SessionCreated row");
    assert_eq!(row.seq, 0);
    assert!(matches!(row.payload, EventPayload::SessionCreated { .. }));
    assert!(first.same_as(&Frame {
        seq: row.seq,
        task_id: row.task_id,
        payload: row.payload.clone(),
    }));
}

/// Every event the turn committed reaches the creator, contiguous from seq 0, before
/// `TurnFinished`, whose `through_seq` is the last of them.
///
/// The creator deliberately reads nothing while the turn runs: the bulk reply is far more
/// than its socket buffer and event channel hold, so its follower is still far behind
/// when the turn's outcome reaches the connection. A viewer on a second connection reads
/// the turn through to its root task's completion, which is the signal that the outcome
/// is (about to be) known. `TurnFinished` must still wait for the creator's own stalled
/// follower to catch up.
#[tokio::test]
async fn submitted_turn_streams_every_committed_event_then_turn_finished() {
    let (provider, mut gate) = gated_provider(Script::Bulk, false);
    let daemon = start_daemon(provider).await;

    let (mut creator, session_id, created) = create(&daemon).await;
    let mut viewer = Conn::open(&daemon.socket_path, &ClientRequest::Attach { session_id }).await;
    assert!(matches!(viewer.recv().await, Some(ClientEvent::Ack { .. })));

    creator.send(&submit(session_id, "hello")).await;
    gate.entered().await;
    gate.release();

    // The viewer reads the turn through to its root task's completion.
    let mut root_task = None;
    loop {
        let event = viewer.recv().await.expect("the viewer is open");
        let frame = committed(event.clone(), session_id)
            .unwrap_or_else(|| panic!("expected a Committed frame, got {event:?}"));
        if root_task.is_none() && matches!(frame.payload, EventPayload::TaskCreated { .. }) {
            root_task = frame.task_id;
        }
        if root_task.is_some()
            && frame.task_id == root_task
            && matches!(frame.payload, EventPayload::TaskCompleted { .. })
        {
            break;
        }
    }

    // Only now does the creator read anything past the handshake.
    let (mut frames, outcome, through_seq) = until_turn_finished(&mut creator, session_id).await;
    assert!(matches!(outcome, TurnOutcome::Completed), "{outcome:?}");
    frames.insert(0, created);
    let got = seqs(&frames);
    let expected: Vec<u64> = (0..got.len() as u64).collect();
    assert_eq!(got, expected, "Committed seqs must be contiguous from 0");
    assert_eq!(
        through_seq,
        got.last().copied(),
        "TurnFinished must come right after the last event the turn committed"
    );
    assert!(
        frames
            .iter()
            .any(|f| f.task_id == root_task
                && matches!(f.payload, EventPayload::TaskCompleted { .. })),
        "the turn's own completed root task must be among the frames"
    );
}

/// `through_seq` must equal the last seq sent before `TurnFinished`, and match the
/// session's head at that point.
#[tokio::test]
async fn turn_finished_through_seq_is_the_last_committed_seq() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;

    let (mut creator, session_id, created) = create(&daemon).await;
    creator.send(&submit(session_id, "hello")).await;
    let (frames, outcome, through_seq) = until_turn_finished(&mut creator, session_id).await;
    assert!(matches!(outcome, TurnOutcome::Completed), "{outcome:?}");
    let last = frames.last().map_or(created.seq, |f| f.seq);
    assert_eq!(through_seq, Some(last));

    let store = roundhouse_store::open(&daemon.db_path).await.unwrap();
    let stored = roundhouse_store::session_events(&store, session_id)
        .await
        .unwrap();
    assert_eq!(stored.last().map(|e| e.seq), through_seq);
}

#[tokio::test]
async fn provider_failure_yields_turn_finished_failed() {
    let (provider, _gate) = gated_provider(Script::Fail, true);
    let daemon = start_daemon(provider).await;

    let (mut creator, session_id, _created) = create(&daemon).await;
    creator.send(&submit(session_id, "hello")).await;
    let (frames, outcome, through_seq) = until_turn_finished(&mut creator, session_id).await;
    match outcome {
        TurnOutcome::Failed { category, message } => {
            assert_eq!(category, "provider");
            assert!(!message.is_empty());
        }
        other => panic!("expected TurnFinished Failed, got {other:?}"),
    }
    assert!(
        frames
            .iter()
            .any(|f| matches!(f.payload, EventPayload::TaskFailed { .. })),
        "the failed task must reach the client before TurnFinished: {frames:?}"
    );
    assert_eq!(through_seq, frames.last().map(|f| f.seq));
}

#[tokio::test]
async fn refused_submit_turn_yields_rejected() {
    let (provider, mut gate) = gated_provider(Script::Text, false);
    let daemon = start_daemon(provider).await;

    let (mut creator, session_id, _created) = create(&daemon).await;
    creator.send(&submit(session_id, "first")).await;
    gate.entered().await;

    // The first turn is provably still in flight: its provider call is parked at the gate.
    creator.send(&submit(session_id, "second")).await;
    let (_, outcome, through_seq) = until_turn_finished(&mut creator, session_id).await;
    match outcome {
        TurnOutcome::Rejected { reason } => assert!(!reason.is_empty()),
        other => panic!("the second SubmitTurn must be Rejected, got {other:?}"),
    }
    assert_eq!(through_seq, None, "a rejected turn committed nothing");

    gate.release();
    let (_, outcome, _) = until_turn_finished(&mut creator, session_id).await;
    assert!(
        matches!(outcome, TurnOutcome::Completed),
        "the first turn must still complete, got {outcome:?}"
    );
}

#[tokio::test]
async fn attach_replays_from_zero() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;
    let (_creator, session_id, frames) = session_with_one_turn(&daemon).await;
    let last = frames.last().unwrap().seq;

    let mut viewer = Conn::open(&daemon.socket_path, &ClientRequest::Attach { session_id }).await;
    assert!(matches!(viewer.recv().await, Some(ClientEvent::Ack { .. })));
    let replay = until_seq(&mut viewer, session_id, last).await;
    assert_eq!(seqs(&replay), seqs(&frames));
    for (replayed, live) in replay.iter().zip(&frames) {
        assert!(replayed.same_as(live), "{replayed:?} != {live:?}");
    }
}

#[tokio::test]
async fn resume_replays_from_cursor_plus_one() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;
    let (_creator, session_id, frames) = session_with_one_turn(&daemon).await;
    let last = frames.last().unwrap().seq;
    let cursor = last / 2;

    let mut viewer = Conn::open(
        &daemon.socket_path,
        &ClientRequest::Resume {
            session_id,
            after_seq: cursor,
        },
    )
    .await;
    assert!(matches!(viewer.recv().await, Some(ClientEvent::Ack { .. })));
    let replay = until_seq(&mut viewer, session_id, last).await;
    let expected: Vec<u64> = (cursor + 1..=last).collect();
    assert_eq!(seqs(&replay), expected);
    for replayed in &replay {
        assert!(replayed.same_as(&frames[replayed.seq as usize]));
    }
}

#[tokio::test]
async fn disconnect_mid_turn_then_resume_has_no_gap_or_duplicate() {
    let (provider, mut gate) = gated_provider(Script::Text, false);
    let daemon = start_daemon(provider).await;

    let (mut first, session_id, created) = create(&daemon).await;
    first.send(&submit(session_id, "hello")).await;
    gate.entered().await;

    // Read while the provider is parked, up to and including the turn's first task,
    // then stop reading and drop the connection. Whatever else was already written to
    // this socket is lost with it.
    let mut received = vec![created];
    loop {
        let event = first.recv().await.expect("the first connection is open");
        let frame = committed(event.clone(), session_id)
            .unwrap_or_else(|| panic!("expected a Committed frame, got {event:?}"));
        let is_task = matches!(frame.payload, EventPayload::TaskCreated { .. });
        received.push(frame);
        if is_task {
            break;
        }
    }
    let root_task = received.last().unwrap().task_id.expect("a task event");
    let cursor = received.last().unwrap().seq;
    drop(first);

    // The turn keeps running without its client (ruling W1-R51).
    gate.release();

    let mut resumed = Conn::open(
        &daemon.socket_path,
        &ClientRequest::Resume {
            session_id,
            after_seq: cursor,
        },
    )
    .await;
    assert!(matches!(
        resumed.recv().await,
        Some(ClientEvent::Ack { .. })
    ));
    loop {
        let event = resumed
            .recv()
            .await
            .expect("the resumed connection is open");
        let frame = committed(event.clone(), session_id)
            .unwrap_or_else(|| panic!("expected a Committed frame, got {event:?}"));
        let done = frame.task_id == Some(root_task)
            && matches!(frame.payload, EventPayload::TaskCompleted { .. });
        received.push(frame);
        if done {
            break;
        }
    }

    let got = seqs(&received);
    let expected: Vec<u64> = (0..got.len() as u64).collect();
    assert_eq!(
        got, expected,
        "the two connections together must cover every seq exactly once"
    );
}

#[tokio::test]
async fn resume_ahead_of_head_gets_resync_required() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;
    let (_creator, session_id, created) = create(&daemon).await;
    assert_eq!(created.seq, 0);

    let mut viewer = Conn::open(
        &daemon.socket_path,
        &ClientRequest::Resume {
            session_id,
            after_seq: 5,
        },
    )
    .await;
    match viewer.recv().await {
        Some(ClientEvent::ResyncRequired {
            session_id: resync,
            head,
        }) => {
            assert_eq!(resync, session_id);
            assert_eq!(head, Some(0));
        }
        other => panic!("expected ResyncRequired, got {other:?}"),
    }
    assert!(
        viewer.recv().await.is_none(),
        "ResyncRequired is terminal: the connection must close after it"
    );
}

/// From `deadlock_invariant`'s pattern: one attached client that never reads cannot hold
/// up anyone else. The bulk script produces far more bytes than the stalled client's
/// socket buffer and event channel can absorb, so its own connection really is wedged
/// while the creator's turn runs.
#[tokio::test]
async fn slow_subscriber_does_not_stall_another() {
    let (provider, _gate) = gated_provider(Script::Bulk, true);
    let daemon = start_daemon(provider).await;
    let (mut creator, session_id, _created) = create(&daemon).await;

    let mut stalled = Conn::open(&daemon.socket_path, &ClientRequest::Attach { session_id }).await;
    assert!(matches!(
        stalled.recv().await,
        Some(ClientEvent::Ack { .. })
    ));
    // From here on `stalled` is never read again, but stays connected.

    creator.send(&submit(session_id, "hello")).await;
    let (frames, outcome, _) = until_turn_finished(&mut creator, session_id).await;
    assert!(matches!(outcome, TurnOutcome::Completed), "{outcome:?}");
    let delta_bytes: usize = frames
        .iter()
        .filter_map(|f| match &f.payload {
            EventPayload::TaskDelta {
                delta: roundhouse_core::Delta::Text { text },
            } => Some(text.len()),
            _ => None,
        })
        .sum();
    assert!(
        delta_bytes >= BULK_DELTAS * BULK_DELTA_BYTES,
        "the creator must have received the whole bulk reply ({delta_bytes} bytes)"
    );
    drop(stalled);
}

/// The creator's `CloseSession`: the connection delivers the durable `SessionClosed`, then
/// the `Ack`, then closes.
#[tokio::test]
async fn close_session_delivers_session_closed_then_ack_then_ends() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;
    let (mut creator, session_id, frames) = session_with_one_turn(&daemon).await;

    creator
        .send(&ClientRequest::CloseSession { session_id })
        .await;
    let mut next_seq = frames.last().unwrap().seq + 1;
    let mut saw_closed = false;
    loop {
        match creator.recv().await {
            Some(ClientEvent::Ack { .. }) => break,
            Some(event) => {
                let frame = committed(event.clone(), session_id)
                    .unwrap_or_else(|| panic!("expected Committed or Ack, got {event:?}"));
                assert_eq!(frame.seq, next_seq, "no gap before the Ack");
                next_seq += 1;
                assert!(!saw_closed, "nothing may follow SessionClosed but the Ack");
                saw_closed = matches!(frame.payload, EventPayload::SessionClosed { .. });
            }
            None => panic!("the connection closed before the Ack"),
        }
    }
    assert!(saw_closed, "SessionClosed must be delivered before the Ack");
    assert!(
        creator.recv().await.is_none(),
        "the creator's connection must end after the Ack"
    );
}

/// The controller's ruling for #40: a session that was closed and then reaped (no live
/// registry entry) can still be resumed from the store, and the replay ends after
/// `SessionClosed`.
#[tokio::test]
async fn resume_after_close_and_reap_replays_the_stored_log_then_ends() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;
    let (mut creator, session_id, mut frames) = session_with_one_turn(&daemon).await;
    creator
        .send(&ClientRequest::CloseSession { session_id })
        .await;
    loop {
        match creator.recv().await {
            Some(ClientEvent::Ack { .. }) => break,
            Some(event) => frames.extend(committed(event, session_id)),
            None => panic!("the connection closed before the Ack"),
        }
    }
    assert!(matches!(
        frames.last().unwrap().payload,
        EventPayload::SessionClosed { .. }
    ));
    // What `spawn_session_reaper` does once the actor is `Closed`, done here directly
    // so the test does not wait on the reaper.
    daemon.registry.remove(session_id);
    assert!(daemon.registry.actor(session_id).is_none());

    let cursor = 2;
    let mut resumed = Conn::open(
        &daemon.socket_path,
        &ClientRequest::Resume {
            session_id,
            after_seq: cursor,
        },
    )
    .await;
    assert!(matches!(
        resumed.recv().await,
        Some(ClientEvent::Ack { .. })
    ));
    let mut replay = Vec::new();
    while let Some(event) = resumed.recv().await {
        replay.extend(committed(event, session_id));
    }
    let expected: Vec<u64> = (cursor + 1..=frames.last().unwrap().seq).collect();
    assert_eq!(
        seqs(&replay),
        expected,
        "the replay must run exactly to SessionClosed and then end"
    );
    for replayed in &replay {
        assert!(replayed.same_as(&frames[replayed.seq as usize]));
    }
}

/// A stored session with no terminator (its actor is gone, for example after a daemon
/// restart) is replayed up to the head it had when the viewer connected, then the
/// connection ends rather than waiting forever for events no actor will write.
#[tokio::test]
async fn attach_to_a_stored_session_without_a_terminator_replays_to_its_head_then_ends() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;
    let (creator, session_id, frames) = session_with_one_turn(&daemon).await;
    drop(creator);
    daemon.registry.remove(session_id);

    let mut viewer = Conn::open(&daemon.socket_path, &ClientRequest::Attach { session_id }).await;
    assert!(matches!(viewer.recv().await, Some(ClientEvent::Ack { .. })));
    let mut replay = Vec::new();
    while let Some(event) = viewer.recv().await {
        replay.extend(committed(event, session_id));
    }
    assert_eq!(seqs(&replay), seqs(&frames));
}

/// An in-process `tracing` sink, the same shape `tests/close_session.rs`'s own
/// `CapturingWriter` uses: the only observable proof, in
/// [`rejection_survives_an_external_close_once`] below, that its `SubmitTurn` has already
/// been refused (queued into `pending_rejections`) before the session is closed — the
/// refusal itself has no other visible side effect until it is either delivered or dropped,
/// which is exactly the two outcomes that helper tells apart.
#[derive(Clone, Default)]
struct CapturingWriter(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
    type Writer = CapturingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn captured_logs() -> (CapturingWriter, tracing::Dispatch) {
    let captured = CapturingWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .finish();
    (captured, tracing::Dispatch::new(subscriber))
}

impl CapturingWriter {
    fn contains(&self, needle: &str) -> bool {
        let rendered = String::from_utf8(self.0.lock().unwrap().clone())
            .expect("the tracing subscriber emits UTF-8");
        rendered.contains(needle)
    }
}

/// One attempt of
/// [`a_rejection_queued_before_an_external_close_is_still_delivered_before_eof`]: queues a
/// `session_not_live` rejection on a connection whose session's `Cancelling` and
/// `SessionClosed` are *already durably committed before the connection is even spawned* —
/// closed by something other than that connection's own `CloseSession`, so `close_task`/
/// `close_ack_pending` are never touched here — and reports whether the resulting
/// `TurnFinished { outcome: Rejected }` reached the wire before the connection ended.
///
/// Driven directly against `drive_established_session`, the same shape
/// `tests/close_session.rs` already uses, rather than a full `Conn` over the real socket.
///
/// Closing the session *before* the connection is spawned, rather than partway through
/// (this helper's first attempt at this test), is what makes the race below fair rather
/// than one-sided: with `Cancelling` and `SessionClosed` both already on disk, the
/// follower's very first catch-up read fetches both in the one real (thread-pool-bound)
/// database round trip, buffering them locally — every `follower.next()` call after that
/// is a plain in-memory `pop_front()`, exactly as cheap as `pending_rejections`' own
/// delivery. Closing the session mid-connection instead (tried first) forced a *second*,
/// separate database read to discover `SessionClosed` once it committed later, and that
/// read was consistently slower than the purely in-memory rejection reserving the freed
/// channel permit first — across 500 attempts against the unfixed guards, the rejection
/// always won, so the drop this finding names never reproduced. Loading both events from
/// one batch read removes that asymmetry and lets `tokio::select!`'s real (unbiased, no
/// `biased;` keyword) tie-break decide which of `pending_event` and `pending_rejections`
/// reaches each freed permit first, which is the actual race the underlying finding names.
///
/// `events_tx` is built with capacity 1, and a `Note` is committed *first*, before the
/// close, so the connection's very first frame consumes that one slot — deterministically,
/// since this test waits for `events_rx` to stop being empty (a non-consuming check) before
/// doing anything else. Only once that slot is confirmed full does this attempt remove the
/// session from the registry and send `SubmitTurn`: with no free capacity, neither
/// `pending_rejections` nor the follower's own next parked event (already fetched, per
/// above) can be delivered yet, so this attempt can queue the rejection and confirm (via
/// the `tracing` capture below) that it was queued with no risk of it — or `Cancelling` —
/// having already been delivered out from under this check.
///
/// What is *not* forced deterministic, deliberately, is which of `pending_rejections` and
/// the follower's own next parked event (`Cancelling`, then `SessionClosed`) wins each
/// *later* contested slot, once this test starts draining: that contention is itself the
/// `tokio::select!` race the underlying finding names ("a rejection queued just before a
/// CloseSession Ack can lose the select! race"). The fix does not make that particular
/// contention disappear; it makes `pending_rejections` win it *every* time by construction
/// (the break/`ack_ready` guards become mutually exclusive with a non-empty
/// `pending_rejections` rather than racing against it at all), so the caller runs this
/// attempt many times, and this helper's own job is only to land on the losing
/// interleaving often enough to prove that.
async fn rejection_survives_an_external_close_once() -> bool {
    let (captured, dispatch) = captured_logs();
    let _log_guard = tracing::dispatcher::set_default(&dispatch);

    let dir = tempfile::tempdir().unwrap();
    let resources = common::real_resources(dir.path()).await;
    let actor = common::real_actor_on(dir.path(), &resources).await;

    let registry = Arc::new(roundhouse_daemon::session_registry::SessionRegistry::new());
    let (session_id, subscription) = registry
        .create(actor.clone(), None, None)
        .expect("registering against a fresh registry must succeed");

    // Both committed, through the ordinary (non-gated) writer `real_actor_on` builds —
    // real `CommitFeed::notify`, so the follower below needs no special-cased wake-up
    // path to see either — and both BEFORE the connection is even spawned. See this
    // function's own doc comment for why that ordering (rather than closing partway
    // through, as a first attempt at this test did) is what makes the race fair.
    common::append_note(actor.writer(), session_id, "occupy the one slot").await;
    actor
        .close(SessionOutcome::Completed)
        .await
        .expect("closing a freshly created session must succeed");

    let (requests_tx, requests_rx) = mpsc::channel::<ClientRequest>(8);
    // Capacity 1 (not the usual 8): the note above must fully occupy this channel before
    // anything else is sent — see this function's own doc comment.
    let (events_tx, mut events_rx) = mpsc::channel::<ClientEvent>(1);

    tokio::spawn(drive_established_session(
        session_id,
        SessionLink::Live(subscription),
        None,
        true,
        requests_rx,
        events_tx,
        registry.clone(),
        resources,
    ));

    // Deterministic, non-consuming: waits for the note to occupy the channel's one slot
    // without draining it (draining here would free the slot this attempt needs held).
    tokio::time::timeout(BOUND, async {
        while events_rx.is_empty() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the connection must deliver its first frame into the one-slot channel");

    // Synchronous — the very next `SubmitTurn` this connection processes deterministically
    // hits `registry.actor(session_id) == None`, i.e. `session_not_live`.
    registry.remove(session_id);
    assert!(registry.actor(session_id).is_none());

    requests_tx.send(submit(session_id, "hello")).await.unwrap();

    // The refusal's only observable side effect before it is either delivered or dropped:
    // proves `pending_rejections` is genuinely non-empty before this attempt starts
    // draining. With the channel's one slot still held by the undrained note, neither the
    // rejection nor `Cancelling` can have been delivered already either.
    tokio::time::timeout(BOUND, async {
        while !captured.contains("refusing SubmitTurn: this session is no longer live") {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the SubmitTurn must be refused (and the refusal logged) before draining starts");

    let mut frames = Vec::new();
    loop {
        let next = tokio::time::timeout(BOUND, events_rx.recv())
            .await
            .unwrap_or_else(|_| panic!("the connection must not hang; frames so far: {frames:?}"));
        match next {
            Some(event) => frames.push(event),
            None => break,
        }
    }

    frames.iter().any(|event| {
        matches!(
            event,
            ClientEvent::TurnFinished {
                outcome: TurnOutcome::Rejected { reason },
                through_seq: None,
                ..
            } if reason == "session_not_live"
        )
    })
}

/// Final-review finding #40/1: a `TurnFinished { outcome: Rejected }` already queued in
/// `pending_rejections` must still reach the client even once this session's
/// `SessionClosed` becomes visible to this connection's own follower — before this fix,
/// `drive_established_session`'s top-of-loop break
/// (`session_closed_seen && turn_settled && close_task.is_none() && !close_ack_pending`)
/// ignored `pending_rejections` entirely, so it could fire (and the connection end) with a
/// reply still owed.
///
/// Runs [`rejection_survives_an_external_close_once`] repeatedly rather than once: which of
/// two starved `events_tx` reservations (the follower's own parked `SessionClosed`, or the
/// queued rejection) wins a given contested slot is itself a `tokio::select!` race — see
/// that helper's doc comment. Fixed code wins this race by construction on every attempt
/// (`pending_rejections.is_empty()` in the break/`ack_ready` guards makes the two
/// mutually exclusive rather than racing at all), so this loop must pass every single
/// attempt; buggy code loses often enough that this reliably fails within a handful.
#[tokio::test]
async fn a_rejection_queued_before_an_external_close_is_still_delivered_before_eof() {
    const ATTEMPTS: usize = 40;
    for attempt in 0..ATTEMPTS {
        assert!(
            rejection_survives_an_external_close_once().await,
            "attempt {attempt}/{ATTEMPTS}: the queued rejection must reach the client before \
             the connection ends"
        );
    }
}

/// An id with no registry entry and no stored events closes the connection with no reply,
/// as `Attach` always has, for `Resume` too.
#[tokio::test]
async fn resume_of_an_unknown_session_closes_without_a_reply() {
    let (provider, _gate) = gated_provider(Script::Text, true);
    let daemon = start_daemon(provider).await;
    let mut conn = Conn::open(
        &daemon.socket_path,
        &ClientRequest::Resume {
            session_id: SessionId::new(),
            after_seq: 0,
        },
    )
    .await;
    assert!(conn.recv().await.is_none());
}

/// A `SubmitTurn` pipelined while the previous turn's `TurnFinished` is still unsent (its
/// turn has finished, but this connection's stalled follower has not caught up to its
/// `through_seq`) must not cost the first turn its reply. The second is refused
/// (`turn_in_flight`), so the connection delivers exactly two `TurnFinished` frames: the
/// first turn's `Completed`, and a `Rejected` for the second.
///
/// The creator reads nothing while the bulk turn runs; a viewer reads it through to its
/// root task's completion, so the turn has finished before the second `SubmitTurn` is sent,
/// while the creator's follower is still far behind.
#[tokio::test]
async fn a_submit_turn_pipelined_behind_an_unsent_turn_finished_does_not_replace_it() {
    let (provider, mut gate) = gated_provider(Script::Bulk, false);
    let daemon = start_daemon(provider).await;

    let (mut creator, session_id, created) = create(&daemon).await;
    let mut viewer = Conn::open(&daemon.socket_path, &ClientRequest::Attach { session_id }).await;
    assert!(matches!(viewer.recv().await, Some(ClientEvent::Ack { .. })));

    creator.send(&submit(session_id, "first")).await;
    gate.entered().await;
    // Open the gate for every later call too, so a wrongly admitted second turn runs
    // to completion and reports.
    gate.permits.add_permits(1024);

    let mut root_task = None;
    loop {
        let event = viewer.recv().await.expect("the viewer is open");
        let frame = committed(event.clone(), session_id)
            .unwrap_or_else(|| panic!("expected a Committed frame, got {event:?}"));
        if root_task.is_none() && matches!(frame.payload, EventPayload::TaskCreated { .. }) {
            root_task = frame.task_id;
        }
        if root_task.is_some()
            && frame.task_id == root_task
            && matches!(frame.payload, EventPayload::TaskCompleted { .. })
        {
            break;
        }
    }

    creator.send(&submit(session_id, "second")).await;

    let mut frames = vec![created];
    let mut finished = Vec::new();
    while finished.len() < 2 {
        let event = creator
            .recv()
            .await
            .expect("the connection must stay open until both TurnFinished frames");
        match event {
            ClientEvent::TurnFinished {
                outcome,
                through_seq,
                ..
            } => finished.push((outcome, through_seq)),
            other => frames.extend(committed(other, session_id)),
        }
    }

    let completed: Vec<_> = finished
        .iter()
        .filter(|(o, _)| matches!(o, TurnOutcome::Completed))
        .collect();
    let rejected: Vec<_> = finished
        .iter()
        .filter(|(o, t)| {
            matches!(o, TurnOutcome::Rejected { reason } if reason == "turn_in_flight")
                && t.is_none()
        })
        .collect();
    assert_eq!(
        (completed.len(), rejected.len()),
        (1, 1),
        "expected the first turn's Completed and a Rejected for the second: {finished:?}"
    );
    let first_through = completed[0].1.expect("a completed turn has a through_seq");
    assert!(
        frames.iter().any(|f| f.seq == first_through),
        "the first turn's TurnFinished must follow every event it committed"
    );
}
