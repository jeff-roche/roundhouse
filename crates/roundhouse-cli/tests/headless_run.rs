//! Black-box tests of the shipping binaries (#40): `round run --message`
//! against a real `round-daemon-internal` process whose Anthropic provider
//! points at a local mock (`support::mock_anthropic`) through
//! `ROUNDHOUSE_ANTHROPIC_BASE_URL`.
//!
//! Everything asserted here is read off the wire: `round`'s own stdout, its
//! exit code, and frames from a fresh socket connection. SQLite is never
//! opened. Every `tokio::time::timeout` is a failure bound (a hang becomes a
//! failed test), never the thing asserted.

mod support {
    pub mod mock_anthropic;
}

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use roundhouse_proto::{ClientEvent, ClientRequest, TurnOutcome};
use serde_json::Value;
use support::mock_anthropic::{MockAnthropic, Mode, HOLD_AFTER_TOOL_MARKER, HOLD_MARKER};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader, Lines};
use tokio::process::ChildStdout;

/// The workspace name the daemon registers and `round run` targets.
const WORKSPACE: &str = "headless";

/// What the `read` tool call reads; the model's second request must carry it.
const FIXTURE_CONTENTS: &str = "contents-the-read-tool-returns";

/// Failure bound for anything this file waits on.
const BOUND: Duration = Duration::from_secs(60);

/// A running daemon, its mock provider and the paths the tests need.
struct Harness {
    dir: tempfile::TempDir,
    socket: PathBuf,
    mock: MockAnthropic,
    _daemon: tokio::process::Child,
}

/// `round-daemon-internal` lives next to `round` in Cargo's target dir.
/// Cargo only builds it for a test run that includes `roundhouse-daemon`.
fn daemon_binary() -> PathBuf {
    let path = Path::new(env!("CARGO_BIN_EXE_round")).with_file_name("round-daemon-internal");
    assert!(
        path.exists(),
        "round-daemon-internal is missing at {}: run through `cargo test --workspace`, \
         which builds every workspace binary",
        path.display()
    );
    path
}

/// The environment both binaries run with: nothing inherited from the
/// developer's shell except `PATH`, so a real `ANTHROPIC_API_KEY` or proxy
/// setting never leaks into a test.
fn hermetic(command: &mut tokio::process::Command, home: &Path) {
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command.env("HOME", home).env("XDG_RUNTIME_DIR", home);
}

impl Harness {
    async fn start(mode: Mode) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().canonicalize().unwrap();
        let socket = home.join("round.sock");
        let workspace_root = home.join("workspace");
        std::fs::create_dir(&workspace_root).unwrap();
        let fixture = workspace_root.join("fixture.txt");
        std::fs::write(&fixture, FIXTURE_CONTENTS).unwrap();

        // An operator-scope (user-global) policy allowing exactly this read,
        // so the `read` task runs to completion instead of stopping at
        // `RequiresApproval`. User-global rules need no trust record.
        let policy_dir = home.join(".config/roundhouse");
        std::fs::create_dir_all(&policy_dir).unwrap();
        std::fs::write(
            policy_dir.join("policy.toml"),
            format!("[[rule]]\nid = 'fixture-read'\noutcome = 'allow'\nread = {fixture:?}\n"),
        )
        .unwrap();

        let mock = MockAnthropic::start(mode, &fixture).await;

        let mut command = tokio::process::Command::new(daemon_binary());
        hermetic(&mut command, &home);
        let daemon = command
            .arg("--socket")
            .arg(&socket)
            .arg("--workspace")
            .arg(format!("{WORKSPACE}={}", workspace_root.display()))
            .arg("--allow-degraded-to")
            .arg("none")
            .env("ANTHROPIC_API_KEY", "test")
            .env("ROUNDHOUSE_ANTHROPIC_BASE_URL", mock.base_url())
            .current_dir(&home)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn round-daemon-internal");

        // Bind happens before the accept loop starts; wait for the process to
        // get there. Bounded: a daemon that never binds fails the test.
        tokio::time::timeout(BOUND, async {
            while !socket.exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the daemon must bind its socket");

        Harness {
            dir,
            socket,
            mock,
            _daemon: daemon,
        }
    }

    /// Starts `round run --message <message>` and reads its `session_id=`
    /// line.
    async fn spawn_round_run(&self, message: &str) -> RunningRound {
        let home = self.dir.path().canonicalize().unwrap();
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_round"));
        hermetic(&mut command, &home);
        let mut child = command
            .args(["run", "--workspace", WORKSPACE, "--message", message])
            .env("ROUND_SOCKET", &self.socket)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn `round`");
        let mut stderr = child.stderr.take().unwrap();
        let stderr = tokio::spawn(async move {
            let mut text = String::new();
            let _ = stderr.read_to_string(&mut text).await;
            text
        });
        let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
        let first = tokio::time::timeout(BOUND, stdout.next_line())
            .await
            .expect("`round` must print its session id")
            .unwrap();
        let session_id = first
            .as_deref()
            .and_then(|line| line.strip_prefix("session_id="))
            .unwrap_or_else(|| panic!("stdout must start with session_id=, got {first:?}"))
            .to_string();
        RunningRound {
            child,
            stdout,
            stderr,
            session_id,
            frames: Vec::new(),
        }
    }

    /// Runs `round run --message <message>` to completion.
    async fn round_run(&self, message: &str) -> RunOutput {
        self.spawn_round_run(message).await.finish().await
    }
}

/// A `round run --message` still running, with the frames read so far.
struct RunningRound {
    child: tokio::process::Child,
    stdout: Lines<BufReader<ChildStdout>>,
    stderr: tokio::task::JoinHandle<String>,
    session_id: String,
    frames: Vec<Value>,
}

impl RunningRound {
    /// Reads stdout until a frame satisfies `wanted`. Bounded, so a frame
    /// that never arrives fails the test.
    async fn read_until(&mut self, what: &str, mut wanted: impl FnMut(&Value) -> bool) {
        let found = tokio::time::timeout(BOUND, async {
            while let Some(line) = self.stdout.next_line().await.unwrap() {
                let frame = parse_frame(&line);
                let done = wanted(&frame);
                self.frames.push(frame);
                if done {
                    return true;
                }
            }
            false
        })
        .await;
        match found {
            Ok(true) => {}
            Ok(false) => panic!("stdout ended before {what}; frames: {:#?}", self.frames),
            Err(_) => panic!(
                "{what} did not reach stdout within {BOUND:?}; frames: {:#?}",
                self.frames
            ),
        }
    }

    /// Reads the rest of stdout and waits for the exit. Bounded: `round`
    /// must exit once its turn finishes.
    async fn finish(mut self) -> RunOutput {
        let status = tokio::time::timeout(BOUND, async {
            while let Some(line) = self.stdout.next_line().await.unwrap() {
                self.frames.push(parse_frame(&line));
            }
            self.child.wait().await.unwrap()
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "`round run --message` must exit once its turn finishes; frames: {:#?}",
                self.frames
            )
        });
        RunOutput {
            code: status.code(),
            session_id: self.session_id,
            frames: self.frames,
            stderr: self.stderr.await.unwrap(),
        }
    }
}

fn parse_frame(line: &str) -> Value {
    serde_json::from_str(line)
        .unwrap_or_else(|err| panic!("stdout line {line:?} is not JSON: {err}"))
}

struct RunOutput {
    code: Option<i32>,
    session_id: String,
    frames: Vec<Value>,
    stderr: String,
}

impl RunOutput {
    /// Every `Committed` frame's body, in stdout order.
    fn committed(&self) -> Vec<&Value> {
        self.frames
            .iter()
            .filter_map(|frame| frame.get("Committed"))
            .collect()
    }

    /// The single `TurnFinished` frame's body, and its index in `frames`.
    fn turn_finished(&self) -> (usize, &Value) {
        let found: Vec<_> = self
            .frames
            .iter()
            .enumerate()
            .filter_map(|(i, frame)| frame.get("TurnFinished").map(|body| (i, body)))
            .collect();
        assert_eq!(
            found.len(),
            1,
            "exactly one TurnFinished expected, frames: {:#?}",
            self.frames
        );
        found[0]
    }

    /// The task ids of every `TaskCreated` of `kind`.
    fn task_ids_of_kind(&self, kind: &str) -> Vec<Value> {
        self.committed()
            .into_iter()
            .filter(|c| {
                c["payload"]
                    .get("TaskCreated")
                    .is_some_and(|created| created["kind"] == kind)
            })
            .map(|c| c["task_id"].clone())
            .collect()
    }

    /// Whether `task_id` has a committed event whose payload variant is
    /// `variant`.
    fn has_event_for_task(&self, task_id: &Value, variant: &str) -> bool {
        self.committed()
            .into_iter()
            .any(|c| &c["task_id"] == task_id && variant_name(&c["payload"]) == variant)
    }

    fn debug(&self) -> String {
        format!(
            "exit code {:?}\nstderr:\n{}\nframes:\n{:#?}",
            self.code, self.stderr, self.frames
        )
    }
}

/// The variant name of an externally tagged serde enum value.
fn variant_name(value: &Value) -> &str {
    match value {
        Value::String(name) => name,
        Value::Object(map) if map.len() == 1 => map.keys().next().unwrap(),
        other => panic!("not an externally tagged enum: {other}"),
    }
}

fn seq_of(committed: &Value) -> u64 {
    committed["seq"].as_u64().expect("Committed.seq is a u64")
}

#[tokio::test]
async fn run_message_streams_tool_turn_and_exits_zero() {
    let harness = Harness::start(Mode::Script).await;
    let mut running = harness
        .spawn_round_run(&format!(
            "please read the fixture: {HOLD_AFTER_TOOL_MARKER}"
        ))
        .await;

    // The read has run and the model's next request is parked, so the turn
    // is still open. Its events must already be on stdout: they are
    // published as they commit, not flushed when the turn ends.
    let release = tokio::time::timeout(BOUND, harness.mock.next_held_request())
        .await
        .expect("the request carrying the tool result must reach the mock");
    let mut read_tasks = Vec::new();
    running
        .read_until(
            "the read task's TaskCompleted while the turn is open",
            |frame| {
                let Some(committed) = frame.get("Committed") else {
                    return false;
                };
                let payload = &committed["payload"];
                if payload
                    .get("TaskCreated")
                    .is_some_and(|created| created["kind"] == "Read")
                {
                    read_tasks.push(committed["task_id"].clone());
                }
                variant_name(payload) == "TaskCompleted"
                    && read_tasks.contains(&committed["task_id"])
            },
        )
        .await;
    release.send(()).unwrap();

    let run = running.finish().await;
    let ctx = run.debug();

    assert_eq!(run.code, Some(0), "a completed turn exits 0\n{ctx}");

    let committed = run.committed();
    let seqs: Vec<u64> = committed.iter().map(|c| seq_of(c)).collect();
    let expected: Vec<u64> = (0..seqs.len() as u64).collect();
    assert_eq!(
        seqs, expected,
        "Committed seqs must be contiguous from 0\n{ctx}"
    );
    assert_eq!(variant_name(&committed[0]["payload"]), "SessionCreated");

    let read_tasks = run.task_ids_of_kind("Read");
    assert_eq!(read_tasks.len(), 1, "exactly one read task\n{ctx}");
    assert!(
        run.has_event_for_task(&read_tasks[0], "TaskCompleted"),
        "the read tool task must complete\n{ctx}"
    );
    // ... having really read the fixture: its contents reached the model's
    // next request as the tool result.
    let bodies = harness.mock.request_bodies();
    assert!(
        bodies
            .iter()
            .any(|body| body.contains("\"tool_result\"") && body.contains(FIXTURE_CONTENTS)),
        "the read's output must reach the next provider request\n{ctx}"
    );

    let (finished_at, finished) = run.turn_finished();
    assert_eq!(finished["outcome"], "Completed", "{ctx}");
    assert_eq!(finished["session_id"], run.session_id.as_str(), "{ctx}");
    let through_seq = finished["through_seq"]
        .as_u64()
        .unwrap_or_else(|| panic!("a completed turn carries through_seq\n{ctx}"));
    let before: Vec<u64> = run.frames[..finished_at]
        .iter()
        .filter_map(|frame| frame.get("Committed"))
        .map(seq_of)
        .collect();
    assert_eq!(
        before.last().copied(),
        Some(through_seq),
        "TurnFinished.through_seq must be the last seq sent before it\n{ctx}"
    );

    // After the outcome `round` closes the session: the close's own events
    // follow TurnFinished, contiguous and ending in SessionClosed, then the
    // Ack is the last frame.
    let (ack, after) = run.frames[finished_at + 1..]
        .split_last()
        .unwrap_or_else(|| panic!("frames must follow the outcome\n{ctx}"));
    assert!(
        ack.get("Ack").is_some(),
        "the close's Ack ends stdout\n{ctx}"
    );
    let after_seqs: Vec<u64> = after
        .iter()
        .map(|frame| {
            seq_of(
                frame
                    .get("Committed")
                    .unwrap_or_else(|| panic!("only Committed before the Ack\n{ctx}")),
            )
        })
        .collect();
    assert_eq!(after_seqs.first(), Some(&(through_seq + 1)), "{ctx}");
    assert_eq!(
        variant_name(&after.last().unwrap()["Committed"]["payload"]),
        "SessionClosed",
        "{ctx}"
    );

    // The daemon outlives the run.
    tokio::time::timeout(
        BOUND,
        roundhouse_tui::connect_create(&harness.socket, WORKSPACE),
    )
    .await
    .expect("connect_create must not hang")
    .expect("the daemon must still accept sessions after `round run` exits");
}

#[tokio::test]
async fn reconnect_resume_sees_the_same_events_exactly_once() {
    let harness = Harness::start(Mode::Script).await;
    let run = harness.round_run("please read the fixture").await;
    let ctx = run.debug();
    assert_eq!(run.code, Some(0), "{ctx}");

    let committed = run.committed();
    let last = seq_of(committed.last().unwrap());
    let k = last / 2;
    assert!(k > 0 && k < last, "a mid-run cursor\n{ctx}");

    let session_id = roundhouse_tui::SessionId::from_uuid(run.session_id.parse().unwrap());
    let mut client = tokio::time::timeout(
        BOUND,
        roundhouse_tui::connect_resume(&harness.socket, session_id, k),
    )
    .await
    .expect("connect_resume must not hang")
    .expect("a closed session can still be resumed from the store");

    let replayed = tokio::time::timeout(BOUND, async {
        let mut frames = Vec::new();
        while let Some(event) = client.recv().await.expect("recv") {
            frames.push(serde_json::to_value(&event).unwrap());
        }
        frames
    })
    .await
    .expect("a replay of a closed session ends after SessionClosed");

    let replayed_seqs: Vec<u64> = replayed
        .iter()
        .map(|frame| {
            seq_of(
                frame
                    .get("Committed")
                    .unwrap_or_else(|| panic!("only Committed frames on a replay: {frame}")),
            )
        })
        .collect();
    let expected: Vec<u64> = (k + 1..=last).collect();
    assert_eq!(
        replayed_seqs,
        expected,
        "a resume from {k} yields exactly {}..={last}\n{ctx}",
        k + 1
    );
    for frame in &replayed {
        let body = &frame["Committed"];
        let original = committed
            .iter()
            .find(|c| seq_of(c) == seq_of(body))
            .unwrap();
        assert_eq!(&body, original, "the replay carries the same event");
    }
    assert_eq!(
        variant_name(&replayed.last().unwrap()["Committed"]["payload"]),
        "SessionClosed"
    );
}

#[tokio::test]
async fn provider_failure_is_visible_and_exits_one() {
    let harness = Harness::start(Mode::Fail).await;
    let run = harness.round_run("please read the fixture").await;
    let ctx = run.debug();

    assert_eq!(run.code, Some(1), "a failed turn exits 1\n{ctx}");

    let infer_tasks = run.task_ids_of_kind("Infer");
    assert!(
        !infer_tasks.is_empty(),
        "the turn opened an infer task\n{ctx}"
    );
    assert!(
        infer_tasks
            .iter()
            .any(|task| run.has_event_for_task(task, "TaskFailed")),
        "the infer task's failure must be on stdout\n{ctx}"
    );

    let (_, finished) = run.turn_finished();
    let failed = finished["outcome"]
        .get("Failed")
        .unwrap_or_else(|| panic!("the outcome must be Failed\n{ctx}"));
    assert_eq!(failed["category"], "provider", "{ctx}");
}

#[tokio::test]
async fn another_active_session_does_not_delay_exit() {
    let harness = Harness::start(Mode::Script).await;

    // A second session whose turn the mock parks until released.
    let mut other = tokio::time::timeout(
        BOUND,
        roundhouse_tui::connect_create(&harness.socket, WORKSPACE),
    )
    .await
    .expect("connect_create must not hang")
    .expect("create the other session");
    let other_id = other.session_id();
    other
        .send(&ClientRequest::SubmitTurn {
            session_id: other_id,
            text: format!("please wait: {HOLD_MARKER}"),
        })
        .await
        .unwrap();
    let release = tokio::time::timeout(BOUND, harness.mock.next_held_request())
        .await
        .expect("the other session's provider request must reach the mock");

    // The other turn is provably in flight; this run must still finish.
    let run = harness.round_run("please read the fixture").await;
    let ctx = run.debug();
    assert_eq!(run.code, Some(0), "{ctx}");
    assert_eq!(run.turn_finished().1["outcome"], "Completed", "{ctx}");

    // Release the other turn, which then finishes normally.
    release.send(()).unwrap();
    let outcome = tokio::time::timeout(BOUND, async {
        loop {
            match other.recv().await.expect("recv") {
                Some(ClientEvent::TurnFinished { outcome, .. }) => return outcome,
                Some(_) => continue,
                None => panic!("the other session's connection ended before its outcome"),
            }
        }
    })
    .await
    .expect("the released turn must finish");
    assert!(matches!(outcome, TurnOutcome::Completed), "{outcome:?}");
}
