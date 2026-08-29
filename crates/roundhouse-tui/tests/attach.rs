use roundhouse_tui::{connect, ServerMessage};
use tokio::io::AsyncWriteExt;
use tokio::net::UnixListener;

#[tokio::test]
async fn attaches_and_decodes_one_ndjson_line() {
    let dir = tempfile::tempdir().unwrap();
    let socket_path = dir.path().join("round.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        stream
            .write_all(b"{\"type\":\"task_delta\",\"task_id\":\"t1\",\"text\":\"Hello\"}\n")
            .await
            .unwrap();
    });

    let mut client = connect(&socket_path).await.unwrap();
    let message = client.recv().await.unwrap();

    server.await.unwrap();

    assert_eq!(
        message,
        Some(ServerMessage::TaskDelta {
            task_id: "t1".into(),
            text: "Hello".into()
        })
    );
}
