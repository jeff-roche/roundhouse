//! Proves the on-disk `.cassette` file format (documented in
//! `src/cassette.rs`'s module doc) round-trips through
//! `CassetteTransport::from_file` correctly, and that `ChunkStrategy` maps
//! onto the existing `chunk_size` field the way the module doc claims.

use futures::StreamExt;
use roundhouse_provider::{CassetteTransport, ChunkStrategy, HttpRequest, HttpTransport};
use std::path::Path;

fn hello_cassette_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cassettes/hello.cassette")
}

#[test]
fn from_file_parses_status_headers_and_body() {
    let transport = CassetteTransport::from_file(&hello_cassette_path(), ChunkStrategy::WholeBody)
        .expect("hello.cassette must parse");

    assert_eq!(transport.status, 200);
    assert_eq!(
        transport.headers,
        vec![
            ("content-type".to_string(), "text/event-stream".to_string()),
            ("x-request-id".to_string(), "abc123".to_string()),
        ]
    );
    assert_eq!(
        transport.body,
        b"data: {\"type\":\"ping\"}\n\ndata: {\"type\":\"pong\"}\n\n".to_vec()
    );
}

#[tokio::test]
async fn chunk_strategy_whole_body_replays_in_one_chunk() {
    let transport =
        CassetteTransport::from_file(&hello_cassette_path(), ChunkStrategy::WholeBody).unwrap();
    let resp = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://example.invalid".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .unwrap();
    let chunks: Vec<Vec<u8>> = resp.body.map(|c| c.unwrap().to_vec()).collect().await;
    assert_eq!(chunks.len(), 1);
}

#[tokio::test]
async fn chunk_strategy_fixed_splits_into_fixed_size_chunks() {
    let transport =
        CassetteTransport::from_file(&hello_cassette_path(), ChunkStrategy::Fixed(3)).unwrap();
    let resp = transport
        .send(HttpRequest {
            method: "POST".into(),
            url: "https://example.invalid".into(),
            headers: vec![],
            body: vec![],
        })
        .await
        .unwrap();
    let chunks: Vec<Vec<u8>> = resp.body.map(|c| c.unwrap().to_vec()).collect().await;
    assert!(chunks.iter().all(|c| c.len() <= 3));
    assert!(chunks.len() > 1);
    let reassembled: Vec<u8> = chunks.concat();
    assert_eq!(reassembled, transport.body);
}

#[tokio::test]
async fn chunk_strategy_prime_uses_the_prime_as_chunk_size() {
    let transport =
        CassetteTransport::from_file(&hello_cassette_path(), ChunkStrategy::Prime(17)).unwrap();
    assert_eq!(transport.chunk_size, 17);
}

#[test]
fn from_file_reports_a_missing_file_as_an_io_error() {
    let missing =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/cassettes/nope.cassette");
    let result = CassetteTransport::from_file(&missing, ChunkStrategy::WholeBody);
    assert!(result.is_err());
}

#[test]
fn from_file_reports_a_missing_blank_line_separator_as_an_io_error() {
    let dir = std::env::temp_dir().join(format!("roundhouse-cassette-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("no_separator.cassette");
    std::fs::write(&path, b"200\ncontent-type: text/plain\nno blank line here").unwrap();

    let result = CassetteTransport::from_file(&path, ChunkStrategy::WholeBody);
    assert!(
        result.is_err(),
        "a cassette with no header/body separator must be rejected"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
