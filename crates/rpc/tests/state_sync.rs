//! End-to-end state-sync test: a real axum server serving
//! `/snapshot/manifest` + `/snapshot/chunk/{i}` over a real socket,
//! fetched by the `statesync` blocking client.
//!
//! This is the wire contract the `--state-sync` fullnode flag
//! depends on — hex bodies, manifest codec, chunk boundaries, and
//! per-chunk hash verification all exercised over TCP, not just
//! handler-level unit calls.

use std::sync::Arc;

use rpc::server::HttpServer;
use rpc::{RpcServer, SnapshotProvider};

/// Deterministic stub provider: a fixed blob + matching meta, as if
/// exported from an executor at height 7.
struct StubProvider {
    blob: Vec<u8>,
    root: primitives::Hash,
}

impl SnapshotProvider for StubProvider {
    fn export_snapshot(&self) -> Result<Vec<u8>, String> {
        Ok(self.blob.clone())
    }
    fn snapshot_meta(&self) -> Result<(u64, primitives::Hash, u32), String> {
        Ok((7, self.root, 2))
    }
}

#[tokio::test]
async fn state_sync_manifest_and_chunks_over_http() {
    // 10 KiB blob → with 4 MiB chunks this is a single-chunk
    // snapshot; the manifest + hash path is what matters, not
    // multi-chunk math (unit-tested in the statesync crate).
    let blob: Vec<u8> = (0..10_000u32).map(|i| (i % 251) as u8).collect();
    let root = primitives::Hash([7; 32]);

    let mut rpc = RpcServer::new(1, 1_000_000_000);
    rpc.set_snapshot_provider(Arc::new(StubProvider { blob: blob.clone(), root }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = HttpServer::from_shared(Arc::new(rpc), addr.clone());
    tokio::spawn(server.serve_on(listener));

    // The blocking client must not run on the test's
    // current-thread runtime — `spawn_blocking` keeps the runtime
    // thread free to drive the spawned server.
    let blob_clone = blob.clone();
    let fetched = tokio::task::spawn_blocking(move || {
        statesync::fetch_snapshot(&addr, 7, &root, 2).expect("fetch_snapshot must succeed")
    })
    .await
    .expect("client task panicked");
    assert_eq!(fetched, blob_clone, "assembled blob must equal the served blob");
}

#[tokio::test]
async fn state_sync_rejects_wrong_trusted_root() {
    let blob: Vec<u8> = vec![1, 2, 3];
    let root = primitives::Hash([7; 32]);
    let wrong = primitives::Hash([9; 32]);

    let mut rpc = RpcServer::new(1, 1_000_000_000);
    rpc.set_snapshot_provider(Arc::new(StubProvider { blob, root }));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = HttpServer::from_shared(Arc::new(rpc), addr.clone());
    tokio::spawn(server.serve_on(listener));

    let result =
        tokio::task::spawn_blocking(move || statesync::fetch_snapshot(&addr, 7, &wrong, 2))
            .await
            .expect("client task panicked");
    assert!(
        matches!(result, Err(statesync::SyncError::Untrusted)),
        "wrong trusted root must abort before downloading, got {result:?}"
    );
}

/// `/snapshot/cert/{height}` over real HTTP: before the engine
/// mirrors a cert the endpoint 404s (the client's poll loop keeps
/// retrying), and once recorded it serves codec bytes that decode
/// to the identical certificate.
#[tokio::test]
async fn exec_cert_over_http() {
    let blob: Vec<u8> = vec![1, 2, 3];
    let root = primitives::Hash([7; 32]);
    let mut rpc = RpcServer::new(1, 1_000_000_000);
    rpc.set_snapshot_provider(Arc::new(StubProvider { blob, root }));
    let rpc = Arc::new(rpc);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = HttpServer::from_shared(Arc::clone(&rpc), addr.clone());
    tokio::spawn(server.serve_on(listener));

    // Nothing mirrored yet → the endpoint 404s (client polls).
    {
        let addr = addr.clone();
        let early =
            tokio::task::spawn_blocking(move || statesync::fetch_exec_certificate(&addr, 7))
                .await
                .expect("client task panicked");
        assert!(early.is_err(), "no cert mirrored yet must fail");
    }

    let cert = types::ExecCertificate {
        height: primitives::Height::new(7),
        state_root: root,
        epoch: primitives::Epoch::new(0),
        signer_bitmap: vec![0b0000_0111],
        aggregate_signature: crypto::AggregateSignature::ZERO,
    };
    rpc.record_exec_certificates(vec![cert.clone()]);

    let fetched = tokio::task::spawn_blocking(move || {
        statesync::fetch_exec_certificate(&addr, 7).expect("cert must be served once mirrored")
    })
    .await
    .expect("client task panicked");
    assert_eq!(fetched, cert, "cert must round-trip over the wire unchanged");
}
