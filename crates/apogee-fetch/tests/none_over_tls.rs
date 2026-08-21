//! `Validator::None` (unverified, explicitly opted into) over HTTPS: the no-hasher path streams,
//! publishes, and resumes without computing any digest.
//!
//! Gated behind the `testing` feature because the fetcher has to trust the chaos server's
//! self-signed loopback certificate. This is an extra trusted root, not a certificate bypass: the
//! client still validates the server against that specific root, so the "cert errors are terminal"
//! posture is intact, and everything else about the client is exactly what ships.

use apogee_fetch::{DownloadSpec, Fetcher, Phase, Validator};
use apogee_test_support::chaos::{ChaosServer, generated_vec};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

#[tokio::test]
async fn an_unverified_download_over_tls_streams_and_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 256 * 1024;
    let server = ChaosServer::builder(4, len).tls().start().await.unwrap();
    let fetcher = Fetcher::builder()
        .extra_root_certificate(server.cert_der().unwrap())
        .build()
        .unwrap();
    let spec = DownloadSpec::builder(server.url("file.bin"), &dest, Validator::None)
        .expected_len(len)
        .allow_unverified()
        .build()
        .unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(4, 0, len as usize)
    );
}

#[tokio::test]
async fn an_unverified_download_over_tls_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 4 * MIB;
    let server = ChaosServer::builder(5, len)
        .tls()
        .etag("\"v1\"")
        .drop_after(2 * MIB)
        .chunk(64 * 1024)
        .start()
        .await
        .unwrap();
    let fetcher = Fetcher::builder()
        .extra_root_certificate(server.cert_der().unwrap())
        .build()
        .unwrap();
    let spec = DownloadSpec::builder(server.url("file.bin"), &dest, Validator::None)
        .expected_len(len)
        .allow_unverified()
        .build()
        .unwrap();

    // The drop is absorbed inside the one call: the conditional range picks up at the watermark and
    // no digest is computed anywhere along the way. The builder takes the default retry policy, so
    // this waits out one real backoff.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let verified = fetcher
        .download(&spec, Some(tx), CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(5, 0, len as usize)
    );
    let mut progress = Vec::new();
    while let Ok(event) = rx.try_recv() {
        progress.push(event);
    }
    // The server's forced write offset is not the client's durable watermark: a TCP reset can cost
    // bytes already handed to the Windows socket. The first connecting event after the retry is the
    // downloader's journaled prefix after it flushed and synced everything the body actually yielded.
    let watermark = progress
        .iter()
        .find(|event| event.phase == Phase::Connecting && event.recoveries.retries == 1)
        .map(|event| event.bytes_done)
        .expect("the retry reports its durable watermark");
    let starts = server.stats().requested_starts();
    assert_eq!(
        starts.len(),
        2,
        "expected one drop and one retry: {starts:?}"
    );
    assert_eq!(starts[0], 0, "the initial request was not a fresh transfer");
    assert_eq!(
        starts[1], watermark,
        "the retry re-fetched bytes the downloader had already journaled",
    );
    assert!(
        watermark > 0 && watermark < len,
        "the retry restarted or skipped the remainder at {watermark} of {len}",
    );
    let served = server.stats().served_ranges();
    assert_eq!(
        served,
        vec![0..2 * MIB, watermark..len],
        "the server did not serve exactly one interrupted body and its unbanked remainder",
    );
    assert!(
        server.stats().bytes_served() < len + 2 * MIB,
        "the recovery spent a full restart or more on a single forced drop",
    );
}
