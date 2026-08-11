//! `Validator::None` (unverified, explicitly opted into) over HTTPS: the no-hasher path streams,
//! publishes, and resumes without computing any digest.
//!
//! Gated behind the `testing` feature because the fetcher has to trust the chaos server's
//! self-signed loopback certificate. This is an extra trusted root, not a certificate bypass: the
//! client still validates the server against that specific root, so the "cert errors are terminal"
//! posture is intact, and everything else about the client is exactly what ships.

use apogee_fetch::{DownloadSpec, Fetcher, Validator};
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
    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(5, 0, len as usize)
    );
    assert_eq!(
        server.stats().served_ranges(),
        vec![0..2 * MIB, 2 * MIB..4 * MIB],
        "the retry asked only for the bytes past the drop",
    );
}
