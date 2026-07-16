//! `Validator::None` (unverified, explicitly opted into) over HTTPS: the no-hasher path streams,
//! publishes, and resumes without computing any digest.
//!
//! Gated behind the `testing` feature because it needs a client that trusts the chaos server's
//! self-signed loopback certificate. This is dependency injection, not a certificate bypass: the
//! injected client still validates the server against that specific root, so the "cert errors are
//! terminal" posture is intact.

use apogee_fetch::{DownloadSpec, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, generated_vec};
use tokio_util::sync::CancellationToken;

const MIB: u64 = 1024 * 1024;

/// A client that trusts `cert_der` (and nothing else new), with the same no-compression policy the
/// real fetcher uses so downloaded bytes are exactly what the server sent.
fn client_trusting(cert_der: &[u8]) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    let cert = reqwest::Certificate::from_der(cert_der)?;
    Ok(reqwest::Client::builder()
        .gzip(false)
        .deflate(false)
        .add_root_certificate(cert)
        .build()?)
}

#[tokio::test]
async fn an_unverified_download_over_tls_streams_and_publishes() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 256 * 1024;
    let server = ChaosServer::builder(4, len).tls().start().await.unwrap();
    let fetcher = Fetcher::from_client(client_trusting(server.cert_der().unwrap()).unwrap());
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
    let fetcher = Fetcher::from_client(client_trusting(server.cert_der().unwrap()).unwrap());
    let spec = DownloadSpec::builder(server.url("file.bin"), &dest, Validator::None)
        .expected_len(len)
        .allow_unverified()
        .build()
        .unwrap();

    fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();
    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(5, 0, len as usize)
    );
}
