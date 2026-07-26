#![cfg(target_os = "linux")]
//! Fetching the signed runner catalog over HTTPS.
//!
//! Gated behind the `testing` feature because it needs a client that trusts the test server's
//! self-signed loopback certificate. That is dependency injection rather than a certificate bypass: the
//! injected client still validates the server against that specific root.
//!
//! The property under test is the one "a runner bump is a manifest edit" rests on. A catalog is fetched
//! with no content pin and no declared length, and under those terms the fetcher considers any existing
//! file at the destination to already satisfy the request. Download onto the cache path and the first
//! catalog ever fetched is served back forever, so a bumped runner row never reaches an install while
//! everything still appears to work.

use apogee_fetch::Fetcher;
use apogee_runtime::{Runtime, RuntimePaths};
use apogee_test_support::chaos::ChaosServer;
use tokio_util::sync::CancellationToken;

/// A client that trusts `cert_der` and nothing else new.
fn client_trusting(cert_der: &[u8]) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    Ok(reqwest::Client::builder()
        .gzip(false)
        .deflate(false)
        .add_root_certificate(reqwest::Certificate::from_der(cert_der)?)
        .build()?)
}

const CATALOG: &str = r#"{ "version": 1, "runners": [], "tools": [], "dxvk": [] }"#;

#[tokio::test]
async fn a_second_catalog_fetch_goes_back_to_the_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let manifest = ChaosServer::serving(CATALOG.as_bytes().to_vec())
        .tls()
        .start()
        .await
        .expect("manifest server");
    let signature = ChaosServer::serving(vec![0u8; 64])
        .tls()
        .start()
        .await
        .expect("signature server");

    let fetcher =
        Fetcher::from_client(client_trusting(manifest.cert_der().expect("cert")).expect("client"));
    let runtime = Runtime::new(
        fetcher,
        RuntimePaths {
            runners: dir.path().join("runners"),
            prefixes: dir.path().join("prefixes"),
        },
    );
    let (manifest_url, signature_url) = (
        manifest.url("manifest.json"),
        signature.url("manifest.json.sig"),
    );
    let cancel = CancellationToken::new();

    for attempt in 1..=2 {
        // The signature is not a real one, so verification fails. That is not what this asserts: the
        // request count is, because a frozen cache is invisible to everything else.
        let _ = runtime
            .fetch_catalog(&manifest_url, &signature_url, &cancel)
            .await;
        assert_eq!(
            manifest.stats().requests(),
            attempt,
            "fetch {attempt} must go back to the server rather than reuse a cached file"
        );
    }
}
