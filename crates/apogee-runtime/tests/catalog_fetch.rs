#![cfg(target_os = "linux")]
//! Fetching the signed runner catalog over HTTPS.
//!
//! Gated behind the `testing` feature for two injections, neither of which weakens anything the
//! shipping path does: a client that trusts the test servers' self-signed loopback certificates (and
//! nothing else new), and the verifying keys the fetch checks the manifest against, so a test can sign
//! bytes it can also produce. The shipping entry point still reads the compiled-in ones.
//!
//! Two properties, both invisible from outside. First, the one "a runner bump is a manifest edit"
//! rests on: a catalog is fetched with no content pin and no declared length, and under those terms
//! the fetcher considers any existing file at the destination to already satisfy the request.
//! Download onto the cache path and the first catalog ever fetched is served back forever, so a
//! bumped runner row never reaches an install while everything still appears to work. Second, only
//! bytes that verified are published, so a fetch carrying a signature that does not verify leaves the
//! last good pair alone.
//!
//! Each `ChaosServer` serves one body on every path, so the manifest and its detached signature come
//! from separate servers with separate certificates, and the client is built trusting all of them.

use std::error::Error;
use std::path::{Path, PathBuf};

use apogee_fetch::Fetcher;
use apogee_runtime::{CatalogError, Runtime, RuntimeError, RuntimePaths};
use apogee_test_support::catalog_sign::{sign_manifest, test_verifying_key_bytes};
use apogee_test_support::chaos::ChaosServer;
use tokio_util::sync::CancellationToken;

/// The shipped fetcher, trusting `certs` and nothing else new.
fn fetcher_trusting(certs: &[&[u8]]) -> Result<Fetcher, Box<dyn Error>> {
    let mut builder = Fetcher::builder();
    for der in certs {
        builder = builder.extra_root_certificate(der);
    }
    Ok(builder.build()?)
}

const CATALOG: &str = r#"{ "version": 1, "runners": [], "tools": [], "dxvk": [] }"#;

/// Where a verified catalog is published, which is the runtime's own layout: a `.catalog` directory
/// beside the runners.
fn published(root: &Path) -> (PathBuf, PathBuf) {
    let cache = root.join("runners").join(".catalog");
    (cache.join("catalog.json"), cache.join("catalog.json.sig"))
}

/// A runtime whose fetcher trusts every server below, plus the three servers: the manifest, a
/// signature over it that verifies, and one that does not.
struct Servers {
    manifest: ChaosServer,
    good: ChaosServer,
    bad: ChaosServer,
}

impl Servers {
    async fn start() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            manifest: ChaosServer::serving(CATALOG.as_bytes().to_vec())
                .tls()
                .start()
                .await?,
            good: ChaosServer::serving(sign_manifest(CATALOG.as_bytes()).to_vec())
                .tls()
                .start()
                .await?,
            // A well-formed 64-byte signature that is simply not this manifest's, so the rejection is
            // the verification failing rather than a length check.
            bad: ChaosServer::serving(sign_manifest(b"a different manifest").to_vec())
                .tls()
                .start()
                .await?,
        })
    }

    fn runtime(&self, root: &Path) -> Result<Runtime, Box<dyn Error>> {
        let der = |s: &ChaosServer| -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(s.cert_der()
                .ok_or("server is not running over tls")?
                .to_vec())
        };
        let (m, g, b) = (der(&self.manifest)?, der(&self.good)?, der(&self.bad)?);
        Ok(Runtime::new(
            fetcher_trusting(&[&m, &g, &b])?,
            RuntimePaths {
                runners: root.join("runners"),
                prefixes: root.join("prefixes"),
            },
        ))
    }
}

/// The fetch is the only thing that establishes the catalog is authentic, so a signature that does not
/// verify has to end it: nothing parsed is returned and nothing reaches the cache, where a later read
/// would find a manifest sitting where a verified one belongs.
#[tokio::test]
async fn a_signature_that_does_not_verify_publishes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let runtime = servers.runtime(dir.path()).expect("runtime");
    let (manifest_path, signature_path) = published(dir.path());

    let err = runtime
        .fetch_catalog_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.bad.url("manifest.json.sig"),
            &[test_verifying_key_bytes()],
            &CancellationToken::new(),
        )
        .await
        .expect_err("a signature over other bytes cannot verify");

    assert!(
        matches!(err, RuntimeError::Catalog(CatalogError::BadSignature)),
        "the rejection must name the signature, not some earlier failure: {err:?}"
    );
    assert!(!manifest_path.exists(), "no manifest may be published");
    assert!(!signature_path.exists(), "no signature may be published");
}

/// The publish is two renames out of staging, so the pair that lands has to be the pair that verified,
/// and it has to land at all: a fetch that verifies and publishes nothing would be a catalog nothing
/// can read back.
#[tokio::test]
async fn a_verified_catalog_is_returned_and_published() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let runtime = servers.runtime(dir.path()).expect("runtime");
    let (manifest_path, signature_path) = published(dir.path());

    let catalog = runtime
        .fetch_catalog_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.good.url("manifest.json.sig"),
            &[test_verifying_key_bytes()],
            &CancellationToken::new(),
        )
        .await
        .expect("a manifest signed by the key it is checked against");

    assert_eq!(catalog.version, 1);
    assert_eq!(
        std::fs::read(&manifest_path).expect("published manifest"),
        CATALOG.as_bytes(),
        "the bytes that verified are the bytes that landed"
    );
    assert_eq!(
        std::fs::read(&signature_path).expect("published signature"),
        sign_manifest(CATALOG.as_bytes()).to_vec()
    );
}

/// A previously published pair is the last good copy, and a failed fetch must not be able to destroy
/// it: staging exists so that only verified bytes ever overwrite it.
#[tokio::test]
async fn a_failed_fetch_leaves_the_last_good_catalog_in_place() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let runtime = servers.runtime(dir.path()).expect("runtime");
    let (manifest_path, signature_path) = published(dir.path());
    let cancel = CancellationToken::new();

    runtime
        .fetch_catalog_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.good.url("manifest.json.sig"),
            &[test_verifying_key_bytes()],
            &cancel,
        )
        .await
        .expect("the good fetch");

    let _ = runtime
        .fetch_catalog_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.bad.url("manifest.json.sig"),
            &[test_verifying_key_bytes()],
            &cancel,
        )
        .await
        .expect_err("the bad fetch");

    assert_eq!(
        std::fs::read(&manifest_path).expect("manifest still there"),
        CATALOG.as_bytes()
    );
    assert_eq!(
        std::fs::read(&signature_path).expect("signature still there"),
        sign_manifest(CATALOG.as_bytes()).to_vec()
    );
}

/// The overlap window, through the path a launch actually takes. A rotation's middle step is a client
/// carrying the new key first and the old one behind it, served a catalog the re-sign has not reached
/// yet; the launch has to keep working, and the bytes have to keep reaching the cache. Asserted here
/// rather than only on the parser, because it is the fetch entry point that chooses which keys the
/// verification sees, and passing only the first would be invisible to a unit test.
#[tokio::test]
async fn a_catalog_signed_by_a_retired_key_still_fetches_and_publishes() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let runtime = servers.runtime(dir.path()).expect("runtime");
    let (manifest_path, _) = published(dir.path());
    // A successor released ahead of the re-sign, so the key that signed this catalog is the second.
    let successor = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
        .verifying_key()
        .to_bytes();

    let catalog = runtime
        .fetch_catalog_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.good.url("manifest.json.sig"),
            &[successor, test_verifying_key_bytes()],
            &CancellationToken::new(),
        )
        .await
        .expect("a key inside its overlap window still admits the catalog");

    assert_eq!(catalog.version, 1);
    assert_eq!(
        std::fs::read(&manifest_path).expect("published manifest"),
        CATALOG.as_bytes()
    );
}

/// The cache-reuse trap: with no content pin and no declared length the fetcher would treat a file
/// already at the destination as satisfying the request, so a catalog downloaded straight onto its
/// cache path is never fetched again. The request count is the only place that shows.
#[tokio::test]
async fn a_second_catalog_fetch_goes_back_to_the_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let runtime = servers.runtime(dir.path()).expect("runtime");
    let cancel = CancellationToken::new();

    for attempt in 1..=2 {
        runtime
            .fetch_catalog_for_testing(
                &servers.manifest.url("manifest.json"),
                &servers.good.url("manifest.json.sig"),
                &[test_verifying_key_bytes()],
                &cancel,
            )
            .await
            .expect("fetch");
        assert_eq!(
            servers.manifest.stats().requests(),
            attempt,
            "fetch {attempt} must go back to the server rather than reuse a cached file"
        );
    }
}
