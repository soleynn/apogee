//! Fetching the signed component manifest over HTTPS.
//!
//! Gated behind the `testing` feature for two injections, neither of which weakens anything the
//! shipping path does: a client that trusts the test servers' self-signed loopback certificates (and
//! nothing else new), and the verifying key the fetch checks the manifest against, so a test can sign
//! bytes it can also produce. The shipping entry point still reads the compiled-in key.
//!
//! Two properties, both invisible from outside. First, the one every "a component is a manifest edit"
//! claim rests on: a manifest is fetched with no content pin and no declared length, and under those
//! terms the fetcher considers any existing file at the destination to already satisfy the request.
//! Download onto the cache path and the first manifest ever fetched is served back forever, while
//! everything still appears to work. Second, only bytes that verified are published, so the cache a
//! launch falls back to holds a manifest that once verified rather than whatever arrived last.
//!
//! Each `ChaosServer` serves one body on every path, so the manifest and its detached signature come
//! from separate servers with separate certificates, and the client is built trusting all of them.

use std::error::Error;
use std::path::{Path, PathBuf};

use apogee_addons::{AddonError, AddonPaths, Addons, ComponentManifest, ManifestError};
use apogee_fetch::Fetcher;
use apogee_runtime::{Runtime, RuntimePaths};
use apogee_test_support::catalog_sign::{sign_manifest, test_verifying_key};
use apogee_test_support::chaos::ChaosServer;
use tokio_util::sync::CancellationToken;

/// A client that trusts `certs` and nothing else new, matching the real fetcher's no-compression policy
/// so the bytes that arrive are exactly what was served.
fn client_trusting(certs: &[&[u8]]) -> Result<reqwest::Client, Box<dyn Error>> {
    let mut builder = reqwest::Client::builder().gzip(false).deflate(false);
    for der in certs {
        builder = builder.add_root_certificate(reqwest::Certificate::from_der(der)?);
    }
    Ok(builder.build()?)
}

const MANIFEST: &str = r#"{ "version": 1, "verbs": [
    { "name": "a-verb", "reason": "why it exists", "ops": [] } ] }"#;

/// Where a verified manifest and its signature are published, which is the crate's own layout: a
/// `.catalog` directory beside the components.
fn published(root: &Path) -> (PathBuf, PathBuf) {
    let cache = root.join("components").join(".catalog");
    (
        cache.join("components.json"),
        cache.join("components.json.sig"),
    )
}

/// The three servers a fetch is driven against: the manifest, a signature over it that verifies, and one
/// that does not.
struct Servers {
    manifest: ChaosServer,
    good: ChaosServer,
    bad: ChaosServer,
}

impl Servers {
    async fn start() -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            manifest: ChaosServer::serving(MANIFEST.as_bytes().to_vec())
                .tls()
                .start()
                .await?,
            good: ChaosServer::serving(sign_manifest(MANIFEST.as_bytes()).to_vec())
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

    /// An `Addons` whose fetcher trusts all three, installing under `root`.
    fn addons(&self, root: &Path) -> Result<Addons, Box<dyn Error>> {
        let der = |s: &ChaosServer| -> Result<Vec<u8>, Box<dyn Error>> {
            Ok(s.cert_der()
                .ok_or("server is not running over tls")?
                .to_vec())
        };
        let (m, g, b) = (der(&self.manifest)?, der(&self.good)?, der(&self.bad)?);
        let fetcher = Fetcher::from_client(client_trusting(&[&m, &g, &b])?);
        let runtime = Runtime::new(fetcher.clone(), RuntimePaths::default());
        Ok(Addons::new(
            runtime,
            fetcher,
            AddonPaths {
                components: root.join("components"),
            },
        ))
    }
}

/// The fetch is the only thing that establishes the manifest is authentic, so a signature that does not
/// verify has to end it: nothing parsed is returned and nothing reaches the cache, where a later read
/// would find a manifest sitting where a verified one belongs.
#[tokio::test]
async fn a_signature_that_does_not_verify_publishes_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let addons = servers.addons(dir.path()).expect("addons");
    let (manifest_path, signature_path) = published(dir.path());

    let err = addons
        .fetch_manifest_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.bad.url("manifest.json.sig"),
            &test_verifying_key(),
            &CancellationToken::new(),
        )
        .await
        .expect_err("a signature over other bytes cannot verify");

    assert!(
        matches!(err, AddonError::Manifest(ManifestError::BadSignature)),
        "the rejection must name the signature, not some earlier failure: {err:?}"
    );
    assert!(!manifest_path.exists(), "no manifest may be published");
    assert!(!signature_path.exists(), "no signature may be published");
}

/// The publish is two renames out of staging, so the pair that lands has to be the pair that verified,
/// and the cache read has to hand back what landed: a fetch that verifies and publishes nothing would
/// leave a launch with no fallback at all.
#[tokio::test]
async fn a_verified_fetch_is_what_the_cache_holds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let addons = servers.addons(dir.path()).expect("addons");
    let (manifest_path, signature_path) = published(dir.path());

    let fetched = addons
        .fetch_manifest_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.good.url("manifest.json.sig"),
            &test_verifying_key(),
            &CancellationToken::new(),
        )
        .await
        .expect("a manifest signed by the key it is checked against");
    assert!(fetched.verb("a-verb").is_some(), "the row that was served");

    assert_eq!(
        std::fs::read(&manifest_path).expect("published manifest"),
        MANIFEST.as_bytes(),
        "the bytes that verified are the bytes that landed"
    );
    assert_eq!(
        std::fs::read(&signature_path).expect("published signature"),
        sign_manifest(MANIFEST.as_bytes()).to_vec()
    );

    // And the fallback path reads that pair back rather than reporting an empty cache.
    let cached = addons
        .cached_manifest_for_testing(&test_verifying_key())
        .await
        .expect("the published pair verifies")
        .expect("a fetch published one");
    assert!(
        cached.verb("a-verb").is_some(),
        "the cache serves the rows that were fetched"
    );
}

/// A previously published pair is the last good copy, and a failed fetch must not be able to destroy it:
/// staging exists so that only verified bytes ever overwrite it.
#[tokio::test]
async fn a_failed_fetch_leaves_the_last_good_manifest_in_place() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let addons = servers.addons(dir.path()).expect("addons");
    let (manifest_path, signature_path) = published(dir.path());
    let cancel = CancellationToken::new();

    addons
        .fetch_manifest_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.good.url("manifest.json.sig"),
            &test_verifying_key(),
            &cancel,
        )
        .await
        .expect("the good fetch");

    let _ = addons
        .fetch_manifest_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.bad.url("manifest.json.sig"),
            &test_verifying_key(),
            &cancel,
        )
        .await
        .expect_err("the bad fetch");

    assert_eq!(
        std::fs::read(&manifest_path).expect("manifest still there"),
        MANIFEST.as_bytes()
    );
    assert_eq!(
        std::fs::read(&signature_path).expect("signature still there"),
        sign_manifest(MANIFEST.as_bytes()).to_vec()
    );
    assert!(
        addons
            .cached_manifest_for_testing(&test_verifying_key())
            .await
            .expect("the surviving pair verifies")
            .is_some(),
        "the fallback a launch depends on survived a fetch that did not verify"
    );
}

/// The cache is read off local disk, so where it came from is no evidence at all: between a file
/// anything on this machine can rewrite and a launch that starts whatever it names, the signature check
/// on the way back out is the only thing there is. Verifying on publish does not cover this, because the
/// bytes can change after they are published.
///
/// The tampered manifest is well-formed and asserted to parse on its own, so a refusal here cannot be
/// the parser rejecting garbage: it has to be the signature, which no longer belongs to these bytes.
#[tokio::test]
async fn a_cache_rewritten_after_it_was_published_is_refused() {
    /// Different rows under the signature that was published beside them.
    const TAMPERED: &str = r#"{ "version": 1, "verbs": [
        { "name": "planted-verb", "reason": "nobody signed this", "ops": [] } ] }"#;

    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let addons = servers.addons(dir.path()).expect("addons");
    let (manifest_path, _) = published(dir.path());

    addons
        .fetch_manifest_for_testing(
            &servers.manifest.url("manifest.json"),
            &servers.good.url("manifest.json.sig"),
            &test_verifying_key(),
            &CancellationToken::new(),
        )
        .await
        .expect("the fetch that publishes the pair");

    assert!(
        ComponentManifest::from_json_bytes(TAMPERED.as_bytes()).is_ok(),
        "the tampered bytes have to parse, or this passes on the parser rather than the signature"
    );
    std::fs::write(&manifest_path, TAMPERED).expect("rewrite the published manifest in place");

    let err = addons
        .cached_manifest_for_testing(&test_verifying_key())
        .await
        .expect_err("rows the key never signed must not reach a launch");
    assert!(
        matches!(err, AddonError::Manifest(ManifestError::BadSignature)),
        "the refusal names the signature rather than something the parser found: {err:?}"
    );
}

/// The cache-reuse trap: with no content pin and no declared length the fetcher would treat a file
/// already at the destination as satisfying the request, so a manifest downloaded straight onto its
/// cache path is never fetched again. The request count is the only place that shows.
#[tokio::test]
async fn a_second_fetch_goes_back_to_the_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    let servers = Servers::start().await.expect("servers");
    let addons = servers.addons(dir.path()).expect("addons");
    let cancel = CancellationToken::new();

    for attempt in 1..=2 {
        addons
            .fetch_manifest_for_testing(
                &servers.manifest.url("manifest.json"),
                &servers.good.url("manifest.json.sig"),
                &test_verifying_key(),
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
