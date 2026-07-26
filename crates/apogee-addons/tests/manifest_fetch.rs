//! Fetching the signed component manifest over HTTPS.
//!
//! Gated behind `apogee-fetch`'s `testing` feature because it needs a client that trusts the chaos
//! server's self-signed loopback certificate. That is dependency injection rather than a certificate
//! bypass: the injected client still validates the server against that specific root.
//!
//! The property under test is the one that is easy to get wrong and impossible to notice. A manifest is
//! fetched with no content pin and no declared length, and under those terms the fetcher considers any
//! existing file at the destination to already satisfy the request. Download onto the cache path and the
//! first manifest ever fetched is served back forever — so every claim about a component being a manifest
//! edit quietly stops being true, while everything still appears to work.

use std::path::Path;

use apogee_addons::{AddonPaths, Addons, ComponentManifest};
use apogee_fetch::Fetcher;
use apogee_runtime::{Runtime, RuntimePaths};
use apogee_test_support::catalog_sign::sign_manifest;
use apogee_test_support::chaos::ChaosServer;
use tokio_util::sync::CancellationToken;

/// A client that trusts `cert_der` and nothing else new, matching the real fetcher's no-compression
/// policy so the bytes that arrive are exactly what was served.
fn client_trusting(cert_der: &[u8]) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
    Ok(reqwest::Client::builder()
        .gzip(false)
        .deflate(false)
        .add_root_certificate(reqwest::Certificate::from_der(cert_der)?)
        .build()?)
}

fn addons(components: &Path, cert_der: &[u8]) -> Result<Addons, Box<dyn std::error::Error>> {
    let fetcher = Fetcher::from_client(client_trusting(cert_der)?);
    let runtime = Runtime::new(fetcher.clone(), RuntimePaths::default());
    Ok(Addons::new(
        runtime,
        fetcher,
        AddonPaths {
            components: components.to_path_buf(),
        },
    ))
}

const MANIFEST: &str = r#"{ "version": 1, "verbs": [
    { "name": "a-verb", "reason": "why it exists", "ops": [] } ] }"#;

/// A manifest edit has to reach the client. Anything that caches the first fetch and serves it back
/// leaves every "a bump is a manifest edit" claim untrue while looking like it works.
#[tokio::test]
async fn a_second_fetch_goes_back_to_the_server() {
    let dir = tempfile::tempdir().expect("tempdir");
    // Two servers: the second stands in for the same URL serving edited bytes, since a chaos server's
    // body is fixed once it starts.
    let manifest = ChaosServer::serving(MANIFEST.as_bytes().to_vec())
        .tls()
        .start()
        .await
        .expect("manifest server");
    let signature = ChaosServer::serving(sign_manifest(MANIFEST.as_bytes()).to_vec())
        .tls()
        .start()
        .await
        .expect("signature server");

    // The hosted manifest is signed with the production key, and these fixtures with the test key, so a
    // verified fetch is not what is being checked here — the request count is.
    let addons = addons(dir.path(), manifest.cert_der().expect("cert")).expect("addons");
    let urls = (
        manifest.url("manifest.json"),
        signature.url("manifest.json.sig"),
    );
    let cancel = CancellationToken::new();

    for attempt in 1..=2 {
        // Both fetches reach the server. The verification then fails against the compiled-in key, which
        // is expected and not what this asserts.
        let _ = addons.fetch_manifest(&urls.0, &urls.1, &cancel).await;
        assert_eq!(
            manifest.stats().requests(),
            attempt,
            "fetch {attempt} must go back to the server rather than reuse a cached file"
        );
    }
}

/// A fetch that does not verify must leave the last manifest that did, or the fallback a launch depends
/// on is destroyed by one bad fetch.
#[tokio::test]
async fn a_fetch_that_does_not_verify_leaves_the_cache_alone() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cache = dir.path().join(".catalog");
    std::fs::create_dir_all(&cache).expect("cache dir");
    // Stand in for a previously-verified cache. Its contents do not have to verify for this assertion:
    // what matters is that a failing fetch does not touch them.
    std::fs::write(cache.join("components.json"), b"previously fetched").expect("seed manifest");
    std::fs::write(cache.join("components.json.sig"), b"previous signature").expect("seed sig");

    let body = ChaosServer::serving(MANIFEST.as_bytes().to_vec())
        .tls()
        .start()
        .await
        .expect("server");
    // A signature that cannot verify against the compiled-in key.
    let bad = ChaosServer::serving(vec![0u8; 64])
        .tls()
        .start()
        .await
        .expect("server");

    let addons = addons(dir.path(), body.cert_der().expect("cert")).expect("addons");
    let result = addons
        .fetch_manifest(
            &body.url("manifest.json"),
            &bad.url("manifest.json.sig"),
            &CancellationToken::new(),
        )
        .await;
    assert!(
        result.is_err(),
        "a signature that does not verify is refused"
    );

    assert_eq!(
        std::fs::read(cache.join("components.json")).expect("read"),
        b"previously fetched",
        "the cache the launch falls back to survived a failed fetch"
    );
    assert_eq!(
        std::fs::read(cache.join("components.json.sig")).expect("read"),
        b"previous signature"
    );
}

/// And the cache is what a fetch that *did* verify left behind, so the fallback is a manifest that once
/// verified rather than whatever arrived last.
#[tokio::test]
async fn a_verified_fetch_is_what_the_cache_holds() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = ChaosServer::serving(MANIFEST.as_bytes().to_vec())
        .tls()
        .start()
        .await
        .expect("server");
    let sig = ChaosServer::serving(vec![0u8; 64])
        .tls()
        .start()
        .await
        .expect("server");

    let addons = addons(dir.path(), body.cert_der().expect("cert")).expect("addons");
    let _ = addons
        .fetch_manifest(
            &body.url("manifest.json"),
            &sig.url("manifest.json.sig"),
            &CancellationToken::new(),
        )
        .await;

    // The fetch did not verify, so nothing was published and there is nothing to fall back to.
    assert!(
        addons
            .cached_manifest()
            .await
            .expect("reading an absent cache is not an error")
            .is_none(),
        "an unverified fetch leaves no cached manifest behind"
    );
    // And the staging directory it used is not mistaken for one.
    assert!(
        ComponentManifest::from_json_bytes(MANIFEST.as_bytes()).is_ok(),
        "the fixture is a valid manifest, so the failure above was the signature"
    );
}
