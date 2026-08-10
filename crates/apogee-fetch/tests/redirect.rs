//! What the client does with a `3xx`: which chains it walks, which it refuses, and what a refused
//! hop costs.
//!
//! The regression that matters most is the first one. Release assets are served through a cross-host
//! redirect, so every runner and DXVK download in the tree arrives that way; a policy that refused
//! cross-host hops would look secure and break the whole artifact path. The rest pin the floor: a
//! chain cannot run away, a refusal is a verdict rather than a fault worth re-asking, and the origin
//! URL is not handed to whatever the chain lands on.
//!
//! The `https`-to-plaintext refusal needs a TLS listener and so lives in `redirect_tls`.

use std::path::Path;
use std::time::Duration;

use apogee_fetch::{
    DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, HeaderPolicy, RetryPolicy, Validator,
};
use apogee_test_support::chaos::{ChaosServer, block_hashes, body_sha256, generated_vec};
use tokio_util::sync::CancellationToken;

/// A `Location` no policy may follow, whatever the chain looks like, so a refusal can be provoked on
/// the very first hop and its cost counted exactly.
const FOREIGN: &str = "ftp://elsewhere.invalid/asset";

/// A policy whose waits are compressed to nothing, so a test that asserts a request *count* is not
/// also a test of how long a backoff sleeps. Retries still happen; they just cost no wall clock.
fn instant_retries() -> RetryPolicy {
    RetryPolicy::default()
        .base_delay(Duration::from_micros(1))
        .max_delay(Duration::from_millis(1))
}

/// A fetcher holding `connections` per file. Returns the `Result` so the helper stays clear of
/// `unwrap` outside a test body.
fn fetcher(connections: usize) -> Result<Fetcher, FetchError> {
    Fetcher::builder()
        .max_connections_per_file(connections)
        .retry_policy(instant_retries())
        .build()
}

/// A whole-file-verified spec for the `len` bytes `seed` generates, fetched from `url`.
fn sha_spec(url: url::Url, dest: &Path, seed: u64, len: u64) -> DownloadSpecBuilder {
    DownloadSpec::builder(url, dest, Validator::Sha256(body_sha256(seed, len))).expected_len(len)
}

/// The same, block-verified. Block mode keeps the ranged engine even at one connection per file, so
/// this is how a test reaches the segment path with a request count it can predict.
fn block_spec(
    url: url::Url,
    dest: &Path,
    seed: u64,
    len: u64,
    block_size: u32,
) -> DownloadSpecBuilder {
    DownloadSpec::builder(
        url,
        dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(seed, len, block_size),
        },
    )
    .expected_len(len)
}

#[tokio::test]
async fn a_cross_host_redirect_still_downloads_and_verifies() {
    // The release-asset shape: the URL in the manifest answers `302` and the bytes come from an
    // object store on another host. Breaking this breaks every runner and DXVK download.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 512 * 1024;
    let store = ChaosServer::builder(71, len).start().await.unwrap();
    let front = ChaosServer::builder(0, len)
        .redirect_to(302, store.url("asset.bin").to_string())
        .start()
        .await
        .unwrap();

    let spec = sha_spec(front.url("asset.bin"), &dest, 71, len)
        .header_policy(HeaderPolicy::Manifest)
        .build()
        .unwrap();
    let verified = fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(71, 0, len as usize),
    );
    assert_eq!(front.stats().bytes_served(), 0, "the front served no body");
    assert!(store.stats().requests() > 0, "the store served the file");
}

#[tokio::test]
async fn a_chain_up_to_the_cap_is_walked() {
    // Three hops is the cap. It has to be walkable, or the refusal below would also pass for a
    // policy that refused every redirect there is.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let server = ChaosServer::builder(72, len)
        .redirect_self_hops(302, 3)
        .start()
        .await
        .unwrap();

    let spec = sha_spec(server.url("f.bin"), &dest, 72, len)
        .build()
        .unwrap();
    let verified = fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(72, 0, len as usize),
    );
    assert_eq!(
        server.stats().requests(),
        4,
        "three redirects and the request that served",
    );
}

#[tokio::test]
async fn a_chain_past_the_cap_is_refused_and_no_bytes_land() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let server = ChaosServer::builder(73, len)
        .redirect_self_hops(302, 4)
        .start()
        .await
        .unwrap();

    let spec = sha_spec(server.url("f.bin"), &dest, 73, len)
        .build()
        .unwrap();
    let err = fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(
        matches!(&err, FetchError::RedirectRefused { detail, .. }
            if *detail == "redirect chain exceeds the hop cap"),
        "got {err:?}",
    );
    assert_eq!(server.stats().bytes_served(), 0, "no body was ever served");
    assert!(!dest.exists(), "nothing was published");
    // The engine opens its `.part` before it asks for the first byte, and a failed transfer keeps
    // that file for a later resume, so what matters is that nothing was written into it.
    let part = dest.with_file_name("out.bin.part");
    let landed = tokio::fs::metadata(&part).await.map_or(0, |m| m.len());
    assert_eq!(landed, 0, "bytes landed in {part:?} from a refused chain");
}

#[tokio::test]
async fn a_refused_redirect_is_not_retried_on_the_streaming_path() {
    // The single-connection engine retries a failed send up to its whole attempt budget. A refusal
    // is not a fault worth re-asking, so the transfer must end on the first one: one request, not
    // one per attempt.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let server = ChaosServer::builder(74, len)
        .redirect_to(302, FOREIGN)
        .start()
        .await
        .unwrap();

    let spec = sha_spec(server.url("f.bin"), &dest, 74, len)
        .build()
        .unwrap();
    let err = fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    // The count comes first: it is the claim, and the error type alone cannot distinguish "refused
    // once" from "refused eight times and then reported".
    assert_eq!(
        server.stats().requests(),
        1,
        "a refused redirect was asked again",
    );
    assert!(
        matches!(&err, FetchError::RedirectRefused { detail, .. }
            if *detail == "redirect targets a non-http scheme"),
        "got {err:?}",
    );
}

#[tokio::test]
async fn a_refused_redirect_is_not_retried_on_the_segment_path() {
    // The segment path is the one that classified every send failure as transient, so a refusal
    // there would have cost the range its whole budget and every backoff in it. Block mode keeps
    // the ranged engine at one connection, so the count is exactly the probe plus one segment.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let server = ChaosServer::builder(75, len)
        .redirect_to_after(1, 302, FOREIGN)
        .start()
        .await
        .unwrap();

    let spec = block_spec(server.url("f.bin"), &dest, 75, len, 16 * 1024)
        .build()
        .unwrap();
    let err = fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert_eq!(
        server.stats().requests(),
        2,
        "the range probe, then one refused segment request and no more",
    );
    assert!(
        matches!(&err, FetchError::RedirectRefused { detail, .. }
            if *detail == "redirect targets a non-http scheme"),
        "got {err:?}",
    );
}

#[tokio::test]
async fn a_location_reqwest_will_not_resolve_fails_the_transfer_rather_than_succeeding() {
    // Measured, and the reason the scheme check cannot be left to reqwest. A `Location` with no
    // authority (`file:`, `data:`) is one reqwest cannot resolve into a request, so the policy is
    // never consulted and the `3xx` itself comes back as the response. The floor still holds: `302`
    // is not a status any engine can use, so the transfer fails on it and is not asked again.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 32 * 1024;
    let server = ChaosServer::builder(78, len)
        .redirect_to(302, "file:///etc/passwd")
        .start()
        .await
        .unwrap();

    let spec = sha_spec(server.url("f.bin"), &dest, 78, len)
        .build()
        .unwrap();
    let err = fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert_eq!(
        server.stats().requests(),
        1,
        "a fatal status was asked again"
    );
    assert!(
        matches!(&err, FetchError::Http { status: 302, .. }),
        "got {err:?}",
    );
    assert!(!dest.exists(), "nothing was published");
}

#[tokio::test]
async fn a_redirect_target_is_not_told_the_origin_url() {
    // reqwest attaches a `Referer` carrying the previous URL by default, handing a third-party host
    // the full path a transfer started from. The client turns it off.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 32 * 1024;
    let store = ChaosServer::builder(76, len).start().await.unwrap();
    let front = ChaosServer::builder(0, len)
        .redirect_to(302, store.url("asset.bin").to_string())
        .start()
        .await
        .unwrap();

    let spec = sha_spec(front.url("secret-path/asset.bin"), &dest, 76, len)
        .build()
        .unwrap();
    fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert!(
        store.stats().referers().iter().all(Option::is_none),
        "the redirect target was sent a Referer: {:?}",
        store.stats().referers(),
    );
}

#[tokio::test]
async fn the_patch_session_id_follows_a_cross_host_redirect() {
    // A measured, deliberate limitation rather than an oversight. reqwest strips only its own
    // sensitive set (`Authorization`, cookies, proxy auth) across a host change, so the patch
    // session's `X-Patch-Unique-Id` follows the hop. A redirect policy can only follow, stop, or
    // error - it cannot rewrite a header - so the alternative was refusing cross-host hops outright,
    // which is exactly the shape the release-asset case above needs. It is also a poor trade on its
    // own terms: patch delivery is plain HTTP, so the id is already in the clear on every request,
    // and whoever can inject the redirect is already reading it.
    //
    // Pinned here so the day reqwest changes its stripping set is a test result, not a surprise.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 16 * 1024;
    let store = ChaosServer::builder(77, len).start().await.unwrap();
    let front = ChaosServer::builder(0, len)
        .redirect_to(302, store.url("patch.bin").to_string())
        .start()
        .await
        .unwrap();

    let spec = sha_spec(front.url("patch.bin"), &dest, 77, len)
        .header_policy(HeaderPolicy::SePatch {
            unique_id: Some("session-abc".to_owned()),
        })
        .build()
        .unwrap();
    fetcher(1)
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert!(
        store
            .stats()
            .patch_unique_ids()
            .iter()
            .all(|id| id.as_deref() == Some("session-abc")),
        "the session id crossed to the redirect target: {:?}",
        store.stats().patch_unique_ids(),
    );
    assert!(
        store
            .stats()
            .user_agents()
            .iter()
            .all(|ua| ua.as_deref() == Some("FFXIV PATCH CLIENT")),
        "the patch user-agent crossed too: {:?}",
        store.stats().user_agents(),
    );
}
