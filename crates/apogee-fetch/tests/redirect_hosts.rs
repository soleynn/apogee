//! A download confined to a host list: every hop of every redirect must land on a listed host.
//!
//! Two loopback servers stand in for two hosts by being named differently: one as `127.0.0.1`, the
//! other as `localhost`. Both resolve to the same machine, which is the point of the off-list case:
//! the refused host is willing and able to serve the exact bytes the spec asks for, so nothing but the
//! refusal stops the transfer.
//!
//! The `https`-to-plaintext case under confinement needs a TLS listener and so lives in
//! `redirect_tls`.

use std::path::Path;
use std::time::Duration;

use apogee_fetch::{
    DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, RetryPolicy, SpecError, Validator,
};
use apogee_test_support::chaos::{ChaosServer, block_hashes, body_sha256, generated_vec};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Retries that cost no wall clock, so a request count is not also a test of a backoff.
fn instant_retries() -> RetryPolicy {
    RetryPolicy::default()
        .base_delay(Duration::from_micros(1))
        .max_delay(Duration::from_millis(1))
}

fn fetcher() -> Result<Fetcher, FetchError> {
    Fetcher::builder()
        .max_connections_per_file(1)
        .retry_policy(instant_retries())
        .build()
}

/// `server`'s URL for `path`, but naming the host `localhost` rather than `127.0.0.1`.
fn as_localhost(server: &ChaosServer, path: &str) -> Result<Url, url::ParseError> {
    let mut url = server.url(path);
    url.set_host(Some("localhost"))?;
    Ok(url)
}

fn sha_spec(url: Url, dest: &Path, seed: u64, len: u64) -> DownloadSpecBuilder {
    DownloadSpec::builder(url, dest, Validator::Sha256(body_sha256(seed, len))).expected_len(len)
}

/// Nothing was published and nothing was written into the `.part` a failed transfer leaves behind.
async fn assert_nothing_landed(dest: &Path) {
    assert!(!dest.exists(), "nothing was published");
    let part = dest.with_file_name("out.bin.part");
    let landed = tokio::fs::metadata(&part).await.map_or(0, |m| m.len());
    assert_eq!(landed, 0, "bytes landed in {part:?} from a refused chain");
}

#[tokio::test]
async fn a_hop_onto_a_listed_host_is_followed() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 256 * 1024;
    let store = ChaosServer::builder(91, len).start().await.unwrap();
    let front = ChaosServer::builder(0, len)
        .redirect_to(302, as_localhost(&store, "asset.bin").unwrap().to_string())
        .start()
        .await
        .unwrap();

    let spec = sha_spec(front.url("asset.bin"), &dest, 91, len)
        .allowed_hosts(["127.0.0.1", "LocalHost"])
        .build()
        .unwrap();
    let verified = fetcher()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(91, 0, len as usize),
    );
    assert!(store.stats().requests() > 0, "the store served the file");
}

#[tokio::test]
async fn a_hop_off_the_list_is_refused_before_the_second_connect() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let store = ChaosServer::builder(92, len).start().await.unwrap();
    let off_list = as_localhost(&store, "asset.bin").unwrap();
    let front = ChaosServer::builder(0, len)
        .redirect_to(302, off_list.to_string())
        .start()
        .await
        .unwrap();

    let spec = sha_spec(front.url("asset.bin"), &dest, 92, len)
        .allowed_hosts(["127.0.0.1"])
        .build()
        .unwrap();
    let err = fetcher()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert_eq!(
        store.stats().requests(),
        0,
        "the off-list host was contacted"
    );
    assert_eq!(front.stats().requests(), 1, "a refused hop was asked again");
    match &err {
        FetchError::RedirectHostNotAllowed { url, host, .. } => {
            assert_eq!(url, &front.url("asset.bin"));
            assert_eq!(host, off_list.host_str().unwrap());
        }
        other => panic!("got {other:?}"),
    }
    assert!(
        err.to_string().contains("localhost"),
        "the message names the host: {err}"
    );
    assert!(!err.is_transient());
    assert_nothing_landed(&dest).await;
}

#[tokio::test]
async fn a_hop_off_the_list_is_refused_on_the_segment_path() {
    // Block mode keeps the ranged engine at one connection: the range probe is served, then the one
    // segment request is redirected off the list. The probe and the segment run through the same
    // confined client, so the refusal ends the transfer at two requests.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let block_size = 16 * 1024;
    let store = ChaosServer::builder(93, len).start().await.unwrap();
    let front = ChaosServer::builder(93, len)
        .redirect_to_after(
            1,
            302,
            as_localhost(&store, "asset.bin").unwrap().to_string(),
        )
        .start()
        .await
        .unwrap();

    let spec = DownloadSpec::builder(
        front.url("asset.bin"),
        &dest,
        Validator::BlockSha1 {
            block_size,
            hashes: block_hashes(93, len, block_size),
        },
    )
    .expected_len(len)
    .allowed_hosts(["127.0.0.1"])
    .build()
    .unwrap();
    let err = fetcher()
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert!(
        matches!(&err, FetchError::RedirectHostNotAllowed { host, .. } if host == "localhost"),
        "got {err:?}",
    );
    assert_eq!(
        store.stats().requests(),
        0,
        "the off-list host was contacted"
    );
    assert_eq!(
        front.stats().requests(),
        2,
        "the probe, then one refused segment request"
    );
}

#[tokio::test]
async fn the_hop_cap_still_holds_on_a_listed_host() {
    // Confinement narrows the shared floor and never replaces it: a chain that never leaves the list
    // still ends at the cap, and one at the cap is still walked.
    let len = 64 * 1024;
    for (hops, refused) in [(3, false), (4, true)] {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("out.bin");
        let server = ChaosServer::builder(94, len)
            .redirect_self_hops(302, hops)
            .start()
            .await
            .unwrap();
        let spec = sha_spec(server.url("f.bin"), &dest, 94, len)
            .allowed_hosts(["127.0.0.1"])
            .build()
            .unwrap();
        let outcome = fetcher()
            .unwrap()
            .download(&spec, None, CancellationToken::new())
            .await;
        if refused {
            assert!(
                matches!(&outcome, Err(FetchError::RedirectRefused { detail, .. })
                    if *detail == "redirect chain exceeds the hop cap"),
                "{hops} hops: {outcome:?}",
            );
            assert_nothing_landed(&dest).await;
        } else {
            assert!(outcome.is_ok(), "{hops} hops: {outcome:?}");
        }
    }
}

#[tokio::test]
async fn submit_runs_under_the_same_confinement() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 64 * 1024;
    let store = ChaosServer::builder(95, len).start().await.unwrap();
    let front = ChaosServer::builder(0, len)
        .redirect_to(302, as_localhost(&store, "asset.bin").unwrap().to_string())
        .start()
        .await
        .unwrap();

    let spec = sha_spec(front.url("asset.bin"), &dest, 95, len)
        .allowed_hosts(["127.0.0.1"])
        .build()
        .unwrap();
    let err = fetcher().unwrap().submit(spec).wait().await.unwrap_err();

    assert!(
        matches!(&err, FetchError::RedirectHostNotAllowed { host, .. } if host == "localhost"),
        "got {err:?}",
    );
    assert_eq!(
        store.stats().requests(),
        0,
        "the off-list host was contacted"
    );
}

#[tokio::test]
async fn one_fetcher_keeps_confined_and_unconfined_downloads_apart() {
    // The same fetcher, the same redirect: confined, it is refused; unconfined, it is followed. A
    // confined client leaking into the shared one, or the other way round, fails one of the two.
    let len = 64 * 1024;
    let store = ChaosServer::builder(96, len).start().await.unwrap();
    let front = ChaosServer::builder(0, len)
        .redirect_to(302, as_localhost(&store, "asset.bin").unwrap().to_string())
        .start()
        .await
        .unwrap();
    let fetcher = fetcher().unwrap();

    for round in 0..2 {
        let dir = tempfile::tempdir().unwrap();
        let confined = sha_spec(front.url("asset.bin"), &dir.path().join("a.bin"), 96, len)
            .allowed_hosts(["127.0.0.1"])
            .build()
            .unwrap();
        let err = fetcher
            .download(&confined, None, CancellationToken::new())
            .await
            .unwrap_err();
        assert!(
            matches!(&err, FetchError::RedirectHostNotAllowed { .. }),
            "round {round}: {err:?}"
        );

        let open = sha_spec(front.url("asset.bin"), &dir.path().join("b.bin"), 96, len)
            .build()
            .unwrap();
        fetcher
            .download(&open, None, CancellationToken::new())
            .await
            .unwrap_or_else(|err| panic!("round {round}: {err:?}"));
    }
}

#[test]
fn a_source_off_the_list_is_refused_at_build() {
    let primary: Url = "https://front.example/a.zip".parse().unwrap();
    let mirror: Url = "https://mirror.example/a.zip".parse().unwrap();
    let build = |hosts: &[&str]| {
        DownloadSpec::builder(primary.clone(), "/tmp/a.zip", Validator::Sha256([0; 32]))
            .mirror(mirror.clone())
            .allowed_hosts(hosts.iter().copied())
            .build()
    };

    assert!(build(&["front.example", "mirror.example"]).is_ok());
    assert!(
        matches!(build(&["front.example"]), Err(SpecError::HostNotAllowed { url, .. }) if url == mirror),
        "the mirror is a source too",
    );
    assert!(
        matches!(build(&["mirror.example"]), Err(SpecError::HostNotAllowed { url, .. }) if url == primary),
    );
    // Naming none confines nothing.
    assert!(build(&[]).unwrap().allowed_hosts().is_empty());
}
