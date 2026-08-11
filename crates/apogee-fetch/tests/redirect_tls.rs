//! The refusal that needs a real TLS listener: a redirect out of `https` into plaintext.
//!
//! This is the rule the rest of the redirect policy exists for. `DownloadSpecBuilder::build` refuses
//! an unverified source over plain `http://`, so an unverified download reaches the engine only over
//! TLS; a server that then answers `302` with an `http://` `Location` walks the transfer into exactly
//! the state that was refused, after the check that would have caught it has already run.
//!
//! Gated behind the `testing` feature because the fetcher has to trust the chaos server's
//! self-signed loopback certificate. That is an extra trusted root, not a certificate bypass: the
//! client still validates the server against that one root, and it comes out of the shipped
//! `build()`, so what is under test is the redirect policy that ships rather than a copy of it.

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, Validator};
use apogee_test_support::chaos::{ChaosServer, body_sha256, generated_vec};
use tokio_util::sync::CancellationToken;

/// The shipped fetcher, trusting `cert_der` (and nothing else new). It takes the default retry
/// policy, which is what makes the request-count assertion below worth making: were a refusal
/// treated as a transient fault, the count would be the full attempt budget rather than one.
fn fetcher(cert_der: &[u8]) -> Result<Fetcher, Box<dyn std::error::Error>> {
    Ok(Fetcher::builder().extra_root_certificate(cert_der).build()?)
}

#[tokio::test]
async fn an_https_to_http_redirect_is_refused_and_the_plaintext_host_is_never_asked() {
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 128 * 1024;

    // The plaintext host is willing and able: it holds the exact bytes the spec asks for, so if the
    // downgrade were followed the download would succeed and verify. Nothing but the refusal stops it.
    let plaintext = ChaosServer::builder(81, len).start().await.unwrap();
    let secure = ChaosServer::builder(0, len)
        .tls()
        .redirect_to(302, plaintext.url("asset.bin").to_string())
        .start()
        .await
        .unwrap();

    let spec = DownloadSpec::builder(
        secure.url("asset.bin"),
        &dest,
        Validator::Sha256(body_sha256(81, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let err = fetcher(secure.cert_der().unwrap())
        .unwrap()
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap_err();

    assert_eq!(
        plaintext.stats().requests(),
        0,
        "the plaintext host was contacted",
    );
    assert!(
        matches!(&err, FetchError::RedirectRefused { detail, .. }
            if *detail == "redirect downgrades https to plaintext"),
        "got {err:?}",
    );
    assert!(!dest.exists(), "nothing was published");
    let part = dest.with_file_name("out.bin.part");
    let landed = tokio::fs::metadata(&part).await.map_or(0, |m| m.len());
    assert_eq!(
        landed, 0,
        "bytes landed in {part:?} from a refused downgrade"
    );
    // The refusal is a verdict, not a fault: the secure host is asked once and not again.
    assert_eq!(
        secure.stats().requests(),
        1,
        "a refused downgrade was asked again",
    );
}

#[tokio::test]
async fn a_redirect_that_stays_on_https_is_followed() {
    // The control for the case above: same shape, same two servers, only the target's scheme differs.
    // Without this a policy that refused every redirect from a TLS origin would look correct.
    let dir = tempfile::tempdir().unwrap();
    let dest = dir.path().join("out.bin");
    let len = 128 * 1024;

    let store = ChaosServer::builder(82, len).tls().start().await.unwrap();
    let front = ChaosServer::builder(0, len)
        .tls()
        .redirect_to(302, store.url("asset.bin").to_string())
        .start()
        .await
        .unwrap();

    // One client has to trust both loopback certificates, since the hop crosses between them.
    let fetcher = Fetcher::builder()
        .extra_root_certificate(front.cert_der().unwrap())
        .extra_root_certificate(store.cert_der().unwrap())
        .build()
        .unwrap();

    let spec = DownloadSpec::builder(
        front.url("asset.bin"),
        &dest,
        Validator::Sha256(body_sha256(82, len)),
    )
    .expected_len(len)
    .build()
    .unwrap();

    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .unwrap();

    assert_eq!(
        tokio::fs::read(verified.path()).await.unwrap(),
        generated_vec(82, 0, len as usize),
    );
    assert!(store.stats().requests() > 0, "the second host served it");
}
