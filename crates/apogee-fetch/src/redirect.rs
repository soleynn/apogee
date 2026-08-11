//! The redirect policy every request in the crate runs under.
//!
//! A redirect policy is a client-wide setting, not a per-request one, so this is a floor rather than
//! something a [`DownloadSpec`](crate::DownloadSpec) can widen: at most 3 hops, no hop that leaves
//! `https` for plaintext, and no hop to a scheme other than `http`/`https`.
//!
//! The downgrade rule carries the real security weight.
//! [`DownloadSpecBuilder::build`](crate::DownloadSpecBuilder::build) refuses an unverified source
//! over plain `http://`, so an unverified download is only ever admitted over TLS. Without the
//! downgrade rule, a redirect from `https` to `http` would land the request in exactly the state
//! that refusal exists to block, just one hop after the check already ran. Plain HTTP paired with an
//! out-of-band validator is still allowed to redirect within plaintext: that shape was admitted on
//! the strength of the validator rather than the transport, so it loses nothing by staying where it
//! started.
//!
//! A custom [`Policy`] gets no loop detection from `reqwest` of its own; only the limit-based default
//! policy counts hops, and that protection is not shared with a custom one. So the hop cap enforced
//! here is what actually ends a redirect cycle: without it, a server that redirects to itself would
//! spin forever inside one `send`.

use reqwest::redirect::Policy;
use url::Url;

/// How many redirects one request may follow.
///
/// Real chains observed are one hop (a release asset handing off to its object store) or none (a
/// patch CDN serving directly); three leaves room for a host that canonicalizes a path or picks a
/// region first, and still ends a redirect cycle after four requests.
const MAX_HOPS: usize = 3;

/// Why a redirect was refused. Carried as the cause of the [`reqwest::Error`] the policy raises, and
/// read back by [`refusal`] to tell a refusal apart from a transport fault after `send`.
#[derive(Debug)]
struct Refused(&'static str);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Refused {}

/// The policy the client is built with.
pub(crate) fn policy() -> Policy {
    Policy::custom(|attempt| match refuse(attempt.previous(), attempt.url()) {
        Some(detail) => attempt.error(Refused(detail)),
        None => attempt.follow(),
    })
}

/// Why the hop from `previous` (every URL already requested, oldest first) to `next` must not be
/// followed, or `None` to follow it.
///
/// Checked in order: foreign scheme, then downgrade, then hop count. A hop from `https` to `ftp` is
/// both a foreign scheme and a downgrade, so this order decides which reason a caller is told; the
/// scheme is checked first because it is the more specific answer.
fn refuse(previous: &[Url], next: &Url) -> Option<&'static str> {
    foreign_scheme(next)
        .or_else(|| downgrade(previous, next))
        .or_else(|| too_many_hops(previous))
}

/// A hop that leaves TLS for plaintext.
fn downgrade(previous: &[Url], next: &Url) -> Option<&'static str> {
    let from = previous.last()?;
    (from.scheme() == "https" && next.scheme() != "https")
        .then_some("redirect downgrades https to plaintext")
}

/// A hop to something that is not HTTP at all.
///
/// `reqwest` refuses some of these itself, but as a builder error rather than a redirect error,
/// which a retry site would read as a transient connect fault and try again. Refusing it here instead
/// makes it a redirect refusal, and so terminal.
fn foreign_scheme(next: &Url) -> Option<&'static str> {
    let scheme = next.scheme();
    (scheme != "http" && scheme != "https").then_some("redirect targets a non-http scheme")
}

/// A chain past the hop cap. `previous` is `1` long at the first redirect decision, so it reaches
/// `MAX_HOPS` at the last hop that may still be followed.
fn too_many_hops(previous: &[Url]) -> Option<&'static str> {
    (previous.len() > MAX_HOPS).then_some("redirect chain exceeds the hop cap")
}

/// Why a send failed a redirect, or `None` if it did not fail on one.
///
/// A refusal comes back from `send` as a `reqwest::Error` whose kind is redirect and whose cause is
/// the [`Refused`] the policy raised. An unrecognized redirect error still answers `Some`: it is
/// still the policy layer declining to proceed, and reading it as a transport fault would retry a
/// request whose answer cannot change.
pub(crate) fn refusal(error: &reqwest::Error) -> Option<&'static str> {
    if !error.is_redirect() {
        return None;
    }
    let mut cause = std::error::Error::source(error);
    while let Some(current) = cause {
        if let Some(refused) = current.downcast_ref::<Refused>() {
            return Some(refused.0);
        }
        cause = current.source();
    }
    Some("redirect refused")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn urls(raw: &[&str]) -> Vec<Url> {
        raw.iter().map(|s| Url::parse(s).unwrap()).collect()
    }

    /// The shipped decision for one hop: the chain walked so far, and the proposed target.
    fn decide(previous: &[&str], next: &str) -> Option<&'static str> {
        refuse(&urls(previous), &Url::parse(next).unwrap())
    }

    /// The shapes a real chain takes are followed: a release asset handing off to its object store,
    /// and a patch host redirecting within itself.
    #[test]
    fn an_ordinary_cross_host_hop_is_followed() {
        assert_eq!(
            decide(
                &["https://github.com/o/r/releases/download/v1/a.tar.xz"],
                "https://objects.githubusercontent.com/blob",
            ),
            None,
        );
        assert_eq!(
            decide(&["http://patch.example/a.patch"], "http://cdn.example/a"),
            None,
        );
    }

    /// The cap admits exactly `MAX_HOPS` and refuses the one after, which is what ends a cycle.
    #[test]
    fn the_cap_admits_its_own_number_of_hops_and_no_more() {
        let chain = ["http://a/1", "http://a/2", "http://a/3", "http://a/4"];
        for hops in 1..=MAX_HOPS {
            assert_eq!(decide(&chain[..hops], "http://a/next"), None, "{hops} hops");
        }
        assert_eq!(
            decide(&chain[..=MAX_HOPS], "http://a/next"),
            Some("redirect chain exceeds the hop cap"),
        );
        // reqwest's own default is 10; this cap has to sit under it to mean anything.
        const { assert!(MAX_HOPS < 10) };
    }

    /// Leaving TLS is refused on the first hop, well before the cap could notice anything.
    #[test]
    fn a_downgrade_out_of_tls_is_refused() {
        assert_eq!(
            decide(&["https://host/a"], "http://host/a"),
            Some("redirect downgrades https to plaintext"),
        );
        // Same host, same path, only the scheme changed: nothing else about the hop is suspicious.
        assert_eq!(decide(&["https://host/a"], "https://host/b"), None);
        // A chain that started in plaintext is not made worse by staying there.
        assert_eq!(decide(&["http://host/a"], "http://other/b"), None);
        // Nor by being upgraded.
        assert_eq!(decide(&["http://host/a"], "https://host/a"), None);
    }

    /// A hop out of HTTP entirely is refused whatever the chain looked like, named for the scheme
    /// rather than for the downgrade when a hop is both.
    #[test]
    fn a_hop_to_a_foreign_scheme_is_refused() {
        for target in ["ftp://host/x", "file:///etc/passwd", "javascript:0"] {
            for from in ["http://host/a", "https://host/a"] {
                assert_eq!(
                    decide(&[from], target),
                    Some("redirect targets a non-http scheme"),
                    "{from} -> {target}",
                );
            }
        }
    }

    /// A refusal survives the trip through `send` as a redirect error whose cause is still readable,
    /// which is what lets a caller tell it apart from a host that could not be reached.
    #[tokio::test]
    async fn a_refusal_is_readable_back_off_the_error() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = sock.read(&mut buf).await;
                    let _ = sock
                        .write_all(
                            b"HTTP/1.1 302 Found\r\nLocation: ftp://elsewhere/x\r\n\
                              Content-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        let client = reqwest::Client::builder()
            .redirect(policy())
            .build()
            .unwrap();
        let err = client
            .get(format!("http://{addr}/start"))
            .send()
            .await
            .unwrap_err();
        assert!(err.is_redirect(), "got {err:?}");
        assert_eq!(refusal(&err), Some("redirect targets a non-http scheme"));
    }

    /// A failure that is not a redirect refusal reads as `None`, so an unreachable host is never
    /// mistaken for a refused hop.
    #[tokio::test]
    async fn a_connect_failure_is_not_read_as_a_refusal() {
        let client = reqwest::Client::builder()
            .redirect(policy())
            .build()
            .unwrap();
        // Port 1 on loopback: nothing listens, so this fails to connect rather than to redirect.
        let err = client.get("http://127.0.0.1:1/x").send().await.unwrap_err();
        assert_eq!(refusal(&err), None);
    }
}
