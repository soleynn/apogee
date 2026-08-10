//! Whether the client that carries an account credential follows a redirect. It does not.
//!
//! reqwest's default follows up to ten hops and checks no scheme, so without this a login or
//! session request that SE's answer points at `http://` is re-sent in the clear, on a hop where the
//! authorities [`crate::trust`] constrains do not apply at all: there is no handshake left to
//! constrain.
//!
//! Every hop is refused rather than each one vetted, because the seam this backs has no room for a
//! request it did not declare. `sqex-proto` states the exact header set of each request and
//! [`crate::transport`] reads it back off the built request before sending, since that set is what
//! SE fingerprints. A followed hop is a second request nothing checks: reqwest adds a `referer`
//! (which two surfaces declare themselves), drops `cookie` once the host changes, turns the login
//! `POST` into a `GET` on a 301, 302 or 303, and on a 307 or 308 re-sends the body carrying the
//! password verbatim to wherever the answer named. None of those is a shape the protocol declared.
//!
//! # What was measured, on 2026-08-10
//!
//! None of the five endpoints this client addresses answers a redirect. `patch-bootver.ffxiv.com`
//! and `patch-gamever.ffxiv.com` answer the version report directly, `frontier.ffxiv.com` serves
//! both status documents at the URL asked for, and `ffxiv-login.square-enix.com` serves the login
//! top page at its own. So refusing costs nothing that is happening today.
//!
//! # What this costs
//!
//! If SE starts redirecting one of them, that step fails until a build follows it, and
//! [`crate::transport`] says a redirect is why. There is no escape hatch, unlike the one
//! [`crate::trust`] carries: a hatch here would be a way to ask the launcher to send an account
//! password wherever the next answer points, which is the thing being refused.

use reqwest::redirect::Policy;

/// What [`policy`] raises for a hop, and the marker [`refusal`] reads back.
#[derive(Debug)]
struct Refused;

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("this client does not follow redirects")
    }
}

impl std::error::Error for Refused {}

/// The policy the credential-bearing client is built with.
///
/// A cycle is unreachable rather than capped: `Policy::custom` gets no loop detection from reqwest
/// (the limit-based default's is not shared with it), so a policy that followed anything at all
/// would have to end a self-redirecting server itself. This one refuses at the first decision, which
/// is the only hop there is.
pub(crate) fn policy() -> Policy {
    Policy::custom(|attempt| attempt.error(Refused))
}

/// Whether `error` is this policy refusing a hop, rather than a transport fault.
///
/// A refusal comes back from `send` as a `reqwest::Error` whose kind is redirect and whose cause is
/// the [`Refused`] the policy raised. The marker is what is read, not the kind: this client follows
/// nothing, so it is the only redirect error it can raise today, and a redirect error from anywhere
/// else would be reported with a sentence written for this one.
pub(crate) fn refusal(error: &reqwest::Error) -> bool {
    if !error.is_redirect() {
        return false;
    }
    let mut cause = std::error::Error::source(error);
    while let Some(current) = cause {
        if current.downcast_ref::<Refused>().is_some() {
            return true;
        }
        cause = current.source();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Answer `/start` with a 302 pointing at `target` and everything else with a plain 200, then
    /// hand back the URL of `/start`.
    ///
    /// The second answer is what lets a control client on reqwest's default policy finish the chain
    /// instead of looping until the hop limit, which is a different failure from the one under test.
    async fn redirecting_to(target: String) -> std::io::Result<String> {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                let target = target.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let read = socket.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..read]).into_owned();
                    let response = if head.starts_with("GET /start ") {
                        format!(
                            "HTTP/1.1 302 Found\r\nLocation: {target}\r\n\
                             content-length: 0\r\nconnection: close\r\n\r\n"
                        )
                    } else {
                        "HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok"
                            .to_owned()
                    };
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        Ok(format!("http://{addr}/start"))
    }

    /// A redirect is refused, and the refusal survives the trip through `send` as something a caller
    /// can tell apart from a host that could not be reached.
    #[tokio::test]
    async fn a_redirect_is_refused_and_is_readable_back_off_the_error() {
        let url = redirecting_to("https://elsewhere.invalid/x".to_owned())
            .await
            .expect("the listener binds");
        let client = reqwest::Client::builder()
            .redirect(policy())
            .build()
            .expect("the client builds");

        let err = client.get(url).send().await.expect_err("a hop is refused");

        assert!(err.is_redirect(), "got {err:?}");
        assert!(refusal(&err), "the refusal was not readable: {err:?}");
    }

    /// The refusal covers the first hop, not the tenth: reqwest's default would have followed this
    /// one, and the same-host, same-scheme target is the least suspicious shape a redirect takes.
    #[tokio::test]
    async fn even_a_same_host_hop_is_refused() {
        let url = redirecting_to("/moved".to_owned())
            .await
            .expect("the listener binds");
        let client = reqwest::Client::builder()
            .redirect(policy())
            .build()
            .expect("the client builds");

        let refused = client.get(url.clone()).send().await;

        // The control: the same server, reached by a client on reqwest's default policy. Without it
        // a refusal proves nothing, since a server that answered nothing at all would also fail.
        let followed = reqwest::Client::new().get(url).send().await;
        assert!(
            followed.is_ok(),
            "the control could not reach the server: {:?}",
            followed.err()
        );
        let err = refused.expect_err("a same-host hop is refused too");
        assert!(refusal(&err), "{err:?}");
    }

    /// A redirect error this policy did not raise is not read as its refusal, which is what the
    /// marker in the cause chain buys over reading the error's kind. reqwest's own hop-limit failure
    /// stands in for one, since it is the other way a `reqwest::Error` reports a redirect.
    #[tokio::test]
    async fn a_redirect_error_from_elsewhere_is_not_this_policys_refusal() {
        let url = redirecting_to("/moved".to_owned())
            .await
            .expect("the listener binds");
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(0))
            .build()
            .expect("the client builds");

        let err = client
            .get(url)
            .send()
            .await
            .expect_err("a hop limit of zero refuses the first hop");

        assert!(err.is_redirect(), "the stand-in is not a redirect: {err:?}");
        assert!(!refusal(&err), "{err:?}");
    }

    /// A failure that is not a refusal reads as one no longer, so an unreachable host is never
    /// reported as a redirect that was declined.
    #[tokio::test]
    async fn a_connect_failure_is_not_read_as_a_refusal() {
        let client = reqwest::Client::builder()
            .redirect(policy())
            .build()
            .expect("the client builds");

        // Port 1 on loopback: nothing listens, so this fails to connect rather than to redirect.
        let err = client
            .get("http://127.0.0.1:1/x")
            .send()
            .await
            .expect_err("nothing listens on port 1");

        assert!(!refusal(&err), "{err:?}");
    }
}
