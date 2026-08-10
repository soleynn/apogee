//! Which certificate authorities the launcher will accept for Square Enix's TLS.
//!
//! The default posture is every root the platform ships plus every root anyone has added to it,
//! which is around 150 organizations and, more to the point, whatever a corporate proxy or a piece
//! of malware installed. Any one of them can mint a certificate for the login host, and a party
//! holding one reads the account password and the one-time code out of the submit that follows.
//!
//! This narrows that to the two operators Square Enix actually uses. It constrains the trust
//! anchors rather than pinning a certificate or a key, which is the only form the measurement below
//! leaves standing.
//!
//! # What was measured, on 2026-08-06
//!
//! `ffxiv-login.square-enix.com` runs two issuance streams at once. One is DigiCert, renewed each
//! October on a 395-day certificate, and is what the host serves. The other is Google Trust
//! Services, a 90-day certificate reissued every two to four weeks, single-name for exactly that
//! host, running continuously since August 2025. Four sampled leaves from it carried four distinct
//! keys, two of them issued the same day four hours apart. The host answers on one global address,
//! identically from two public resolvers, so that stream is not observable from here at all.
//!
//! A leaf or key pin therefore cannot be built. Whatever set one measured would omit a stream that
//! is provisioned, live, and one routing change away from being served, and the launcher would stop
//! logging anyone in on a day nothing shipped.
//!
//! An intermediate pin fares no better. The login host has moved through six intermediates in ten
//! years, and the current one expires in November 2027.
//!
//! Roots are the level that holds still: the four below expire in 2036 and 2038, and they covered
//! every chain the four TLS endpoints served when this was written, including the Google stream's.
//!
//! # What this does and does not buy
//!
//! It stops a certificate minted by a locally installed root, which is the corporate proxy and the
//! malware case. It does not stop a mis-issuance by DigiCert or Google, and it does not stop anyone
//! who has taken over Square Enix's own edge. Those are the same parties the account password
//! already rests on, so what it removes is the extra one: whoever installed a root on this machine.
//!
//! # Which proxy this refuses, measured on 2026-08-10
//!
//! Every client the launcher builds follows `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`,
//! because `reqwest` reads them at build time and nothing here turns that off. The two proxy shapes
//! land on opposite sides of the anchor set, and the split is the point rather than a limitation.
//!
//! A proxy that opens a `CONNECT` tunnel forwards the handshake untouched, so Square Enix's own
//! certificate arrives and the anchor set validates it. All four endpoints above were reached
//! through one, indistinguishably from no proxy at all.
//!
//! A proxy that terminates TLS and re-signs with its own root is refused, which is this module
//! working: that root is a locally installed one, and it is the party the anchor set exists to
//! remove. `rustls` reports it as `InvalidCertificate(UnknownIssuer)` through the tunnel exactly as
//! it does without one, so [`crate::transport`] names it and points at the hatch above rather than
//! rendering a bare connect failure.

use crate::error::CoreError;

/// The roots every Square Enix endpoint this launcher opens TLS to chained to when this was
/// written, as DER.
///
/// `ffxiv-login.square-enix.com` reaches G2 through `GeoTrust TLS RSA CA G1` and R1 through
/// `Google Trust Services WR3`. `frontier.ffxiv.com` and `patch-gamever.ffxiv.com` share one
/// `*.ffxiv.com` certificate that also reaches G2. `launcher.finalfantasyxiv.com` reaches G3
/// through `DigiCert Global G3 TLS ECC SHA384 2020 CA1`.
///
/// R4 is Google's ECDSA root and no measured chain uses it. It is here because it belongs to an
/// operator already trusted through R1, so carrying it widens the set of certificate authorities
/// this accepts by nobody, and it covers Square Enix moving that stream to ECDSA without warning.
///
/// `patch-bootver.ffxiv.com` and `patch-dl.ffxiv.com` are absent because the protocol addresses
/// them over plain HTTP. There is no handshake on either to constrain.
///
/// DER rather than PEM so that the digest a reviewer checks against DigiCert's and Google's
/// published fingerprints is a digest of the shipped file itself, with no decoding step in between
/// for either the test or the reviewer to get wrong.
const ANCHORS: [&[u8]; 4] = [
    include_bytes!("roots/digicert_global_root_g2.der"),
    include_bytes!("roots/digicert_global_root_g3.der"),
    include_bytes!("roots/gts_root_r1.der"),
    include_bytes!("roots/gts_root_r4.der"),
];

/// Constrain `builder` to [`ANCHORS`], or leave it on the platform's trust store when the escape
/// hatch is set.
///
/// The hatch exists because the failure this can cause is total and silent from the user's side: if
/// Square Enix moves to a fifth authority, or a network the user cannot change terminates TLS on
/// the way out, every login fails with a certificate error and nothing the launcher offers gets
/// them past it. `APOGEE_TLS_SYSTEM_ROOTS` set to anything non-empty puts the client back on the
/// platform's roots for that run.
///
/// It does not weaken this against the case worth defending. Malware that can set an environment
/// variable for the launcher's process could also install the root that this refuses, and code
/// running as the user does not need a certificate to read the user's password. What the hatch
/// covers is the person whose employer intercepts TLS and who would otherwise have a launcher that
/// cannot be made to work.
///
/// "The platform's roots" is a claim about the build, not just about this function: it holds only
/// while `reqwest` carries `rustls-tls-native-roots`, because `rustls-tls` alone resolves to a
/// Mozilla set compiled into the binary and never reads the machine at all. Under that build the
/// hatch handed the intercepted user back a list that by construction could not contain their
/// employer's root, so the only way out of the anchor set led nowhere. The workspace manifest carries
/// it, `scripts/audit.sh` asserts the shipping selection still does, and
/// [`the_hatch_reaches_this_machines_trust_store`] fails without it.
///
/// # Errors
/// [`CoreError::Init`] if an embedded root does not parse, which is a corrupt build rather than
/// anything about the machine it runs on.
pub(crate) fn anchor(builder: reqwest::ClientBuilder) -> Result<reqwest::ClientBuilder, CoreError> {
    let hatch = std::env::var_os("APOGEE_TLS_SYSTEM_ROOTS");
    apply(builder, anchoring(hatch.as_deref()))
}

/// Whose roots a client validates against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Anchoring {
    /// [`ANCHORS`] and nothing else.
    Constrained,
    /// Whatever this machine trusts, which is what the hatch asks for.
    System,
}

/// Read the escape hatch. Split from [`anchor`] so the rule is testable: setting an environment
/// variable is `unsafe` under this edition and the workspace does not permit it, so a test cannot
/// reach this branch by setting the real thing.
///
/// Present but empty reads as unset, which is how a shell hands over a variable it was told to clear
/// and is the reading that keeps the constraint rather than dropping it.
fn anchoring(hatch: Option<&std::ffi::OsStr>) -> Anchoring {
    match hatch {
        Some(set) if !set.is_empty() => Anchoring::System,
        _ => Anchoring::Constrained,
    }
}

/// Put `mode` on `builder`.
fn apply(
    builder: reqwest::ClientBuilder,
    mode: Anchoring,
) -> Result<reqwest::ClientBuilder, CoreError> {
    if mode == Anchoring::System {
        tracing::warn!(
            "TLS trust anchors are not constrained: this run accepts any root this machine trusts"
        );
        return Ok(builder);
    }
    let mut builder = builder.tls_built_in_root_certs(false);
    for der in ANCHORS {
        let root = reqwest::Certificate::from_der(der).map_err(|e| CoreError::Init {
            detail: e.to_string(),
        })?;
        builder = builder.add_root_certificate(root);
    }
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_test_support::chaos::ChaosServer;
    use sha2::{Digest, Sha256};

    /// SHA-256 over each embedded file, in [`ANCHORS`] order. A DER file is the certificate, so
    /// these are also the fingerprints DigiCert and Google publish for
    /// `DigiCert Global Root G2`, `DigiCert Global Root G3`, `GTS Root R1` and `GTS Root R4`, and a
    /// reviewer checks them there.
    ///
    /// Pinned because nothing else in the build would notice these files being swapped. A root here
    /// is a certificate authority this launcher obeys, so a replaced file is a party that gets to
    /// answer for the login host, and it would pass every other test in the suite by doing nothing.
    const FINGERPRINTS: [&[u8; 32]; 4] = [
        b"\xcb\x3c\xcb\xb7\x60\x31\xe5\xe0\x13\x8f\x8d\xd3\x9a\x23\xf9\xde\x47\xff\xc3\x5e\x43\xc1\x14\x4c\xea\x27\xd4\x6a\x5a\xb1\xcb\x5f",
        b"\x31\xad\x66\x48\xf8\x10\x41\x38\xc7\x38\xf3\x9e\xa4\x32\x01\x33\x39\x3e\x3a\x18\xcc\x02\x29\x6e\xf9\x7c\x2a\xc9\xef\x67\x31\xd0",
        b"\xd9\x47\x43\x2a\xbd\xe7\xb7\xfa\x90\xfc\x2e\x6b\x59\x10\x1b\x12\x80\xe0\xe1\xc7\xe4\xe4\x0f\xa3\xc6\x88\x7f\xff\x57\xa7\xf4\xcf",
        b"\x34\x9d\xfa\x40\x58\xc5\xe2\x63\x12\x3b\x39\x8a\xe7\x95\x57\x3c\x4e\x13\x13\xc8\x3f\xe6\x8f\x93\x55\x6c\xd5\xe8\x03\x1b\x3c\x7d",
    ];

    /// Every embedded root parses as one reqwest accepts. A file that did not would take the whole
    /// client build down at startup, which is a failure worth having before a release rather than
    /// on a user's first login.
    #[test]
    fn every_embedded_root_parses() {
        for (i, der) in ANCHORS.iter().enumerate() {
            assert!(
                reqwest::Certificate::from_der(der).is_ok(),
                "embedded root {i} does not parse"
            );
        }
    }

    /// Each embedded root is the certificate authority it is documented to be. Guards the swap the
    /// constant above describes.
    #[test]
    fn every_embedded_root_is_the_authority_it_claims() {
        for (i, (der, want)) in ANCHORS.iter().zip(FINGERPRINTS).enumerate() {
            let got: [u8; 32] = Sha256::digest(der).into();
            assert_eq!(
                &got, want,
                "embedded root {i} is not the published authority"
            );
        }
    }

    /// The anchor set holds no duplicates, which would mean one authority was pasted twice and one
    /// the comment claims is covered is missing.
    #[test]
    fn the_anchors_are_four_distinct_authorities() {
        let mut seen = ANCHORS.to_vec();
        seen.sort_unstable();
        let before = seen.len();
        seen.dedup();
        assert_eq!(seen.len(), before, "an embedded root appears twice");
    }

    /// The hatch takes a value, and an empty one is not a value. A shell that exports the name with
    /// nothing in it has not asked for anything, and reading that as a request would turn the
    /// constraint off for a user who never wanted it off.
    #[rstest::rstest]
    #[case(None, Anchoring::Constrained)]
    #[case(Some(""), Anchoring::Constrained)]
    #[case(Some("1"), Anchoring::System)]
    #[case(Some("0"), Anchoring::System)]
    #[case(Some("no"), Anchoring::System)]
    fn the_hatch_needs_a_value(#[case] hatch: Option<&str>, #[case] want: Anchoring) {
        let got = anchoring(hatch.map(std::ffi::OsStr::new));
        assert_eq!(got, want, "the hatch read {hatch:?} the wrong way");
    }

    /// A client built this way refuses a server whose certificate it was given no root for.
    ///
    /// What this covers is the anchor set being wired in at all: an empty set, or roots that failed
    /// to load, would take this with them. What it cannot cover is
    /// `tls_built_in_root_certs(false)`, because the chaos server's certificate is unknown to the
    /// platform as well as to the anchor set and is refused either way. Deleting that line leaves
    /// this test green, which was checked rather than assumed;
    /// [`the_anchor_set_refuses_a_root_this_machine_trusts`] is where that line is covered, by making
    /// the certificate one the machine does trust.
    ///
    /// The control is what makes the refusal mean anything: a test that only asserted a failed
    /// request would pass just as well against a server that was never listening.
    #[tokio::test]
    async fn a_constrained_client_refuses_a_root_it_does_not_carry() {
        let server = ChaosServer::builder(1, 64)
            .tls()
            .start()
            .await
            .expect("the chaos server starts");
        let url = server.url("file.bin");
        let cert = server
            .cert_der()
            .expect("a TLS chaos server has a certificate");

        let constrained = apply(reqwest::Client::builder(), Anchoring::Constrained)
            .expect("the embedded roots parse")
            .build()
            .expect("the constrained client builds");
        let refused = constrained.get(url.clone()).send().await;

        // The control: the same server, reached by a client that was handed its certificate. This is
        // the request the one above would have made had the constraint not been in force.
        let trusting = reqwest::Client::builder()
            .add_root_certificate(
                reqwest::Certificate::from_der(cert).expect("the chaos certificate parses"),
            )
            .build()
            .expect("the trusting client builds");
        let accepted = trusting.get(url).send().await;

        assert!(
            accepted.is_ok(),
            "the control could not reach the server, so the refusal above proves nothing: {:?}",
            accepted.err()
        );
        // Named rather than matched on a type: rustls reports this through a boxed transport error
        // that reqwest does not classify, so the rendering is the only place the reason survives. It
        // is asserted because "the request failed" on its own would also be satisfied by a refused
        // connection or a timeout, neither of which is this module working.
        let err = refused.expect_err("a constrained client must refuse an unknown root");
        let why = format!("{err:?}").to_ascii_lowercase();
        assert!(
            why.contains("unknownissuer") || why.contains("invalidcertificate"),
            "the request failed for a reason other than trust: {err:?}"
        );
    }

    /// The platform's roots really are off, and Square Enix really does still answer without them.
    ///
    /// These are the two halves of the change, and neither can be shown from a fixture. The first
    /// needs a certificate this machine trusts and the anchor set does not, which no test can mint;
    /// Let's Encrypt publishes one for exactly this purpose. The second needs the live endpoints,
    /// because the claim being made is about certificates Square Enix serves and rotates, not about
    /// anything in this repository.
    ///
    /// Run it when the anchor set changes, and on a patch day if login starts refusing:
    /// ```text
    /// APOGEE_TLS_LIVE=1 cargo test -p apogee-core --lib trust:: -- --ignored --nocapture
    /// ```
    #[tokio::test]
    #[ignore = "set APOGEE_TLS_LIVE=1 to reach Square Enix and the public internet"]
    async fn live_the_platform_roots_are_off_and_square_enix_still_answers() {
        if std::env::var("APOGEE_TLS_LIVE").is_err() {
            return;
        }
        let client = |mode| {
            apply(reqwest::Client::builder(), mode)
                .expect("the embedded roots parse")
                .build()
                .expect("the client builds")
        };

        // A host on a root the platform carries and the anchor set does not. Refused under the
        // constraint and reachable without it: the pair is what pins the line that turns the
        // platform's roots off, since dropping it makes the first of these succeed.
        let off_set = "https://valid-isrgrootx1.letsencrypt.org/";
        let refused = client(Anchoring::Constrained).get(off_set).send().await;
        let err = refused.expect_err("a root outside the anchor set must be refused");
        let why = format!("{err:?}").to_ascii_lowercase();
        assert!(
            why.contains("unknownissuer") || why.contains("invalidcertificate"),
            "the off-set host failed for a reason other than trust, so this proves nothing: {err:?}"
        );
        assert!(
            client(Anchoring::System).get(off_set).send().await.is_ok(),
            "the hatch did not put the platform's roots back, so the refusal above may be unrelated"
        );

        // Every endpoint the constrained client actually has to reach. A failure here is the one
        // this change can cause: Square Enix issuing from an authority the anchor set does not hold.
        for url in [
            "https://ffxiv-login.square-enix.com/oauth/ffxivarr/login/top",
            "https://frontier.ffxiv.com/worldStatus/gate_status.json",
            "https://patch-gamever.ffxiv.com/",
            "https://launcher.finalfantasyxiv.com/",
        ] {
            // Any status at all: what is being asserted is that the handshake completed, and one of
            // these answers 403 to a bare GET.
            let reached = client(Anchoring::Constrained).get(url).send().await;
            assert!(
                reached.is_ok(),
                "{url} could not be reached under the anchor set (or is down): {:?}",
                reached.err()
            );
        }
    }

    /// The environment variable naming the URL a [`probe_child`] run should request. Its presence is
    /// also what tells that test it is the child rather than an ordinary `--ignored` sweep.
    ///
    /// A function rather than a constant because `apogee-core` carries no `&str` constants at all:
    /// user-facing text belongs to the shell, and `scripts/audit.sh` holds that line across the whole
    /// crate rather than trying to guess which strings are presentation.
    fn probe_url_var() -> &'static str {
        "APOGEE_TRUST_PROBE_URL"
    }

    /// The environment variable naming the file a [`probe_child`] run writes its outcome to.
    fn probe_out_var() -> &'static str {
        "APOGEE_TRUST_PROBE_OUT"
    }

    /// One request, made by a freshly started process, reported as a single line in a file.
    ///
    /// Everything the tests below are about is read out of the environment while the client is being
    /// built: the hatch by [`anchor`], the proxy variables and `SSL_CERT_FILE` by `reqwest` and the
    /// platform root loader underneath it. Setting an environment variable is `unsafe` under this
    /// edition and the workspace does not permit it, and it would not be sound here anyway, because
    /// these run in a threaded harness beside every other test. So the environment is assembled for a
    /// child process instead, and this is the far side of it.
    ///
    /// A file rather than stdout: no library crate here writes to the terminal, which
    /// `scripts/audit.sh` enforces including in test code, and a file does not depend on the harness
    /// being asked to stop capturing either.
    ///
    /// [`anchor`] rather than [`apply`] on purpose: the hatch's own reading of the environment is
    /// part of what is under test, and going through `apply` would step over it.
    #[tokio::test]
    #[ignore = "the child half of the probes below; driven through a spawned process, not directly"]
    async fn probe_child() {
        let (Ok(url), Ok(out)) = (
            std::env::var(probe_url_var()),
            std::env::var(probe_out_var()),
        ) else {
            return;
        };
        // Capped so that a shape nobody anticipated fails the parent's wait rather than wedging it.
        let builder = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20));
        let outcome = match anchor(builder).and_then(|b| {
            b.build().map_err(|e| CoreError::Init {
                detail: e.to_string(),
            })
        }) {
            Err(e) => format!("build-failed {e}"),
            Ok(client) => match client.get(&url).send().await {
                Ok(resp) => format!("reached {}", resp.status().as_u16()),
                // The same reading [`crate::transport`] does, and the reason it has to read the
                // rendering is documented there: `reqwest` classifies a refused chain and a dead
                // route alike.
                Err(err) => {
                    let why = format!("{err:?}").to_ascii_lowercase();
                    let kind =
                        if why.contains("unknownissuer") || why.contains("invalidcertificate") {
                            "trust"
                        } else {
                            "other"
                        };
                    format!("refused {kind}")
                }
            },
        };
        std::fs::write(out, outcome).expect("the probe reports");
    }

    /// Run [`probe_child`] in a new process against `url`, with `env` applied on top of an
    /// environment this one has been cleared out of, and hand back what it reported.
    ///
    /// A `None` value removes the variable, which is not the same as setting it empty: an inherited
    /// `SSL_CERT_FILE` (several distributions set one) or a hatch left over from a live run would
    /// otherwise decide the answer instead of the case being tested.
    fn probe(url: &url::Url, env: &[(&str, Option<&str>)]) -> std::io::Result<String> {
        let dir = tempfile::tempdir()?;
        let out = dir.path().join("outcome");
        let mut cmd = std::process::Command::new(std::env::current_exe()?);
        cmd.args(["--exact", "trust::tests::probe_child", "--ignored"])
            .env(probe_url_var(), url.as_str())
            .env(probe_out_var(), &out)
            .env_remove("APOGEE_TLS_SYSTEM_ROOTS")
            .env_remove("SSL_CERT_FILE")
            .env_remove("SSL_CERT_DIR")
            .env_remove("HTTP_PROXY")
            .env_remove("http_proxy")
            .env_remove("HTTPS_PROXY")
            .env_remove("https_proxy")
            .env_remove("ALL_PROXY")
            .env_remove("all_proxy")
            .env_remove("NO_PROXY")
            .env_remove("no_proxy");
        for (name, value) in env {
            match value {
                Some(value) => cmd.env(name, value),
                None => cmd.env_remove(name),
            };
        }
        let finished = cmd.output()?;
        std::fs::read_to_string(&out).map_err(|e| {
            std::io::Error::other(format!(
                "the probe reported nothing ({e}):\n--- stdout\n{}\n--- stderr\n{}",
                String::from_utf8_lossy(&finished.stdout),
                String::from_utf8_lossy(&finished.stderr),
            ))
        })
    }

    /// The launcher takes its proxy from the environment, and that is the whole of the feature.
    ///
    /// This is the answer to whether a launcher-level proxy setting was needed: no client here turns
    /// `reqwest`'s environment handling off, so a user who has configured a proxy the way every other
    /// program on their machine reads one is already configured for this too, and a setting would be
    /// a second place to say it that could disagree with the first.
    ///
    /// Asserted as a pair. A request that fails once the proxy variable is set proves the variable is
    /// read; the same request succeeding under `NO_PROXY` proves the failure was the proxy and not
    /// the server having gone away between the two.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_proxy_in_the_environment_is_used_and_no_proxy_overrides_it() {
        let server = ChaosServer::builder(1, 64)
            .start()
            .await
            .expect("the chaos server starts");
        let url = server.url("file.bin");
        // A port nothing is listening on. Connecting to it is refused rather than left hanging, so a
        // proxy pointed here is a proxy that visibly fails, which is what makes "the request went
        // through the proxy" observable without running one.
        let dead_proxy = "http://127.0.0.1:1";

        let through = probe(&url, &[("HTTP_PROXY", Some(dead_proxy))]).expect("the probe reports");
        assert_eq!(
            through, "refused other",
            "the request reached the server, so HTTP_PROXY was not read"
        );

        let bypassed = probe(
            &url,
            &[
                ("HTTP_PROXY", Some(dead_proxy)),
                ("NO_PROXY", Some("127.0.0.1")),
            ],
        )
        .expect("the probe reports");
        assert_eq!(
            bypassed, "reached 200",
            "NO_PROXY did not exempt the host, so the refusal above may not be the proxy"
        );
    }

    /// A root this machine trusts still does not get to answer for Square Enix.
    ///
    /// This is the intercepting-proxy case reduced to what actually decides it: such a proxy works by
    /// having its own root installed locally, and `SSL_CERT_FILE` is that installation, in a form a
    /// test can perform. The anchor set must refuse it, and the reason must survive as a trust
    /// failure rather than an opaque one, because [`crate::transport`] reads exactly that to tell the
    /// user which of their problems this is.
    ///
    /// The control is [`the_hatch_reaches_this_machines_trust_store`]: the same server, the same
    /// certificate, reached once the hatch is set. Without it a refusal here would also be satisfied
    /// by a certificate that was never valid for this host to begin with.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_anchor_set_refuses_a_root_this_machine_trusts() {
        let server = ChaosServer::builder(1, 64)
            .tls()
            .start()
            .await
            .expect("the chaos server starts");
        let dir = tempfile::tempdir().expect("a scratch directory");
        let pem = dir.path().join("root.pem");
        std::fs::write(
            &pem,
            server.cert_pem().expect("a TLS chaos server has a PEM"),
        )
        .expect("the root is written");

        let got = probe(
            &server.url("file.bin"),
            &[("SSL_CERT_FILE", Some(&pem.to_string_lossy()))],
        )
        .expect("the probe reports");

        assert_eq!(
            got, "refused trust",
            "a locally trusted root answered for a constrained client, or it failed for some other \
             reason and the message the user gets would be the wrong one"
        );
    }

    /// The hatch reaches this machine's trust store, which is the only thing it is for.
    ///
    /// Its whole audience is the user behind a TLS-intercepting proxy, and the root that proxy signs
    /// with is installed on their machine and nowhere else. A build carrying only `reqwest`'s
    /// `rustls-tls` restores a Mozilla root set compiled into the binary instead, which cannot
    /// contain that root, so the hatch reported success and changed nothing they could observe. This
    /// goes red on that build. See the manifest's note on `rustls-tls-native-roots`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_hatch_reaches_this_machines_trust_store() {
        let server = ChaosServer::builder(1, 64)
            .tls()
            .start()
            .await
            .expect("the chaos server starts");
        let dir = tempfile::tempdir().expect("a scratch directory");
        let pem = dir.path().join("root.pem");
        std::fs::write(
            &pem,
            server.cert_pem().expect("a TLS chaos server has a PEM"),
        )
        .expect("the root is written");

        let got = probe(
            &server.url("file.bin"),
            &[
                ("APOGEE_TLS_SYSTEM_ROOTS", Some("1")),
                ("SSL_CERT_FILE", Some(&pem.to_string_lossy())),
            ],
        )
        .expect("the probe reports");

        assert_eq!(
            got, "reached 200",
            "the hatch did not put this machine's roots in play, so the user it exists for has no \
             way past the anchor set"
        );
    }
}
