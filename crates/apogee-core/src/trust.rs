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
    /// this test green, which was checked rather than assumed, so the line is covered live in
    /// [`live_the_platform_roots_are_off_and_square_enix_still_answers`] instead.
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
}
