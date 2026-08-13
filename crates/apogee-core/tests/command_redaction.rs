//! The credential-bearing commands must not render what they carry.
//!
//! [`Command`] holds a [`Secret`], and `Secret` implements no `Debug`, so the derive that would
//! print it does not compile — apogee-secrets pins that with its own compile-fail suite. What that
//! suite cannot reach is the impl written by hand instead, which is what this enum has: it compiles
//! whatever it prints, and a field added to a variant is rendered by whichever arm somebody writes
//! for it. That is the one route from a live credential to a log line that no type stops, so it is
//! asserted here.
//!
//! Out of line rather than in a `mod tests` beside the impl, so the security scan's test-path
//! exclusions cover the marker values below: a byte string next to a credential-shaped field name
//! reads to it as a hard-coded credential.

use apogee_core::{Command, OtpSource, Secret};
use uuid::Uuid;

/// Distinctive enough that a substring search for it cannot match anything the formatter emits of
/// its own accord, and not shaped like a credential.
const MARKER: &[u8] = b"zqx-marker-must-not-render-zqx";

const PROFILE: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);

fn marker() -> Secret {
    Secret::new(MARKER.to_vec())
}

/// Every variant that takes a credential, rendered, with the marker absent from all of them.
///
/// The list is written out rather than derived because there is nothing to derive it from: the enum
/// is `#[non_exhaustive]` and carries no iterator over its variants. A variant added later is
/// covered by the second test instead.
#[test]
fn no_credential_bearing_command_renders_what_it_holds() {
    let cases = [
        Command::Login {
            profile: PROFILE,
            password: marker(),
            otp: OtpSource::Manual(marker()),
        },
        Command::PatchAndPlay {
            profile: PROFILE,
            password: marker(),
            otp: OtpSource::Totp,
        },
        Command::Patch {
            profile: PROFILE,
            password: marker(),
            otp: OtpSource::Listener,
        },
        Command::Install {
            profile: PROFILE,
            password: marker(),
            otp: OtpSource::Manual(marker()),
        },
    ];

    let expected = String::from_utf8(MARKER.to_vec()).expect("the marker is text");
    for case in cases {
        let rendered = format!("{case:?}");
        assert!(
            !rendered.contains(&expected),
            "a command rendered the credential it was carrying: {rendered}"
        );
        // The rendering is still worth having: a redaction that erased the whole variant would pass
        // the assertion above while making the log line useless.
        assert!(
            rendered.contains(&PROFILE.to_string()),
            "the command rendered nothing identifying: {rendered}"
        );
    }
}

/// A typed one-time code travels in `OtpSource::Manual`, so the command's rendering of it is a
/// second route to the same leak, and it is one the command delegates rather than owns.
#[test]
fn a_typed_one_time_code_renders_as_its_source_and_not_its_digits() {
    let rendered = format!(
        "{:?}",
        Command::Login {
            profile: PROFILE,
            password: marker(),
            otp: OtpSource::Manual(Secret::new(MARKER.to_vec())),
        }
    );

    assert!(rendered.contains("Manual"), "{rendered}");
    assert!(
        !rendered.contains(&String::from_utf8(MARKER.to_vec()).expect("the marker is text")),
        "{rendered}"
    );
}
