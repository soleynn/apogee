//! Differential tests for the ticket transform against recorded launcher output.
//!
//! The fixture is a recording: it was produced once, out of process, by a reference launcher build,
//! and nothing here invokes that build. So the recording itself has to be checked, not just trusted.
//! Three tests do that from different directions:
//!
//! - [`recorded_vectors_match`] is the headline diff, and would pass even if a row were recorded
//!   wrong and our code were wrong the same way.
//! - [`hand_derived_vector_matches_the_recorded_text`] rebuilds the smallest row's plaintext as a
//!   source literal and encrypts it directly, never calling the transform, so it fails if that row
//!   was mis-recorded.
//! - [`recorded_vectors_are_self_consistent`] decrypts every row and checks its structure against
//!   the row's own declared input, so a mis-recorded row fails without any reference to our output.

use apogee_test_support::golden::from_hex;
use serde::Deserialize;
use sqex_crypto::{Blowfish, ObfuscatedTicket, ServerTime, sqex_base64};

/// The padding alphabet, restated here rather than exported from the crate: a test that imported the
/// implementation's copy could not tell a wrong alphabet from a right one.
const PAD_ALPHABET: &[u8; 64] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-_";

#[derive(Deserialize)]
struct Fixture {
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    /// The mistake this row rejects. Unused by the assertions, and deliberately kept: it is what
    /// stops a future reader deleting a row as redundant.
    #[allow(dead_code)]
    why: String,
    ticket_hex: String,
    time: u32,
    text: String,
    length: usize,
}

/// Load the recorded vectors.
///
/// Returns `Result` rather than unwrapping: the unwrap exemption covers `#[test]` function bodies,
/// not free helpers in an integration test file.
fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let raw = include_str!("fixtures/ticket_vectors.json");
    Ok(serde_json::from_str(raw)?)
}

fn ticket_bytes(v: &Vector) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    from_hex(&v.ticket_hex).ok_or_else(|| format!("row {} has malformed hex", v.name).into())
}

/// Restated independently of the implementation, so a wrong rounding in the crate cannot make the
/// self-consistency check agree with it.
fn rounded_key(time: u32) -> Vec<u8> {
    let t = time.wrapping_sub(5);
    let rounded = t - t % 60;
    format!("{rounded:08x}#un@e=x>").into_bytes()
}

#[test]
fn recorded_vectors_match() {
    let fixture = fixture().expect("the fixture parses");
    assert_eq!(fixture.vectors.len(), 9, "rows were added or removed");

    for v in &fixture.vectors {
        let raw = ticket_bytes(v).expect("the row's hex parses");
        let ticket = ObfuscatedTicket::from_auth_ticket(&raw, ServerTime(v.time))
            .unwrap_or_else(|e| panic!("row {} failed: {e}", v.name));
        assert_eq!(ticket.text(), v.text, "text differs on row {}", v.name);
        assert_eq!(
            ticket.length(),
            v.length,
            "length differs on row {}",
            v.name
        );
    }
}

/// Reaches the smallest row's recorded text without calling the transform at all.
///
/// The plaintext block is written out as a literal, derived by hand: a one-byte ticket `0xab`
/// expands to the hex digits `61 62`, the 16-bit sum of those two bytes and the terminator is 195,
/// the generator seeded with `60 ^ 195` draws 871, 28819 and 21850 to select the padding `g`, `z`,
/// `-`, and the running sum ends at `0x626101d1`, which overwrites the head little-endian before
/// bytes 0 and 1 are swapped. If the fixture row were mis-recorded, this fails; the traces in the
/// unit tests catch that only by human inspection.
#[test]
fn hand_derived_vector_matches_the_recorded_text() {
    let fixture = fixture().expect("the fixture parses");
    let row = fixture
        .vectors
        .iter()
        .find(|v| v.name == "one_byte")
        .expect("the one_byte row exists");

    let plaintext = [0x01, 0xd1, 0x61, 0x62, 0x00, 0x67, 0x7a, 0x2d];
    let ciphertext = Blowfish::new(b"0000003c#un@e=x>").encrypt(&plaintext);
    let encoded = sqex_base64::encode(&ciphertext);

    assert_eq!(encoded, row.text);
    assert_eq!(encoded.len(), row.length);
}

/// Decrypts every recorded row and checks it against the row's own declared input.
///
/// This never calls the transform, so it fails on a row that was recorded wrong even if our code
/// reproduces the same mistake. It deliberately says nothing about the first four plaintext bytes:
/// the head write and the swap own those, and asserting on them here would just restate the
/// implementation.
#[test]
fn recorded_vectors_are_self_consistent() {
    let fixture = fixture().expect("the fixture parses");

    for v in &fixture.vectors {
        let raw = ticket_bytes(v).expect("the row's hex parses");
        let name = &v.name;

        let joined: String = v.text.chars().filter(|c| *c != ',').collect();
        assert_eq!(
            joined.len(),
            v.length,
            "row {name} reports the wrong length"
        );

        let ciphertext = sqex_base64::decode(&joined)
            .unwrap_or_else(|| panic!("row {name} is not valid mangled base64"));
        let plaintext = Blowfish::new(&rounded_key(v.time)).decrypt(&ciphertext);

        // Two sum bytes, two hex digits per ticket byte, one terminator, padded to a block.
        let expected_len = (2 * raw.len() + 3).next_multiple_of(8);
        assert_eq!(
            plaintext.len(),
            expected_len,
            "row {name} is the wrong length"
        );

        // The hex expansion, from offset 4 onward; the first two digits sit under the head write.
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let tail_start = 4;
        let hex_end = 2 + hex.len();
        assert_eq!(
            &plaintext[tail_start..hex_end],
            &hex.as_bytes()[tail_start - 2..],
            "row {name} does not decrypt to its own ticket"
        );
        assert_eq!(plaintext[hex_end], 0, "row {name} lost its terminator");

        let padding = &plaintext[hex_end + 1..];
        assert!(!padding.is_empty(), "row {name} has no padding");
        assert!(
            padding.iter().all(|b| PAD_ALPHABET.contains(b)),
            "row {name} padded outside the alphabet"
        );
    }
}
