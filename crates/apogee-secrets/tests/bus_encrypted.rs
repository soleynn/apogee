//! What actually crosses the session bus when a secret is stored.
//!
//! The CI job puts a relay between this process and the real bus socket and keeps both directions of
//! the byte stream. This case writes a sentinel through the store, then reads those captures back
//! and asserts the sentinel is not in them and that the session was negotiated with the
//! Diffie-Hellman transport rather than the plaintext one.
//!
//! The assertion has teeth: the same write over a plaintext session puts the sentinel in the
//! capture verbatim and names `plain` where this names the Diffie-Hellman algorithm. Note that the
//! bare word `plain` is not usable as the negative signal, since it also occurs in the `text/plain`
//! content type, which is why the algorithm name is asserted positively instead.
//!
//! What it proves: the secret did not cross the bus in the clear, and the session named the
//! encrypted algorithm. What it does not prove: anything about how the provider stores the item on
//! disk, anything about the strength of the transport beyond its name, and nothing at all about
//! another process on the same bus reading the item back afterwards. The bus is a same-user trust
//! boundary and this does not change that. The item's attributes, including the account this is
//! keyed by, do cross in the clear: only the secret value is encrypted.

use std::path::PathBuf;

use apogee_secrets::{OsKeyring, Secret, SecretKind, SecretStore};
use uuid::Uuid;

/// Distinctive enough that finding it in a capture cannot be a coincidence.
const SENTINEL: &[u8] = b"apogee-bus-capture-sentinel-9f2c41";

/// The algorithm name the encrypted session negotiates, as the Secret Service spells it.
const DH_ALGORITHM: &[u8] = b"dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// Where the relay wrote the two directions of the stream.
fn capture_dir() -> Option<PathBuf> {
    std::env::var_os("APOGEE_BUS_CAPTURE").map(PathBuf::from)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[test]
fn the_secret_never_crosses_the_bus_in_the_clear() {
    let store = OsKeyring::new();
    let account = Uuid::new_v4();

    store
        .set(
            account,
            SecretKind::Password,
            Secret::new(SENTINEL.to_vec()),
        )
        .expect("store the sentinel");
    let read = store
        .get(account, SecretKind::Password)
        .expect("read the sentinel")
        .expect("the sentinel is there");
    assert_eq!(read.expose(), SENTINEL);
    store
        .delete(account, SecretKind::Password)
        .expect("delete the sentinel");

    let dir = capture_dir()
        .expect("APOGEE_BUS_CAPTURE names the directory the relay writes both directions into");
    let to_service = std::fs::read(dir.join("c2s.bin")).expect("the client-to-service capture");
    let from_service = std::fs::read(dir.join("s2c.bin")).expect("the service-to-client capture");

    assert!(
        !to_service.is_empty() && !from_service.is_empty(),
        "the relay captured nothing, so this case asserts nothing"
    );
    assert!(
        !contains(&to_service, SENTINEL),
        "the secret crossed the bus in the clear on the way in"
    );
    assert!(
        !contains(&from_service, SENTINEL),
        "the secret crossed the bus in the clear on the way back"
    );
    assert!(
        contains(&to_service, DH_ALGORITHM),
        "the session was not negotiated with the encrypted transport"
    );
}
