use super::*;

const KEY: [u8; KEY_LEN] = [0x5a; KEY_LEN];
const NONCE: [u8; NONCE_LEN] = [0x17; NONCE_LEN];

#[test]
fn a_body_round_trips_under_its_own_associated_data() {
    let mut buf = *b"the record table";
    let tag = seal_body(&KEY, &NONCE, b"header", &mut buf).expect("seal");
    assert_ne!(&buf, b"the record table");
    open_body(&KEY, &NONCE, b"header", &mut buf, &tag).expect("open");
    assert_eq!(&buf, b"the record table");
}

/// The body is bound to its associated data, which is what stops one file's body being spliced onto
/// another's header. Without the binding, two stores under one passphrase would be swappable.
#[test]
fn a_body_sealed_under_one_header_will_not_open_under_another() {
    let mut buf = *b"the record table";
    let tag = seal_body(&KEY, &NONCE, b"header one", &mut buf).expect("seal");
    let err = open_body(&KEY, &NONCE, b"header two", &mut buf, &tag);
    assert!(matches!(
        err,
        Err(SecretsError::Corrupt {
            detail: "authentication tag"
        })
    ));
}

/// The check envelope is the only thing separating a typo from a damaged file, so its two
/// answers are pinned here rather than left to whichever error the cipher happens to return.
#[test]
fn the_check_envelope_answers_whether_the_key_is_the_right_one() {
    let tag = seal_check(&KEY, &NONCE, b"parameters").expect("seal");
    open_check(&KEY, &NONCE, b"parameters", &tag).expect("the right key");

    let mut wrong = KEY;
    wrong[0] ^= 1;
    assert!(matches!(
        open_check(&wrong, &NONCE, b"parameters", &tag),
        Err(SecretsError::WrongPassphrase)
    ));
    assert!(matches!(
        open_check(&KEY, &NONCE, b"other parameters", &tag),
        Err(SecretsError::WrongPassphrase)
    ));
}

/// Every write draws its own nonces. A repeat under one key is the failure mode this cipher has
/// no defence against, so the property is asserted rather than assumed from the call site.
#[test]
fn drawn_bytes_are_not_the_same_twice() {
    let first: [u8; NONCE_LEN] = draw().expect("draw");
    let second: [u8; NONCE_LEN] = draw().expect("draw");
    assert_ne!(first, second);
    assert_ne!(first, [0u8; NONCE_LEN]);
}
