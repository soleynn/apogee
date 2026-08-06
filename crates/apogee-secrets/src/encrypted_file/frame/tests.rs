use super::*;

fn header() -> Header {
    Header {
        cost: KdfCost::CURRENT,
        salt: [0x11; SALT_LEN],
        check_nonce: [0x22; NONCE_LEN],
        check_tag: [0x33; TAG_LEN],
        body_nonce: [0x44; NONCE_LEN],
    }
}

/// The offsets are the on-disk contract. Written out as literals rather than derived from the
/// constants, because a test that computed them from the same constants it is guarding would
/// still pass after a layout change that orphans every stored secret.
#[test]
fn the_header_layout_is_frozen() {
    assert_eq!(HEADER_LEN, 100);
    assert_eq!((OFF_MAGIC, OFF_VERSION, OFF_SUITE), (0, 4, 6));
    assert_eq!((OFF_M_COST, OFF_T_COST, OFF_P_COST), (8, 12, 16));
    assert_eq!((OFF_SALT, OFF_CHECK_NONCE), (20, 36));
    assert_eq!((OFF_CHECK_TAG, OFF_BODY_NONCE), (60, 76));
    assert_eq!((SALT_LEN, NONCE_LEN, TAG_LEN, KEY_LEN), (16, 24, 16, 32));
    assert_eq!((BUCKET, OVERHEAD, MIN_FILE), (512, 116, 628));

    let bytes = header().to_bytes();
    assert_eq!(&bytes[0..4], b"APSF");
    assert_eq!(&bytes[4..8], &[0x00, 0x02, 0x01, 0x01]);
    assert_eq!(&bytes[20..36], &[0x11; 16]);
    assert_eq!(&bytes[36..60], &[0x22; 24]);
    assert_eq!(&bytes[60..76], &[0x33; 16]);
    assert_eq!(&bytes[76..100], &[0x44; 24]);
}

/// The check envelope covers the fields that decide the key and stops before the body's nonce.
/// Extending it would fold a damaged body into a wrong-passphrase report.
#[test]
fn the_check_envelope_covers_exactly_what_decides_the_key() {
    assert_eq!(CHECK_AAD_LEN, 36);
    assert_eq!(CHECK_AAD_LEN, OFF_CHECK_NONCE);
}

/// The body skips the check envelope's own nonce and tag, which is what lets damage to them be told
/// apart from a wrong passphrase. Widening this back to the whole header collapses the two again,
/// and the only thing that would notice is the pair of cases in the tamper suite.
#[test]
fn the_body_envelope_leaves_out_the_check_envelope() {
    assert_eq!(BODY_AAD_LEN, 60);
    assert_eq!(BODY_AAD_LEN, CHECK_AAD_LEN + NONCE_LEN);
    assert_eq!(HEADER_LEN - BODY_AAD_LEN, NONCE_LEN + TAG_LEN);

    // What it is bound to, positionally: the key material, then the body's own nonce, and nothing
    // from the twenty-four plus sixteen bytes in between.
    let aad = header().body_aad();
    assert_eq!(&aad[0..4], b"APSF");
    assert_eq!(&aad[20..36], &[0x11; 16]);
    assert_eq!(&aad[36..60], &[0x44; 24]);
}

#[test]
fn a_header_round_trips_through_its_bytes() {
    let original = header();
    let mut file = original.to_bytes().to_vec();
    file.resize(MIN_FILE, 0);
    assert_eq!(Header::parse(&file).expect("parse"), original);
}

/// Each rejection has to name a different part of the file: the string is what a front end
/// triages on, and two conditions sharing one would make a corrupt header and an unsupported
/// build indistinguishable.
#[test]
fn each_structural_rejection_names_a_different_part() {
    let mut seen = Vec::new();
    let cases: [(usize, u8, &str); 5] = [
        (0, b'X', "file magic"),
        (5, 0x03, "format version"),
        (6, 0x02, "key derivation function"),
        (7, 0x02, "cipher"),
        // The second byte of the memory cost, which is the only one of its four that is nonzero
        // at the shipped value: zeroing it takes the cost to nothing rather than leaving it be.
        (9, 0x00, "key derivation cost"),
    ];
    for (at, value, expected) in cases {
        let mut file = header().to_bytes().to_vec();
        file.resize(MIN_FILE, 0);
        file[at] = value;
        let Err(SecretsError::Corrupt { detail }) = Header::parse(&file) else {
            panic!("byte {at} set to {value} must be refused");
        };
        assert_eq!(detail, expected);
        seen.push(detail);
    }
    seen.sort_unstable();
    let before = seen.len();
    seen.dedup();
    assert_eq!(seen.len(), before, "two conditions share one detail string");
}

/// The length rule is the whole of what makes a truncation a structural error. Without it a file
/// cut short would reach the cipher and come back as a tag failure, which reads as damage to the
/// contents rather than to the container.
#[test]
fn a_file_that_is_not_a_whole_number_of_buckets_is_refused() {
    for len in [0, 1, HEADER_LEN, MIN_FILE - 1, MIN_FILE + 1, MIN_FILE + 511] {
        assert!(matches!(
            check_length(len),
            Err(SecretsError::Corrupt {
                detail: "file length"
            })
        ));
    }
    for len in [MIN_FILE, MIN_FILE + BUCKET, MIN_FILE + BUCKET * 9] {
        check_length(len).expect("a whole number of buckets");
    }
}

/// A hostile file must be refused from the size the directory entry reports, so nothing that big
/// is ever read into memory.
#[test]
fn a_file_larger_than_the_cap_is_refused_from_its_size_alone() {
    assert!(check_size_on_disk(MAX_FILE + 1).is_err());
    check_size_on_disk(MIN_FILE as u64).expect("the smallest well-formed file");
}

/// A cost outside the band this build accepts is refused before the derivation is entered, so a
/// header asking for a terabyte of memory or an hour of passes costs a comparison. The elapsed
/// time is the only observable proof the derivation was never run.
#[test]
fn a_hostile_cost_is_refused_without_deriving() {
    let mut file = header().to_bytes().to_vec();
    file.resize(MIN_FILE, 0);
    file[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    file[12..16].copy_from_slice(&u32::MAX.to_be_bytes());
    let start = std::time::Instant::now();
    let parsed = Header::parse(&file);
    assert!(matches!(
        parsed,
        Err(SecretsError::Corrupt {
            detail: "key derivation cost"
        })
    ));
    assert!(start.elapsed() < std::time::Duration::from_millis(50));
}
