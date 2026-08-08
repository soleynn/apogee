//! What the fallback store does when its file has been edited.
//!
//! The point of an authenticated format is that nothing in the file is ignored, so the table below
//! walks every region of it and states what each one has to produce. Two answers are possible and the
//! difference matters: a region that decides the key produces a wrong passphrase, because a key
//! derived from an edited salt or edited work parameters honestly is a wrong key and no check can say
//! otherwise; everything else produces a damaged file. A front end offers to start over for the
//! second, which destroys secrets, and it must never offer that for the first.
//!
//! Every case also asserts that the refused open left the file exactly as it found it, and that
//! nothing the store was holding is rendered into the error.

use std::sync::Arc;

use apogee_secrets::{
    Consent, EncryptedFile, KdfCost, Passphrase, Secret, SecretKind, SecretStore, SecretsError,
};
use uuid::Uuid;

const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);
const OTHER: Uuid = Uuid::from_u128(2);
const PASSPHRASE: &[u8] = b"correct horse battery staple";

/// A value that never appears in the file except inside the seal, so finding it anywhere is a leak.
const SENTINEL: &str = "hunter2-sentinel";

/// Header field boundaries, written out rather than imported: the crate does not publish them, and a
/// test that read them from the code it is guarding would follow a layout change instead of catching
/// it.
const MAGIC: std::ops::Range<usize> = 0..4;
const VERSION: std::ops::Range<usize> = 4..6;
const KDF_ID: usize = 6;
const AEAD_ID: usize = 7;
const COST: std::ops::Range<usize> = 8..20;
const SALT: std::ops::Range<usize> = 20..36;
const CHECK_NONCE: std::ops::Range<usize> = 36..60;
const CHECK_TAG: std::ops::Range<usize> = 60..76;
const BODY_NONCE: std::ops::Range<usize> = 76..100;
const HEADER_LEN: usize = 100;
const TAG_LEN: usize = 16;
const BUCKET: usize = 512;

struct Fixed;

impl Passphrase for Fixed {
    fn unlock(&self) -> Result<Secret, SecretsError> {
        Ok(Secret::new(PASSPHRASE.to_vec()))
    }
}

fn pw(text: &str) -> Secret {
    Secret::new(text.as_bytes().to_vec())
}

/// A two-account store holding the sentinel, and the bytes it sealed to.
///
/// `padding` pushes the record table past one bucket where a case needs a file more than one bucket
/// long, which is the only way to test a truncation that is still a legal length.
fn store(padding: usize) -> Result<(tempfile::TempDir, std::path::PathBuf, Vec<u8>), SecretsError> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(EncryptedFile::FILE_NAME);
    let store = EncryptedFile::open(&path, Arc::new(Fixed));
    store.create(
        Consent::granted(),
        &Secret::new(PASSPHRASE.to_vec()),
        KdfCost::floor(),
    )?;
    store.set(ACCOUNT, SecretKind::Password, pw(SENTINEL))?;
    // At least one byte: a store refuses a value with nothing in it, and what this second account
    // is for is the record's *length*, not its emptiness.
    store.set(
        OTHER,
        SecretKind::TotpSecret,
        Secret::new(vec![b'x'; padding.max(1)]),
    )?;
    let bytes = std::fs::read(&path)?;
    Ok((dir, path, bytes))
}

/// Put `bytes` at the path, try to read the sentinel back, and answer what happened.
///
/// A fresh handle every time, so no case can pass because a previous one left a usable key cached.
fn open(path: &std::path::Path, bytes: &[u8]) -> Result<Option<Secret>, SecretsError> {
    std::fs::write(path, bytes).map_err(SecretsError::Io)?;
    EncryptedFile::open(path, Arc::new(Fixed)).get(ACCOUNT, SecretKind::Password)
}

/// What a tampered region has to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    Passphrase,
    Damaged(&'static str),
}

/// Answers rather than asserts, because a free function in an integration test may not panic: the
/// workspace lint that forbids it exempts `#[test]` bodies only. Each caller turns the message into
/// the failure.
fn refused(
    path: &std::path::Path,
    bytes: &[u8],
    expected: Refusal,
    case: &str,
) -> Result<(), String> {
    let err = match open(path, bytes) {
        Err(err) => err,
        Ok(found) => {
            return Err(format!(
                "{case}: an edited store must not open, and it handed back {}",
                if found.is_some() {
                    "a secret"
                } else {
                    "nothing"
                }
            ));
        }
    };
    let rendered = format!("{err} {err:?}");
    if rendered.contains(SENTINEL) {
        return Err(format!(
            "{case}: the error carried the stored value: {rendered}"
        ));
    }
    match (expected, &err) {
        (Refusal::Passphrase, SecretsError::WrongPassphrase) => {}
        (Refusal::Damaged(want), SecretsError::Corrupt { detail }) if *detail == want => {}
        _ => return Err(format!("{case}: expected {expected:?}, got {err:?}")),
    }
    // A refused open must change nothing: a store that rewrote itself while failing would turn a
    // recoverable edit into a permanent one.
    let after = std::fs::read(path).map_err(|e| format!("{case}: {e}"))?;
    if after != bytes {
        return Err(format!("{case}: the refused open rewrote the file"));
    }
    Ok(())
}

/// Flip the low bit of one byte.
fn flipped(bytes: &[u8], at: usize) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at] ^= 1;
    out
}

/// Every region of the header, at both ends, with the answer each one owes.
#[test]
fn every_header_region_is_covered_by_a_tag_or_a_check() {
    let (_dir, path, sealed) = store(0).expect("a sealed store");
    assert_eq!(sealed.len(), HEADER_LEN + BUCKET + TAG_LEN);

    let regions: [(&str, std::ops::Range<usize>, Refusal); 7] = [
        ("magic", MAGIC, Refusal::Damaged("file magic")),
        ("version", VERSION, Refusal::Damaged("format version")),
        (
            "key derivation id",
            KDF_ID..KDF_ID + 1,
            Refusal::Damaged("key derivation function"),
        ),
        (
            "cipher id",
            AEAD_ID..AEAD_ID + 1,
            Refusal::Damaged("cipher"),
        ),
        ("salt", SALT, Refusal::Passphrase),
        // Damage, not a typo. These two fields fail the check envelope under a perfectly good key,
        // so a tag alone cannot separate them from a wrong passphrase, and reporting one told the
        // user to retype something that was already right, forever. They are the one region the
        // body is not bound to, so the body settles it: it opens, therefore the key is the file's.
        (
            "check nonce",
            CHECK_NONCE,
            Refusal::Damaged("check envelope"),
        ),
        ("check tag", CHECK_TAG, Refusal::Damaged("check envelope")),
    ];
    for (name, region, expected) in regions {
        for at in [region.start, region.end - 1] {
            refused(
                &path,
                &flipped(&sealed, at),
                expected,
                &format!("{name} at {at}"),
            )
            .expect("refused");
        }
    }

    // The body nonce is the region that proves the two envelopes are doing different jobs. It is
    // outside what the check envelope is bound to, so the key still verifies and only the contents
    // fail, which is what lets a front end say "damaged" here and "mistyped" above.
    for at in [BODY_NONCE.start, BODY_NONCE.end - 1] {
        refused(
            &path,
            &flipped(&sealed, at),
            Refusal::Damaged("authentication tag"),
            &format!("body nonce at {at}"),
        )
        .expect("refused");
    }
}

/// The work parameters are inside the check envelope, so editing them to another legal value is
/// indistinguishable from a wrong passphrase, and editing them outside the band is refused before
/// any derivation is entered at all.
#[test]
fn editing_the_work_parameters_is_refused_two_different_ways() {
    let (_dir, path, sealed) = store(0).expect("a sealed store");

    // Still inside the band this build accepts, so it reaches the derivation and comes back as a key
    // that does not open the file.
    let mut in_band = sealed.clone();
    in_band[COST.start + 4..COST.start + 8].copy_from_slice(&3u32.to_be_bytes());
    refused(
        &path,
        &in_band,
        Refusal::Passphrase,
        "passes raised in band",
    )
    .expect("refused");

    // Outside the band, which is refused on the comparison. The elapsed time is the only observable
    // proof that a header asking for a terabyte never reached the allocator.
    for (name, at, value) in [
        ("memory below the floor", COST.start, 4u32),
        ("memory at the maximum", COST.start, u32::MAX),
        ("passes at the maximum", COST.start + 4, u32::MAX),
        ("lanes at the maximum", COST.start + 8, u32::MAX),
    ] {
        let mut out_of_band = sealed.clone();
        out_of_band[at..at + 4].copy_from_slice(&value.to_be_bytes());
        let start = std::time::Instant::now();
        refused(
            &path,
            &out_of_band,
            Refusal::Damaged("key derivation cost"),
            name,
        )
        .expect("refused");
        assert!(
            start.elapsed() < std::time::Duration::from_millis(200),
            "{name} reached the derivation"
        );
    }
}

/// The ciphertext and its tag, at both ends. This is the part an AEAD is bought for, and it is
/// asserted rather than assumed.
#[test]
fn editing_the_body_or_its_tag_is_refused() {
    let (_dir, path, sealed) = store(0).expect("a sealed store");
    let last = sealed.len() - 1;
    for (name, at) in [
        ("first ciphertext byte", HEADER_LEN),
        ("last ciphertext byte", last - TAG_LEN),
        ("first tag byte", last - TAG_LEN + 1),
        ("last tag byte", last),
    ] {
        refused(
            &path,
            &flipped(&sealed, at),
            Refusal::Damaged("authentication tag"),
            name,
        )
        .expect("refused");
    }
}

/// A file that is the wrong length is refused on its length, before the cipher is reached, and one
/// that is a legal length but short of its contents is refused on the tag. Both are damage; naming
/// them apart is what tells a truncated file from an edited one.
#[test]
fn a_file_of_the_wrong_length_is_refused_before_the_cipher() {
    let (_dir, path, sealed) = store(600).expect("a sealed store");
    assert!(
        sealed.len() >= HEADER_LEN + 2 * BUCKET + TAG_LEN,
        "the padded case needs more than one bucket"
    );

    for (name, len) in [
        ("empty", 0),
        ("header only", HEADER_LEN),
        (
            "one byte short of the minimum",
            HEADER_LEN + BUCKET + TAG_LEN - 1,
        ),
        ("one byte short", sealed.len() - 1),
    ] {
        refused(&path, &sealed[..len], Refusal::Damaged("file length"), name).expect("refused");
    }

    let mut longer = sealed.clone();
    longer.push(0);
    refused(
        &path,
        &longer,
        Refusal::Damaged("file length"),
        "one byte longer",
    )
    .expect("refused");

    let mut huge = sealed.clone();
    huge.resize(HEADER_LEN + (1 << 20) + TAG_LEN, 0);
    refused(
        &path,
        &huge,
        Refusal::Damaged("file length"),
        "past the cap",
    )
    .expect("refused");

    // A whole bucket removed is still a legal length, so this one gets as far as the tag.
    refused(
        &path,
        &sealed[..sealed.len() - BUCKET],
        Refusal::Damaged("authentication tag"),
        "one bucket short",
    )
    .expect("refused");

    let mut padded = sealed.clone();
    padded.splice(HEADER_LEN..HEADER_LEN, std::iter::repeat_n(0u8, BUCKET));
    refused(
        &path,
        &padded,
        Refusal::Damaged("authentication tag"),
        "one bucket longer",
    )
    .expect("refused");
}

/// Two stores under the same passphrase still have different salts, so neither's body opens under
/// the other's header. Without the salt in the body's associated data this would be a way to swap
/// one user's secrets for another's without either noticing.
#[test]
fn one_store_s_body_will_not_open_under_another_s_header() {
    let (_first, path, mine) = store(0).expect("a sealed store");
    let (_second, _other_path, theirs) = store(0).expect("a second sealed store");
    assert_ne!(mine[SALT], theirs[SALT], "two stores must not share a salt");

    let mut spliced = theirs[..HEADER_LEN].to_vec();
    spliced.extend_from_slice(&mine[HEADER_LEN..]);
    refused(
        &path,
        &spliced,
        Refusal::Damaged("authentication tag"),
        "a body under a foreign header",
    )
    .expect("refused");

    // The whole file swapped, header and all, is a different matter: it is a perfectly good store,
    // and the honest answer is that this passphrase does not open it.
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let other_path = elsewhere.path().join(EncryptedFile::FILE_NAME);
    let other = EncryptedFile::open(&other_path, Arc::new(Fixed));
    other
        .create(
            Consent::granted(),
            &pw("a different passphrase"),
            KdfCost::floor(),
        )
        .expect("create");
    let foreign = std::fs::read(&other_path).expect("read");
    refused(
        &path,
        &foreign,
        Refusal::Passphrase,
        "a store under another passphrase",
    )
    .expect("refused");
}

/// The headline claim, walked byte by byte rather than sampled: no byte of the file is ignored.
///
/// Every byte outside the key material is flipped in turn and the store has to refuse. That is all of
/// the frame, the body nonce, the whole ciphertext and the whole tag.
///
/// The key material, bytes 8 through 75, is deliberately not walked here and is covered at both ends
/// of each of its regions by the tests above. Two reasons, and neither is a shortcut. Each of those
/// bytes forces a fresh Argon2 derivation, which costs the better part of a second in an unoptimized
/// build and would put minutes on every run of the suite. And there is nothing per-byte to find:
/// within one region, the salt and the two envelope fields reach the same code as whole slices, with
/// no branch that could treat position three differently from position four. What varies between
/// *regions*, which is what decides whether an edit reads as a wrong passphrase or as damage, is
/// exactly what those tests enumerate.
///
/// One handle throughout, so the key is derived once. That works precisely because none of the
/// conditions reachable here is a wrong passphrase, which is the one answer that discards the cached
/// key: everything in this range is either refused on the frame or refused on the body's tag.
#[test]
fn every_byte_outside_the_key_material_is_covered() {
    let (_dir, path, sealed) = store(0).expect("a sealed store");
    let store = EncryptedFile::open(&path, Arc::new(Fixed));

    // The negative control. Without it the sweep would pass just as well against a store that never
    // opened at all.
    let read = store
        .get(ACCOUNT, SecretKind::Password)
        .expect("the untouched store opens")
        .expect("the sentinel is there");
    assert_eq!(read.expose(), SENTINEL.as_bytes());
    drop(read);

    let walked = (0..COST.start).chain(BODY_NONCE.start..sealed.len());
    let mut covered = 0usize;
    for at in walked {
        for bit in 0..8u8 {
            let mut tampered = sealed.clone();
            tampered[at] ^= 1 << bit;
            std::fs::write(&path, &tampered).expect("write");
            match store.get(ACCOUNT, SecretKind::Password) {
                Err(SecretsError::Corrupt { .. }) => {}
                other => panic!(
                    "bit {bit} of byte {at} was ignored: {:?}",
                    other.map(|found| found.is_some())
                ),
            }
        }
        covered += 1;
    }
    assert_eq!(covered, COST.start + sealed.len() - BODY_NONCE.start);

    // And the store still opens once the file is put back, so nothing above was passing because the
    // handle had quietly given up partway through.
    std::fs::write(&path, &sealed).expect("write");
    assert!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("the restored store opens")
            .is_some()
    );
}
