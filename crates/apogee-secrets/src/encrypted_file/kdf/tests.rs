use super::*;

/// If a dependency bump changes what the derivation produces, every stored secret is silently
/// orphaned: the file still parses, the tags still fail, and the user is told their passphrase is
/// wrong. Nothing else in the suite would catch it.
#[test]
fn the_derivation_is_pinned_to_a_known_answer() {
    let salt: [u8; SALT_LEN] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let key = derive(b"apogee test vector", &salt, KdfCost::floor()).expect("derive");
    let hex: String = key.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "958659efad7bfa7268c148994dc27faa5079571d21fe10c1e59dd59d86d580e6"
    );
}

/// The floor is the whole defence for a store created on weak hardware, and the ceiling is what
/// bounds the allocation. Both are read out of a file, so both are checked here rather than
/// trusted.
#[test]
fn only_costs_inside_the_band_are_accepted() {
    assert!(KdfCost::new(MIN_MEMORY_KIB - 1, 2, 1).is_none());
    assert!(KdfCost::new(0, 2, 1).is_none());
    assert!(KdfCost::new(u32::MAX, 2, 1).is_none());
    assert!(KdfCost::new(MIN_MEMORY_KIB, 1, 1).is_none());
    assert!(KdfCost::new(MIN_MEMORY_KIB, u32::MAX, 1).is_none());
    assert!(KdfCost::new(MIN_MEMORY_KIB, 2, 0).is_none());
    assert!(KdfCost::new(MIN_MEMORY_KIB, 2, u32::MAX).is_none());
    assert_eq!(KdfCost::new(MIN_MEMORY_KIB, 2, 1), Some(KdfCost::floor()));

    // The edges again, by literal. Everything above is written in terms of the constants, so it
    // moves with them: widening the ceiling leaves all of it true while a header can then ask for
    // gibibytes of Argon2 memory, which is an allocation the parse is supposed to have refused.
    assert!(KdfCost::new(19_456, 2, 1).is_some());
    assert!(KdfCost::new(19_455, 2, 1).is_none());
    assert!(KdfCost::new(1 << 20, 2, 1).is_some());
    assert!(KdfCost::new((1 << 20) + 1, 2, 1).is_none());
    assert!(KdfCost::new(65_536, 16, 4).is_some());
    assert!(KdfCost::new(65_536, 17, 1).is_none());
    assert!(KdfCost::new(65_536, 3, 5).is_none());
}

/// The shipped triple, by literal.
///
/// Everything else that looks at `CURRENT` is self-referential: the band check derives its arguments
/// from `CURRENT`, `default()` is compared against `CURRENT`, and the store reports back whatever it
/// was sealed under. So passes 3 to 2 is a third of the derivation gone, and lanes 1 to 4 is the
/// change the constant's own comment argues against, and neither turns anything red. Because the
/// cost travels in each file, a store written under a weakened value keeps opening at it forever.
#[test]
fn the_shipped_cost_is_the_measured_triple() {
    assert_eq!(KdfCost::CURRENT.memory_kib(), 65_536);
    assert_eq!(KdfCost::CURRENT.passes(), 3);
    assert_eq!(KdfCost::CURRENT.lanes(), 1);
}

/// Lowering the shipped cost below the floor has to be one edit, not two that can be made apart.
#[test]
fn the_shipped_cost_is_inside_the_band() {
    assert_eq!(
        KdfCost::new(
            KdfCost::CURRENT.memory_kib(),
            KdfCost::CURRENT.passes(),
            KdfCost::CURRENT.lanes()
        ),
        Some(KdfCost::CURRENT)
    );
    assert_eq!(KdfCost::default(), KdfCost::CURRENT);
}

/// Every input has to reach the key. A parameter that was accepted, stored, and then ignored
/// would let an attacker edit the header down to the floor and have the file still open.
#[test]
fn changing_any_one_input_changes_the_key() {
    let salt = [7u8; SALT_LEN];
    let base = derive(b"pw", &salt, KdfCost::floor()).expect("derive");
    let cases = [
        derive(b"px", &salt, KdfCost::floor()).expect("other passphrase"),
        derive(b"pw", &[8u8; SALT_LEN], KdfCost::floor()).expect("other salt"),
        derive(
            b"pw",
            &salt,
            KdfCost::new(MIN_MEMORY_KIB + 1024, 2, 1).expect("in band"),
        )
        .expect("other memory"),
        derive(
            b"pw",
            &salt,
            KdfCost::new(MIN_MEMORY_KIB, 3, 1).expect("in band"),
        )
        .expect("other passes"),
        derive(
            b"pw",
            &salt,
            KdfCost::new(MIN_MEMORY_KIB, 2, 2).expect("in band"),
        )
        .expect("other lanes"),
    ];
    for other in cases {
        assert_ne!(*base, *other);
    }
}
