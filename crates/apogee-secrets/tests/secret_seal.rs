//! Compile-fail proof that the types carrying the crate's invariants cannot be talked out of them.
//!
//! A secret that can be `Debug`-printed, `Display`-formatted, or serialized is one log line or one
//! settings write away from disk. Nothing in the crate stops a consumer reaching for those; what
//! stops them is that the traits are not implemented, which only holds as long as nobody adds them.
//! These cases pin that every such attempt is a compile error rather than a review comment.

#[test]
fn secret_implements_none_of_the_forbidden_traits() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/secret_debug.rs");
    cases.compile_fail("tests/ui/secret_display.rs");
    cases.compile_fail("tests/ui/secret_to_string.rs");
    cases.compile_fail("tests/ui/secret_derive_debug.rs");
    cases.compile_fail("tests/ui/secret_derive_serialize.rs");
    cases.compile_fail("tests/ui/secret_derive_clone.rs");
    cases.compile_fail("tests/ui/secret_derive_partial_eq.rs");
    cases.compile_fail("tests/ui/secret_derive_default.rs");
    cases.compile_fail("tests/ui/secret_orphan_debug.rs");
}

/// The routes above are the ones that render a value. These two are the ones that hand the bytes
/// over so something else renders them, which the absence of a `Debug` does nothing about.
///
/// Both are shaped like a convenience somebody would reach for rather than like a leak, which is
/// why they are pinned: `expose` is the word that marks a deliberate read, and an impl either of
/// these traits would make the same read happen without it.
#[test]
fn secret_hands_its_bytes_to_nothing_implicitly() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/secret_deref.rs");
    cases.compile_fail("tests/ui/secret_as_ref.rs");
}

/// The other half of "no silent fallback": creating an encrypted store takes a token only a caller
/// that can ask a user is supposed to mint, and the token is spent by the call it authorizes. Both
/// properties rest on what the type does *not* offer, so both are pinned the same way.
#[test]
fn consent_can_be_neither_forged_nor_reused() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/consent_forged.rs");
    cases.compile_fail("tests/ui/consent_reused.rs");
}
