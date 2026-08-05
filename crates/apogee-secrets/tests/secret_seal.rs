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
    cases.compile_fail("tests/ui/secret_orphan_debug.rs");
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
