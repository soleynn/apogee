//! Compile-fail proof that [`apogee_fetch::VerifiedFile`] cannot be forged.
//!
//! The proof type has a private field and no public constructor, so only the crate's verification
//! path can mint one. This pins that a consumer cannot fabricate a `VerifiedFile` to smuggle
//! unverified bytes past a `VerifiedFile`-only apply queue.

#[test]
fn verified_file_is_unconstructable_from_outside_the_crate() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/verified_file_extern.rs");
}
