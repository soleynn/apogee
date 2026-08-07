//! Compile-fail proof that a live code cannot be copied, printed or conjured, and that nothing here
//! hands a stored secret back.
//!
//! Every property below is the absence of something: a trait that is not implemented, a constructor
//! that is not public, a method that does not exist. Absences are what a test written against
//! behaviour cannot reach, and they hold only as long as nobody adds the missing item, so each one
//! is pinned as a compile error rather than left to review.

/// A code lives for one submit. A clone is a second buffer of digits with its own lifetime, a
/// rendering is the shortest route those digits have to a log line, and a comparison is the shape
/// that invites a caller to keep the previous one around to compare against.
#[test]
fn a_live_code_can_be_neither_copied_nor_printed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/code_clone.rs");
    cases.compile_fail("tests/ui/code_display.rs");
    cases.compile_fail("tests/ui/code_compared.rs");
    cases.compile_fail("tests/ui/code_orphan_display.rs");
}

/// The same two absences on what a wait hands back, which holds a live code until it is taken. Its
/// own cases rather than a comment saying `Code`'s cover it: the wrapper is the type a caller actually
/// holds, and a derive on it would be a second buffer whatever the inner type promises.
#[test]
fn a_delivered_code_can_be_neither_copied_nor_printed() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/received_clone.rs");
    cases.compile_fail("tests/ui/received_display.rs");
}

/// Only this crate mints a code, so a code in a caller's hands came from a secret this crate holds.
/// A public constructor would make that untrue, and every caller that took a `Code` would have to go
/// back to checking where it came from.
#[test]
fn a_code_cannot_be_conjured_from_digits() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/code_forged.rs");
}

/// The write-only rule, as the type system sees it. A shared secret goes into the store and the only
/// thing that comes back out is a code derived from it: the profile holding the key hands out its
/// parameters and never the key, and the handle that reads the store hands out a code and never what
/// it read. Neither is a rule anything enforces at run time, so both are absences pinned here.
#[test]
fn nothing_reads_a_stored_secret_back_out() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/params_key_read_back.rs");
    cases.compile_fail("tests/ui/params_clone.rs");
    cases.compile_fail("tests/ui/otp_reads_the_secret_back.rs");
}
