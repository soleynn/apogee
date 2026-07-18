//! Compile-fail proof that [`apogee_zipatch::SafePath`] and [`apogee_zipatch::TargetPath`] cannot be
//! minted outside the crate.
//!
//! Both wrap a private field and expose only a crate-private confinement constructor, so a sink can
//! never be handed a path that skipped confinement. This pins that seal against a struct-literal forge.

#[test]
fn confined_path_newtypes_are_unconstructable_from_outside_the_crate() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/safe_path_extern.rs");
    cases.compile_fail("tests/ui/target_path_extern.rs");
}
