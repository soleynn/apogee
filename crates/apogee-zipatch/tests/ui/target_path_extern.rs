//! `TargetPath` wraps a private field and has no public constructor, so this forge must not compile.

use apogee_zipatch::TargetPath;

fn main() {
    let _ = TargetPath(std::path::PathBuf::new());
}
