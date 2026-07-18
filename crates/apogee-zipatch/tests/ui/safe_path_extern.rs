//! `SafePath` wraps a private field and has no public constructor, so this forge must not compile.

use apogee_zipatch::SafePath;

fn main() {
    let _ = SafePath(std::path::PathBuf::new());
}
