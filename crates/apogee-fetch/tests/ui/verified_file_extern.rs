//! `VerifiedFile` is sealed: a private field and no public constructor. Neither a struct literal nor
//! any associated function can mint one from another crate, so this must fail to compile.

use apogee_fetch::VerifiedFile;

fn main() {
    let forged = VerifiedFile {
        path: std::path::PathBuf::new(),
    };
    let _ = forged.path();
}
