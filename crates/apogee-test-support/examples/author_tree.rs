//! Author a tree manifest from a directory and write it as committed oracle JSON.
//!
//! The reference applier (run out-of-process on a developer machine) lays down a tree; this records
//! that tree's recorded facts (per-file relative path, length, SHA256) so CI can diff our applier's
//! output against it. It calls the same tested `tree_manifest::author`, so the committed artifact and
//! the CI comparison can never drift.
//!
//! ```text
//! cargo run -p apogee-test-support --example author_tree -- <root-dir> <out.json>
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apogee_test_support::tree_manifest;

fn main() -> ExitCode {
    let mut args = std::env::args_os().skip(1);
    let (Some(root), Some(out), None) = (args.next(), args.next(), args.next()) else {
        eprintln!("usage: author_tree <root-dir> <out.json>");
        return ExitCode::FAILURE;
    };
    match author(&PathBuf::from(root), &PathBuf::from(out)) {
        Ok((count, out)) => {
            println!("wrote {count} file fact(s) to {}", out.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn author(root: &Path, out: &Path) -> std::io::Result<(usize, PathBuf)> {
    let manifest = tree_manifest::author(root)?;
    std::fs::write(out, manifest.to_json_pretty())?;
    Ok((manifest.files.len(), out.to_path_buf()))
}
