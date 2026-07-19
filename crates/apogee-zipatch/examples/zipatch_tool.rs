//! `zipatch-tool`: the patch-day inspection and index binary. Three verbs:
//!
//! ```text
//! cargo run -p apogee-zipatch --example zipatch_tool -- dump <file.patch>
//! cargo run -p apogee-zipatch --example zipatch_tool -- index <out.apzi> <patch>...
//! cargo run -p apogee-zipatch --example zipatch_tool -- verify <game-root> <index.apzi>
//! ```
//!
//! `dump` renders every chunk with its file offset; `index` builds a block index from a patch chain;
//! `verify` checks an install against one and reports broken/missing/size-mismatched/stray files. All
//! formatting lives in the library (the `Display` impls and the typed report), so this example stays
//! an I/O shell that the library never has to become.

use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apogee_zipatch::{Index, PatchReader, Platform, VerifyOptions, build_index};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((verb, rest)) if verb == "dump" && rest.len() == 1 => dump(Path::new(&rest[0])),
        Some((verb, rest)) if verb == "index" && rest.len() >= 2 => index(rest),
        Some((verb, rest)) if verb == "verify" && rest.len() == 2 => {
            verify(Path::new(&rest[0]), Path::new(&rest[1]))
        }
        _ => {
            eprintln!(
                "usage:\n  zipatch_tool dump <file.patch>\n  zipatch_tool index <out.apzi> <patch>...\n  zipatch_tool verify <game-root> <index.apzi>"
            );
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(clean) => {
            if clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Dump every chunk with its offset. Always "clean".
fn dump(path: &Path) -> Result<bool, Box<dyn Error>> {
    let mut reader = PatchReader::open(BufReader::new(File::open(path)?))?;
    let mut count = 0usize;
    loop {
        let offset = reader.position();
        let Some(chunk) = reader.next_chunk()? else {
            break;
        };
        println!("{offset:#010x}  {chunk}");
        count += 1;
    }
    println!("{count} chunk(s)");
    Ok(true)
}

/// Build an index over `out, patch...` and write it to the `.apzi` path. Always "clean".
fn index(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let (out, patches) = args.split_first().ok_or("index needs an output path")?;
    let mut inputs = Vec::new();
    for patch in patches {
        let path = PathBuf::from(patch);
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("patch")
            .to_owned();
        inputs.push((name, File::open(&path)?));
    }
    let index = build_index(inputs, Platform::Win32, "")?;
    index.write_apzi(BufWriter::new(File::create(out)?))?;
    println!("wrote {out}");
    Ok(true)
}

/// Verify `root` against `index.apzi`, printing a summary. "Clean" when the report has nothing.
fn verify(root: &Path, index_path: &Path) -> Result<bool, Box<dyn Error>> {
    let index = Index::read_apzi(BufReader::new(File::open(index_path)?))?;
    let report = index.verify(root, &VerifyOptions::default())?;
    println!(
        "broken={} size_mismatches={} missing={} strays={}",
        report.broken.len(),
        report.size_mismatches.len(),
        report.missing_files.len(),
        report.stray_files.len(),
    );
    Ok(report.is_clean())
}
