//! `zipatch-tool`: the patch-day inspection and index binary. Five verbs:
//!
//! ```text
//! cargo run -p apogee-zipatch --example zipatch_tool -- dump <file.patch>
//! cargo run -p apogee-zipatch --example zipatch_tool -- index <out.apzi> <repo-version> <patch>...
//! cargo run -p apogee-zipatch --example zipatch_tool -- verify <game-root> <index.apzi>
//! cargo run -p apogee-zipatch --example zipatch_tool -- repair <game-root> <index.apzi> <patch>...
//! cargo run -p apogee-zipatch --example zipatch_tool -- mods <game-dir> <index.apzi> <repo>...
//! ```
//!
//! `dump` renders every chunk with its file offset; `index` builds a block index from a patch chain;
//! `verify` checks an install against one and reports broken/missing/size-mismatched/stray files;
//! `repair` heals a damaged install by pulling the broken ranges from local patch files; `mods`
//! answers the question a repair should ask first, which files it would replace with something else.
//! All formatting lives in the libraries (the `Display` impls and the typed reports), so this example
//! stays an I/O shell that they never have to become.
//!
//! `mods` is here rather than beside the reader because it needs both halves: this crate owns the
//! block index and the verification, `apogee-sqpack` owns the archive and the comparison, and the
//! byte-range map between them is all either has to know about the other.

use std::error::Error;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use apogee_sqpack::mods::{ModOptions, PristineMap};
use apogee_sqpack::{GameData, Repo};
use apogee_zipatch::{Index, LocalPatchSource, PatchReader, Platform, VerifyOptions, build_index};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((verb, rest)) if verb == "dump" && rest.len() == 1 => dump(Path::new(&rest[0])),
        Some((verb, rest)) if verb == "index" && rest.len() >= 3 => index(rest),
        Some((verb, rest)) if verb == "verify" && rest.len() == 2 => {
            verify(Path::new(&rest[0]), Path::new(&rest[1]))
        }
        Some((verb, rest)) if verb == "repair" && rest.len() >= 3 => repair(rest),
        Some((verb, rest)) if verb == "mods" && rest.len() >= 2 => mods(rest),
        _ => {
            eprintln!(
                "usage:\n  zipatch_tool dump <file.patch>\n  zipatch_tool index <out.apzi> <repo-version> <patch>...\n  zipatch_tool verify <game-root> <index.apzi>\n  zipatch_tool repair <game-root> <index.apzi> <patch>...\n  zipatch_tool mods <game-dir> <index.apzi> <repo>..."
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

/// Build an index for `repo-version` over `patch...` and write it to the `out.apzi` path.
/// `args` is `out.apzi, repo-version, patch...`. The version labels the index for the repair
/// cross-check, so it must be the version the chain brings the repo to. Always "clean".
fn index(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let (out, rest) = args.split_first().ok_or("index needs an output path")?;
    let (version, patches) = rest.split_first().ok_or("index needs a repo version")?;
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
    let index = build_index(inputs, Platform::Win32, version.as_str())?;
    index.write_apzi(BufWriter::new(File::create(out)?))?;
    println!("wrote {out} for version {version}");
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

/// Verify `game-dir` against `index.apzi`, then say which of its files a repair would replace.
/// "Clean" when the install holds only what the chain put there. `args` is `game-dir, index.apzi,
/// repo...`, where each `repo` (`ffxiv`, `ex1`, …) is the caller asserting that the index covers that
/// repository exhaustively: without one, a container the index does not name is unknown rather than
/// added, which is the safe direction for an index built from part of a chain.
fn mods(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let root = Path::new(&args[0]);
    let index = Index::read_apzi(BufReader::new(File::open(&args[1])?))?;
    let report = index.verify(root, &VerifyOptions::default())?;

    let mut builder = PristineMap::builder();
    for name in &args[2..] {
        let repo = Repo::from_dir_name(name).ok_or("not a repository name")?;
        builder.accounts_for(repo);
    }
    index.describe_containers(&report, &mut builder);
    let map = builder.build();

    let found = GameData::open(root)?.detect_mods(&map, &ModOptions::default());
    println!(
        "pristine={} modified={} foreign={} broken={} unknown={} shared={}",
        found.totals.pristine,
        found.totals.modified,
        found.totals.foreign,
        found.totals.broken,
        found.totals.unknown,
        found.totals.shared,
    );
    if !found.is_exhaustive() {
        println!("note: part of the install was not judged; name its repositories to include it");
    }
    for file in found.replaced() {
        println!("{file}");
    }
    println!(
        "{} file(s) a repair would replace",
        found.would_be_replaced()
    );
    Ok(found.is_pristine())
}

/// Verify `root` against `index.apzi`, then repair the broken ranges from the given patch files (in
/// the index's chain order). "Clean" when nothing is left broken. `args` is `root, index.apzi,
/// patch...`.
fn repair(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let root = Path::new(&args[0]);
    let index = Index::read_apzi(BufReader::new(File::open(&args[1])?))?;
    let paths: Vec<PathBuf> = args[2..].iter().map(PathBuf::from).collect();

    let report = index.verify(root, &VerifyOptions::default())?;
    if report.is_clean() {
        println!("already clean, nothing to repair");
        return Ok(true);
    }
    let mut source = LocalPatchSource::new(paths);
    let outcome = index.repair(root, &report, &mut source)?;
    println!(
        "repaired={} still_broken={} recreated={} resized={} bytes_fetched={}",
        outcome.repaired.len(),
        outcome.still_broken.len(),
        outcome.recreated.len(),
        outcome.resized.len(),
        outcome.bytes_fetched,
    );
    Ok(outcome.is_complete())
}
