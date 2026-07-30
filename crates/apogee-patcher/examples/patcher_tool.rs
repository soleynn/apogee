//! `patcher-tool`: the orchestration-level questions, which need more than one format at once.
//!
//! ```text
//! cargo run -p apogee-patcher --example patcher_tool -- mods <game-dir> <index.apzi> <version> <repo>...
//! ```
//!
//! `mods` answers what a repair should ask first: which of an install's files it would replace with
//! something else. It is here rather than beside either format because it needs both. This crate
//! holds the block index and the verification; `apogee-sqpack` holds the archive and the comparison;
//! the byte-range map between them is all either has to know about the other.
//!
//! `version` is the version the repository is at, cross-checked against the one the index was built
//! for. An index for another patch level would report every file that changed since as one somebody
//! modified, so it is refused rather than believed.
//!
//! Each `repo` (`ffxiv`, `ex1`, …) is the caller asserting that the index covers that repository
//! exhaustively. Without one, a container the index does not name reads as unjudged rather than as a
//! mod tool's work, which is the safe direction for an index built from part of a chain.

use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::process::ExitCode;

use apogee_patcher::mods::describe_containers;
use apogee_sqpack::mods::{ModOptions, PristineMap};
use apogee_sqpack::{GameData, Repo};
use apogee_zipatch::{Index, VerifyOptions};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((verb, rest)) if verb == "mods" && rest.len() >= 3 => mods(rest),
        _ => {
            eprintln!("usage:\n  patcher_tool mods <game-dir> <index.apzi> <version> <repo>...");
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(pristine) => {
            if pristine {
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

/// Verify `game-dir` against `index.apzi`, then say which of its files a repair would replace.
/// "Clean" when the install holds only what the chain put there.
fn mods(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let root = Path::new(&args[0]);
    let index = Index::read_apzi(BufReader::new(File::open(&args[1])?))?;
    let version = &args[2];
    let report = index.verify(root, &VerifyOptions::default())?;

    let mut repos = Vec::new();
    for name in &args[3..] {
        repos.push(Repo::from_dir_name(name).ok_or("not a repository name")?);
    }
    let mut builder = PristineMap::builder();
    describe_containers(&index, &report, version, &repos, &mut builder)?;

    let found = GameData::open(root)?.detect_mods(&builder.build(), &ModOptions::default());
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
        println!(
            "note: {} file(s) were not judged; name a repository to include it, and see the \
             containers below for what could not be read",
            found.totals.unknown + found.totals.broken,
        );
    }
    for container in found.altered_containers() {
        println!("{container}");
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
