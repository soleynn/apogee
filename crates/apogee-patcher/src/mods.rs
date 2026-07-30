//! Building the map mod detection compares against, out of a block index and a verification of it.
//!
//! The index says how long each file was when the patch chain finished writing it; the verify pass
//! says which of its byte ranges no longer match. Those are the two facts a
//! [`PristineMap`](apogee_sqpack::mods::PristineMap) is made of, so the lowering is one walk over
//! each. It lives here because this is the layer that already holds both: the reader knows archives
//! and nothing about patches, the patch format knows patches and nothing about what a launcher does
//! with a verify report, and composing the two is this crate's whole job.
//!
//! Only SqPack containers are described. A chain writes `ffxivboot.exe`, movies and loose data files
//! too, and a map speaks for archives, so a boot-repo index lowers to a map that covers nothing at
//! all, which is what makes every boot container unknown rather than foreign.
//!
//! One repository at a time into a builder the caller owns, because an install has six or more and
//! each has its own chain, its own index and its own verification.

use std::collections::HashMap;
use std::path::Path;

use apogee_sqpack::Repo;
use apogee_sqpack::integrity::ContainerRef;
use apogee_sqpack::mods::MapBuilder;
use apogee_zipatch::{Index, VerifyReport};

/// Why a block index cannot describe the install in front of it.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MapError {
    /// The index describes a different patch level than the install is at.
    ///
    /// Refused rather than reported, because the consequence of using it is the worst answer the
    /// comparison can give: every file a patch touched since would read as one somebody modified,
    /// and the user would be told a repair reverts work they never did. A stale map is not a
    /// partial map, and nothing downstream can tell them apart.
    #[error("the index describes version {indexed}, the install is at {installed}")]
    VersionMismatch { indexed: String, installed: String },
}

/// Describe every SqPack container `index` covers into `map`, with what `report` measured about it.
///
/// `installed_version` is the repository's version as the tree reports it, cross-checked against the
/// version the index was built for. Passed in rather than read here: a version file that is missing
/// and one that is unreadable both read as absent through the reader's tolerant path, and a check
/// that cannot tell those apart is not a check.
///
/// `exhaustive_for` is the caller's claim that the index covers those repositories completely. Only
/// the caller knows whether the chain this was built from was the whole history or the last patch,
/// and claiming it wrongly turns a pristine archive the map never saw into a wholly foreign one.
///
/// The claim is made *here*, rather than by the caller against the builder, so that this returning
/// an error leaves the builder exactly as it found it. Claimed separately, a caller that ignored the
/// error would be holding a builder that accounts for a repository and describes none of its
/// containers, and that map does not say "I do not know": it says every file in the install is one a
/// mod tool put there.
///
/// `report` must come from a full pass. A refine pass fills in only the broken parts, so the
/// missing-file signal a map needs is simply absent from one and every container would read as
/// present and clean.
///
/// What each of the report's four lists means here:
///
/// - **broken parts** are runs whose bytes do not match, recorded as such.
/// - **missing files** are containers the chain wrote and the tree does not have, so every byte of
///   them disagrees.
/// - **size mismatches** need nothing recorded. The length the map carries is the index's, and
///   comparing it against the tree is the reader's job; in particular a file *longer* than the index
///   expects reports no broken part at all, because each part checks only its own bytes, and the
///   length is the only thing that says the extra bytes are there.
/// - **strays** are containers on disk that no target explains, so the map does not describe them
///   and `accounts_for` decides what that means.
///
/// # Errors
/// [`MapError::VersionMismatch`] when the index was built for a different version than the install
/// is at.
pub fn describe_containers(
    index: &Index,
    report: &VerifyReport,
    installed_version: &str,
    exhaustive_for: &[Repo],
    map: &mut MapBuilder,
) -> Result<(), MapError> {
    if index.repo_version() != installed_version {
        return Err(MapError::VersionMismatch {
            indexed: index.repo_version().to_owned(),
            installed: installed_version.to_owned(),
        });
    }
    for repo in exhaustive_for {
        map.accounts_for(*repo);
    }

    let mut lengths: HashMap<&Path, u64> = HashMap::new();
    for (path, len) in index.targets() {
        let Some(at) = ContainerRef::from_relative_path(path) else {
            continue;
        };
        lengths.insert(path, len);
        map.container(at, len);
    }
    for path in &report.missing_files {
        if let Some(at) = ContainerRef::from_relative_path(path)
            && let Some(len) = lengths.get(path.as_path())
        {
            map.absent(at, *len);
        }
    }
    for part in &report.broken {
        if let Some(at) = ContainerRef::from_relative_path(&part.path) {
            map.dirty(at, part.target_off, part.target_len);
        }
    }
    Ok(())
}
