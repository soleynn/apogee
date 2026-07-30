//! Lowering a block index and a verification of it into the map `apogee-sqpack` compares against.
//!
//! The index says how long each file was when the patch chain finished writing it; the verify pass
//! says which of its byte ranges no longer match. Those are exactly the two facts a pristine map is
//! made of, so the lowering is one walk over each, and it lives here because this is the crate that
//! holds both. Nothing about mod detection crosses into this crate: what leaves is a set of byte
//! ranges over containers, and what is made of it is the other crate's business.
//!
//! Only SqPack containers are described. A chain writes `ffxivboot.exe`, movies and loose data files
//! too, and a map speaks for archives, so a boot-repo index lowers to a map that covers nothing at
//! all, which is what makes every boot container unknown rather than foreign.
//!
//! One repository at a time, into a builder the caller owns, because an install has six or more and
//! each has its own chain, its own index and its own verification. Whether the map is *exhaustive*
//! for a repository is the caller's claim, made with
//! [`MapBuilder::accounts_for`](apogee_sqpack::mods::MapBuilder::accounts_for): only the caller knows
//! whether the chain it built this from was the whole history or the last patch.

use std::collections::HashMap;
use std::path::Path;

use apogee_sqpack::integrity::ContainerRef;
use apogee_sqpack::mods::MapBuilder;

use crate::index::model::Index;
use crate::index::verify::VerifyReport;

impl Index {
    /// The files this index describes and the length each should have.
    #[must_use]
    pub fn targets(&self) -> impl ExactSizeIterator<Item = (&Path, u64)> {
        self.targets
            .iter()
            .map(|target| (target.path.as_path(), target.final_len()))
    }

    /// Describe every SqPack container this index covers into `map`, with what `report` measured
    /// about it.
    ///
    /// `report` must come from a full pass. A refine pass fills in only the broken parts, so the
    /// missing-file signal a map needs is simply absent from one, and every container would read as
    /// present and clean.
    ///
    /// What each of the report's four lists means here:
    ///
    /// - **broken parts** are runs whose bytes do not match, recorded as such.
    /// - **missing files** are containers the chain wrote and the tree does not have, so every byte
    ///   of them disagrees.
    /// - **size mismatches** need nothing recorded. The length the map carries is the index's, and
    ///   comparing it against the tree is what the other crate does; in particular a file *longer*
    ///   than the index expects reports no broken part at all, because each part checks only its own
    ///   bytes, and the length is the only thing that says the extra bytes are there.
    /// - **strays** are containers on disk that no target explains, so the map does not describe them
    ///   and `accounts_for` decides what that means.
    pub fn describe_containers(&self, report: &VerifyReport, map: &mut MapBuilder) {
        let mut lengths: HashMap<&Path, u64> = HashMap::new();
        for target in &self.targets {
            let Some(at) = ContainerRef::from_relative_path(&target.path) else {
                continue;
            };
            let len = target.final_len();
            lengths.insert(target.path.as_path(), len);
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
    }
}
