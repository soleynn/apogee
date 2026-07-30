//! A synthetic archive for the inspector's own tests: both index forms and the data files they point
//! into, laid out over one list of files with every digest right.
//!
//! What makes it worth having is that it is *clean*: everything the checks judge is coherent, so a
//! finding out of one of these is a bug in a check rather than a fixture that never held together. The
//! shapes a pristine install varies on are carried on purpose, because those are what a naive check
//! trips over.
//!
//! The index forms are derived rather than declared: the files are grouped by the key each form hashes
//! them to, a group of one becomes an ordinary entry, and a group of several becomes a placeholder plus
//! a collision record apiece. That is exactly how the two forms come to differ on a real archive, and it
//! is what makes both of them name the same locations without anything saying so.

use std::collections::BTreeMap;
use std::path::Path;

use crate::archive::ArchiveId;
use crate::dat::MODEL_LOD_COUNT;
use crate::dat::builder::{Built, DatBuilder, EntrySpec};
use crate::game::Repo;
use crate::hash::hash_path;
use crate::index::IndexKind;
use crate::index::build::{IndexBuilder, packed};

/// Two paths in one folder whose file-name hashes are equal, so an `.index` keys them the same and has
/// to file both in its collision table. Their whole-path hashes differ, so an `.index2` keys them
/// apart, which is the real shape: the second form folds collisions the first does not.
///
/// Searched once and pinned rather than searched at test time. The hash is CRC-32 with the final
/// inversion left off, which is affine, so a family of same-shaped paths never collides and a search
/// over one never terminates; these came out of a search over random lengths.
const SHARED_FILE_HASH: [&str; 2] = [
    "chara/monster/m0001/obj/body/b0001/model/1ki1h5.mdl",
    "chara/monster/m0001/obj/body/b0001/model/n7_vzit0l0y.mdl",
];

/// Two paths whose whole-path hashes are equal, which is what an `.index2` is keyed by. Their file-name
/// hashes differ, so an `.index` keys them apart. Pinned for the same reason.
const SHARED_PATH_HASH: [&str; 2] = [
    "chara/monster/m0001/obj/body/b0001/model/59c3iwc.mdl",
    "chara/monster/m0001/obj/body/b0001/model/v6gpxc.mdl",
];

/// The leftovers a real collision record carries in its path field after the path's terminating NUL:
/// the field is never zeroed, so it holds whatever longer path was written there before.
const PATH_TAIL: &[u8] = b"chara/monster/m0001/obj/body/b0001/model/was_longer.mdl";

/// How much of the third segment to give the `.index`: it carries 16-byte records nothing here claims
/// to understand, and an `.index2` never carries any.
const UNCLASSIFIED_LEN: usize = 32;

/// Builds one archive: an `.index`, an `.index2` and as many data files as it was asked for.
pub struct ArchiveFixture {
    repo: Repo,
    id: ArchiveId,
    dats: Vec<DatBuilder>,
    /// The path each entry of a data file is named by, in the order the entries were laid down.
    /// `None` for an entry no index points at: what a mod tool leaves behind when it moves a file's
    /// bytes elsewhere and repoints the row.
    paths: Vec<Vec<Option<String>>>,
}

/// A built archive: the bytes of each of its files, and where each data file's entries and unclaimed
/// runs landed.
pub struct BuiltArchive {
    pub index1: Vec<u8>,
    pub index2: Vec<u8>,
    pub dats: Vec<Built>,
}

impl ArchiveFixture {
    /// An empty archive of `dats` data files.
    pub fn new(repo: Repo, id: ArchiveId, dats: usize) -> Self {
        Self {
            repo,
            id,
            dats: (0..dats).map(|_| DatBuilder::new()).collect(),
            paths: vec![Vec::new(); dats],
        }
    }

    /// An archive carrying, on purpose, every shape a pristine install varies on: one entry of each
    /// content type, a texture whose mips span several blocks, a volume texture declaring more than it
    /// stores, a standard entry whose size, allocation and occupancy words are all zero, another
    /// occupying nothing under a large allocation, slack inside a slot, a `span_index` that is not the
    /// dat number, a `max_file_size` the file exceeds, two data files, a single wiped region and a chain
    /// of three, and a collision in each index form.
    pub fn clean(repo: Repo, id: ArchiveId) -> Self {
        let mut f = Self::new(repo, id, 2);
        f.dat(1).span_index(1).max_file_size(2_000);
        f.file(
            0,
            "exd/root.exl",
            EntrySpec::standard(vec![b"ROOT".to_vec()]),
        )
        .file(
            0,
            "exd/item.exh",
            EntrySpec::standard(vec![b"ITEM ".repeat(500), b"tail".to_vec()]),
        )
        .file(
            0,
            "common/font/font1.tex",
            EntrySpec::texture_blocks(
                vec![0xAB; 80],
                vec![vec![vec![1u8; 4096], vec![2u8; 4096]], vec![vec![3u8; 256]]],
            ),
        )
        .gap(0, 3)
        .file(
            0,
            "common/font/font2.tex",
            EntrySpec::texture_declaring(vec![0xCD; 80], vec![vec![3u8; 512]], 4096),
        )
        .file(0, "exd/empty.exd", EntrySpec::standard(vec![]));
        // The two colliding pairs, one folded by each form, laid into the second data file beside a
        // model, an empty entry and the slack an archive that shrank a file in place leaves reserved.
        f.dat(1).slack(2);
        f.file(
            1,
            "exd/deleted.exd",
            EntrySpec::empty_with_leftovers(83_952, 2, 57_472),
        );
        f.dat(1).slack(0);
        for path in SHARED_FILE_HASH {
            f.file(1, path, EntrySpec::model(model_sections()));
        }
        f.dat(1).slack(4);
        for path in SHARED_PATH_HASH {
            f.file(1, path, EntrySpec::standard(vec![b"collides".to_vec()]));
        }
        f.dat(1).slack(0);
        f.gap_chain(1, &[2, 1, 5]);
        f
    }

    /// Lay `spec` into data file `dat` and name it `path` in both index forms.
    pub fn file(&mut self, dat: usize, path: &str, spec: EntrySpec) -> &mut Self {
        self.dats[dat].entry(spec);
        self.paths[dat].push(Some(path.to_owned()));
        self
    }

    /// Lay `spec` down after everything already in data file `dat` and repoint `path` at it, leaving
    /// the bytes it used to have where they were with nothing naming them.
    ///
    /// This is the shape every appending mod tool leaves: the archive grows past the length the patch
    /// chain gave it, the index row moves, and the original content is orphaned rather than
    /// overwritten. Nothing happens if the archive does not already carry `path`, since there would be
    /// no row to repoint.
    pub fn retarget(&mut self, dat: usize, path: &str, spec: EntrySpec) -> &mut Self {
        let Some(slot) = self.paths[dat]
            .iter_mut()
            .find(|named| named.as_deref() == Some(path))
        else {
            return self;
        };
        *slot = None;
        self.file(dat, path, spec)
    }

    /// Leave `units` of space no entry claims in data file `dat`.
    pub fn gap(&mut self, dat: usize, units: u32) -> &mut Self {
        self.dats[dat].gap(units);
        self
    }

    /// The same as a chain of wiped regions, which is what adjacent deletions leave.
    pub fn gap_chain(&mut self, dat: usize, units: &[u32]) -> &mut Self {
        self.dats[dat].gap_chain(units);
        self
    }

    /// One data file's builder, for the knobs that container's own checks need.
    pub fn dat(&mut self, dat: usize) -> &mut DatBuilder {
        &mut self.dats[dat]
    }

    /// Which repository and archive this is.
    pub fn id(&self) -> (Repo, ArchiveId) {
        (self.repo, self.id)
    }

    /// The archive's files, and where everything in them landed.
    pub fn built(&self) -> BuiltArchive {
        let dats: Vec<Built> = self.dats.iter().map(DatBuilder::built).collect();
        let mut placed: Vec<Named> = Vec::new();
        for (n, (built, paths)) in dats.iter().zip(&self.paths).enumerate() {
            for (path, at) in paths.iter().zip(&built.placed) {
                // An entry no path names is one nothing points at, so no index row is written for it.
                let Some(path) = path else { continue };
                placed.push(Named {
                    path: path.clone(),
                    dat: n as u8,
                    offset: at.offset,
                });
            }
        }
        BuiltArchive {
            index1: self.index(IndexKind::Index1, &placed),
            index2: self.index(IndexKind::Index2, &placed),
            dats,
        }
    }

    /// Write the archive's files into `dir`, creating it if it is not there.
    ///
    /// # Errors
    /// Whatever the filesystem raises.
    pub fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        let built = self.built();
        std::fs::create_dir_all(dir)?;
        for (kind, bytes) in [
            (IndexKind::Index1, &built.index1),
            (IndexKind::Index2, &built.index2),
        ] {
            std::fs::write(dir.join(self.id.index_file_name(kind)), bytes)?;
        }
        for (n, dat) in built.dats.iter().enumerate() {
            std::fs::write(dir.join(self.id.dat_file_name(n as u8)), &dat.bytes)?;
        }
        Ok(())
    }

    /// One index form over the placed files: a group of one key becomes an entry, a group of several
    /// becomes a placeholder plus a record apiece, which is how a real container spells a collision.
    fn index(&self, kind: IndexKind, placed: &[Named]) -> Vec<u8> {
        let mut b = IndexBuilder::new(kind);
        b.data_file_count(self.dats.len() as u32)
            .collision_path_tail(PATH_TAIL)
            .sort_entries();
        if kind == IndexKind::Index1 {
            b.unclassified(UNCLASSIFIED_LEN);
        }
        let mut groups: BTreeMap<u64, Vec<&Named>> = BTreeMap::new();
        for file in placed {
            groups
                .entry(key_of(kind, &file.path))
                .or_default()
                .push(file);
        }
        for (key, group) in &groups {
            match group.as_slice() {
                [only] => {
                    b.entry(*key, packed(only.dat, only.offset));
                }
                several => {
                    b.entry(*key, 1);
                    for (i, file) in several.iter().enumerate() {
                        b.collision(*key, packed(file.dat, file.offset), i as u32, &file.path);
                    }
                }
            }
        }
        b.bytes()
    }
}

/// One file of the archive once its entry has been laid down.
struct Named {
    path: String,
    dat: u8,
    offset: u64,
}

/// The key one index form holds `path` under.
fn key_of(kind: IndexKind, path: &str) -> u64 {
    let hash = hash_path(path);
    match kind {
        IndexKind::Index1 => hash.key(),
        IndexKind::Index2 => u64::from(hash.full),
    }
}

/// A model's eleven sections, two levels of detail carrying nothing at all.
fn model_sections() -> [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT] {
    let mut sections: [Vec<u8>; 2 + 3 * MODEL_LOD_COUNT] = Default::default();
    sections[0] = b"stack".repeat(20);
    sections[1] = b"runtime".repeat(30);
    sections[2] = vec![7u8; 4096];
    sections[4] = vec![1u8; 300];
    sections
}
