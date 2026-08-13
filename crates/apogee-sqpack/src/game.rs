//! Install enumeration and lookup: which repositories and archives a game tree carries, and where in
//! them a given path lives.
//!
//! [`GameData::open`] takes the game subtree (the directory holding `sqpack/` and `ffxivgame.ver`),
//! discovers the base repository and any expansion repositories present, reads each one's version
//! file best-effort, and enumerates the archives beneath them. It is the read-only inspection entry
//! point the patcher and core use before a patch or repair; unlike the login version report, a missing
//! version file is reported as absent rather than treated as a fault.
//!
//! [`GameData::lookup`] answers "which dat file, at what offset" for a game path. Indexes are parsed
//! on first use and kept, because a sweep asks the same archive thousands of times.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::archive::{ArchiveId, Category, PLATFORM_TAG};
use crate::dat::{Dat, Entry};
use crate::error::Result;
use crate::index::{Index, IndexKind};

/// The index cache's shape: one parsed container per archive and index form, shared across clones.
type IndexCache = Arc<Mutex<HashMap<(Repo, ArchiveId, IndexKind), Arc<Index>>>>;

/// The dat cache's shape: one open container per file, shared across clones.
type DatCache = Arc<Mutex<HashMap<PathBuf, Arc<Dat>>>>;

/// A SqPack repository within a game tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Repo {
    /// The base game repository (`sqpack/ffxiv`).
    Base,
    /// An expansion repository (`sqpack/ex{n}`), 1-based.
    Ex(u8),
}

impl Repo {
    /// The repository's directory name under `sqpack/` (`ffxiv` or `ex{n}`).
    #[must_use]
    pub fn dir_name(self) -> String {
        match self {
            Repo::Base => "ffxiv".to_owned(),
            Repo::Ex(n) => format!("ex{n}"),
        }
    }

    /// The expansion byte the repository's archives carry.
    #[must_use]
    pub fn expansion(self) -> u8 {
        match self {
            Repo::Base => 0,
            Repo::Ex(n) => n,
        }
    }

    /// The repository a directory under `sqpack/` names, or `None` if it names none.
    #[must_use]
    pub fn from_dir_name(name: &str) -> Option<Self> {
        if name == "ffxiv" {
            return Some(Repo::Base);
        }
        expansion_of(name).map(Repo::Ex)
    }

    /// The repository a game path belongs to: a second segment spelled `ex{n}` names an expansion
    /// (`bg/ex3/…`, `cut/ex1/…`, `music/ex5/…`); anything else is the base repository. Case-insensitive,
    /// like the path hash and the category, so an uppercase path resolves the same as a lowercase one.
    #[must_use]
    pub fn from_path(path: &str) -> Self {
        let Some(segment) = path.split('/').nth(1) else {
            return Repo::Base;
        };
        expansion_of(segment).map_or(Repo::Base, Repo::Ex)
    }
}

/// The expansion number `ex{n}` spells, case-insensitively, or `None` for anything else. Digits only:
/// `u8::from_str` would otherwise read `ex+1` as expansion one.
fn expansion_of(name: &str) -> Option<u8> {
    let (head, tail) = name.split_at_checked(2)?;
    if !head.eq_ignore_ascii_case("ex") || tail.is_empty() {
        return None;
    }
    if !tail.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    tail.parse::<u8>().ok().filter(|n| *n > 0)
}

/// A discovered repository and its version, if a readable version file was present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoInfo {
    /// Which repository this is.
    pub repo: Repo,
    /// The repository's directory under the game tree's `sqpack/`.
    pub dir: PathBuf,
    /// The trimmed contents of the repository's version file, or `None` if it was absent or unreadable.
    pub version: Option<String>,
}

/// One archive discovered in a repository, and the index files it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveInfo {
    /// The repository holding the archive.
    pub repo: Repo,
    /// The archive's identity, as its file names spell it.
    pub id: ArchiveId,
    /// The directory the archive's files sit in.
    pub dir: PathBuf,
    /// Whether an `.index` sits beside the archive's data files.
    pub has_index1: bool,
    /// Whether an `.index2` does.
    pub has_index2: bool,
    /// The `.dat{n}` numbers sitting beside the archive, ascending. Filled by the directory walk that
    /// discovered the archive, so what an index declares can be judged against what is there without
    /// a second listing and without probing a dat space nobody enumerated.
    pub dats: Vec<u8>,
}

impl ArchiveInfo {
    /// Whether the archive carries an index of this form.
    #[must_use]
    pub fn has_index(&self, kind: IndexKind) -> bool {
        match kind {
            IndexKind::Index2 => self.has_index2,
            _ => self.has_index1,
        }
    }

    /// The path of one of the archive's index files.
    #[must_use]
    pub fn index_path(&self, kind: IndexKind) -> PathBuf {
        self.dir.join(self.id.index_file_name(kind))
    }

    /// The path of one of the archive's data files.
    #[must_use]
    pub fn dat_path(&self, dat: u8) -> PathBuf {
        self.dir.join(self.id.dat_file_name(dat))
    }
}

/// Where a game path's bytes live: the archive that holds it and the offset into one of its dat files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileLocation {
    /// The repository holding the archive.
    pub repo: Repo,
    /// The archive holding the file.
    pub archive: ArchiveId,
    /// Which of the archive's indexes answered.
    pub index_kind: IndexKind,
    /// Which `.dat{n}` of the archive holds the file.
    pub dat: u8,
    /// The file's byte offset within that dat file.
    pub offset: u64,
    /// The dat file itself, ready to open.
    pub dat_path: PathBuf,
}

/// The repositories and archives of an FFXIV game tree.
#[derive(Clone)]
pub struct GameData {
    game_dir: PathBuf,
    repos: Vec<RepoInfo>,
    archives: Vec<ArchiveInfo>,
    /// Indexes parsed on first use. Shared across clones on purpose: two handles on one install
    /// should not each pay to parse the same twelve megabytes.
    indexes: IndexCache,
    /// Dat containers opened on first use, for the same reason. Not the same snapshot an index is:
    /// a container's headers are read once and its entries are read live (see [`Dat`]).
    dats: DatCache,
}

impl fmt::Debug for GameData {
    /// Summarizes rather than dumping: an install's parsed indexes run to millions of entries.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GameData")
            .field("game_dir", &self.game_dir)
            .field("repos", &self.repos.len())
            .field("archives", &self.archives.len())
            .field("indexes_open", &self.cached_index_count())
            .field("dats_open", &self.cached_dat_count())
            .finish()
    }
}

impl GameData {
    /// Open the game subtree at `game_dir` (the directory containing `sqpack/` and `ffxivgame.ver`)
    /// and enumerate the repositories and archives present.
    ///
    /// The repositories are whichever directories `sqpack/` actually holds: `ffxiv` is the base and
    /// every `ex{n}` an expansion, so the expansion the game ships next needs no code change here.
    /// Version files are read best-effort. An archive is discovered by an index file, so a directory
    /// holding only dat files enumerates nothing.
    ///
    /// # Errors
    /// [`crate::Error::Io`] only for a genuine failure listing `sqpack/` or a repository directory; an
    /// absent `sqpack/` yields an empty repository list, not an error.
    pub fn open(game_dir: impl Into<PathBuf>) -> Result<Self> {
        let game_dir = game_dir.into();
        let sqpack = game_dir.join("sqpack");
        let mut repos = enumerate_repos(&game_dir, &sqpack)?;
        repos.sort_by_key(|info| info.repo);

        let mut archives = Vec::new();
        for info in &repos {
            archives.extend(enumerate_archives(info)?);
        }
        archives.sort_by_key(|a| (a.repo, a.id));

        Ok(Self {
            game_dir,
            repos,
            archives,
            indexes: Arc::new(Mutex::new(HashMap::new())),
            dats: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// The game subtree this was opened against.
    #[must_use]
    pub fn game_dir(&self) -> &Path {
        &self.game_dir
    }

    /// The repositories discovered, base first, then expansions in index order.
    #[must_use]
    pub fn repos(&self) -> &[RepoInfo] {
        &self.repos
    }

    /// The archives discovered, grouped by repository (base first, then expansions in index order,
    /// the same order as [`GameData::repos`]), and in archive-id order within each.
    #[must_use]
    pub fn archives(&self) -> &[ArchiveInfo] {
        &self.archives
    }

    /// One archive by repository and id. An id alone is not enough: a stray copy of an expansion's
    /// archive left in the base repository carries the same id as the real one.
    #[must_use]
    pub fn archive(&self, repo: Repo, id: ArchiveId) -> Option<&ArchiveInfo> {
        self.archives.iter().find(|a| a.repo == repo && a.id == id)
    }

    /// How many indexes have been parsed and kept so far.
    #[must_use]
    pub fn cached_index_count(&self) -> usize {
        self.lock_indexes().len()
    }

    /// One archive's index, parsed on first use and kept afterwards. `None` when the install carries
    /// no such archive, or no index of that kind for it.
    ///
    /// # Errors
    /// Everything [`Index::open`] raises: the file cannot be read, is larger than the default cap, or
    /// does not parse.
    pub fn index(&self, repo: Repo, id: ArchiveId, kind: IndexKind) -> Result<Option<Arc<Index>>> {
        let Some(info) = self.archive(repo, id) else {
            return Ok(None);
        };
        self.index_of(info, kind)
    }

    /// One archive's index, parsed on first use and kept afterwards. `None` when the archive carries
    /// no index of that form.
    ///
    /// # Errors
    /// Everything [`Index::open`] raises.
    pub fn index_of(&self, info: &ArchiveInfo, kind: IndexKind) -> Result<Option<Arc<Index>>> {
        let key = (info.repo, info.id, kind);
        if let Some(hit) = self.lock_indexes().get(&key) {
            return Ok(Some(Arc::clone(hit)));
        }
        if !info.has_index(kind) {
            return Ok(None);
        }
        let index = Arc::new(Index::open(info.index_path(kind))?);
        // A racing caller may have inserted the same index; either copy is equally good, so keep
        // whichever landed first and let this one drop.
        Ok(Some(Arc::clone(
            self.lock_indexes()
                .entry(key)
                .or_insert_with(|| Arc::clone(&index)),
        )))
    }

    /// Resolve a game path to the dat file and offset holding it, or `None` if the install has no such
    /// file.
    ///
    /// Each candidate archive is asked through its `.index`, whose 64-bit key is specific enough that
    /// a miss means the archive does not hold the path. Only an archive with no `.index` at all is
    /// asked through its `.index2`, because that form's key is a bare 32-bit hash: on a category with
    /// a few hundred thousand entries, roughly one absent path in ten thousand collides with some
    /// unrelated file's key, and answering from that would hand back another file's bytes.
    ///
    /// # Errors
    /// - [`crate::Error::SynonymUnresolved`] if the path's key collides and no collision record spells
    ///   that path, which is the one case where an answer would have to be a guess. Reported only if
    ///   no other candidate archive answered.
    /// - Everything [`GameData::index_of`] raises.
    pub fn lookup(&self, path: &str) -> Result<Option<FileLocation>> {
        self.probe(path, None)
    }

    /// Resolve a game path through one index form only, whether or not the archive carries the other.
    ///
    /// This is how the two forms are cross-checked against each other; ordinary callers want
    /// [`GameData::lookup`]. An `.index2` answer is worth exactly a 32-bit hash match: it confirms a
    /// path the `.index` already resolved, and means little on its own.
    ///
    /// # Errors
    /// The same faults [`GameData::lookup`] raises.
    pub fn lookup_in(&self, path: &str, kind: IndexKind) -> Result<Option<FileLocation>> {
        self.probe(path, Some(kind))
    }

    /// Walk the archives that could hold `path`. `only` pins the index form; without it, an archive
    /// answers through its `.index` and falls back to its `.index2` only when it has no `.index`.
    ///
    /// The path's first segment picks the category and its second picks the repository; every archive
    /// of that category in that repository is probed in archive order. A path whose first segment
    /// names no category resolves to `None`: no archive could hold it.
    fn probe(&self, path: &str, only: Option<IndexKind>) -> Result<Option<FileLocation>> {
        let Some(category) = Category::from_path(path) else {
            return Ok(None);
        };
        let repo = Repo::from_path(path);
        let mut unresolved = None;

        for info in self
            .archives
            .iter()
            .filter(|a| a.repo == repo && a.id.category == category.id())
        {
            let kinds: &[IndexKind] = match only {
                Some(IndexKind::Index2) => &[IndexKind::Index2],
                Some(_) => &[IndexKind::Index1],
                None if info.has_index1 => &[IndexKind::Index1],
                None => &[IndexKind::Index2],
            };
            for kind in kinds {
                let Some(index) = self.index_of(info, *kind)? else {
                    continue;
                };
                // A collision the container cannot spell is remembered rather than raised: another
                // archive may hold the path outright, and only a lookup that finds nothing else owes
                // the caller that fault.
                let location = match index.resolve(path) {
                    Ok(Some(location)) => location,
                    Ok(None) => continue,
                    Err(err) => {
                        unresolved.get_or_insert(err);
                        continue;
                    }
                };
                return Ok(Some(FileLocation {
                    repo,
                    archive: info.id,
                    index_kind: *kind,
                    dat: location.dat,
                    offset: location.offset,
                    dat_path: info.dat_path(location.dat),
                }));
            }
        }
        match unresolved {
            Some(err) => Err(err),
            None => Ok(None),
        }
    }

    /// The dat file a lookup landed in, opened on first use and kept afterwards.
    ///
    /// # Errors
    /// Everything [`Dat::open`] raises: the file cannot be opened, or its headers do not parse.
    pub fn dat(&self, location: &FileLocation) -> Result<Arc<Dat>> {
        self.dat_at(&location.dat_path)
    }

    /// One of an archive's dat files, opened on first use and kept afterwards. This is how a sweep
    /// reaches a container it has only enumerated, without resolving a path first.
    ///
    /// # Errors
    /// Everything [`Dat::open`] raises.
    pub fn dat_of(&self, info: &ArchiveInfo, dat: u8) -> Result<Arc<Dat>> {
        self.dat_at(&info.dat_path(dat))
    }

    /// One dat file, keyed by the path it was opened from: a cache keyed on an archive's identity
    /// instead could hand back a container from somewhere else, since a [`FileLocation`] carries both
    /// and nothing binds them together.
    fn dat_at(&self, path: &Path) -> Result<Arc<Dat>> {
        if let Some(hit) = self.lock_dats().get(path) {
            return Ok(Arc::clone(hit));
        }
        let dat = Arc::new(Dat::open(path)?);
        // A racing caller may have opened the same container; either handle is equally good.
        Ok(Arc::clone(
            self.lock_dats()
                .entry(path.to_path_buf())
                .or_insert_with(|| Arc::clone(&dat)),
        ))
    }

    /// How many dat containers have been opened and kept so far.
    #[must_use]
    pub fn cached_dat_count(&self) -> usize {
        self.lock_dats().len()
    }

    /// Resolve a game path and parse the entry holding it, or `None` if the install has no such
    /// file.
    ///
    /// # Errors
    /// - [`crate::Error::EntryOutOfBounds`] if the index answered with an offset its dat file does
    ///   not reach, which a repair sweep meets when an index survives a rewrite its dat did not.
    ///   This is the one caller that knows the key that landed there, so it is the one that can say
    ///   which entry was wrong rather than only where the file ended.
    /// - Everything [`GameData::lookup`], [`GameData::dat`] and [`Dat::entry_at`] raise.
    pub fn entry(&self, path: &str) -> Result<Option<(Arc<Dat>, Entry)>> {
        let Some(found) = self.lookup(path)? else {
            return Ok(None);
        };
        let dat = self.dat(&found)?;
        let entry = dat.entry_at(found.offset).map_err(|err| match err {
            crate::Error::Truncated { .. } => crate::Error::EntryOutOfBounds {
                index_key: index_key(path, found.index_kind),
                offset: found.offset,
            },
            other => other,
        })?;
        Ok(Some((dat, entry)))
    }

    /// Read a game path's bytes, or `None` if the install has no such file.
    ///
    /// # Errors
    /// Everything [`GameData::entry`] and [`Dat::read`] raise.
    pub fn read(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let Some((dat, entry)) = self.entry(path)? else {
            return Ok(None);
        };
        Ok(Some(dat.read(&entry)?))
    }

    /// Read a game path's bytes into `out`, returning how many were written, or `None` if the
    /// install has no such file.
    ///
    /// # Errors
    /// Everything [`GameData::entry`] and [`Dat::read_into`] raise.
    pub fn read_into(&self, path: &str, out: &mut impl Write) -> Result<Option<u64>> {
        let Some((dat, entry)) = self.entry(path)? else {
            return Ok(None);
        };
        Ok(Some(dat.read_into(&entry, out)?))
    }

    /// The index cache, with a poisoned lock treated as a live one: it holds only parsed containers,
    /// so a panic elsewhere leaves nothing inconsistent to protect.
    fn lock_indexes(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<(Repo, ArchiveId, IndexKind), Arc<Index>>> {
        self.indexes.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The dat cache, poisoned-as-live for the same reason as [`GameData::lock_indexes`].
    fn lock_dats(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, Arc<Dat>>> {
        self.dats.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// List the repository directories under `sqpack/`, each with its version file read best-effort. An
/// absent `sqpack/` is no repositories rather than a fault: inspection is tolerant.
fn enumerate_repos(game_dir: &Path, sqpack: &Path) -> Result<Vec<RepoInfo>> {
    if !sqpack.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(sqpack)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let repo = if name == Repo::Base.dir_name() {
            Repo::Base
        } else {
            match Repo::from_dir_name(name) {
                Some(repo) => repo,
                None => continue,
            }
        };
        // The base repository's version lives at the game-tree root, not inside sqpack/.
        let version = match repo {
            Repo::Base => read_version_file(&game_dir.join("ffxivgame.ver")),
            _ => read_version_file(&entry.path().join(format!("{name}.ver"))),
        };
        out.push(RepoInfo {
            repo,
            dir: entry.path(),
            version,
        });
    }
    Ok(out)
}

/// List one repository's archives, keyed off the index files present. Both forms are looked for, so an
/// archive that lost its `.index` is still discovered rather than silently absent.
///
/// The data files are collected in the same pass and attached to whichever archive an index file
/// names: a directory holding only dat files still enumerates nothing, so an archive that lost both
/// its indexes is absent rather than half-discovered.
fn enumerate_archives(info: &RepoInfo) -> Result<Vec<ArchiveInfo>> {
    let suffixes = [
        (
            IndexKind::Index1,
            format!(".{PLATFORM_TAG}.{}", IndexKind::Index1.extension()),
        ),
        (
            IndexKind::Index2,
            format!(".{PLATFORM_TAG}.{}", IndexKind::Index2.extension()),
        ),
    ];
    let dat_suffix = format!(".{PLATFORM_TAG}.dat");
    let mut found: BTreeMap<ArchiveId, (bool, bool)> = BTreeMap::new();
    let mut dats: BTreeMap<ArchiveId, Vec<u8>> = BTreeMap::new();
    for entry in std::fs::read_dir(&info.dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if let Some((id, dat)) = parse_dat_name(name, &dat_suffix) {
            dats.entry(id).or_default().push(dat);
            continue;
        }
        // `.index` is a suffix of nothing else, but `.index2` ends in `.index2`, so the longer suffix
        // is tested first.
        for (kind, suffix) in suffixes.iter().rev() {
            let Some(stem) = name.strip_suffix(suffix.as_str()) else {
                continue;
            };
            // The stem has to be the one an id spells, or the path this crate builds from that id
            // would name a file the directory does not hold.
            let Some(id) = ArchiveId::parse_stem(stem).filter(|id| id.stem() == stem) else {
                break;
            };
            let seen = found.entry(id).or_insert((false, false));
            match kind {
                IndexKind::Index2 => seen.1 = true,
                _ => seen.0 = true,
            }
            break;
        }
    }
    Ok(found
        .into_iter()
        .map(|(id, (has_index1, has_index2))| {
            let mut dats = dats.remove(&id).unwrap_or_default();
            dats.sort_unstable();
            ArchiveInfo {
                repo: info.repo,
                id,
                dir: info.dir.clone(),
                has_index1,
                has_index2,
                dats,
            }
        })
        .collect())
}

/// The archive and `.dat{n}` number a data file's name spells, or `None` for a name that is not one.
/// A suffix that is not a `u8`, or a stem no id spells, is skipped for the same reason an index file's
/// is: this crate would never build that path.
fn parse_dat_name(name: &str, dat_suffix: &str) -> Option<(ArchiveId, u8)> {
    let (stem, number) = name.split_once(dat_suffix)?;
    let id = ArchiveId::parse_stem(stem).filter(|id| id.stem() == stem)?;
    Some((id, number.parse::<u8>().ok()?))
}

/// The key an index of this form holds `path` under, for a fault that has to name the entry rather
/// than only the byte it stopped at.
fn index_key(path: &str, kind: IndexKind) -> u64 {
    let hash = crate::hash::hash_path(path);
    match kind {
        IndexKind::Index2 => u64::from(hash.full),
        _ => hash.key(),
    }
}

/// Read and trim a version file, returning `None` if it is absent or unreadable. Inspection is
/// tolerant; the strict sanity gate lives on the login path, not here.
fn read_version_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    // Strip a leading BOM the way the reference launcher's text reader does.
    let text = text.strip_prefix('\u{feff}').unwrap_or(&text);
    Some(text.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dat::builder::{DatBuilder, EntrySpec};
    use crate::hash::hash_path;
    use crate::index::build::{IndexBuilder, packed};
    use std::fs;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    /// Lay down one archive's index files under a repository directory.
    fn write_archive(dir: &Path, id: ArchiveId, files: &[(&str, u8, u64)]) {
        fs::create_dir_all(dir).unwrap();
        for kind in [IndexKind::Index1, IndexKind::Index2] {
            let mut b = IndexBuilder::new(kind);
            b.data_file_count(4);
            for (path, dat, offset) in files {
                b.path(path, packed(*dat, *offset));
            }
            fs::write(dir.join(id.index_file_name(kind)), b.bytes()).unwrap();
        }
    }

    /// A game tree with `common` and `exd` archives in the base repository and a `bg` archive in ex1.
    fn game_tree() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        write(&game.join("ffxivgame.ver"), "2024.03.27.0000.0000");
        write(&game.join("sqpack/ex1/ex1.ver"), "2024.03.01.0000.0000");
        write_archive(
            &game.join("sqpack/ffxiv"),
            ArchiveId::new(0x00, 0, 0),
            &[("common/font/font1.tex", 0, 0x100_000)],
        );
        write_archive(
            &game.join("sqpack/ffxiv"),
            ArchiveId::new(0x0a, 0, 0),
            &[("exd/root.exl", 2, 0x200_000)],
        );
        write_archive(
            &game.join("sqpack/ex1"),
            ArchiveId::new(0x02, 1, 1),
            &[("bg/ex1/01_roc_r2/twn/r2t1/level/planmap.lgb", 1, 0x300_000)],
        );
        tmp
    }

    #[test]
    fn dir_names_match_the_layout() {
        assert_eq!(Repo::Base.dir_name(), "ffxiv");
        assert_eq!(Repo::Ex(1).dir_name(), "ex1");
        assert_eq!(Repo::Ex(4).dir_name(), "ex4");
        assert_eq!(Repo::Base.expansion(), 0);
        assert_eq!(Repo::Ex(4).expansion(), 4);
    }

    #[test]
    fn enumerates_base_and_expansions_with_versions() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        fs::create_dir_all(game.join("sqpack/ffxiv")).unwrap();
        fs::create_dir_all(game.join("sqpack/ex1")).unwrap();
        fs::create_dir_all(game.join("sqpack/ex2")).unwrap();
        write(&game.join("ffxivgame.ver"), "2024.03.27.0000.0000");
        write(&game.join("sqpack/ex1/ex1.ver"), "2024.03.01.0000.0000");
        // ex2 has no version file.

        let data = GameData::open(game).unwrap();
        let repos = data.repos();
        assert_eq!(repos.len(), 3);

        assert_eq!(repos[0].repo, Repo::Base);
        assert_eq!(repos[0].version.as_deref(), Some("2024.03.27.0000.0000"));

        assert_eq!(repos[1].repo, Repo::Ex(1));
        assert_eq!(repos[1].version.as_deref(), Some("2024.03.01.0000.0000"));

        assert_eq!(repos[2].repo, Repo::Ex(2));
        assert_eq!(repos[2].version, None);
    }

    #[test]
    fn missing_sqpack_yields_no_repos() {
        let tmp = tempfile::tempdir().unwrap();
        let data = GameData::open(tmp.path()).unwrap();
        assert!(data.repos().is_empty());
        assert!(data.archives().is_empty());
        assert_eq!(data.game_dir(), tmp.path());
    }

    #[test]
    fn version_file_is_trimmed_and_bom_stripped() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        fs::create_dir_all(game.join("sqpack/ffxiv")).unwrap();
        write(
            &game.join("ffxivgame.ver"),
            "\u{feff}2024.03.27.0000.0000\n",
        );

        let data = GameData::open(game).unwrap();
        assert_eq!(
            data.repos()[0].version.as_deref(),
            Some("2024.03.27.0000.0000")
        );
    }

    #[test]
    fn present_but_empty_version_file_is_carried_as_empty() {
        // Inspection is tolerant: an empty version file is present, so it reads as Some(""), distinct
        // from the None of an absent file. (The strict sanity gate lives on the login path.)
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        fs::create_dir_all(game.join("sqpack/ffxiv")).unwrap();
        write(&game.join("ffxivgame.ver"), "");

        let data = GameData::open(game).unwrap();
        assert_eq!(data.repos()[0].version.as_deref(), Some(""));
    }

    #[test]
    fn expansion_without_base_still_enumerates() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        fs::create_dir_all(game.join("sqpack/ex1")).unwrap();
        write(&game.join("sqpack/ex1/ex1.ver"), "2024.03.01.0000.0000");

        let data = GameData::open(game).unwrap();
        let repos = data.repos();
        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].repo, Repo::Ex(1));
    }

    #[test]
    fn a_second_path_segment_spelled_ex_names_the_expansion_repository() {
        assert_eq!(Repo::from_path("bg/ex1/01_roc_r2/level/x.lgb"), Repo::Ex(1));
        assert_eq!(Repo::from_path("music/ex5/bgm.scd"), Repo::Ex(5));
        assert_eq!(Repo::from_path("bg/ffxiv/sea_s1/x.lgb"), Repo::Base);
        assert_eq!(Repo::from_path("exd/root.exl"), Repo::Base);
        assert_eq!(Repo::from_path("common"), Repo::Base);
        // `ex` with a non-numeric tail, or `ex0`, is an ordinary directory name.
        assert_eq!(Repo::from_path("exd/exhibit/x.exh"), Repo::Base);
        assert_eq!(Repo::from_path("bg/ex0/x.lgb"), Repo::Base);
        assert_eq!(Repo::from_path("bg/ex+1/x.lgb"), Repo::Base);
        assert_eq!(Repo::from_path("bg/ex256/x.lgb"), Repo::Base);
        // Case-insensitive, so an uppercase path resolves where its lowercase twin does. The path
        // hash and the category both fold case, and a repository that did not would lose the lookup.
        assert_eq!(Repo::from_path("BG/EX1/01_ROC_R2/x.lgb"), Repo::Ex(1));
    }

    #[test]
    fn archives_are_enumerated_from_the_index_files_present() {
        let tmp = game_tree();
        let data = GameData::open(tmp.path()).unwrap();
        let found: Vec<(Repo, ArchiveId)> =
            data.archives().iter().map(|a| (a.repo, a.id)).collect();
        assert_eq!(
            found,
            vec![
                (Repo::Base, ArchiveId::new(0x00, 0, 0)),
                (Repo::Base, ArchiveId::new(0x0a, 0, 0)),
                (Repo::Ex(1), ArchiveId::new(0x02, 1, 1)),
            ]
        );
        assert!(data.archives().iter().all(|a| a.has_index1 && a.has_index2));
        assert_eq!(
            data.archive(Repo::Base, ArchiveId::new(0x0a, 0, 0))
                .unwrap()
                .repo,
            Repo::Base
        );
        assert_eq!(data.archive(Repo::Base, ArchiveId::new(0x0b, 0, 0)), None);
    }

    #[test]
    fn an_archives_data_files_are_listed_by_the_walk_that_discovered_it() {
        let tmp = game_tree();
        let dir = tmp.path().join("sqpack/ffxiv");
        let id = ArchiveId::new(0x0a, 0, 0);
        for name in [
            id.dat_file_name(0),
            id.dat_file_name(2),
            // Names this crate would never build a path to are not data files of this archive.
            format!("{}.bck", id.dat_file_name(3)),
            "0a0000.win32.dat".to_owned(),
            "0A0000.win32.dat4".to_owned(),
        ] {
            write(&dir.join(name), "");
        }
        let data = GameData::open(tmp.path()).unwrap();
        assert_eq!(data.archive(Repo::Base, id).unwrap().dats, [0, 2]);
        // An archive with no dat files beside it lists none rather than assuming a `dat0`.
        assert!(
            data.archive(Repo::Base, ArchiveId::new(0x00, 0, 0))
                .unwrap()
                .dats
                .is_empty()
        );
    }

    #[test]
    fn a_dat_only_directory_enumerates_no_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        fs::create_dir_all(game.join("sqpack/ffxiv")).unwrap();
        write(&game.join("sqpack/ffxiv/000000.win32.dat0"), "");
        let data = GameData::open(game).unwrap();
        assert_eq!(data.repos().len(), 1);
        assert!(data.archives().is_empty());
    }

    #[test]
    fn a_path_resolves_to_the_archive_dat_and_offset_holding_it() {
        let tmp = game_tree();
        let data = GameData::open(tmp.path()).unwrap();

        let found = data.lookup("exd/root.exl").unwrap().unwrap();
        assert_eq!(found.repo, Repo::Base);
        assert_eq!(found.archive, ArchiveId::new(0x0a, 0, 0));
        assert_eq!(found.index_kind, IndexKind::Index1);
        assert_eq!(found.dat, 2);
        assert_eq!(found.offset, 0x200_000);
        assert!(found.dat_path.ends_with("sqpack/ffxiv/0a0000.win32.dat2"));

        let bg = data
            .lookup("bg/ex1/01_roc_r2/twn/r2t1/level/planmap.lgb")
            .unwrap()
            .unwrap();
        assert_eq!(bg.repo, Repo::Ex(1));
        assert_eq!(bg.archive, ArchiveId::new(0x02, 1, 1));
        assert_eq!(bg.dat, 1);
    }

    #[test]
    fn a_lookup_is_case_insensitive_and_misses_cleanly() {
        let tmp = game_tree();
        let data = GameData::open(tmp.path()).unwrap();
        assert!(data.lookup("EXD/Root.EXL").unwrap().is_some());
        assert!(data.lookup("exd/nothing.exl").unwrap().is_none());
        // No archive can hold a path whose first segment names no category.
        assert!(data.lookup("nope/root.exl").unwrap().is_none());
        // The category exists but this install carries no archive for it.
        assert!(data.lookup("music/ffxiv/bgm.scd").unwrap().is_none());
    }

    #[test]
    fn a_lookup_falls_back_to_the_second_index_only_when_there_is_no_first() {
        let tmp = game_tree();
        let dir = tmp.path().join("sqpack/ffxiv");
        let id = ArchiveId::new(0x0a, 0, 0);
        fs::remove_file(dir.join(id.index_file_name(IndexKind::Index1))).unwrap();

        let data = GameData::open(tmp.path()).unwrap();
        // The archive is still discovered: enumeration looks for either index form.
        let info = data.archive(Repo::Base, id).unwrap();
        assert!(!info.has_index1 && info.has_index2);
        let found = data.lookup("exd/root.exl").unwrap().unwrap();
        assert_eq!(found.index_kind, IndexKind::Index2);
        assert_eq!(found.dat, 2);
    }

    #[test]
    fn a_path_the_first_index_misses_is_absent_even_if_the_second_has_its_short_hash() {
        // The `.index2` key is a bare 32-bit hash, so on a real category roughly one absent path in
        // ten thousand collides with some unrelated file's key. Answering from that would hand back
        // another file's bytes, so an archive that has an `.index` is judged only by it.
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        write(&game.join("ffxivgame.ver"), "2024.03.27.0000.0000");
        let dir = game.join("sqpack/ffxiv");
        fs::create_dir_all(&dir).unwrap();
        let id = ArchiveId::new(0x0a, 0, 0);

        // The `.index` holds one file; the `.index2` additionally holds an entry under the whole-path
        // hash of a file that is not in the archive at all.
        let mut one = IndexBuilder::new(IndexKind::Index1);
        one.path("exd/root.exl", packed(0, 0x100_000));
        fs::write(dir.join(id.index_file_name(IndexKind::Index1)), one.bytes()).unwrap();
        let mut two = IndexBuilder::new(IndexKind::Index2);
        two.path("exd/root.exl", packed(0, 0x100_000))
            .path("exd/absent.exh", packed(3, 0x900_000));
        fs::write(dir.join(id.index_file_name(IndexKind::Index2)), two.bytes()).unwrap();

        let data = GameData::open(game).unwrap();
        assert_eq!(data.lookup("exd/absent.exh").unwrap(), None);
        // Asked through the second form on purpose, it answers: that is what makes the cross-check
        // useful and why an ordinary lookup must not take it.
        let forced = data
            .lookup_in("exd/absent.exh", IndexKind::Index2)
            .unwrap()
            .unwrap();
        assert_eq!(forced.dat, 3);
    }

    #[test]
    fn a_stray_copy_of_an_expansion_archive_does_not_shadow_the_real_one() {
        // A repair sweep quarantines exactly this: an archive left in the wrong repository. Its file
        // name spells the same id, so anything keyed on the id alone would open the stray instead.
        let tmp = game_tree();
        let id = ArchiveId::new(0x02, 1, 1);
        let stray = tmp.path().join("sqpack/ffxiv");
        write_archive(&stray, id, &[("bg/ffxiv/decoy.lgb", 0, 0x80)]);

        let data = GameData::open(tmp.path()).unwrap();
        let found = data
            .lookup("bg/ex1/01_roc_r2/twn/r2t1/level/planmap.lgb")
            .unwrap()
            .unwrap();
        assert_eq!(found.repo, Repo::Ex(1));
        assert_eq!(found.dat, 1);
        assert!(found.dat_path.starts_with(tmp.path().join("sqpack/ex1")));
    }

    #[test]
    fn a_collision_one_archive_cannot_spell_does_not_stop_another_from_answering() {
        // Two chunks of one category: the first carries a placeholder its collision table cannot
        // spell, the second holds the file outright. The fault is only worth raising if nothing
        // answers at all.
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        write(&game.join("sqpack/ex1/ex1.ver"), "2024.03.01.0000.0000");
        let dir = game.join("sqpack/ex1");
        let path = "bg/ex1/01_roc_r2/twn/r2t1/level/planmap.lgb";

        let mut blocked = IndexBuilder::new(IndexKind::Index1);
        blocked.entry(hash_path(path).key(), 1);
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join(ArchiveId::new(0x02, 1, 0).index_file_name(IndexKind::Index1)),
            blocked.bytes(),
        )
        .unwrap();
        write_archive(&dir, ArchiveId::new(0x02, 1, 1), &[(path, 1, 0x300_000)]);

        let data = GameData::open(game).unwrap();
        let found = data.lookup(path).unwrap().unwrap();
        assert_eq!(found.archive, ArchiveId::new(0x02, 1, 1));

        // With nothing else holding it, the same placeholder is the reported fault.
        let mut alone = IndexBuilder::new(IndexKind::Index1);
        alone.entry(hash_path("bg/ex1/other.lgb").key(), 1);
        fs::write(
            dir.join(ArchiveId::new(0x02, 1, 0).index_file_name(IndexKind::Index1)),
            alone.bytes(),
        )
        .unwrap();
        let data = GameData::open(game).unwrap();
        assert!(matches!(
            data.lookup("bg/ex1/other.lgb"),
            Err(crate::Error::SynonymUnresolved { .. })
        ));
    }

    #[test]
    fn an_expansion_the_crate_has_never_heard_of_enumerates() {
        // The repository list is whatever `sqpack/` holds, so the next expansion needs no code change.
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        write(&game.join("sqpack/ex9/ex9.ver"), "2030.01.01.0000.0000");
        write_archive(
            &game.join("sqpack/ex9"),
            ArchiveId::new(0x02, 9, 0),
            &[("bg/ex9/00_new/level/planmap.lgb", 0, 0x80)],
        );

        let data = GameData::open(game).unwrap();
        assert_eq!(data.repos().len(), 1);
        assert_eq!(data.repos()[0].repo, Repo::Ex(9));
        let found = data
            .lookup("bg/ex9/00_new/level/planmap.lgb")
            .unwrap()
            .unwrap();
        assert_eq!(found.repo, Repo::Ex(9));
    }

    #[test]
    fn a_directory_named_like_an_index_is_not_an_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        fs::create_dir_all(game.join("sqpack/ffxiv/0a0000.win32.index")).unwrap();
        // An uppercase stem names a file this crate would never build a path to, so it is skipped
        // rather than enumerated into a lookup that cannot open it.
        write(&game.join("sqpack/ffxiv/0B0000.win32.index"), "");
        let data = GameData::open(game).unwrap();
        assert!(data.archives().is_empty());
    }

    #[test]
    fn indexes_are_parsed_once_and_kept() {
        let tmp = game_tree();
        let data = GameData::open(tmp.path()).unwrap();
        assert_eq!(data.cached_index_count(), 0);
        data.lookup("exd/root.exl").unwrap();
        let after_first = data.cached_index_count();
        assert_eq!(after_first, 1);
        data.lookup("exd/root.exl").unwrap();
        assert_eq!(data.cached_index_count(), after_first);
        // A clone shares the cache rather than re-parsing the same containers.
        let twin = data.clone();
        twin.lookup("exd/root.exl").unwrap();
        assert_eq!(twin.cached_index_count(), after_first);
    }

    #[test]
    fn an_absent_archive_or_index_is_reported_as_absent_rather_than_an_error() {
        let tmp = game_tree();
        let data = GameData::open(tmp.path()).unwrap();
        assert!(
            data.index(Repo::Base, ArchiveId::new(0x0b, 0, 0), IndexKind::Index1)
                .unwrap()
                .is_none()
        );
        assert!(
            data.index(Repo::Base, ArchiveId::new(0x0a, 0, 0), IndexKind::Index1)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn a_stale_handle_keeps_answering_from_the_indexes_it_first_parsed() {
        // The cache has no invalidation on purpose: a handle is a snapshot. A caller that rewrites the
        // archives (a patch, a repair) has to open a fresh one, and this is what says so.
        let tmp = game_tree();
        let data = GameData::open(tmp.path()).unwrap();
        assert_eq!(data.lookup("exd/root.exl").unwrap().unwrap().dat, 2);

        write_archive(
            &tmp.path().join("sqpack/ffxiv"),
            ArchiveId::new(0x0a, 0, 0),
            &[("exd/root.exl", 3, 0x400_000)],
        );
        assert_eq!(data.lookup("exd/root.exl").unwrap().unwrap().dat, 2);
        let fresh = GameData::open(tmp.path()).unwrap();
        assert_eq!(fresh.lookup("exd/root.exl").unwrap().unwrap().dat, 3);
    }

    /// An archive whose index really points at entries in a dat file beside it.
    fn archive_with_data(dir: &Path, id: ArchiveId, files: &[(&str, EntrySpec)]) -> Vec<Vec<u8>> {
        use crate::dat::builder::DatBuilder;
        fs::create_dir_all(dir).unwrap();
        let mut dat = DatBuilder::new();
        for (_, spec) in files {
            dat.entry(spec.clone());
        }
        let (bytes, placed) = dat.build();
        fs::write(dir.join(id.dat_file_name(0)), &bytes).unwrap();

        let mut index = IndexBuilder::new(IndexKind::Index1);
        for ((path, _), at) in files.iter().zip(&placed) {
            index.path(path, packed(0, at.offset));
        }
        fs::write(
            dir.join(id.index_file_name(IndexKind::Index1)),
            index.bytes(),
        )
        .unwrap();
        placed.into_iter().map(|p| p.content).collect()
    }

    #[test]
    fn a_path_reads_the_bytes_its_archive_holds() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        write(&game.join("ffxivgame.ver"), "2024.03.27.0000.0000");
        let content = archive_with_data(
            &game.join("sqpack/ffxiv"),
            ArchiveId::new(0x0a, 0, 0),
            &[
                ("exd/root.exl", EntrySpec::standard(vec![b"ROOT".to_vec()])),
                (
                    "exd/item.exh",
                    EntrySpec::standard(vec![b"ITEM ".repeat(500), b"tail".to_vec()]),
                ),
            ],
        );

        let data = GameData::open(game).unwrap();
        assert_eq!(
            data.read("exd/root.exl").unwrap().as_ref(),
            Some(&content[0])
        );
        assert_eq!(
            data.read("EXD/Item.EXH").unwrap().as_ref(),
            Some(&content[1])
        );
        // A path the install does not hold is absent rather than an error, the way a lookup is.
        assert_eq!(data.read("exd/nothing.exl").unwrap(), None);
        assert_eq!(data.read("nope/root.exl").unwrap(), None);

        // Streaming into a sink writes the same bytes and reports the count.
        let mut sink = Vec::new();
        assert_eq!(
            data.read_into("exd/item.exh", &mut sink).unwrap(),
            Some(content[1].len() as u64)
        );
        assert_eq!(sink, content[1]);
        assert_eq!(data.read_into("exd/nothing.exl", &mut sink).unwrap(), None);
    }

    #[test]
    fn an_archive_spanning_several_dat_files_reads_each_from_its_own_container() {
        // Every large archive in a real install spans two to seven dat files in one directory, so a
        // cache keyed on anything coarser than the file would answer a lookup in `dat1` with `dat0`'s
        // handle and hand back whatever sits at that offset in the wrong file.
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("sqpack/ffxiv");
        fs::create_dir_all(&dir).unwrap();
        let id = ArchiveId::new(0x0a, 0, 0);

        let mut placed = Vec::new();
        for (n, body) in [b"from dat zero".as_slice(), b"from dat one".as_slice()]
            .into_iter()
            .enumerate()
        {
            let mut dat = DatBuilder::new();
            dat.entry(EntrySpec::standard(vec![body.to_vec()]));
            let (bytes, at) = dat.build();
            fs::write(dir.join(id.dat_file_name(n as u8)), &bytes).unwrap();
            placed.push(at[0].clone());
        }
        let mut index = IndexBuilder::new(IndexKind::Index1);
        index.path("exd/zero.exl", packed(0, placed[0].offset));
        index.path("exd/one.exl", packed(1, placed[1].offset));
        fs::write(
            dir.join(id.index_file_name(IndexKind::Index1)),
            index.bytes(),
        )
        .unwrap();

        let data = GameData::open(tmp.path()).unwrap();
        assert_eq!(
            data.read("exd/zero.exl").unwrap().unwrap(),
            b"from dat zero"
        );
        assert_eq!(data.read("exd/one.exl").unwrap().unwrap(), b"from dat one");
        assert_eq!(data.cached_dat_count(), 2);

        // And the same two containers are what an enumerating sweep reaches by dat number.
        let info = data.archive(Repo::Base, id).unwrap();
        let zero = data.dat_of(info, 0).unwrap();
        let one = data.dat_of(info, 1).unwrap();
        assert!(!Arc::ptr_eq(&zero, &one));
        assert_eq!(data.cached_dat_count(), 2);
        assert_eq!(
            zero.read_entry_at(placed[0].offset).unwrap(),
            b"from dat zero"
        );
        assert_eq!(
            one.read_entry_at(placed[1].offset).unwrap(),
            b"from dat one"
        );
    }

    #[test]
    fn dat_containers_are_opened_once_and_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        archive_with_data(
            &game.join("sqpack/ffxiv"),
            ArchiveId::new(0x0a, 0, 0),
            &[("exd/root.exl", EntrySpec::standard(vec![b"ROOT".to_vec()]))],
        );
        let data = GameData::open(game).unwrap();
        assert_eq!(data.cached_dat_count(), 0);
        data.read("exd/root.exl").unwrap();
        assert_eq!(data.cached_dat_count(), 1);
        data.read("exd/root.exl").unwrap();
        assert_eq!(data.cached_dat_count(), 1);
        // A clone shares the open containers rather than opening its own.
        let twin = data.clone();
        twin.read("exd/root.exl").unwrap();
        assert_eq!(twin.cached_dat_count(), 1);
        assert!(format!("{data:?}").contains("dats_open"));
    }

    #[test]
    fn an_entry_carries_the_container_it_was_read_from() {
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        archive_with_data(
            &game.join("sqpack/ffxiv"),
            ArchiveId::new(0x0a, 0, 0),
            &[("exd/root.exl", EntrySpec::standard(vec![b"ROOT".to_vec()]))],
        );
        let data = GameData::open(game).unwrap();
        let (dat, entry) = data.entry("exd/root.exl").unwrap().unwrap();
        assert_eq!(entry.declared_len(), 4);
        assert_eq!(dat.read(&entry).unwrap(), b"ROOT");
        assert!(data.entry("exd/nothing.exl").unwrap().is_none());
    }

    #[test]
    fn a_lookup_that_lands_outside_its_dat_file_is_reported_rather_than_read() {
        // A repair sweep meets exactly this: an index that survived a rewrite its dat file did not.
        let tmp = tempfile::tempdir().unwrap();
        let game = tmp.path();
        let dir = game.join("sqpack/ffxiv");
        archive_with_data(
            &dir,
            ArchiveId::new(0x0a, 0, 0),
            &[("exd/root.exl", EntrySpec::standard(vec![b"ROOT".to_vec()]))],
        );
        let id = ArchiveId::new(0x0a, 0, 0);
        let mut index = IndexBuilder::new(IndexKind::Index1);
        index.path("exd/root.exl", packed(0, 0x40_000));
        fs::write(
            dir.join(id.index_file_name(IndexKind::Index1)),
            index.bytes(),
        )
        .unwrap();

        let data = GameData::open(game).unwrap();
        match data.read("exd/root.exl") {
            Err(crate::Error::EntryOutOfBounds { index_key, offset }) => {
                assert_eq!(index_key, hash_path("exd/root.exl").key());
                assert_eq!(offset, 0x40_000);
            }
            other => panic!("expected EntryOutOfBounds, got {other:?}"),
        }
    }

    #[test]
    fn an_archive_without_a_second_index_still_answers_from_its_first() {
        let tmp = game_tree();
        let dir = tmp.path().join("sqpack/ffxiv");
        let id = ArchiveId::new(0x0a, 0, 0);
        fs::remove_file(dir.join(id.index_file_name(IndexKind::Index2))).unwrap();

        let data = GameData::open(tmp.path()).unwrap();
        assert!(!data.archive(Repo::Base, id).unwrap().has_index2);
        assert!(
            data.index(Repo::Base, id, IndexKind::Index2)
                .unwrap()
                .is_none()
        );
        assert_eq!(data.lookup("exd/root.exl").unwrap().unwrap().dat, 2);
    }
}
