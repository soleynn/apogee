//! What is checked before an install or a repair touches anything: that the game is not running in
//! the install, and that the two disk pools have room.
//!
//! The game check comes first and has no escape hatch. It is a positive question asked of a
//! [`GameProbe`] the composition root injects, rather than something inferred from a write that
//! failed: a running client holds its own files open, so an apply into a live install fails partway
//! through, at a moment that varies by which file the patch reached first. Asking beforehand is what
//! makes the refusal say what to do about it.
//!
//! The space check is a heuristic with an escape hatch ([`PatcherConfig::ignore_space`], which covers
//! space and nothing else) and a backstop. The patch store must hold the concurrent downloads (a
//! rolling window, or all of them when kept); the install dir must hold the applied result, which
//! patch length overestimates since patches both add and delete. A pool whose free space cannot be
//! read (a non-existent tree, or a non-Unix target) is not blocked on.
//!
//! Two pools, but not always two filesystems: a patch store under the game root, or both under one
//! home directory, is the ordinary arrangement. Pools that resolve onto the same mount are guarded
//! once against their summed need, because free space they both draw on is not free space each of
//! them has.
//!
//! The backstop is fetch's eager disk-full detection, and it reaches a caller as its own arm rather
//! than through this one: `install::acquire_err` routes it to
//! [`PatchError::OutOfSpace`](crate::PatchError::OutOfSpace), so a
//! transfer that fills the disk after this check passed (or after it was skipped) is still typed as
//! a space failure. The two are kept apart because they say different things. This one is a
//! prediction from patchlist lengths that names a pool and a needed/free pair; that one is an
//! observation that names the path the filesystem refused.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use sqex_proto::PatchListEntry;

use crate::{PatcherConfig, PreflightError, SpacePool};

/// The rolling window of patches assumed resident at once when not keeping them (XL checks the first
/// six); the largest six bound any six concurrent.
const WINDOW: usize = 6;

/// Answers whether the game is running in a given install.
///
/// The seam the game-running guard is built on. This crate holds no process knowledge and does not
/// depend on the one that does: what a live game looks like on a machine is an operating-system
/// question, and the answer differs by runner, so it is injected through
/// [`PatcherConfig::game_probe`] the same way the [`Fetcher`](apogee_fetch::Fetcher) is.
///
/// The probe is asked once per install or repair, on the caller's task, before anything is spawned
/// or created. A probe that has to go to the kernel for the answer is expected; one that goes to the
/// network is not.
///
/// A probe that cannot tell answers `false`. The guard exists to stop the ordinary mistake, and it
/// is not the only thing standing between a running game and a corrupted install: the apply itself
/// still fails on a file the client holds. Reporting an install as running because nobody could look
/// would block a machine the launcher cannot see into from ever patching.
#[derive(Clone)]
pub struct GameProbe(Arc<dyn Fn(&Path) -> bool + Send + Sync>);

impl GameProbe {
    /// A probe that answers `check`, which is given the install root to look in.
    #[must_use]
    pub fn new(check: impl Fn(&Path) -> bool + Send + Sync + 'static) -> Self {
        Self(Arc::new(check))
    }

    /// A probe that always answers "not running".
    ///
    /// For a caller with no process table to consult: tests, and anything driving the patcher against
    /// a tree no game could be running in. Named rather than defaulted so that opting out of the
    /// guard is a decision that appears in the code, and so every place that took it can be found.
    #[must_use]
    pub fn never_running() -> Self {
        Self::new(|_| false)
    }

    /// Whether the game is running in the install at `game_root`.
    #[must_use]
    pub fn is_running(&self, game_root: &Path) -> bool {
        (self.0)(game_root)
    }
}

impl std::fmt::Debug for GameProbe {
    /// The probe is a function, which has nothing to render.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GameProbe")
    }
}

/// Refuse the operation if the game is running in the install at `game_root`.
///
/// Unconditional: [`PatcherConfig::ignore_space`] turns off the space estimate and nothing else. That
/// hatch exists for a caller who knows the free-space arithmetic is wrong about its disk, which is a
/// claim about a prediction. Whether a process is running is not a prediction, and no caller is in a
/// position to know better than the machine.
pub(crate) fn game_not_running(
    config: &PatcherConfig,
    game_root: &Path,
) -> Result<(), PreflightError> {
    if config.game_probe.is_running(game_root) {
        return Err(PreflightError::GameRunning);
    }
    Ok(())
}

/// The bytes each pool must have free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Need {
    patch_store: u64,
    game_root: u64,
}

/// Identifies the filesystem a pool resolved onto, so two pools sharing one can be told from two
/// that do not.
type FsId = u64;

/// What one pool needs, beside the filesystem that answered for it: which one, and its free bytes.
/// `fs` is `None` when no reading could be taken, which is what "not blocked on" is made of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Reading {
    pool: SpacePool,
    needed: u64,
    fs: Option<(FsId, u64)>,
}

/// One free-space comparison: what to blame if it fails, and the two numbers to compare.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Check {
    pool: SpacePool,
    needed: u64,
    free: u64,
}

/// Refuse the install if the pools lack the heuristic required space.
pub(crate) fn check(
    config: &PatcherConfig,
    game_root: &Path,
    patches: &[PatchListEntry],
) -> Result<(), PreflightError> {
    let need = required_bytes(config.keep_patches, patches);
    let readings = [
        reading(SpacePool::PatchStore, need.patch_store, &config.patch_store),
        reading(SpacePool::GameRoot, need.game_root, game_root),
    ];
    for check in checks(&readings) {
        if check.needed > check.free {
            return Err(PreflightError::NotEnoughSpace {
                pool: check.pool,
                needed: check.needed,
                free: check.free,
            });
        }
    }
    Ok(())
}

/// Turn per-pool readings into the comparisons to make, folding pools that share a filesystem into a
/// single summed check.
///
/// The fold is the whole point of the indirection: comparing each pool against its own reading of
/// one shared mount passes an install needing the sum whenever the larger half fits, and with
/// `keep_patches` on the two needs are equal, so it clears a request for twice what the volume
/// holds. Pure over the readings, so the folding is testable without a second filesystem to mount.
fn checks(readings: &[Reading]) -> Vec<Check> {
    let mut out: Vec<Check> = Vec::with_capacity(readings.len());
    let mut seen: Vec<FsId> = Vec::with_capacity(readings.len());
    for reading in readings {
        // A pool whose filesystem could not be read is not blocked on; the rest still are.
        let Some((fs, free)) = reading.fs else {
            continue;
        };
        if let Some(i) = seen.iter().position(|s| *s == fs) {
            // Saturating for the same reason the per-pool sums are: the lengths are hostile input.
            out[i].needed = out[i].needed.saturating_add(reading.needed);
            // Naming either pool once they are one volume would point the user at a distinction that
            // does not exist on their disk, and the number to beat is the sum rather than the half
            // that happened to be read first. The first reading's `free` is kept rather than the
            // later one, arbitrarily: both are the same filesystem, moments apart, and nothing here
            // makes one the better number.
            out[i].pool = SpacePool::SharedFilesystem;
        } else {
            seen.push(fs);
            out.push(Check {
                pool: reading.pool,
                needed: reading.needed,
                free,
            });
        }
    }
    out
}

/// Take one pool's reading.
fn reading(pool: SpacePool, needed: u64, path: &Path) -> Reading {
    Reading {
        pool,
        needed,
        fs: filesystem(path),
    }
}

/// The heuristic requirement per pool. Pure and testable.
fn required_bytes(keep_patches: bool, patches: &[PatchListEntry]) -> Need {
    // Lengths are hostile input, so the sums saturate rather than overflow-panic; a saturated total
    // simply forces the check (or defers to fetch's disk-full backstop).
    let total = patches
        .iter()
        .map(|p| p.length)
        .fold(0u64, u64::saturating_add);
    let patch_store = if keep_patches {
        total
    } else {
        window_bytes(patches)
    };
    Need {
        patch_store,
        game_root: total,
    }
}

/// The sum of the largest [`WINDOW`] patch lengths (an upper bound on any window that many wide).
fn window_bytes(patches: &[PatchListEntry]) -> u64 {
    let mut lens: Vec<u64> = patches.iter().map(|p| p.length).collect();
    lens.sort_unstable_by(|a, b| b.cmp(a));
    lens.into_iter()
        .take(WINDOW)
        .fold(0u64, u64::saturating_add)
}

/// The filesystem holding `path`: an id distinguishing it from other mounts, and the bytes free on it
/// to an unprivileged process. Walks up to the nearest existing ancestor (the game root may not exist
/// yet). `None` when it cannot be read.
///
/// The id is `st_dev` rather than `statvfs`'s `f_fsid`, which Linux leaves zero or non-unique on
/// several filesystems; `st_dev` is what `find -xdev` compares. It answers "one mount" and not "one
/// physical volume", so two btrfs subvolumes drawing on one pool read as separate and fall back to
/// the per-pool guard. That is an underestimate, which is the direction this whole check already errs
/// in, and the download backstop covers.
#[cfg(unix)]
fn filesystem(path: &Path) -> Option<(FsId, u64)> {
    use std::os::unix::fs::MetadataExt;

    let existing = nearest_existing(path)?;
    let dev = std::fs::metadata(&existing).ok()?.dev();
    let vfs = rustix::fs::statvfs(&existing).ok()?;
    Some((dev, vfs.f_bavail.saturating_mul(vfs.f_frsize)))
}

/// Off Unix the free-space query is unavailable, so no pool is blocked on; the fetch disk-full
/// backstop still fires during download.
#[cfg(not(unix))]
fn filesystem(_path: &Path) -> Option<(FsId, u64)> {
    None
}

#[cfg(unix)]
fn nearest_existing(path: &Path) -> Option<PathBuf> {
    let mut cur = path;
    loop {
        if cur.exists() {
            return Some(cur.to_path_buf());
        }
        cur = cur.parent()?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(length: u64) -> PatchListEntry {
        PatchListEntry {
            length,
            version_id: "D2024.01.01.0000.0000".to_owned(),
            url: "http://h/game/4e9a232b/D2024.01.01.0000.0000.patch".to_owned(),
            hashes: None,
        }
    }

    /// A reading for `pool` needing `needed`, taken on filesystem `fs` with `free` bytes on it.
    const fn on(pool: SpacePool, needed: u64, fs: FsId, free: u64) -> Reading {
        Reading {
            pool,
            needed,
            fs: Some((fs, free)),
        }
    }

    /// A reading whose filesystem could not be read at all.
    const fn unread(pool: SpacePool, needed: u64) -> Reading {
        Reading {
            pool,
            needed,
            fs: None,
        }
    }

    #[test]
    fn pools_on_one_filesystem_are_guarded_once_against_their_sum() {
        // 60 free, each pool wants 40: every per-pool comparison passes and the install still needs
        // 80 of the same 60 bytes. This is the shape `keep_patches` makes routine, where the two
        // needs are equal, and the shape a patch store under the game root makes ordinary.
        let readings = [
            on(SpacePool::PatchStore, 40, 1, 60),
            on(SpacePool::GameRoot, 40, 1, 60),
        ];
        assert_eq!(
            checks(&readings),
            vec![Check {
                pool: SpacePool::SharedFilesystem,
                needed: 80,
                free: 60,
            }],
        );
    }

    #[test]
    fn pools_on_different_filesystems_keep_their_own_comparisons() {
        // The reason the fold has to be conditional: 40 against each of two 60s genuinely fits, and
        // summing here would refuse an install that has the space for it twice over.
        let readings = [
            on(SpacePool::PatchStore, 40, 1, 60),
            on(SpacePool::GameRoot, 40, 2, 60),
        ];
        assert_eq!(
            checks(&readings),
            vec![
                Check {
                    pool: SpacePool::PatchStore,
                    needed: 40,
                    free: 60,
                },
                Check {
                    pool: SpacePool::GameRoot,
                    needed: 40,
                    free: 60,
                },
            ],
        );
    }

    #[test]
    fn a_pool_with_no_reading_is_dropped_and_the_other_is_still_guarded_alone() {
        // "Not blocked on" has to survive the fold: an unreadable pool contributes nothing, and must
        // not drag the pool beside it out of the check or fold into it as a zero.
        let readings = [
            unread(SpacePool::PatchStore, 40),
            on(SpacePool::GameRoot, 40, 1, 60),
        ];
        assert_eq!(
            checks(&readings),
            vec![Check {
                pool: SpacePool::GameRoot,
                needed: 40,
                free: 60,
            }],
        );
        assert!(checks(&[unread(SpacePool::GameRoot, 40)]).is_empty());
    }

    #[test]
    fn a_folded_sum_saturates_instead_of_overflow_panicking() {
        // Two hostile lengths land here already saturated, and folding them adds them again.
        let readings = [
            on(SpacePool::PatchStore, u64::MAX, 1, 60),
            on(SpacePool::GameRoot, u64::MAX, 1, 60),
        ];
        assert_eq!(checks(&readings)[0].needed, u64::MAX);
    }

    #[test]
    fn kept_patches_need_the_whole_set_in_the_store() {
        let patches = [entry(10), entry(20), entry(30)];
        let need = required_bytes(true, &patches);
        assert_eq!(need.patch_store, 60);
        assert_eq!(need.game_root, 60);
    }

    #[test]
    fn hostile_lengths_saturate_instead_of_overflow_panicking() {
        // Two u64::MAX lengths would overflow a plain sum (a panic in a debug build); the saturating
        // fold caps at u64::MAX so hostile patchlist lengths cannot crash preflight.
        let patches = [entry(u64::MAX), entry(u64::MAX), entry(10)];
        let need = required_bytes(true, &patches);
        assert_eq!(need.game_root, u64::MAX);
        assert_eq!(need.patch_store, u64::MAX);
        assert_eq!(required_bytes(false, &patches).patch_store, u64::MAX);
    }

    #[test]
    fn unkept_patches_need_only_the_rolling_window_in_the_store() {
        // Seven patches, the window is six: the store need drops the smallest.
        let patches: Vec<_> = [7, 1, 6, 2, 5, 3, 4].into_iter().map(entry).collect();
        let need = required_bytes(false, &patches);
        assert_eq!(need.patch_store, 7 + 6 + 5 + 4 + 3 + 2); // largest six
        assert_eq!(need.game_root, 28); // still the whole applied result
    }
}
