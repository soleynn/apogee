//! Disk-space preflight, two pools.
//!
//! A heuristic with an escape hatch ([`PatcherConfig::ignore_space`]) and a backstop (fetch's eager
//! disk-full detection). The patch store must hold the concurrent downloads (a rolling window, or
//! all of them when kept); the install dir must hold the applied result, which patch length
//! overestimates since patches both add and delete. A pool whose free space cannot be read (a
//! non-existent tree, or a non-Unix target) is not blocked on.

use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;

use sqex_proto::PatchListEntry;

use crate::{PatcherConfig, PreflightError, SpacePool};

/// The rolling window of patches assumed resident at once when not keeping them (XL checks the first
/// six); the largest six bound any six concurrent.
const WINDOW: usize = 6;

/// The bytes each pool must have free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Need {
    patch_store: u64,
    game_root: u64,
}

/// Refuse the install if either pool lacks the heuristic required space.
pub(crate) fn check(
    config: &PatcherConfig,
    game_root: &Path,
    patches: &[PatchListEntry],
) -> Result<(), PreflightError> {
    let need = required_bytes(config.keep_patches, patches);
    guard(SpacePool::PatchStore, need.patch_store, &config.patch_store)?;
    guard(SpacePool::GameRoot, need.game_root, game_root)?;
    Ok(())
}

fn guard(pool: SpacePool, needed: u64, path: &Path) -> Result<(), PreflightError> {
    if let Some(free) = available_bytes(path)
        && needed > free
    {
        return Err(PreflightError::NotEnoughSpace { pool, needed, free });
    }
    Ok(())
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

/// Free bytes available to an unprivileged process on the filesystem holding `path`, walking up to
/// the nearest existing ancestor (the game root may not exist yet). `None` when it cannot be read.
#[cfg(unix)]
fn available_bytes(path: &Path) -> Option<u64> {
    let existing = nearest_existing(path)?;
    let vfs = rustix::fs::statvfs(&existing).ok()?;
    Some(vfs.f_bavail.saturating_mul(vfs.f_frsize))
}

/// Off Unix the free-space query is unavailable, so the pool is not blocked on; the fetch disk-full
/// backstop still fires during download.
#[cfg(not(unix))]
fn available_bytes(_path: &Path) -> Option<u64> {
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
