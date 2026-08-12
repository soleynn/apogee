//! Stray-file quarantine: a repair never deletes a file the index cannot explain, it moves it into a
//! timestamped recycler under the install root and reports where it went.
//!
//! The recycler sits at `{game_root}/apogee_repair_recycler/{yyyymmdd_hhmmss}/{repo}/…`, a sibling of
//! the `boot/` and `game/` repo subtrees rather than inside them, so a later verify (which scans one
//! repo subtree) never re-flags a quarantined file as a fresh stray. Which files count as strays is
//! `apogee-zipatch`'s verify decision (its compiled-in keep-filter already spares `.ver`/`.bck`,
//! movie streams, and the DXVK cache); this module only relocates whatever it is handed.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use apogee_zipatch::StrayFile;

use crate::{PatchError, Repo, store};

/// The recycler directory name beneath the install root.
const RECYCLER_DIR: &str = "apogee_repair_recycler";

/// Where one stray goes: the two ends of the move and the path to report it under, all relative to
/// the install root.
///
/// Both ends are named relative to the install root rather than absolutely because a repair that
/// cannot write the tree from this process hands them to one that can, and that side resolves them
/// against the tree its session bound. The install root is what both ends need in common: the
/// recycler is a sibling of the repo subtrees, so a stray leaves its subtree by design.
pub(crate) struct Relocation {
    /// The stray today, with `/` separators.
    pub(crate) from: String,
    /// Where it lands, with `/` separators.
    pub(crate) to: String,
    /// The same destination in this platform's spelling, for the outcome.
    pub(crate) reported: PathBuf,
}

/// Where each stray of `repo` goes in the `batch` recycler, preserving its repo-relative path.
///
/// # Errors
/// [`PatchError::Io`] if a stray's path is not the plain relative descent verify produces.
pub(crate) fn plan(
    repo: Repo,
    batch: &str,
    strays: &[StrayFile],
) -> Result<Vec<Relocation>, PatchError> {
    let subdir = store::repo_subdir(repo);
    strays
        .iter()
        .map(|stray| {
            let rel = store::slashed(&stray.path).ok_or_else(|| not_relative(&stray.path))?;
            Ok(Relocation {
                from: format!("{subdir}/{rel}"),
                to: format!("{RECYCLER_DIR}/{batch}/{subdir}/{rel}"),
                reported: Path::new(RECYCLER_DIR)
                    .join(batch)
                    .join(subdir)
                    .join(&stray.path),
            })
        })
        .collect()
}

/// Move each stray of `repo` into the `batch` recycler directory beneath `game_root`, preserving its
/// repo-relative path. Returns the quarantined destinations (install-root-relative) for reporting.
/// Never deletes: a file that cannot be moved is a hard [`PatchError::Io`].
pub(crate) fn quarantine(
    game_root: &Path,
    repo: Repo,
    batch: &str,
    strays: &[StrayFile],
) -> Result<Vec<PathBuf>, PatchError> {
    let mut moved = Vec::with_capacity(strays.len());
    for relocation in plan(repo, batch, strays)? {
        let (src, dest) = (
            game_root.join(&relocation.from),
            game_root.join(&relocation.to),
        );
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|source| io_err(parent, source))?;
        }
        move_file(&src, &dest)?;
        moved.push(relocation.reported);
    }
    Ok(moved)
}

/// A path that is not the plain relative descent the index and verify produce.
fn not_relative(rel: &Path) -> PatchError {
    PatchError::Io {
        path: rel.to_path_buf(),
        source: std::io::Error::other("not a relative path inside the install"),
    }
}

/// Move `src` to `dest`, never deleting. A rename covers the same-filesystem case (always true here:
/// the recycler is under the install root); a cross-device rename falls back to copy-then-remove so
/// the bytes survive even if `src` sits on a different mount.
fn move_file(src: &Path, dest: &Path) -> Result<(), PatchError> {
    match std::fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(_) => {
            std::fs::copy(src, dest).map_err(|source| io_err(dest, source))?;
            std::fs::remove_file(src).map_err(|source| io_err(src, source))
        }
    }
}

/// Format a `SystemTime` as `yyyymmdd_hhmmss` (UTC), the recycler batch name. Pre-epoch times (a
/// clock set before 1970) fold to the epoch rather than fail: the name only needs to be stable and
/// roughly ordered, never authoritative.
pub(crate) fn batch_name(now: SystemTime) -> String {
    let secs = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (year, month, day, hour, min, sec) = civil_from_unix(secs);
    format!("{year:04}{month:02}{day:02}_{hour:02}{min:02}{sec:02}")
}

/// Break a Unix timestamp into `(year, month, day, hour, minute, second)` in UTC. Uses Howard
/// Hinnant's `civil_from_days` algorithm (proleptic Gregorian, valid for any date), so no date crate
/// is pulled in for a directory name.
fn civil_from_unix(secs: u64) -> (i64, u32, u32, u32, u32, u32) {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = (rem / 3_600) as u32;
    let min = ((rem % 3_600) / 60) as u32;
    let sec = (rem % 60) as u32;

    // Shift the era so day 0 is 0000-03-01, then map back to civil y/m/d.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // [0, 146096]
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if month <= 2 { year + 1 } else { year };
    (year, month, day, hour, min, sec)
}

fn io_err(path: &Path, source: std::io::Error) -> PatchError {
    PatchError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_name_formats_known_instants() {
        // 2024-03-28 12:34:56 UTC = 1711629296.
        let t = UNIX_EPOCH + std::time::Duration::from_secs(1_711_629_296);
        assert_eq!(batch_name(t), "20240328_123456");
        // The epoch itself.
        assert_eq!(batch_name(UNIX_EPOCH), "19700101_000000");
        // A leap day.
        let leap = UNIX_EPOCH + std::time::Duration::from_secs(1_582_934_400); // 2020-02-29 00:00:00
        assert_eq!(batch_name(leap), "20200229_000000");
    }

    #[test]
    fn quarantine_moves_strays_and_never_deletes() {
        let dir = tempfile::tempdir().unwrap();
        let game_root = dir.path();
        let repo_root = store::repo_root(game_root, Repo::Game);
        std::fs::create_dir_all(repo_root.join("mods")).unwrap();
        std::fs::write(repo_root.join("mods/extra.dat"), b"user data").unwrap();

        let strays = [StrayFile {
            path: PathBuf::from("mods/extra.dat"),
        }];
        let moved = quarantine(game_root, Repo::Game, "20240101_000000", &strays).unwrap();
        assert_eq!(moved.len(), 1);

        // The original is gone from the tree, the bytes live on under the recycler, unchanged.
        assert!(!repo_root.join("mods/extra.dat").exists());
        let dest = game_root.join(&moved[0]);
        assert_eq!(std::fs::read(&dest).unwrap(), b"user data");
        assert!(
            dest.starts_with(game_root.join(RECYCLER_DIR)),
            "quarantined under the recycler: {dest:?}"
        );
    }

    /// The plan names both ends relative to the install root, in the one spelling both sides read
    /// the same way, and puts the recycler outside the repo subtree it took the stray from.
    #[test]
    fn a_relocation_names_both_ends_under_the_install_root() {
        let strays = [StrayFile {
            path: PathBuf::from("sqpack").join("ex1").join("extra.dat"),
        }];
        let plan = plan(Repo::Expansion(1), "20240101_000000", &strays).unwrap();
        assert_eq!(plan[0].from, "game/sqpack/ex1/extra.dat");
        assert_eq!(
            plan[0].to,
            "apogee_repair_recycler/20240101_000000/game/sqpack/ex1/extra.dat"
        );
        assert!(
            !plan[0].to.starts_with("game/"),
            "the recycler must sit outside the subtree the stray came from",
        );
        // The reported path is the destination in this platform's own spelling.
        assert_eq!(
            plan[0].reported,
            Path::new("apogee_repair_recycler")
                .join("20240101_000000")
                .join("game")
                .join("sqpack")
                .join("ex1")
                .join("extra.dat")
        );
    }

    /// A stray path that is not a plain descent is refused rather than reinterpreted, so nothing
    /// hands the far side a `..` to resolve.
    #[test]
    fn a_stray_path_that_is_not_a_plain_descent_is_refused() {
        for raw in ["../escape.dat", "/etc/passwd", ""] {
            let strays = [StrayFile {
                path: PathBuf::from(raw),
            }];
            assert!(
                plan(Repo::Game, "b", &strays).is_err(),
                "{raw:?} was accepted"
            );
        }
    }

    #[test]
    fn quarantine_of_nothing_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            quarantine(dir.path(), Repo::Boot, "b", &[])
                .unwrap()
                .is_empty()
        );
        assert!(!dir.path().join(RECYCLER_DIR).exists());
    }
}
