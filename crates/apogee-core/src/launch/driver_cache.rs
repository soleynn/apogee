//! The GPU driver's own shader caches, kept inside the prefix they serve.
//!
//! By default the NVIDIA driver keeps one pipeline cache per user (`~/.cache/nvidia/GLCache`) and
//! Mesa one more (`~/.cache/mesa_shader_cache`), each with a size cap shared by every game on the
//! machine. FFXIV's alone is several hundred megabytes, so another game can evict it, and the next
//! launch pays the whole first-run compile burst again. Pointing both at a directory beside the
//! prefix gives each prefix its own cache that nothing else competes for.
//!
//! A driver update invalidates what the driver compiled, so the driver's version is recorded beside
//! the cache and a change empties it. Only the driver's cache is emptied: DXVK's own cache holds the
//! translation's shader output rather than the driver's, and survives a driver update intact.

use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// The directory beside the prefix's `dxvk_cache` that holds the driver caches.
const CACHE_DIR: &str = "driver_cache";
/// The file beside [`CACHE_DIR`] recording which driver filled it.
const STAMP_FILE: &str = "driver_cache.version";

/// The NVIDIA cache size limit, in bytes: 10 GiB, so the cap is never what evicts FFXIV's cache.
const NVIDIA_CACHE_SIZE: &str = "10737418240";

/// A late-bound read of the installed GPU driver's version, `None` when there is nothing to read.
/// Kept as a seam so the invalidation rule is testable without the host's driver.
pub(crate) type DriverVersionSource = fn() -> Option<String>;

/// The loaded NVIDIA kernel module's version string, or `None` when no NVIDIA driver is loaded.
///
/// The whole string is the version: it names the build as well as the number, so a rebuild of the
/// same release still counts as a change.
pub(crate) fn nvidia_driver_version() -> Option<String> {
    let text = std::fs::read_to_string("/proc/driver/nvidia/version").ok()?;
    let trimmed = text.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// Bring `prefix`'s driver cache up to `driver` and return its root, or `None` when it could not be
/// created (the driver then falls back to its own default location, which is slower but not broken).
///
/// `driver` is `None` on a host with no NVIDIA driver loaded. That leaves the recorded version alone:
/// Mesa keys its own entries by driver build, so there is nothing to invalidate, and a recorded
/// NVIDIA version still says what the `nv` half was filled by if that driver comes back.
pub(crate) fn prepare(prefix: &Path, driver: Option<&str>) -> Option<PathBuf> {
    let root = prefix.join(CACHE_DIR);
    let stamp = prefix.join(STAMP_FILE);
    if let Some(driver) = driver {
        let recorded = std::fs::read_to_string(&stamp).ok();
        // A missing record with a cache present is a cache of unknown origin, so it is emptied too.
        if recorded.as_deref().map(str::trim) != Some(driver) {
            match std::fs::remove_dir_all(&root) {
                Ok(()) => {}
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => {
                    // The record is left as it was so the next launch tries again. The driver itself
                    // discards entries it cannot use, so a stale cache costs a slower start, not a
                    // broken one.
                    tracing::warn!(%error, path = %root.display(), "driver cache was not emptied");
                    return create(&root);
                }
            }
            let root = create(&root)?;
            if let Err(error) = std::fs::write(&stamp, driver) {
                tracing::warn!(%error, path = %stamp.display(), "driver version was not recorded");
            }
            return Some(root);
        }
    }
    create(&root)
}

/// Create the cache root and both halves. The NVIDIA driver does not create the directory it is
/// pointed at, so one that is missing is a cache that silently never persists.
fn create(root: &Path) -> Option<PathBuf> {
    for half in ["nv", "mesa"] {
        if let Err(error) = std::fs::create_dir_all(root.join(half)) {
            tracing::warn!(%error, path = %root.display(), "no driver cache directory");
            return None;
        }
    }
    Some(root.to_path_buf())
}

/// The variables that point the drivers at `root`, as `(name, value)` pairs.
pub(crate) fn env(root: &Path) -> [(&'static str, String); 4] {
    [
        (
            "__GL_SHADER_DISK_CACHE_PATH",
            root.join("nv").to_string_lossy().into_owned(),
        ),
        ("__GL_SHADER_DISK_CACHE_SIZE", NVIDIA_CACHE_SIZE.to_owned()),
        // Asks the driver not to trim the cache toward its default size. Not every driver honours
        // it; the size limit above is what actually keeps the cache whole.
        ("__GL_SHADER_DISK_CACHE_SKIP_CLEANUP", "1".to_owned()),
        (
            "MESA_SHADER_CACHE_DIR",
            root.join("mesa").to_string_lossy().into_owned(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fill(dir: &Path) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join("entry"), b"compiled").unwrap();
    }

    #[test]
    fn a_driver_change_empties_only_the_driver_cache() {
        let prefix = tempfile::tempdir().unwrap();
        let root = prepare(prefix.path(), Some("NVRM 595.71.05")).unwrap();
        fill(&root.join("nv"));
        fill(&prefix.path().join("dxvk_cache"));

        let root = prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        assert!(!root.join("nv/entry").exists());
        assert!(root.join("nv").is_dir() && root.join("mesa").is_dir());
        assert!(prefix.path().join("dxvk_cache/entry").exists());
        assert_eq!(
            std::fs::read_to_string(prefix.path().join(STAMP_FILE)).unwrap(),
            "NVRM 595.84"
        );
    }

    #[test]
    fn the_same_driver_keeps_the_cache() {
        let prefix = tempfile::tempdir().unwrap();
        let root = prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        fill(&root.join("nv"));
        prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        assert!(root.join("nv/entry").exists());
    }

    #[test]
    fn an_unrecorded_cache_is_emptied_once_a_driver_is_known() {
        let prefix = tempfile::tempdir().unwrap();
        fill(&prefix.path().join(CACHE_DIR).join("nv"));
        let root = prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        assert!(!root.join("nv/entry").exists());
    }

    #[test]
    fn no_driver_leaves_cache_and_record_alone() {
        let prefix = tempfile::tempdir().unwrap();
        let root = prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        fill(&root.join("mesa"));
        prepare(prefix.path(), None).unwrap();
        assert!(root.join("mesa/entry").exists());
        // The NVIDIA driver coming back at the same version is not a change.
        fill(&root.join("nv"));
        prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        assert!(root.join("nv/entry").exists());
    }

    #[test]
    fn a_record_with_a_trailing_newline_still_matches() {
        // Someone inspecting the prefix may rewrite the record with an editor that adds one.
        let prefix = tempfile::tempdir().unwrap();
        let root = prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        fill(&root.join("nv"));
        std::fs::write(prefix.path().join(STAMP_FILE), "NVRM 595.84\n").unwrap();
        prepare(prefix.path(), Some("NVRM 595.84")).unwrap();
        assert!(root.join("nv/entry").exists());
    }

    #[test]
    fn a_cache_root_that_cannot_be_a_directory_sets_nothing() {
        let prefix = tempfile::tempdir().unwrap();
        std::fs::write(prefix.path().join(CACHE_DIR), b"not a directory").unwrap();
        // With no driver known nothing removes the file, so the cache cannot be created.
        assert!(prepare(prefix.path(), None).is_none());
    }
}
