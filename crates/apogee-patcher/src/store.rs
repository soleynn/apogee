//! Patch-store layout and the `.ver`/`.bck` version files.
//!
//! The patch store mirrors the patchlist URL path (host discarded) so a download resumes at the
//! same on-disk location. The version files match `sqex-proto`'s [`InstallPaths`] layout so a
//! report written here is read back strict there: bare `YYYY.MM.DD.PPPP.RRRR`, no trailing newline
//! (an embedded newline fails that crate's sanity gate).
//!
//! [`InstallPaths`]: sqex_proto::InstallPaths

use std::path::{Path, PathBuf};

use url::Url;

use crate::{PatchError, Repo};

/// Map a patch URL to its local path under `patch_store`, mirroring the URL path (host discarded).
///
/// The `url` crate already normalizes `.`/`..` dot-segments during parse, so the path carries no
/// traversal; every segment is still re-checked and any residual `..` refused, keeping the result
/// confined under `patch_store`.
pub(crate) fn patch_dest(patch_store: &Path, url: &Url, index: u32) -> Result<PathBuf, PatchError> {
    let bad = |detail: &str| PatchError::Patchlist {
        index,
        detail: detail.to_owned(),
    };
    let segments = url.path_segments().ok_or_else(|| bad("url has no path"))?;
    let mut dest = patch_store.to_path_buf();
    let mut any = false;
    for seg in segments {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            return Err(bad("url path escapes the patch store"));
        }
        dest.push(seg);
        any = true;
    }
    if !any {
        return Err(bad("url path is empty"));
    }
    Ok(dest)
}

/// The apply root for `repo` beneath the install `game_root`: boot patches target `boot/`, game and
/// expansion patches target `game/` (expansion data lives under `game/sqpack/ex{n}`).
pub(crate) fn repo_root(game_root: &Path, repo: Repo) -> PathBuf {
    game_root.join(repo_subdir(repo))
}

/// The install-root-relative subtree name for `repo`: `boot` for the boot repo, `game` for the game
/// and every expansion repo (expansion data lives beneath `game/sqpack/ex{n}`).
pub(crate) fn repo_subdir(repo: Repo) -> &'static str {
    match repo {
        Repo::Boot => "boot",
        Repo::Game | Repo::Expansion(_) => "game",
    }
}

/// The `.ver` path for `repo`, matching `sqex-proto`'s `InstallPaths` layout.
pub(crate) fn ver_path(game_root: &Path, repo: Repo) -> PathBuf {
    match repo {
        Repo::Boot => game_root.join("boot").join("ffxivboot.ver"),
        Repo::Game => game_root.join("game").join("ffxivgame.ver"),
        Repo::Expansion(n) => game_root
            .join("game")
            .join("sqpack")
            .join(format!("ex{n}"))
            .join(format!("ex{n}.ver")),
    }
}

/// The `.bck` path for `repo` (the `.ver` backup taken after a whole set applies).
fn bck_path(game_root: &Path, repo: Repo) -> PathBuf {
    ver_path(game_root, repo).with_extension("bck")
}

/// Strip a patchlist version's leading list-prefix letter (e.g. `D2024.03.28.0000.0001` →
/// `2024.03.28.0000.0001`) to the bare `.ver` form. Versions are otherwise digits and dots, so
/// trimming leading ASCII letters is safe.
pub(crate) fn bare_version(version_id: &str) -> String {
    version_id
        .trim_start_matches(|c: char| c.is_ascii_alphabetic())
        .to_owned()
}

/// Write `bare` to the repo's `.ver` after a clean apply (bare version, no trailing newline).
pub(crate) fn write_ver(game_root: &Path, repo: Repo, bare: &str) -> Result<(), PatchError> {
    let path = ver_path(game_root, repo);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| io_err(parent, source))?;
    }
    std::fs::write(&path, bare).map_err(|source| io_err(&path, source))
}

/// Copy the repo's `.ver` to `.bck` after the whole set applies (`VerToBck`); a no-op if no `.ver`
/// was written.
pub(crate) fn backup_ver(game_root: &Path, repo: Repo) -> Result<(), PatchError> {
    let ver = ver_path(game_root, repo);
    if !ver.exists() {
        return Ok(());
    }
    let bck = bck_path(game_root, repo);
    std::fs::copy(&ver, &bck)
        .map(|_| ())
        .map_err(|source| io_err(&bck, source))
}

/// Read the repo's current `.ver` (bare, trimmed), or an empty string if none is present.
pub(crate) fn read_ver(game_root: &Path, repo: Repo) -> String {
    std::fs::read_to_string(ver_path(game_root, repo))
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
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
    fn patch_dest_mirrors_the_url_path_under_the_store() {
        let store = Path::new("/cache/patches");
        let url = Url::parse(
            "http://patch.example.invalid/game/ex1/abcd1234/D2024.01.02.0000.0000.patch",
        )
        .unwrap();
        assert_eq!(
            patch_dest(store, &url, 0).unwrap(),
            Path::new("/cache/patches/game/ex1/abcd1234/D2024.01.02.0000.0000.patch")
        );
    }

    #[test]
    fn patch_dest_discards_the_host_and_query() {
        let store = Path::new("/cache");
        let url =
            Url::parse("http://any-host:8080/boot/2b5cbc63/D2024.01.01.0000.0000.patch?sid=x")
                .unwrap();
        assert_eq!(
            patch_dest(store, &url, 0).unwrap(),
            Path::new("/cache/boot/2b5cbc63/D2024.01.01.0000.0000.patch")
        );
    }

    #[test]
    fn patch_dest_stays_confined_when_the_url_carries_dot_segments() {
        let store = Path::new("/cache");
        // The url crate resolves `..` at parse time, so this cannot climb out of the store.
        let url = Url::parse("http://h/game/../../../etc/passwd").unwrap();
        let dest = patch_dest(store, &url, 0).unwrap();
        assert!(dest.starts_with(store), "escaped the store: {dest:?}");
    }

    #[test]
    fn repo_root_places_boot_and_game_subtrees() {
        let root = Path::new("/game");
        assert_eq!(repo_root(root, Repo::Boot), Path::new("/game/boot"));
        assert_eq!(repo_root(root, Repo::Game), Path::new("/game/game"));
        assert_eq!(repo_root(root, Repo::Expansion(2)), Path::new("/game/game"));
    }

    #[test]
    fn ver_path_matches_the_install_layout() {
        let root = Path::new("/g");
        assert_eq!(
            ver_path(root, Repo::Boot),
            Path::new("/g/boot/ffxivboot.ver")
        );
        assert_eq!(
            ver_path(root, Repo::Game),
            Path::new("/g/game/ffxivgame.ver")
        );
        assert_eq!(
            ver_path(root, Repo::Expansion(3)),
            Path::new("/g/game/sqpack/ex3/ex3.ver")
        );
    }

    #[test]
    fn bare_version_strips_the_list_prefix_letter() {
        assert_eq!(
            bare_version("D2024.03.28.0000.0001"),
            "2024.03.28.0000.0001"
        );
        assert_eq!(bare_version("2024.03.28.0000.0001"), "2024.03.28.0000.0001");
        assert_eq!(
            bare_version("H2012.01.01.0000.0000"),
            "2012.01.01.0000.0000"
        );
    }

    #[test]
    fn write_and_backup_ver_roundtrip_without_a_trailing_newline() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_ver(root, Repo::Game, "2024.03.28.0000.0001").unwrap();
        let ver = std::fs::read_to_string(ver_path(root, Repo::Game)).unwrap();
        assert_eq!(ver, "2024.03.28.0000.0001");
        assert!(
            !ver.contains('\n'),
            "the sanity gate rejects an embedded newline"
        );
        backup_ver(root, Repo::Game).unwrap();
        let bck = std::fs::read_to_string(bck_path(root, Repo::Game)).unwrap();
        assert_eq!(bck, "2024.03.28.0000.0001");
        assert_eq!(read_ver(root, Repo::Game), "2024.03.28.0000.0001");
    }
}
