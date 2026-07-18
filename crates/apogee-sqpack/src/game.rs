//! Install enumeration: which repositories a game tree carries and at what version.
//!
//! [`GameData::open`] takes the game subtree (the directory holding `sqpack/` and `ffxivgame.ver`),
//! discovers the base repository and any expansion repositories present, and reads each one's version
//! file best-effort. It is the read-only inspection entry point the patcher and core use before a
//! patch or repair; unlike the login version report, a missing version file is reported as absent
//! rather than treated as a fault.

use std::path::{Path, PathBuf};

use crate::error::Result;

/// The highest expansion index enumerated.
const MAX_EXPANSION: u8 = 5;

/// A SqPack repository within a game tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// The repositories of an FFXIV game tree.
#[derive(Debug, Clone)]
pub struct GameData {
    game_dir: PathBuf,
    repos: Vec<RepoInfo>,
}

impl GameData {
    /// Open the game subtree at `game_dir` (the directory containing `sqpack/` and `ffxivgame.ver`)
    /// and enumerate the repositories present.
    ///
    /// The base repository is included when `sqpack/ffxiv` exists; expansions when `sqpack/ex{n}`
    /// exists, for `n` in `1..=5`. Version files are read best-effort.
    ///
    /// # Errors
    /// [`crate::Error::Io`] only for a genuine failure reading the `sqpack/` directory listing; an
    /// absent `sqpack/` yields an empty repository list, not an error.
    pub fn open(game_dir: impl Into<PathBuf>) -> Result<Self> {
        let game_dir = game_dir.into();
        let sqpack = game_dir.join("sqpack");
        let mut repos = Vec::new();

        let base_dir = sqpack.join(Repo::Base.dir_name());
        if base_dir.is_dir() {
            // The base repository's version lives at the game-tree root, not inside sqpack/.
            let version = read_version_file(&game_dir.join("ffxivgame.ver"));
            repos.push(RepoInfo {
                repo: Repo::Base,
                dir: base_dir,
                version,
            });
        }

        for n in 1..=MAX_EXPANSION {
            let repo = Repo::Ex(n);
            let dir = sqpack.join(repo.dir_name());
            if dir.is_dir() {
                let version = read_version_file(&dir.join(format!("ex{n}.ver")));
                repos.push(RepoInfo { repo, dir, version });
            }
        }

        Ok(Self { game_dir, repos })
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
    use std::fs;

    fn write(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, contents).unwrap();
    }

    #[test]
    fn dir_names_match_the_layout() {
        assert_eq!(Repo::Base.dir_name(), "ffxiv");
        assert_eq!(Repo::Ex(1).dir_name(), "ex1");
        assert_eq!(Repo::Ex(4).dir_name(), "ex4");
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
}
