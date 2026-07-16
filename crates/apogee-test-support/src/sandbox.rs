//! Throwaway on-disk sandboxes: a temp settings store and a temp game root, each auto-removed when
//! the returned handle drops. Minimal for now; grows a real prefix layout later.

use tempfile::{Builder, TempDir};

/// A temp directory standing in for the settings/profile store.
pub fn temp_store() -> std::io::Result<TempDir> {
    Builder::new().prefix("apogee-store-").tempdir()
}

/// A temp directory standing in for the game installation root.
pub fn temp_game_root() -> std::io::Result<TempDir> {
    Builder::new().prefix("apogee-game-").tempdir()
}

/// The four boot EXE names, in the order the version report hashes them.
const BOOT_EXE_NAMES: [&str; 4] = [
    "ffxivboot.exe",
    "ffxivboot64.exe",
    "ffxivlauncher64.exe",
    "ffxivupdater64.exe",
];

/// Build a complete game install under a fresh temp dir for version-report tests.
///
/// Lays down the four boot EXEs, `boot/ffxivboot.ver`, `game/ffxivgame.ver`, and
/// `game/sqpack/ex{n}/ex{n}.ver` for each expansion. `boot_exes` are the raw contents of
/// `ffxivboot.exe`, `ffxivboot64.exe`, `ffxivlauncher64.exe`, `ffxivupdater64.exe`, in that order, so
/// their length and SHA1 are deterministic. Tests that need a corrupt, missing, or `.bck` file mutate
/// the returned tree.
pub fn build_game_install(
    boot_ver: &str,
    boot_exes: [&[u8]; 4],
    game_ver: &str,
    expansions: &[&str],
) -> std::io::Result<TempDir> {
    let dir = Builder::new().prefix("apogee-install-").tempdir()?;
    let root = dir.path();

    let boot = root.join("boot");
    std::fs::create_dir_all(&boot)?;
    for (name, contents) in BOOT_EXE_NAMES.into_iter().zip(boot_exes) {
        std::fs::write(boot.join(name), contents)?;
    }
    std::fs::write(boot.join("ffxivboot.ver"), boot_ver)?;

    let game = root.join("game");
    std::fs::create_dir_all(&game)?;
    std::fs::write(game.join("ffxivgame.ver"), game_ver)?;

    for (i, ver) in expansions.iter().enumerate() {
        let n = i + 1;
        let ex = game.join("sqpack").join(format!("ex{n}"));
        std::fs::create_dir_all(&ex)?;
        std::fs::write(ex.join(format!("ex{n}.ver")), ver)?;
    }

    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandboxes_are_distinct_live_directories() {
        let store = temp_store().expect("store");
        let game = temp_game_root().expect("game root");
        assert!(store.path().is_dir());
        assert!(game.path().is_dir());
        assert_ne!(store.path(), game.path());
    }

    #[test]
    fn game_install_lays_down_boot_and_expansion_files() {
        let dir = build_game_install(
            "2024.01.01.0000.0000",
            [b"a" as &[u8], b"bb", b"ccc", b"dddd"],
            "2024.02.02.0000.0000",
            &["2024.03.03.0000.0000"],
        )
        .expect("install");
        let root = dir.path();
        assert!(root.join("boot/ffxivboot.exe").is_file());
        assert!(root.join("boot/ffxivupdater64.exe").is_file());
        assert!(root.join("boot/ffxivboot.ver").is_file());
        assert!(root.join("game/ffxivgame.ver").is_file());
        assert!(root.join("game/sqpack/ex1/ex1.ver").is_file());
    }
}
