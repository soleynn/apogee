//! Throwaway on-disk sandboxes: a temp settings store, a temp game root, and a minimal wine prefix,
//! each auto-removed when the returned handle drops.

use std::path::Path;

use tempfile::{Builder, TempDir};

/// A temp directory standing in for the settings/profile store.
pub fn temp_store() -> std::io::Result<TempDir> {
    Builder::new().prefix("apogee-store-").tempdir()
}

/// A temp directory standing in for the game installation root.
pub fn temp_game_root() -> std::io::Result<TempDir> {
    Builder::new().prefix("apogee-game-").tempdir()
}

/// Lay down a minimal healthy wine prefix under a fresh temp dir: `drive_c/windows`, a `dosdevices/`
/// with `c:` → `../drive_c` and `z:` → `/`, and a placeholder `system.reg`. Enough for the drive-map
/// and health-check paths without a real `wineboot`. Tests that need drift mutate the returned tree.
#[cfg(unix)]
pub fn build_minimal_prefix() -> std::io::Result<TempDir> {
    let dir = Builder::new().prefix("apogee-prefix-").tempdir()?;
    write_prefix_skeleton(dir.path())?;
    Ok(dir)
}

/// Write the minimal wine skeleton into an existing prefix directory (used by [`build_minimal_prefix`]
/// and by tests that own the directory's lifetime).
#[cfg(unix)]
pub fn write_prefix_skeleton(root: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::symlink;

    std::fs::create_dir_all(root.join("drive_c/windows"))?;
    let dosdevices = root.join("dosdevices");
    std::fs::create_dir_all(&dosdevices)?;
    symlink("../drive_c", dosdevices.join("c:"))?;
    symlink("/", dosdevices.join("z:"))?;
    std::fs::write(root.join("system.reg"), b"WINE REGISTRY Version 2\n")?;
    Ok(())
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

    #[cfg(unix)]
    #[test]
    fn minimal_prefix_has_a_drive_map_and_skeleton() {
        let prefix = build_minimal_prefix().expect("prefix");
        let root = prefix.path();
        assert!(root.join("drive_c/windows").is_dir());
        assert!(root.join("system.reg").is_file());
        assert_eq!(
            std::fs::read_link(root.join("dosdevices/z:")).expect("z:"),
            std::path::PathBuf::from("/")
        );
        assert_eq!(
            std::fs::read_link(root.join("dosdevices/c:")).expect("c:"),
            std::path::PathBuf::from("../drive_c")
        );
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
