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
}
