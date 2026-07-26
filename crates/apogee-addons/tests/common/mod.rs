//! A config tree shaped like the one the game really writes.
//!
//! The casings, the doubled extensions, and the fact that character settings live in directories
//! rather than in files are copied from a live install, because those are exactly the details a
//! selection or an archive can get wrong while still appearing to work.

use std::io;
use std::path::Path;

/// The fourteen settings files a character directory holds, uppercase as the game writes them.
pub const CHARACTER_FILES: &[&str] = &[
    "ACQ.DAT",
    "ADDON.DAT",
    "COMMON.DAT",
    "CONTROL0.DAT",
    "CONTROL1.DAT",
    "GEARSET.DAT",
    "GS.DAT",
    "HOTBAR.DAT",
    "ITEMFDR.DAT",
    "ITEMODR.DAT",
    "KEYBIND.DAT",
    "LOGFLTR.DAT",
    "MACRO.DAT",
    "UISAVE.DAT",
];

pub const CHARACTER_DIR: &str = "FFXIV_CHR004000174C116E58";

/// Write `body` to `path`, creating parents.
pub fn write(path: &Path, body: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, body)
}

/// The full tree: root config, one character directory with its settings, chat logs, rotation
/// shadows, the config-copy directory, the game's restore blob, and screenshots.
pub fn game_tree(root: &Path) -> io::Result<()> {
    write(&root.join("FFXIV.cfg"), "cfg")?;
    // Rotation shadows carry an uppercase extension and a lowercase suffix at once.
    write(&root.join("FFXIV.cfg.old"), "stale")?;
    for name in CHARACTER_FILES {
        write(&root.join(CHARACTER_DIR).join(name), name)?;
    }
    write(&root.join(CHARACTER_DIR).join("ADDON.DAT.old"), "stale")?;
    for n in 0..3 {
        write(
            &root
                .join(CHARACTER_DIR)
                .join("log")
                .join(format!("{n:08x}.log")),
            "chat",
        )?;
    }
    // The config-copy payload is lowercase where the character payloads are uppercase.
    write(
        &root
            .join("cfgcopy")
            .join("FFXIV_CFGCPYB4E9C66C1760C0EE.dat"),
        "copy",
    )?;
    write(
        &root
            .join("backup")
            .join("FFXIV_BKCHR004000174C116E58_00.dat"),
        "blob",
    )?;
    std::fs::create_dir_all(root.join("screenshots"))?;
    Ok(())
}

/// The same tree written in the opposite order, so the filesystem hands its entries back differently.
pub fn game_tree_reversed(root: &Path) -> io::Result<()> {
    std::fs::create_dir_all(root.join("screenshots"))?;
    write(
        &root
            .join("backup")
            .join("FFXIV_BKCHR004000174C116E58_00.dat"),
        "blob",
    )?;
    write(
        &root
            .join("cfgcopy")
            .join("FFXIV_CFGCPYB4E9C66C1760C0EE.dat"),
        "copy",
    )?;
    for n in (0..3).rev() {
        write(
            &root
                .join(CHARACTER_DIR)
                .join("log")
                .join(format!("{n:08x}.log")),
            "chat",
        )?;
    }
    write(&root.join(CHARACTER_DIR).join("ADDON.DAT.old"), "stale")?;
    for name in CHARACTER_FILES.iter().rev() {
        write(&root.join(CHARACTER_DIR).join(name), name)?;
    }
    write(&root.join("FFXIV.cfg.old"), "stale")?;
    write(&root.join("FFXIV.cfg"), "cfg")?;
    Ok(())
}
