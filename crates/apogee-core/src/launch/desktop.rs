//! The game's identity on the Linux desktop.
//!
//! A desktop groups windows into one task by their X11 class and draws the task with the icon of the
//! desktop entry whose `StartupWMClass` matches. Under umu every window in the game's container gets
//! the class Proton derives from the launch's game id, programs started beside the game included, and
//! with no matching entry the task shows whatever small icon the first window carried, scaled up. So
//! the launch gives the game a class of its own and keeps a hidden desktop entry for it, with the
//! game's own largest icon read out of its executable on this machine. Nothing is shipped, and the
//! entry is `NoDisplay`, so the application menu is unchanged.

use std::path::{Path, PathBuf};

use apogee_runtime::RunnerKind;

/// The basename the icon and the desktop entry are installed under.
fn identity() -> &'static str {
    "apogee-ffxiv"
}

/// The class the game's windows carry under `runner`: Proton's, from the game id the runtime launches
/// with, or plain wine's, the executable's name.
pub(crate) fn window_class(runner: Option<RunnerKind>) -> &'static str {
    match runner {
        Some(RunnerKind::ProtonUmu) => "steam_app_apogee",
        _ => "ffxiv_dx11.exe",
    }
}

/// Install the icon (once) and the desktop entry (whenever its class changes) under `data_home`.
///
/// Best effort by design: a desktop that ignores the entry, or a home that cannot be written, costs a
/// nicer taskbar icon and nothing else, so the caller logs a failure and launches anyway.
///
/// # Errors
/// Whatever reading the executable or writing the files raised.
pub(crate) fn ensure(data_home: &Path, game_exe: &Path, class: &str) -> std::io::Result<()> {
    let icon_dir = data_home.join("icons/hicolor");
    let installed = ["256x256", "128x128", "64x64", "48x48", "32x32"]
        .iter()
        .any(|size| icon_path(&icon_dir, size).is_file());
    if !installed {
        let exe = read_capped(game_exe, MAX_EXE_BYTES)?;
        let Some((size, png)) = largest_png_icon(&exe) else {
            return Err(std::io::Error::other(
                "the game executable carries no PNG icon",
            ));
        };
        write_replacing(&icon_path(&icon_dir, &format!("{size}x{size}")), png)?;
    }
    let entry = format!(
        "[Desktop Entry]\nType=Application\nName=FINAL FANTASY XIV\nComment=Launched by Apogee\n\
         Icon={}\nExec=apogee\nStartupWMClass={class}\nNoDisplay=true\n",
        identity()
    );
    let path = data_home
        .join("applications")
        .join(format!("{}.desktop", identity()));
    if std::fs::read(&path).ok().as_deref() != Some(entry.as_bytes()) {
        write_replacing(&path, entry.as_bytes())?;
    }
    Ok(())
}

fn icon_path(icon_dir: &Path, size: &str) -> PathBuf {
    icon_dir
        .join(size)
        .join("apps")
        .join(format!("{}.png", identity()))
}

/// Larger than any build of the game's executable has been, so a corrupt or substituted file is
/// refused rather than read whole into memory.
const MAX_EXE_BYTES: u64 = 256 * 1024 * 1024;

fn read_capped(path: &Path, cap: u64) -> std::io::Result<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(cap + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::other(
            "the game executable is larger than any build",
        ));
    }
    Ok(bytes)
}

/// Write `bytes` beside `path` and rename over it, so a reader never sees half a file and a link
/// standing at `path` is replaced rather than written through.
fn write_replacing(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("a path with no parent"))?;
    std::fs::create_dir_all(parent)?;
    let staged = path.with_extension("apogee-new");
    let _ = std::fs::remove_file(&staged);
    std::fs::write(&staged, bytes)?;
    std::fs::rename(&staged, path)
}

/// The largest PNG among a PE file's icon resources, with its edge length.
///
/// The executable is the game's and is read as hostile: every offset is checked against the buffer,
/// the walk is the fixed three levels of a resource tree (type, name, language) and never recursive,
/// and the number of entries visited is capped.
fn largest_png_icon(pe: &[u8]) -> Option<(u32, &[u8])> {
    const RT_ICON: u32 = 3;
    const MAX_ENTRIES: usize = 4096;
    let pe_offset = rd32(pe, 0x3c)? as usize;
    if pe.get(..2)? != b"MZ" || pe.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let coff = pe_offset + 4;
    let sections = usize::from(rd16(pe, coff + 2)?);
    let optional = coff + 20;
    let optional_size = usize::from(rd16(pe, coff + 16)?);
    let (dirs, count_at) = match rd16(pe, optional)? {
        0x20b => (optional + 112, optional + 108),
        0x10b => (optional + 96, optional + 92),
        _ => return None,
    };
    if rd32(pe, count_at)? < 3 {
        return None;
    }
    let resource_rva = rd32(pe, dirs + 16)?;
    let table = optional.checked_add(optional_size)?;
    let to_offset = |rva: u32| -> Option<usize> {
        (0..sections.min(96)).find_map(|i| {
            let header = table + i * 40;
            let virtual_size = rd32(pe, header + 8)?;
            let virtual_address = rd32(pe, header + 12)?;
            let raw_size = rd32(pe, header + 16)?;
            let raw_pointer = rd32(pe, header + 20)?;
            let within = rva.checked_sub(virtual_address)?;
            (within < virtual_size.max(raw_size))
                .then(|| raw_pointer.checked_add(within).map(|o| o as usize))?
        })
    };
    let root = to_offset(resource_rva)?;
    let entries = |dir: usize| -> Option<Vec<(u32, u32)>> {
        let count = usize::from(rd16(pe, dir + 12)?) + usize::from(rd16(pe, dir + 14)?);
        (0..count.min(MAX_ENTRIES))
            .map(|i| Some((rd32(pe, dir + 16 + i * 8)?, rd32(pe, dir + 20 + i * 8)?)))
            .collect()
    };
    let subdirectory = |target: u32| -> Option<usize> {
        (target & 0x8000_0000 != 0).then(|| root.checked_add((target & 0x7fff_ffff) as usize))?
    };
    let icons = entries(root)?
        .into_iter()
        .find(|&(id, target)| id == RT_ICON && target & 0x8000_0000 != 0)?;
    let mut best: Option<(u32, &[u8])> = None;
    for (_, name) in entries(subdirectory(icons.1)?)? {
        let Some(languages) = subdirectory(name).and_then(entries) else {
            continue;
        };
        let Some(&(_, leaf)) = languages.first() else {
            continue;
        };
        if leaf & 0x8000_0000 != 0 {
            continue;
        }
        let data = root.checked_add(leaf as usize)?;
        let (Some(rva), Some(size)) = (rd32(pe, data), rd32(pe, data + 4)) else {
            continue;
        };
        let Some(bytes) =
            to_offset(rva).and_then(|start| pe.get(start..start.checked_add(size as usize)?))
        else {
            continue;
        };
        if let Some(edge) = png_edge(bytes)
            && best.is_none_or(|(current, _)| edge > current)
        {
            best = Some((edge, bytes));
        }
    }
    best
}

/// The width of a square PNG, or `None` for anything else.
fn png_edge(bytes: &[u8]) -> Option<u32> {
    if bytes.get(..8)? != b"\x89PNG\r\n\x1a\n" || bytes.get(12..16)? != b"IHDR" {
        return None;
    }
    let width = u32::from_be_bytes(bytes.get(16..20)?.try_into().ok()?);
    let height = u32::from_be_bytes(bytes.get(20..24)?.try_into().ok()?);
    (width == height && (16..=1024).contains(&width)).then_some(width)
}

fn rd16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn rd32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png(edge: u32) -> Vec<u8> {
        let mut bytes = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
        bytes.extend(edge.to_be_bytes());
        bytes.extend(edge.to_be_bytes());
        bytes.extend([0u8; 16]);
        bytes
    }

    /// A PE32+ image with one section holding a resource tree of icons, laid out by hand.
    fn image(icons: &[Vec<u8>]) -> Vec<u8> {
        const SECTION_RVA: u32 = 0x1000;
        const RAW: usize = 0x400;
        let mut pe = vec![0u8; RAW];
        pe[..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        pe[coff + 2..coff + 4].copy_from_slice(&1u16.to_le_bytes());
        pe[coff + 16..coff + 18].copy_from_slice(&240u16.to_le_bytes());
        let optional = coff + 20;
        pe[optional..optional + 2].copy_from_slice(&0x20bu16.to_le_bytes());
        pe[optional + 108..optional + 112].copy_from_slice(&16u32.to_le_bytes());
        pe[optional + 112 + 16..optional + 112 + 20].copy_from_slice(&SECTION_RVA.to_le_bytes());

        // Resource section: root dir (1 id entry) -> icon dir (n entries) -> n language dirs ->
        // n data entries -> the icons.
        let n = icons.len();
        let mut rsrc = vec![0u8; 16 + 8];
        rsrc[14..16].copy_from_slice(&1u16.to_le_bytes());
        rsrc[16..20].copy_from_slice(&3u32.to_le_bytes());
        rsrc[20..24].copy_from_slice(&(0x8000_0000u32 | 24).to_le_bytes());
        let icon_dir = rsrc.len();
        rsrc.extend(vec![0u8; 16 + 8 * n]);
        rsrc[icon_dir + 14..icon_dir + 16].copy_from_slice(&(n as u16).to_le_bytes());
        let languages = rsrc.len();
        rsrc.extend(vec![0u8; (16 + 8) * n]);
        let leaves = rsrc.len();
        rsrc.extend(vec![0u8; 16 * n]);
        for (i, icon) in icons.iter().enumerate() {
            let lang = languages + i * 24;
            let entry = icon_dir + 16 + i * 8;
            rsrc[entry..entry + 4].copy_from_slice(&(i as u32 + 1).to_le_bytes());
            rsrc[entry + 4..entry + 8]
                .copy_from_slice(&(0x8000_0000u32 | lang as u32).to_le_bytes());
            rsrc[lang + 14..lang + 16].copy_from_slice(&1u16.to_le_bytes());
            rsrc[lang + 20..lang + 24].copy_from_slice(&((leaves + i * 16) as u32).to_le_bytes());
            let at = rsrc.len();
            rsrc.extend(icon);
            let leaf = leaves + i * 16;
            rsrc[leaf..leaf + 4].copy_from_slice(&(SECTION_RVA + at as u32).to_le_bytes());
            rsrc[leaf + 4..leaf + 8].copy_from_slice(&(icon.len() as u32).to_le_bytes());
        }
        let header = optional + 240;
        let size = rsrc.len() as u32;
        pe[header + 8..header + 12].copy_from_slice(&size.to_le_bytes());
        pe[header + 12..header + 16].copy_from_slice(&SECTION_RVA.to_le_bytes());
        pe[header + 16..header + 20].copy_from_slice(&size.to_le_bytes());
        pe[header + 20..header + 24].copy_from_slice(&(RAW as u32).to_le_bytes());
        pe.extend(rsrc);
        pe
    }

    #[test]
    fn the_largest_png_icon_is_chosen_and_other_icons_are_ignored() {
        let pe = image(&[
            png(32),
            b"\x28\0\0\0 a bitmap icon".to_vec(),
            png(256),
            png(64),
        ]);
        let (edge, bytes) = largest_png_icon(&pe).expect("an icon");
        assert_eq!(edge, 256);
        assert_eq!(bytes, png(256).as_slice());
    }

    /// Every truncation of a valid image and a few corruptions are a quiet `None`, never a panic.
    #[test]
    fn a_damaged_executable_yields_no_icon() {
        let pe = image(&[png(256)]);
        for len in 0..pe.len() {
            let _ = largest_png_icon(&pe[..len]);
        }
        let mut wrong_magic = pe.clone();
        wrong_magic[0x84 + 20] = 0;
        assert!(largest_png_icon(&wrong_magic).is_none());
        let mut far = pe.clone();
        far[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(largest_png_icon(&far).is_none());
        assert!(largest_png_icon(b"not an executable").is_none());
        assert!(png_edge(&png(48)[..20]).is_none());
    }

    #[test]
    fn the_entry_names_the_class_and_is_rewritten_only_when_it_changes() {
        let home = tempfile::tempdir().unwrap();
        let exe = home.path().join("ffxiv_dx11.exe");
        std::fs::write(&exe, image(&[png(256)])).unwrap();
        ensure(home.path(), &exe, "steam_app_apogee").unwrap();
        let icon = home
            .path()
            .join("icons/hicolor/256x256/apps/apogee-ffxiv.png");
        assert_eq!(std::fs::read(&icon).unwrap(), png(256));
        let entry = home.path().join("applications/apogee-ffxiv.desktop");
        let text = std::fs::read_to_string(&entry).unwrap();
        assert!(
            text.contains("StartupWMClass=steam_app_apogee\n") && text.contains("NoDisplay=true\n")
        );
        // An installed icon is not read again, so a missing executable is no failure afterwards.
        std::fs::remove_file(&exe).unwrap();
        ensure(home.path(), &exe, "ffxiv_dx11.exe").unwrap();
        assert!(
            std::fs::read_to_string(&entry)
                .unwrap()
                .contains("StartupWMClass=ffxiv_dx11.exe\n")
        );
    }
}
