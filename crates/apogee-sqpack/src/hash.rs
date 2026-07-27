//! The path hash SqPack indexes are keyed by.
//!
//! An archive carries no file names: an index entry is a hash and a location. A `.index` splits the
//! path at its last `/` and hashes the two halves separately; a `.index2` hashes the whole path. Both
//! use the same function, so [`hash_path`] computes all three values at once and nothing outside this
//! module has to know which variant of CRC-32 the game picked.

/// CRC-32 (the reflected `0xEDB88320` polynomial) with the final bit-inversion left off, sometimes
/// called JAMCRC. This is what a real install's tables carry: `common/font`'s folder hash is
/// `0x66210F73`, which is the complement of the `0x99DEF08C` a standard CRC-32 produces.
#[must_use]
fn jamcrc(bytes: &[u8]) -> u32 {
    !crc32fast::hash(bytes)
}

/// The three hashes a path resolves to: the two halves a `.index` is keyed by, and the whole-path
/// hash an `.index2` is keyed by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathHash {
    /// Hash of everything before the last `/`. `0xFFFFFFFF` (the hash of the empty string) when the
    /// path has no `/` at all.
    pub folder: u32,
    /// Hash of everything after the last `/`.
    pub file: u32,
    /// Hash of the whole path.
    pub full: u32,
}

impl PathHash {
    /// The 64-bit key a `.index` entry carries: the folder hash in the high half, the file-name hash
    /// in the low half.
    #[must_use]
    pub fn key(&self) -> u64 {
        (u64::from(self.folder) << 32) | u64::from(self.file)
    }
}

/// Hash a game path the way the indexes were built.
///
/// The path is lowercased before hashing, ASCII-only: game paths are ASCII, and folding the rest
/// would make the result depend on Unicode tables the game never consulted. Separators are `/`; a
/// backslash is an ordinary character here and will not resolve.
#[must_use]
pub fn hash_path(path: &str) -> PathHash {
    let lower = path.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    // ASCII lowercasing preserves length, so the separator sits at the same index it did in `path`.
    let (folder, file) = match bytes.iter().rposition(|&b| b == b'/') {
        Some(cut) => (&bytes[..cut], &bytes[cut + 1..]),
        None => (&bytes[..0], bytes),
    };
    PathHash {
        folder: jamcrc(folder),
        file: jamcrc(file),
        full: jamcrc(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Folder hashes read verbatim out of a real `000000.win32.index`'s folder table. They are the
    /// pin that settles which CRC-32 variant the game uses: the standard final inversion is *not*
    /// applied, so every value below is the complement of what a stock CRC-32 returns.
    const REAL_FOLDER_HASHES: [(&str, u32, u32); 4] = [
        ("common", 0x1A13_8FAE, 0xE5EC_7051),
        ("common/font", 0x6621_0F73, 0x99DE_F08C),
        ("common/graphics", 0xAAA5_47E5, 0x555A_B81A),
        ("common/softwarecursor", 0xE7AB_FB26, 0x1854_04D9),
    ];

    #[test]
    fn folder_hashes_match_a_real_folder_table() {
        for (path, recorded, standard_crc32) in REAL_FOLDER_HASHES {
            assert_eq!(hash_path(path).full, recorded, "{path}");
            // The same bytes under a standard CRC-32, to show the two are not accidentally equal.
            assert_eq!(!recorded, standard_crc32, "{path}");
        }
    }

    #[test]
    fn a_path_splits_at_its_last_separator() {
        let h = hash_path("common/font/font1.tex");
        assert_eq!(h.folder, hash_path("common/font").full);
        assert_eq!(h.file, hash_path("font1.tex").full);
        assert_eq!(h.key(), (u64::from(h.folder) << 32) | u64::from(h.file));
    }

    #[test]
    fn a_path_with_no_separator_hashes_an_empty_folder() {
        let h = hash_path("root.exl");
        assert_eq!(h.folder, jamcrc(b""));
        assert_eq!(h.folder, 0xFFFF_FFFF);
        assert_eq!(h.file, h.full);
    }

    #[test]
    fn hashing_is_case_insensitive_over_ascii() {
        assert_eq!(hash_path("EXD/Root.EXL"), hash_path("exd/root.exl"));
    }

    #[test]
    fn a_trailing_separator_leaves_an_empty_file_half() {
        // Not a real game path, but it must not panic and must split where the bytes say.
        let h = hash_path("exd/");
        assert_eq!(h.folder, hash_path("exd").full);
        assert_eq!(h.file, jamcrc(b""));
    }

    #[test]
    fn an_empty_path_hashes_the_empty_string_three_times() {
        let h = hash_path("");
        assert_eq!(
            (h.folder, h.file, h.full),
            (0xFFFF_FFFF, 0xFFFF_FFFF, 0xFFFF_FFFF)
        );
    }

    #[test]
    fn a_non_ascii_path_is_left_alone_rather_than_folded() {
        // Only ASCII is folded, so these stay distinct. The assertion is that nothing panics on a
        // multi-byte boundary and that the rule is the documented one.
        assert_ne!(hash_path("exd/Ä.exh"), hash_path("exd/ä.exh"));
    }
}
