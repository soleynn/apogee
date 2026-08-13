//! Archive naming: which file on disk holds a given game path.
//!
//! A repository's archives are named `{category:02x}{expansion:02x}{chunk:02x}.{platform}.{ext}`, and
//! the category is the path's first segment (`exd/root.exl` lives in a `0a…` archive). The expansion
//! and chunk bytes are not derivable from a path in general, so a lookup probes every archive of the
//! right category in the right repository rather than guessing.
//!
//! The probe takes the first archive that answers, which is exact for an `.index`: across a full
//! retail install no 64-bit key appears in two chunks of one category. An `.index2`'s 32-bit key does
//! collide across chunks, four times in that same install, which is one more reason a lookup is judged
//! by the `.index` wherever an archive has one.

use crate::index::IndexKind;

/// The platform tag in every archive file name this crate reads. Console archives are recognized by
/// their common header and declined there, not named here.
pub const PLATFORM_TAG: &str = "win32";

/// The category byte and directory name of every category a game tree carries.
const CATEGORIES: [(u8, &str); 15] = [
    (0x00, "common"),
    (0x01, "bgcommon"),
    (0x02, "bg"),
    (0x03, "cut"),
    (0x04, "chara"),
    (0x05, "shader"),
    (0x06, "ui"),
    (0x07, "sound"),
    (0x08, "vfx"),
    (0x09, "ui_script"),
    (0x0a, "exd"),
    (0x0b, "game_script"),
    (0x0c, "music"),
    (0x12, "sqpack_test"),
    (0x13, "debug"),
];

/// A game path's top-level category, which is the high byte of every archive holding it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Category {
    /// `common`, category `0x00`.
    Common,
    /// `bgcommon`, category `0x01`.
    BgCommon,
    /// `bg`, category `0x02`.
    Bg,
    /// `cut`, category `0x03`.
    Cut,
    /// `chara`, category `0x04`.
    Chara,
    /// `shader`, category `0x05`.
    Shader,
    /// `ui`, category `0x06`.
    Ui,
    /// `sound`, category `0x07`.
    Sound,
    /// `vfx`, category `0x08`.
    Vfx,
    /// `ui_script`, category `0x09`.
    UiScript,
    /// `exd`, category `0x0a`.
    Exd,
    /// `game_script`, category `0x0b`.
    GameScript,
    /// `music`, category `0x0c`.
    Music,
    /// `sqpack_test`, category `0x12`.
    SqpackTest,
    /// `debug`, category `0x13`.
    Debug,
    /// A category byte outside the known set, carried verbatim for the inspector to judge.
    Unknown(u8),
}

impl Category {
    /// The category byte an archive file name spells.
    #[must_use]
    pub fn id(self) -> u8 {
        match self {
            Category::Common => 0x00,
            Category::BgCommon => 0x01,
            Category::Bg => 0x02,
            Category::Cut => 0x03,
            Category::Chara => 0x04,
            Category::Shader => 0x05,
            Category::Ui => 0x06,
            Category::Sound => 0x07,
            Category::Vfx => 0x08,
            Category::UiScript => 0x09,
            Category::Exd => 0x0a,
            Category::GameScript => 0x0b,
            Category::Music => 0x0c,
            Category::SqpackTest => 0x12,
            Category::Debug => 0x13,
            Category::Unknown(id) => id,
        }
    }

    /// The category a byte names.
    #[must_use]
    pub fn from_id(id: u8) -> Self {
        match id {
            0x00 => Category::Common,
            0x01 => Category::BgCommon,
            0x02 => Category::Bg,
            0x03 => Category::Cut,
            0x04 => Category::Chara,
            0x05 => Category::Shader,
            0x06 => Category::Ui,
            0x07 => Category::Sound,
            0x08 => Category::Vfx,
            0x09 => Category::UiScript,
            0x0a => Category::Exd,
            0x0b => Category::GameScript,
            0x0c => Category::Music,
            0x12 => Category::SqpackTest,
            0x13 => Category::Debug,
            other => Category::Unknown(other),
        }
    }

    /// The path segment that names this category, or `None` for one outside the known set.
    #[must_use]
    pub fn dir_name(self) -> Option<&'static str> {
        if matches!(self, Category::Unknown(_)) {
            return None;
        }
        let id = self.id();
        CATEGORIES
            .iter()
            .find(|(known, _)| *known == id)
            .map(|(_, name)| *name)
    }

    /// The category the first segment of `path` names, or `None` if that segment names none. A path
    /// whose category is unknown cannot be in any archive, so a lookup on it simply finds nothing.
    #[must_use]
    pub fn from_path(path: &str) -> Option<Self> {
        let head = path.split('/').next()?;
        CATEGORIES
            .iter()
            .find(|(_, name)| head.eq_ignore_ascii_case(name))
            .map(|(id, _)| Category::from_id(*id))
    }
}

/// One archive within a repository, identified the way its file name spells it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ArchiveId {
    /// The category byte.
    pub category: u8,
    /// The expansion byte, which matches the repository the archive sits in (`0` for the base).
    pub expansion: u8,
    /// The chunk byte, splitting a large category across several archives.
    pub chunk: u8,
}

impl ArchiveId {
    /// An archive id from its three bytes.
    #[must_use]
    pub fn new(category: u8, expansion: u8, chunk: u8) -> Self {
        Self {
            category,
            expansion,
            chunk,
        }
    }

    /// The six hex digits every one of the archive's file names starts with.
    #[must_use]
    pub fn stem(self) -> String {
        format!(
            "{:02x}{:02x}{:02x}",
            self.category, self.expansion, self.chunk
        )
    }

    /// The archive id six hex digits spell, or `None` if they are not six hex digits.
    #[must_use]
    pub fn parse_stem(stem: &str) -> Option<Self> {
        if stem.len() != 6 || !stem.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let byte = |at: usize| u8::from_str_radix(stem.get(at..at + 2)?, 16).ok();
        Some(Self {
            category: byte(0)?,
            expansion: byte(2)?,
            chunk: byte(4)?,
        })
    }

    /// The file name of one of the archive's indexes.
    #[must_use]
    pub fn index_file_name(self, kind: IndexKind) -> String {
        format!("{}.{PLATFORM_TAG}.{}", self.stem(), kind.extension())
    }

    /// The file name of one of the archive's data files.
    #[must_use]
    pub fn dat_file_name(self, dat: u8) -> String {
        format!("{}.{PLATFORM_TAG}.dat{dat}", self.stem())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_category_round_trips_through_its_byte_and_its_directory_name() {
        for (id, name) in CATEGORIES {
            let category = Category::from_id(id);
            assert_eq!(category.id(), id, "{name}");
            assert_eq!(category.dir_name(), Some(name));
            assert_eq!(
                Category::from_path(&format!("{name}/a/b.dat")),
                Some(category)
            );
        }
    }

    #[test]
    fn an_unknown_category_byte_is_carried_verbatim_and_names_no_directory() {
        assert_eq!(Category::from_id(0x7f), Category::Unknown(0x7f));
        assert_eq!(Category::from_id(0x7f).id(), 0x7f);
        assert_eq!(Category::from_id(0x7f).dir_name(), None);
    }

    #[test]
    fn a_path_whose_first_segment_names_no_category_has_none() {
        assert_eq!(Category::from_path("nope/root.exl"), None);
        assert_eq!(Category::from_path(""), None);
        // The segment must match whole: `exd2` is not `exd`.
        assert_eq!(Category::from_path("exd2/root.exl"), None);
    }

    #[test]
    fn a_path_with_no_separator_still_reads_its_category() {
        assert_eq!(Category::from_path("exd"), Some(Category::Exd));
    }

    #[test]
    fn archive_file_names_match_a_real_install_layout() {
        let id = ArchiveId::new(0x0a, 0x00, 0x00);
        assert_eq!(id.stem(), "0a0000");
        assert_eq!(id.index_file_name(IndexKind::Index1), "0a0000.win32.index");
        assert_eq!(id.index_file_name(IndexKind::Index2), "0a0000.win32.index2");
        assert_eq!(id.dat_file_name(3), "0a0000.win32.dat3");
        assert_eq!(
            ArchiveId::new(0x02, 0x01, 0x05).index_file_name(IndexKind::Index1),
            "020105.win32.index"
        );
    }

    #[test]
    fn a_stem_round_trips() {
        for stem in ["000000", "0a0000", "020105", "130000"] {
            assert_eq!(
                ArchiveId::parse_stem(stem).map(ArchiveId::stem).as_deref(),
                Some(stem)
            );
        }
    }

    #[test]
    fn a_stem_that_is_not_six_hex_digits_is_rejected() {
        for stem in ["", "0a000", "0a00000", "0a00zz", "0A0000 "] {
            assert_eq!(ArchiveId::parse_stem(stem), None, "{stem}");
        }
    }

    #[test]
    fn an_uppercase_stem_parses_to_the_same_archive() {
        assert_eq!(
            ArchiveId::parse_stem("0A0000"),
            ArchiveId::parse_stem("0a0000")
        );
    }
}
