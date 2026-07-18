//! The typed model of a ZiPatch stream: one [`Chunk`] per container chunk, with SQPK commands broken
//! out into [`Sqpk`]. These are pure data — [`crate::parse`] turns bytes into them, and the
//! [`std::fmt::Display`] impls render the dump the `zipatch-tool` prints and the golden tests pin.
//!
//! The format is documented in the crate's design notes; the field-by-field endianness is enforced
//! at the read sites in [`crate::parse`] through [`crate::bytes`]. Every value here is already
//! decoded (offsets are the `<<7`-expanded byte positions, strings are decoded paths), so nothing
//! downstream re-derives the wire layout.

use std::fmt;

/// The 12-byte file magic: `\x91ZIPATCH\r\n\x1A\n` (PNG-style: high-bit byte, name, CRLF, EOF, LF).
pub const MAGIC: [u8; 12] = [
    0x91, 0x5A, 0x49, 0x50, 0x41, 0x54, 0x43, 0x48, 0x0D, 0x0A, 0x1A, 0x0A,
];

/// The target platform a patch resolves `.dat`/`.index` paths for, set by the SQPK `T` command. Only
/// [`Platform::Win32`] is ever applied; the console variants parse but are refused at apply time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Win32,
    Ps3,
    Ps4,
}

impl Platform {
    /// Map the `T` command's platform word (`0`/`1`/`2`); any other value is not a known platform.
    #[must_use]
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            0 => Some(Platform::Win32),
            1 => Some(Platform::Ps3),
            2 => Some(Platform::Ps4),
            _ => None,
        }
    }

    /// The lowercase filename suffix (`win32`/`ps3`/`ps4`) that keys `.dat`/`.index` path resolution.
    #[must_use]
    pub fn suffix(self) -> &'static str {
        match self {
            Platform::Win32 => "win32",
            Platform::Ps3 => "ps3",
            Platform::Ps4 => "ps4",
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.suffix())
    }
}

/// The `mainId`/`subId`/`fileId` triple every dat/index-targeting SQPK command carries. It resolves
/// to a game-root-relative path once a [`Platform`] is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileTarget {
    pub main_id: u16,
    pub sub_id: u16,
    pub file_id: u32,
}

impl FileTarget {
    /// The expansion the target lives under: `subId`'s high byte (`0` = base game).
    #[must_use]
    pub fn expansion_id(&self) -> u8 {
        (self.sub_id >> 8) as u8
    }

    /// The `sqpack` sub-folder for this expansion (`ffxiv` for the base game, `ex{n}` otherwise).
    #[must_use]
    pub fn expansion_folder(&self) -> String {
        let expansion = self.expansion_id();
        if expansion == 0 {
            "ffxiv".to_owned()
        } else {
            format!("ex{expansion}")
        }
    }

    /// The bundle path shared by the dat and index files, e.g. `sqpack/ffxiv/0a0000.win32`.
    #[must_use]
    pub fn bundle_path(&self, platform: Platform) -> String {
        format!(
            "sqpack/{}/{:02x}{:04x}.{}",
            self.expansion_folder(),
            self.main_id,
            self.sub_id,
            platform.suffix(),
        )
    }

    /// The dat-file path, e.g. `sqpack/ffxiv/0a0000.win32.dat0`.
    #[must_use]
    pub fn dat_path(&self, platform: Platform) -> String {
        format!("{}.dat{}", self.bundle_path(platform), self.file_id)
    }

    /// The index-file path: `.index` for `fileId` 0, `.index{fileId}` otherwise (so `fileId` 2 is
    /// the `.index2`). Matches the reference launcher's `SqpackIndexFile` naming.
    #[must_use]
    pub fn index_path(&self, platform: Platform) -> String {
        if self.file_id == 0 {
            format!("{}.index", self.bundle_path(platform))
        } else {
            format!("{}.index{}", self.bundle_path(platform), self.file_id)
        }
    }
}

/// The `FHDR` chunk: patch metadata and the command counts that drive progress reporting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    /// Format version, `2` or `3` (older boot patches are `2`, modern game patches `3`).
    pub version: u8,
    /// The 4-char patch kind, e.g. `DIFF` or `HIST`.
    pub patch_type: [u8; 4],
    /// The number of entry files the patch declares.
    pub entry_files: u32,
    /// The extra `v3` fields; `None` for `v2` headers.
    pub v3: Option<FileHeaderV3>,
}

impl FileHeader {
    /// The patch kind as text, trailing NULs trimmed.
    #[must_use]
    pub fn patch_type_str(&self) -> String {
        String::from_utf8_lossy(&self.patch_type)
            .trim_end_matches('\0')
            .to_owned()
    }
}

/// The `v3`-only tail of an [`FileHeader`]: directory and per-command-kind counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileHeaderV3 {
    pub add_directories: u32,
    pub delete_directories: u32,
    pub delete_data_size: u64,
    pub minor_version: u32,
    pub repository_name: u32,
    pub commands: u32,
    pub sqpk_add: u32,
    pub sqpk_delete: u32,
    pub sqpk_expand: u32,
    pub sqpk_header: u32,
    pub sqpk_file: u32,
}

/// The apply-config flag an `APLY` chunk carries. Both flags are observed always-false in real
/// patches; the parser records what is written and lets the applier decide.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOptionKind {
    /// A missing target file is not an error.
    IgnoreMissing,
    /// A mismatched pre-image is not an error.
    IgnoreOldMismatch,
    /// A kind outside the known set, carried verbatim.
    Unknown(u32),
}

impl ApplyOptionKind {
    fn from_u32(v: u32) -> Self {
        match v {
            1 => ApplyOptionKind::IgnoreMissing,
            2 => ApplyOptionKind::IgnoreOldMismatch,
            other => ApplyOptionKind::Unknown(other),
        }
    }
}

/// An `APLY` chunk: one apply-config flag and its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyOption {
    pub kind: ApplyOptionKind,
    pub value: bool,
}

impl ApplyOption {
    #[must_use]
    pub(crate) fn new(kind: u32, value: bool) -> Self {
        Self {
            kind: ApplyOptionKind::from_u32(kind),
            value,
        }
    }
}

/// An `APFS` (apply free space) chunk. Legacy: absent from modern patches, parsed for completeness.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplyFreeSpace {
    pub field_a: i64,
    pub field_b: i64,
}

/// An `ADIR`/`DELD` chunk: a directory to create or remove under the game root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    pub path: String,
}

/// The `SQPK` `T` (TargetInfo) command: sets the platform for later path resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetInfo {
    pub platform: Platform,
    pub region: i16,
    pub is_debug: bool,
    pub version: u16,
    pub deleted_data_size: u64,
    pub seek_count: u64,
}

/// The `SQPK` `X` (PatchInfo) command: metadata, a NOP on apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchInfo {
    pub status: u8,
    pub version: u8,
    pub install_size: u64,
}

/// The `SQPK` `A` (AddData) command: raw bytes written into a `.dat`, then a plain zero wipe.
/// `data` is borrowed straight from the patch buffer. Offsets/lengths are the `<<7`-expanded byte
/// values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddData<'a> {
    pub target: FileTarget,
    /// Byte offset in the dat to write at.
    pub block_offset: u64,
    /// Byte length of `data` (always equal to `data.len()`).
    pub block_size: u64,
    /// Byte count to zero-wipe immediately after `data` (a plain wipe, no empty-block header).
    pub block_delete_size: u64,
    pub data: &'a [u8],
}

/// The `SQPK` `D` (DeleteData) and `E` (ExpandData) commands: both write a 20-byte empty-block
/// header at `block_offset` and zero `block_count` 128-byte blocks after it (identical in the
/// reference).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmptyBlock {
    pub target: FileTarget,
    /// Byte offset in the dat (the `<<7`-expanded value).
    pub block_offset: u64,
    /// The number of 128-byte blocks the region spans (not shifted).
    pub block_count: u32,
}

impl EmptyBlock {
    /// The wiped region's byte length: `block_count` 128-byte blocks.
    #[must_use]
    pub fn byte_len(&self) -> u64 {
        u64::from(self.block_count) << 7
    }
}

/// Which file a `SQPK` `H` header targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderFileKind {
    Dat,
    Index,
    Other(u8),
}

/// Which header of the target file a `SQPK` `H` command writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderTargetKind {
    Version,
    Index,
    Data,
    Other(u8),
}

impl HeaderFileKind {
    pub(crate) fn parse(v: u8) -> Self {
        match v {
            b'D' => HeaderFileKind::Dat,
            b'I' => HeaderFileKind::Index,
            other => HeaderFileKind::Other(other),
        }
    }

    /// Whether the target resolves as an index file (the reference's `else` branch: anything that is
    /// not explicitly a dat).
    #[must_use]
    pub fn is_index(self) -> bool {
        !matches!(self, HeaderFileKind::Dat)
    }
}

impl HeaderTargetKind {
    pub(crate) fn parse(v: u8) -> Self {
        match v {
            b'V' => HeaderTargetKind::Version,
            b'I' => HeaderTargetKind::Index,
            b'D' => HeaderTargetKind::Data,
            other => HeaderTargetKind::Other(other),
        }
    }

    /// The write offset this header lands at: the version header overwrites offset 0, every other
    /// header the second 1024-byte block.
    #[must_use]
    pub fn write_offset(self) -> u64 {
        match self {
            HeaderTargetKind::Version => 0,
            _ => 1024,
        }
    }
}

/// The `SQPK` `H` (Header) command: writes a 1024-byte header blob. `data` is borrowed from the
/// patch buffer and is always [`Header::HEADER_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header<'a> {
    pub file_kind: HeaderFileKind,
    pub header_kind: HeaderTargetKind,
    pub target: FileTarget,
    pub data: &'a [u8],
}

impl Header<'_> {
    /// The fixed length of a header blob.
    pub const HEADER_LEN: usize = 1024;
}

/// The operation a `SQPK` `F` command performs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOperation {
    /// Truncate-if-offset-0, then write a stream of compressed blocks.
    AddFile,
    /// Delete every file of the expansion, sparing `.var` and the movie `.bk2`s.
    RemoveAll,
    /// Delete one file.
    DeleteFile,
    /// Create a directory tree.
    MakeDirTree,
    /// An operation outside the known set, carried verbatim.
    Other(u8),
}

impl FileOperation {
    pub(crate) fn parse(v: u8) -> Self {
        match v {
            b'A' => FileOperation::AddFile,
            b'R' => FileOperation::RemoveAll,
            b'D' => FileOperation::DeleteFile,
            b'M' => FileOperation::MakeDirTree,
            other => FileOperation::Other(other),
        }
    }
}

/// The `SQPK` `F` (FileOp) command. For [`FileOperation::AddFile`], `blocks` borrows the raw
/// compressed-block stream that fills the rest of the payload; for every other op it is empty. Block
/// decoding is deferred to the apply engine (the shared SqPack codec), so this stays a byte view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOp<'a> {
    pub operation: FileOperation,
    pub file_offset: i64,
    pub file_size: i64,
    pub expansion_id: u16,
    pub path: String,
    pub blocks: &'a [u8],
}

/// Whether a `SQPK` `I` index command adds or deletes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndexOp {
    Add,
    Delete,
    Other(u8),
}

impl IndexOp {
    pub(crate) fn parse(v: u8) -> Self {
        match v {
            b'A' => IndexOp::Add,
            b'D' => IndexOp::Delete,
            other => IndexOp::Other(other),
        }
    }
}

/// The `SQPK` `I` (Index) command: a NOP on modern patchers (index files are rewritten via `H`/`F`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IndexCommand {
    pub command: IndexOp,
    pub is_synonym: bool,
    pub target: FileTarget,
    pub file_hash: u64,
    pub block_offset: u32,
    pub block_number: u32,
}

/// One `SQPK` sub-command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sqpk<'a> {
    AddData(AddData<'a>),
    DeleteData(EmptyBlock),
    ExpandData(EmptyBlock),
    Header(Header<'a>),
    TargetInfo(TargetInfo),
    PatchInfo(PatchInfo),
    File(FileOp<'a>),
    Index(IndexCommand),
}

/// One ZiPatch container chunk. Chunks that borrow raw payload bytes (`SQPK A`/`H`/`F:A`) tie their
/// lifetime to the parser's internal buffer, so a chunk is used before the next is read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Chunk<'a> {
    FileHeader(FileHeader),
    ApplyOption(ApplyOption),
    ApplyFreeSpace(ApplyFreeSpace),
    AddDirectory(Directory),
    DeleteDirectory(Directory),
    Sqpk(Sqpk<'a>),
    EndOfFile,
    /// An `XXXX` padding chunk.
    Padding,
}

/// Render a byte that is meant to be a printable command tag, falling back to hex.
fn tag(byte: u8) -> String {
    if byte.is_ascii_graphic() {
        (byte as char).to_string()
    } else {
        format!("{byte:#04x}")
    }
}

impl fmt::Display for HeaderFileKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderFileKind::Dat => f.write_str("dat"),
            HeaderFileKind::Index => f.write_str("index"),
            HeaderFileKind::Other(b) => write!(f, "?{}", tag(*b)),
        }
    }
}

impl fmt::Display for HeaderTargetKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HeaderTargetKind::Version => f.write_str("version"),
            HeaderTargetKind::Index => f.write_str("index"),
            HeaderTargetKind::Data => f.write_str("data"),
            HeaderTargetKind::Other(b) => write!(f, "?{}", tag(*b)),
        }
    }
}

impl fmt::Display for FileOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileOperation::AddFile => f.write_str("add"),
            FileOperation::RemoveAll => f.write_str("removeall"),
            FileOperation::DeleteFile => f.write_str("delete"),
            FileOperation::MakeDirTree => f.write_str("mkdir"),
            FileOperation::Other(b) => write!(f, "?{}", tag(*b)),
        }
    }
}

impl fmt::Display for IndexOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IndexOp::Add => f.write_str("add"),
            IndexOp::Delete => f.write_str("delete"),
            IndexOp::Other(b) => write!(f, "?{}", tag(*b)),
        }
    }
}

impl fmt::Display for ApplyOptionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplyOptionKind::IgnoreMissing => f.write_str("ignore-missing"),
            ApplyOptionKind::IgnoreOldMismatch => f.write_str("ignore-old-mismatch"),
            ApplyOptionKind::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

impl fmt::Display for Sqpk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Paths render for Win32, the only platform the launcher installs; the reference's dumps do
        // the same. These lines carry offsets and ids, never SE bytes, so they commit cleanly.
        let p = Platform::Win32;
        match self {
            Sqpk::AddData(a) => write!(
                f,
                "SQPK A {} off={} len={} wipe={}",
                a.target.dat_path(p),
                a.block_offset,
                a.block_size,
                a.block_delete_size,
            ),
            Sqpk::DeleteData(d) => write!(
                f,
                "SQPK D {} off={} blocks={}",
                d.target.dat_path(p),
                d.block_offset,
                d.block_count,
            ),
            Sqpk::ExpandData(e) => write!(
                f,
                "SQPK E {} off={} blocks={}",
                e.target.dat_path(p),
                e.block_offset,
                e.block_count,
            ),
            Sqpk::Header(h) => {
                let path = if h.file_kind.is_index() {
                    h.target.index_path(p)
                } else {
                    h.target.dat_path(p)
                };
                write!(f, "SQPK H {} {}/{}", path, h.file_kind, h.header_kind)
            }
            Sqpk::TargetInfo(t) => write!(
                f,
                "SQPK T platform={} region={} debug={} version={}",
                t.platform, t.region, t.is_debug, t.version,
            ),
            Sqpk::PatchInfo(x) => write!(
                f,
                "SQPK X status={} version={} install_size={}",
                x.status, x.version, x.install_size,
            ),
            Sqpk::File(file) => write!(
                f,
                "SQPK F {} {} off={} size={} exp={} blocks={}B",
                file.operation,
                file.path,
                file.file_offset,
                file.file_size,
                file.expansion_id,
                file.blocks.len(),
            ),
            Sqpk::Index(i) => write!(
                f,
                "SQPK I {} {} synonym={} hash={:#018x}",
                i.command,
                i.target.index_path(p),
                i.is_synonym,
                i.file_hash,
            ),
        }
    }
}

impl fmt::Display for Chunk<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Chunk::FileHeader(h) => {
                write!(
                    f,
                    "FHDR v{} type={} entry_files={}",
                    h.version,
                    h.patch_type_str(),
                    h.entry_files,
                )
            }
            Chunk::ApplyOption(a) => write!(f, "APLY {}={}", a.kind, a.value),
            Chunk::ApplyFreeSpace(s) => write!(f, "APFS {} {}", s.field_a, s.field_b),
            Chunk::AddDirectory(d) => write!(f, "ADIR {}", d.path),
            Chunk::DeleteDirectory(d) => write!(f, "DELD {}", d.path),
            Chunk::Sqpk(s) => write!(f, "{s}"),
            Chunk::EndOfFile => f.write_str("EOF_"),
            Chunk::Padding => f.write_str("XXXX"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dat_and_index_paths_resolve_like_the_reference() {
        // Base game, fileId 0: `.index`; the dat carries its fileId.
        let base = FileTarget {
            main_id: 0x0a,
            sub_id: 0x0000,
            file_id: 0,
        };
        assert_eq!(base.expansion_id(), 0);
        assert_eq!(
            base.dat_path(Platform::Win32),
            "sqpack/ffxiv/0a0000.win32.dat0"
        );
        assert_eq!(
            base.index_path(Platform::Win32),
            "sqpack/ffxiv/0a0000.win32.index"
        );

        // fileId 2 is the `.index2`; fileId 1 would be `.index1`.
        let idx2 = FileTarget {
            main_id: 0x0a,
            sub_id: 0x0000,
            file_id: 2,
        };
        assert_eq!(
            idx2.index_path(Platform::Win32),
            "sqpack/ffxiv/0a0000.win32.index2"
        );

        // Expansion 2: subId high byte selects `ex2`; the low byte stays in the filename.
        let ex = FileTarget {
            main_id: 0x0c,
            sub_id: 0x0201,
            file_id: 1,
        };
        assert_eq!(ex.expansion_id(), 2);
        assert_eq!(ex.dat_path(Platform::Win32), "sqpack/ex2/0c0201.win32.dat1");
        assert_eq!(ex.dat_path(Platform::Ps3), "sqpack/ex2/0c0201.ps3.dat1");
    }

    #[test]
    fn platform_maps_known_words_only() {
        assert_eq!(Platform::from_u16(0), Some(Platform::Win32));
        assert_eq!(Platform::from_u16(1), Some(Platform::Ps3));
        assert_eq!(Platform::from_u16(2), Some(Platform::Ps4));
        assert_eq!(Platform::from_u16(3), None);
    }

    #[test]
    fn empty_block_byte_len_is_block_count_times_128() {
        let e = EmptyBlock {
            target: FileTarget {
                main_id: 0,
                sub_id: 0,
                file_id: 0,
            },
            block_offset: 0,
            block_count: 4,
        };
        assert_eq!(e.byte_len(), 512);
    }

    #[test]
    fn header_write_offset_splits_version_from_the_rest() {
        assert_eq!(HeaderTargetKind::Version.write_offset(), 0);
        assert_eq!(HeaderTargetKind::Index.write_offset(), 1024);
        assert_eq!(HeaderTargetKind::Data.write_offset(), 1024);
        assert_eq!(HeaderTargetKind::Other(b'Z').write_offset(), 1024);
    }
}
