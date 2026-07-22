//! The version report and the install's version files.
//!
//! [`VersionReport`] is the tamper-check body sent with session registration: a boot line naming the
//! four boot EXEs by length and SHA1, then one line per installed expansion. [`VersionReport::from_parts`]
//! is pure and testable; [`VersionReport::from_install`] is the crate's only filesystem access
//! (read-only, synchronous, run before any request). It reads the `.ver` files and hashes the boot
//! EXEs, gating on a sanity check first: a `.ver` (or a present `.bck`) that is empty, carries an
//! embedded line feed, or is all-NUL is a repairable [`ProtoError::InvalidVersionFiles`] and no report
//! is produced. Unlike the reference launcher, a missing or corrupt file is never silently replaced
//! with the base version.

use std::fmt::Write as _;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use sha1::{Digest, Sha1};

use crate::error::ProtoError;

/// The four boot EXEs, in the fixed order they are hashed into the boot line.
const BOOT_EXES: [&str; 4] = [
    "ffxivboot.exe",
    "ffxivboot64.exe",
    "ffxivlauncher64.exe",
    "ffxivupdater64.exe",
];

/// The highest expansion index a version report carries.
const MAX_EXPANSION: u8 = 5;

/// The base-game version string (`YYYY.MM.DD.PPPP.RRRR` at all zeros): the sentinel a repository
/// reports when it is not installed, so the server returns the full patch chain for
/// install-from-nothing. It is substituted only through the opt-in install-mode paths
/// ([`VersionReport::from_install_or_base`], [`InstallPaths::boot_version_or_sentinel`]); the strict
/// paths reject a missing repository instead of silently base-versioning it.
pub const BASE_GAME_VERSION: &str = "2012.01.01.0000.0000";

/// Which repository a bad version file belongs to, for triage. `Boot` covers `ffxivboot.ver` and the
/// four boot EXEs (the boot directory is the unit of repair).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionRepo {
    /// The boot component (`{root}/boot`).
    Boot,
    /// The base game (`{root}/game`).
    Game,
    /// An expansion pack (`{root}/game/sqpack/ex{n}`), 1-based.
    Ex(u8),
}

/// How a version file failed the sanity gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SanityKind {
    /// A required file is absent.
    Missing,
    /// The file is empty or only whitespace.
    Empty,
    /// The file carries an embedded line feed.
    ContainsNewline,
    /// Every byte is NUL.
    AllNul,
    /// The file exists but could not be read (a non-not-found I/O error).
    Unreadable,
}

/// The paths of a game installation, rooted at the directory holding `boot/` and `game/`.
#[derive(Debug, Clone)]
pub struct InstallPaths {
    root: PathBuf,
}

impl InstallPaths {
    /// An install rooted at `root` (the directory containing `boot/` and `game/`).
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn boot_dir(&self) -> PathBuf {
        self.root.join("boot")
    }

    fn boot_ver(&self) -> PathBuf {
        self.boot_dir().join("ffxivboot.ver")
    }

    fn boot_bck(&self) -> PathBuf {
        self.boot_dir().join("ffxivboot.bck")
    }

    fn game_dir(&self) -> PathBuf {
        self.root.join("game")
    }

    fn game_ver(&self) -> PathBuf {
        self.game_dir().join("ffxivgame.ver")
    }

    fn game_bck(&self) -> PathBuf {
        self.game_dir().join("ffxivgame.bck")
    }

    fn ex_dir(&self, n: u8) -> PathBuf {
        self.game_dir().join("sqpack").join(format!("ex{n}"))
    }

    fn ex_ver(&self, n: u8) -> PathBuf {
        self.ex_dir(n).join(format!("ex{n}.ver"))
    }

    fn ex_bck(&self, n: u8) -> PathBuf {
        self.ex_dir(n).join(format!("ex{n}.bck"))
    }

    /// Read the boot repository's version for the boot-version check, using the strict posture: a
    /// missing or corrupt `ffxivboot.ver` is a repairable [`ProtoError::InvalidVersionFiles`], never a
    /// silent base-version fallback. This is the default; [`InstallPaths::boot_version_or_sentinel`] is
    /// the opt-in install-from-nothing variant.
    pub fn boot_version(&self) -> Result<String, ProtoError> {
        read_sane_ver(&self.boot_ver(), VersionRepo::Boot)
    }

    /// Read the boot version for the boot-version check, substituting [`BASE_GAME_VERSION`] when
    /// `ffxivboot.ver` is absent or whitespace-only. Opt-in, for install-from-nothing: an absent boot
    /// repository must report the base sentinel so the server returns the full boot chain. A present but
    /// unreadable file is still a repairable fault.
    pub fn boot_version_or_sentinel(&self) -> Result<String, ProtoError> {
        read_ver_or_sentinel(&self.boot_ver(), VersionRepo::Boot)
    }
}

/// A version report: the base-game version for the request URL and the report body for its payload.
///
/// The body is byte-identical to the reference launcher's `GetVersionReport` output; the sanity gate
/// in [`VersionReport::from_install`] is Apogee's deliberate divergence (it refuses a corrupt install
/// rather than silently substituting the base version).
#[derive(Debug)]
pub struct VersionReport {
    game_version: String,
    body: String,
}

impl VersionReport {
    /// The base-game version: the `{gamever}` URL path segment for session registration.
    #[must_use]
    pub fn game_version(&self) -> &str {
        &self.game_version
    }

    /// The report body: the exact bytes POSTed to the registration endpoint.
    #[must_use]
    pub fn body(&self) -> &str {
        &self.body
    }

    /// Assemble a report from its already-read parts. Pure: no filesystem, no sanity checks (callers
    /// reading from disk go through [`VersionReport::from_install`], which gates on sanity first).
    ///
    /// `exe_hashes` is `(byte length, lowercase-hex SHA1)` for the four boot EXEs in `BOOT_EXES`
    /// order; `expansions` is the `ex{n}.ver` contents, expansion 1 first. The body always ends with a
    /// line feed, matching the reference launcher.
    #[must_use]
    pub fn from_parts(
        game_version: String,
        boot_ver: &str,
        exe_hashes: [(u64, String); 4],
        expansions: &[String],
    ) -> Self {
        let mut body = String::new();
        body.push_str(boot_ver);
        body.push('=');
        for (i, (length, sha1)) in exe_hashes.iter().enumerate() {
            if i != 0 {
                body.push(',');
            }
            // `write!` to a String is infallible.
            let _ = write!(body, "{}/{length}/{sha1}", BOOT_EXES[i]);
        }
        body.push('\n');
        for (i, ver) in expansions.iter().enumerate() {
            // `writeln!` to a String is infallible; it writes an LF, matching the report format.
            let _ = writeln!(body, "ex{}\t{ver}", i + 1);
        }
        Self { game_version, body }
    }

    /// Read `paths`' version files and hash its boot EXEs into a report for `max_expansion` expansions.
    ///
    /// The crate's only filesystem access: read-only and synchronous, run before any request. Every
    /// `.ver` and any present `.bck` consulted must pass the sanity gate, or this is a repairable
    /// [`ProtoError::InvalidVersionFiles`] and no report is produced. Expansions above `MAX_EXPANSION`
    /// are ignored (the report carries at most that many).
    pub fn from_install(paths: &InstallPaths, max_expansion: u8) -> Result<Self, ProtoError> {
        let expansions = max_expansion.min(MAX_EXPANSION);

        // Sanity-gate the `.ver` (and any present `.bck`) of every repository the report reads, in the
        // reference launcher's order: boot, base game, then each expansion.
        let boot_ver = read_sane_ver(&paths.boot_ver(), VersionRepo::Boot)?;
        check_bck(&paths.boot_bck(), VersionRepo::Boot)?;
        let game_version = read_sane_ver(&paths.game_ver(), VersionRepo::Game)?;
        check_bck(&paths.game_bck(), VersionRepo::Game)?;

        let mut expansion_vers = Vec::with_capacity(expansions as usize);
        for n in 1..=expansions {
            let repo = VersionRepo::Ex(n);
            expansion_vers.push(read_sane_ver(&paths.ex_ver(n), repo)?);
            check_bck(&paths.ex_bck(n), repo)?;
        }

        let exe_hashes = hash_boot_exes(paths)?;

        Ok(Self::from_parts(
            game_version,
            &boot_ver,
            exe_hashes,
            &expansion_vers,
        ))
    }

    /// Read `paths` into a report for install-from-nothing, reporting [`BASE_GAME_VERSION`] for any
    /// repository whose `.ver` is absent or whitespace-only, so the server returns the full patch chain
    /// into an empty install.
    ///
    /// Opt-in and deliberately unlike [`VersionReport::from_install`]: a missing game or expansion
    /// `.ver` is the expected state here, not a fault, so no sanity gate runs and no `.bck` is consulted;
    /// a present `.ver` is reported as-is. The boot line still names the installed boot version
    /// (base-fallback when absent) and the four boot EXEs, which must be present: install-from-nothing
    /// brings up the boot component first, then reports the game at the sentinel.
    ///
    /// This is *per-repository* base-fallback, mirroring the reference launcher's ordinary
    /// `Repository.GetVer` (`Repository.cs:67-76`: absent/whitespace → base, present → verbatim), which
    /// is the semantics its non-forced register uses. For install-from-nothing (the game and every
    /// expansion repo absent) the bytes are byte-identical to what the reference registers. It is
    /// **not** the reference's blanket `forceBaseVersion` Repair report (`Launcher.cs:271-283,402`),
    /// which forces base even for a present `.ver`; Apogee's repair is block-level over the index, not a
    /// base re-registration, so do not reuse this for repair.
    pub fn from_install_or_base(
        paths: &InstallPaths,
        max_expansion: u8,
    ) -> Result<Self, ProtoError> {
        let expansions = max_expansion.min(MAX_EXPANSION);

        let game_version = read_ver_or_sentinel(&paths.game_ver(), VersionRepo::Game)?;
        let boot_ver = read_ver_or_sentinel(&paths.boot_ver(), VersionRepo::Boot)?;

        let mut expansion_vers = Vec::with_capacity(expansions as usize);
        for n in 1..=expansions {
            expansion_vers.push(read_ver_or_sentinel(&paths.ex_ver(n), VersionRepo::Ex(n))?);
        }

        let exe_hashes = hash_boot_exes(paths)?;

        Ok(Self::from_parts(
            game_version,
            &boot_ver,
            exe_hashes,
            &expansion_vers,
        ))
    }
}

/// Read a required `.ver` file, gate it on sanity, and return its decoded contents (embedded into the
/// report unchanged). A missing or unreadable file is a repairable fault, never a base-version fallback.
fn read_sane_ver(path: &Path, repo: VersionRepo) -> Result<String, ProtoError> {
    let text = decode_ver(&read_file(path, repo)?);
    check_sanity(&text).map_err(|kind| ProtoError::InvalidVersionFiles { repo, kind })?;
    Ok(text)
}

/// Read a `.ver` the way the install-from-nothing report does, mirroring the reference launcher's
/// `Repository.GetVer` (`Repository.cs:67-76`): an absent or whitespace-only file reports
/// [`BASE_GAME_VERSION`]; a present file's decoded content is used verbatim (no sanity gate — the
/// install-mode paths substitute base for a missing repository, they never reject one). A present but
/// unreadable file is still a repairable [`ProtoError::InvalidVersionFiles`].
fn read_ver_or_sentinel(path: &Path, repo: VersionRepo) -> Result<String, ProtoError> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let text = decode_ver(&bytes);
            Ok(if text.trim().is_empty() {
                BASE_GAME_VERSION.to_owned()
            } else {
                text
            })
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(BASE_GAME_VERSION.to_owned()),
        Err(_) => Err(ProtoError::InvalidVersionFiles {
            repo,
            kind: SanityKind::Unreadable,
        }),
    }
}

/// Sanity-check a `.bck` backup only when it is present; an absent backup is the normal healthy state.
fn check_bck(path: &Path, repo: VersionRepo) -> Result<(), ProtoError> {
    match std::fs::read(path) {
        Ok(bytes) => check_sanity(&decode_ver(&bytes))
            .map_err(|kind| ProtoError::InvalidVersionFiles { repo, kind }),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(ProtoError::InvalidVersionFiles {
            repo,
            kind: SanityKind::Unreadable,
        }),
    }
}

/// SHA1-hash the four boot EXEs into `(byte length, lowercase-hex digest)` pairs in `BOOT_EXES`
/// order. A missing or unreadable EXE is a repairable boot-repository fault, matching the `.ver`
/// treatment (the reference launcher instead throws on a missing EXE). EXE contents are hashed as-is,
/// never sanity-checked.
fn hash_boot_exes(paths: &InstallPaths) -> Result<[(u64, String); 4], ProtoError> {
    let boot = paths.boot_dir();
    let mut hashes: [(u64, String); 4] = std::array::from_fn(|_| (0, String::new()));
    for (i, name) in BOOT_EXES.iter().enumerate() {
        let bytes = read_file(&boot.join(name), VersionRepo::Boot)?;
        let digest = Sha1::digest(&bytes);
        hashes[i] = (bytes.len() as u64, hex_lower(&digest));
    }
    Ok(hashes)
}

/// Read a required file, mapping absence and I/O failure to a typed repairable fault (no path or
/// `io::Error` is carried, keeping the error taxonomy leak-free).
fn read_file(path: &Path, repo: VersionRepo) -> Result<Vec<u8>, ProtoError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(err) if err.kind() == ErrorKind::NotFound => Err(ProtoError::InvalidVersionFiles {
            repo,
            kind: SanityKind::Missing,
        }),
        Err(_) => Err(ProtoError::InvalidVersionFiles {
            repo,
            kind: SanityKind::Unreadable,
        }),
    }
}

/// Decode a version file's bytes to text the way the reference launcher does: lossy UTF-8 with a single
/// leading byte-order mark stripped (`File.ReadAllText` consumes a BOM). The result is what the report
/// embeds and what the sanity gate inspects, so both stay byte-identical to the oracle.
/// Decode a `.ver` file's bytes to its canonical version string: lossy UTF-8, with one leading UTF-8
/// BOM stripped (the reference launcher's `File.ReadAllText` consumes it). This is the one decode every
/// `.ver` reader must share, so a version compared against the registration report or the signed index
/// catalog matches byte-for-byte regardless of a BOM or stray non-UTF-8 byte.
#[must_use]
pub fn decode_ver(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    text.strip_prefix('\u{feff}').unwrap_or(&text).to_owned()
}

/// The version-file content gate, over the decoded text: not empty/whitespace, no embedded line feed
/// (`\n` only, not `\r`), and not all-NUL. Mirrors the reference launcher's `IsBadVersionSanity`.
fn check_sanity(text: &str) -> Result<(), SanityKind> {
    if !text.is_empty() && text.bytes().all(|b| b == 0) {
        return Err(SanityKind::AllNul);
    }
    if text.trim().is_empty() {
        return Err(SanityKind::Empty);
    }
    if text.contains('\n') {
        return Err(SanityKind::ContainsNewline);
    }
    Ok(())
}

/// Render bytes as lowercase, space-free hex.
fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        // `write!` to a String is infallible.
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Four placeholder `(length, sha1)` pairs: length = index, digest = the index as 40 hex chars.
    fn placeholder_hashes() -> [(u64, String); 4] {
        std::array::from_fn(|i| (i as u64, format!("{i:040x}")))
    }

    #[test]
    fn from_parts_joins_boot_exes_with_commas_and_no_trailing_comma() {
        let report = VersionReport::from_parts(
            "2024.03.01.0000.0000".to_owned(),
            "2024.02.01.0000.0000",
            placeholder_hashes(),
            &[],
        );
        let boot_line = report.body().lines().next().unwrap();
        assert_eq!(
            boot_line,
            "2024.02.01.0000.0000=\
             ffxivboot.exe/0/0000000000000000000000000000000000000000,\
             ffxivboot64.exe/1/0000000000000000000000000000000000000001,\
             ffxivlauncher64.exe/2/0000000000000000000000000000000000000002,\
             ffxivupdater64.exe/3/0000000000000000000000000000000000000003"
        );
        assert!(!boot_line.ends_with(','));
    }

    #[test]
    fn from_parts_numbers_expansion_lines_from_one() {
        let report = VersionReport::from_parts(
            "g".to_owned(),
            "b",
            placeholder_hashes(),
            &["A".to_owned(), "B".to_owned()],
        );
        assert!(report.body().ends_with("ex1\tA\nex2\tB\n"));
    }

    #[test]
    fn from_parts_zero_expansions_is_boot_line_plus_newline() {
        let report = VersionReport::from_parts("g".to_owned(), "b", placeholder_hashes(), &[]);
        assert_eq!(report.body().matches('\n').count(), 1);
        assert!(report.body().ends_with('\n'));
    }

    #[test]
    fn sanity_flags_empty_whitespace_newline_and_all_nul_but_not_lone_cr() {
        assert_eq!(check_sanity(""), Err(SanityKind::Empty));
        assert_eq!(check_sanity("   \t"), Err(SanityKind::Empty));
        assert_eq!(
            check_sanity("2024.01.01.0000.0000\n"),
            Err(SanityKind::ContainsNewline)
        );
        assert_eq!(check_sanity("\u{0}\u{0}\u{0}"), Err(SanityKind::AllNul));
        // A lone trailing CR is not a newline to the gate; the value passes and is embedded verbatim.
        assert_eq!(check_sanity("2024.01.01.0000.0000\r"), Ok(()));
        assert_eq!(check_sanity("2024.01.01.0000.0000"), Ok(()));
    }

    #[test]
    fn decode_ver_strips_one_leading_bom() {
        // The reference launcher's File.ReadAllText consumes a UTF-8 BOM, so a BOM-prefixed .ver embeds
        // without it (a byte-identity concern for the report body and the gamever URL segment). A bare
        // BOM decodes to empty and is then caught by the sanity gate.
        assert_eq!(
            decode_ver(b"\xef\xbb\xbf2024.01.01.0000.0000"),
            "2024.01.01.0000.0000"
        );
        assert_eq!(decode_ver(b"2024.01.01.0000.0000"), "2024.01.01.0000.0000");
        assert_eq!(decode_ver(b"\xef\xbb\xbf"), "");
        assert_eq!(
            check_sanity(&decode_ver(b"\xef\xbb\xbf")),
            Err(SanityKind::Empty)
        );
    }
}
