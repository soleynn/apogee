//! The signed runner catalog: a JSON manifest of runners, tools and DXVK builds, authenticated by a
//! detached Ed25519 signature before anything inside it is trusted.
//!
//! [`Catalog::from_json_bytes`] is a pure, total parser over untrusted bytes and carries no
//! authenticity guarantee of its own. [`Catalog::parse_and_verify`] gates that parse behind the
//! signature check, and is what a caller that downloaded a manifest uses.

use apogee_fetch::{DigestPin, HexPins};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use url::Url;

use crate::error::CatalogError;

/// The manifest schema version this build understands.
///
/// Compared for equality rather than as a minimum: a manifest carrying any other `version` is
/// refused with [`CatalogError::UnsupportedVersion`] instead of being read best-effort.
pub const CATALOG_MANIFEST_VERSION: u32 = 1;

/// The public keys a runner catalog may be authenticated against, the one it is signed with today
/// first.
///
/// A signature is accepted when it verifies against any entry, so the list is a rotation window and
/// not a set of co-equal signers: a new key is added here and released, the hosted manifest is
/// re-signed once that build is in the field, and the retired key is dropped in a later release. A
/// single constant admits no such ordering, since re-signing first rejects every client in the field
/// and shipping first rejects the catalog until the re-sign.
///
/// These are the runner catalog's own keys, not the component catalog's: the two are published by
/// different steps on different cadences, and one compromised signer should not authenticate both.
/// Only the public bytes are committed; the matching seeds are held offline.
// It widens nothing. Every entry was compiled into this binary by the same build, so anyone who can
// append one can already replace the first, and a retired key is dropped rather than kept forever:
// the window is for finishing a rotation, not for keeping an old signer trusted.
pub const CATALOG_PUBLIC_KEYS: &[[u8; 32]] = &[[
    0x5e, 0x3e, 0xed, 0x4c, 0xe1, 0x58, 0xa5, 0xb5, 0xf0, 0x4e, 0x6c, 0x36, 0x3c, 0xcb, 0x98, 0xc8,
    0x5c, 0xb4, 0xea, 0x34, 0x7a, 0x69, 0x86, 0x9c, 0x59, 0x2d, 0xe8, 0xca, 0xd7, 0x2b, 0xa3, 0x27,
]];

// A build with no key admits nothing, and would say so as a signature that did not verify, at a
// launch, on a user's machine. It is a typo, so it is caught here instead.
const _: () = assert!(
    !CATALOG_PUBLIC_KEYS.is_empty(),
    "a build with no trusted key can admit no catalog at all"
);

/// Which of the trusted keys admitted a catalog.
///
/// Worth reading once [`CATALOG_PUBLIC_KEYS`] holds more than one entry. A catalog that only ever
/// verifies against a retired key is a rotation whose re-sign never happened, and the release that
/// drops that key from the list is where it becomes an outage.
///
/// # Examples
///
/// ```
/// use apogee_runtime::TrustedKey;
///
/// assert!(TrustedKey::Current.is_current());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustedKey {
    /// The first entry in [`CATALOG_PUBLIC_KEYS`]: the key the catalog is signed with today.
    Current,
    /// A later entry, still inside its overlap window. Whatever served this catalog has not been
    /// re-signed since the rotation started.
    #[non_exhaustive]
    Retired {
        /// Its index in [`CATALOG_PUBLIC_KEYS`], which is what locates it in a release.
        position: usize,
    },
}

impl TrustedKey {
    /// Classify the position that verified: index zero is current, anything else is retired.
    const fn at(position: usize) -> Self {
        if position == 0 {
            Self::Current
        } else {
            Self::Retired { position }
        }
    }

    /// Whether the signature came from the key in use today.
    #[must_use]
    pub const fn is_current(&self) -> bool {
        matches!(self, Self::Current)
    }
}

/// The keys compiled into this build.
///
/// One accessor, so every path that admits a catalog against a shipping key reads the same constant
/// and no field anywhere holds a key that could have been substituted.
pub(crate) const fn default_keys() -> &'static [[u8; 32]] {
    CATALOG_PUBLIC_KEYS
}

/// Decompress raw key bytes into verifying keys, preserving order.
///
/// Takes any list rather than reading [`CATALOG_PUBLIC_KEYS`] itself, so the failure and the
/// position it names are testable without a build whose own constant is broken.
///
/// # Errors
///
/// Returns [`CatalogError::TrustedKeyUnusable`] naming the first position whose bytes are not a
/// usable ed25519 key.
fn trusted_keys(raw: &[[u8; 32]]) -> Result<Vec<VerifyingKey>, CatalogError> {
    raw.iter()
        .enumerate()
        .map(|(position, bytes)| {
            VerifyingKey::from_bytes(bytes)
                .map_err(|_| CatalogError::TrustedKeyUnusable { position })
        })
        .collect()
}

/// The three runner kinds the launch path understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunnerKind {
    /// A Proton build driven through the umu launcher (`proton_umu` in the manifest). umu relocates
    /// the live prefix to a `pfx` directory inside the prefix root.
    ProtonUmu,
    /// A Wine build launched by running its own `wine` binary (`wine` in the manifest).
    Wine,
    /// A bring-your-own runner directory (`custom` in the manifest), driven exactly like
    /// [`RunnerKind::Wine`].
    Custom,
}

/// The archive container a runner, tool, or component ships in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveFormat {
    /// A gzip-compressed tar (`tar.gz`), and what a DXVK or nvapi row that names no format gets.
    TarGz,
    /// An xz-compressed tar (`tar.xz`).
    TarXz,
    /// A zstd-compressed tar (`tar.zst`).
    TarZst,
    /// A zip archive (`zip`). What the Windows-side companions publish. Never a runner container,
    /// but the same extractor lays it down, so a component row picks it like any other format.
    Zip,
}

/// How to lay a downloaded archive onto disk.
#[derive(Debug, Clone)]
pub struct ArchiveLayout {
    /// The container the archive is packed in.
    pub format: ArchiveFormat,
    /// A leading path component stripped from every entry (upstream tarballs wrap their content in a
    /// versioned top directory).
    pub strip_prefix: Option<String>,
}

/// A Wine/Proton runner: an installable, pinned artifact.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Runner {
    /// The build's name, one half of the identity [`Catalog::runner`] matches on.
    pub name: String,
    /// The build's version, the other half of that identity.
    pub version: String,
    /// How a launch through this build is driven.
    pub kind: RunnerKind,
    /// Where the archive is downloaded from.
    pub url: Url,
    /// The whole-file digest, carrying which function a row pinned it under.
    pub pin: DigestPin,
    /// How to unpack the downloaded archive.
    pub archive: ArchiveLayout,
    /// Whether this build uses ntsync, which is a property of the build rather than of the kernel:
    /// a row omits it when nobody has said. Read [`Runner::uses_ntsync`] rather than this field,
    /// which keeps "nobody said" distinguishable from "no" for a later row that wants to say so.
    pub ntsync: Option<bool>,
}

impl Runner {
    /// Whether a launch through this runner may resolve to ntsync.
    ///
    /// An unstated capability reads as no. ntsync is selected by setting no variable at all, so a
    /// build wrongly assumed to use it runs with neither esync nor fsync either: a prefix with no
    /// accelerated synchronization that still launches and reports success. Wrongly assuming the
    /// other way costs fsync, which has been available since kernel 5.16.
    #[must_use]
    pub fn uses_ntsync(&self) -> bool {
        self.ntsync.unwrap_or(false)
    }
}

/// A supporting tool managed as data (`umu-launcher` today), installed like a runner.
#[derive(Debug, Clone)]
pub struct ToolEntry {
    /// The tool's name, what [`Catalog::tool`] matches on.
    pub name: String,
    /// The tool's version.
    pub version: String,
    /// Where the archive is downloaded from.
    pub url: Url,
    /// The whole-file digest, carrying which function a row pinned it under.
    pub pin: DigestPin,
    /// How to unpack the downloaded archive.
    pub archive: ArchiveLayout,
}

/// A DXVK build: the pinned tarball plus an optional, equally-pinned `dxvk-nvapi` companion.
#[derive(Debug, Clone)]
pub struct DxvkEntry {
    /// The DXVK release, as the manifest spells it.
    pub version: String,
    /// Where the archive is downloaded from.
    pub url: Url,
    /// The whole-file digest, carrying which function a row pinned it under.
    pub pin: DigestPin,
    /// The container format (`tar.gz` by default); data-driven like a runner's, not hardcoded.
    pub format: ArchiveFormat,
    /// `dxvk-nvapi`, present only when both its URL and its pin are in the manifest.
    pub nvapi: Option<NvapiRef>,
}

/// A pinned `dxvk-nvapi` artifact, installed alongside a [`DxvkEntry`].
#[derive(Debug, Clone)]
pub struct NvapiRef {
    /// Where the archive is downloaded from.
    pub url: Url,
    /// The whole-file digest, carrying which function a row pinned it under.
    pub pin: DigestPin,
    /// The container the archive is packed in (`tar.gz` by default).
    pub format: ArchiveFormat,
}

/// A parsed runner catalog.
///
/// Holding one is not evidence that it was authenticated: [`Catalog::from_json_bytes`] builds one
/// from any bytes that parse.
#[derive(Debug, Clone)]
pub struct Catalog {
    /// The manifest's schema version, always [`CATALOG_MANIFEST_VERSION`] for a catalog that parsed.
    pub version: u32,
    /// The runner rows, in manifest order.
    pub runners: Vec<Runner>,
    /// The DXVK rows, in manifest order; the first is the default (see [`Catalog::default_dxvk`]).
    pub dxvk: Vec<DxvkEntry>,
    /// The supporting-tool rows, in manifest order.
    pub tools: Vec<ToolEntry>,
}

impl Catalog {
    /// Parse a catalog from untrusted JSON.
    ///
    /// Pure and total: any byte sequence yields a `Catalog` or a typed [`CatalogError`], never a
    /// panic or an unbounded allocation, which is what makes it the fuzz entry point. It carries no
    /// authenticity guarantee, so a caller that has not already verified a signature over these
    /// exact bytes wants [`Catalog::parse_and_verify`] instead.
    ///
    /// # Errors
    ///
    /// [`CatalogError::Malformed`] if the bytes are not JSON in the schema,
    /// [`CatalogError::UnsupportedVersion`] if `version` is not [`CATALOG_MANIFEST_VERSION`],
    /// [`CatalogError::UnknownRunnerKind`] or [`CatalogError::UnknownArchiveFormat`] for a value
    /// outside the fixed sets, [`CatalogError::BadPin`] for a row carrying neither a `blake3` nor a
    /// `sha256` pin of 32 hex bytes (or a `dxvk-nvapi` companion that gives a URL without a pin, or
    /// the reverse), and [`CatalogError::BadUrl`] for a URL that does not parse.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), apogee_runtime::CatalogError> {
    /// use apogee_runtime::{ArchiveFormat, Catalog, RunnerKind};
    ///
    /// let json = br#"{
    ///   "version": 1,
    ///   "runners": [
    ///     { "name": "GE-Proton", "version": "11-1", "kind": "proton_umu",
    ///       "url": "https://example.invalid/GE-Proton11-1.tar.gz",
    ///       "blake3": "0000000000000000000000000000000000000000000000000000000000000000",
    ///       "archive": { "format": "tar.gz", "strip_prefix": "GE-Proton11-1" } }
    ///   ]
    /// }"#;
    ///
    /// let catalog = Catalog::from_json_bytes(json)?;
    /// let runner = catalog.runner("GE-Proton", "11-1").expect("the row parsed");
    /// assert_eq!(runner.kind, RunnerKind::ProtonUmu);
    /// assert_eq!(runner.archive.format, ArchiveFormat::TarGz);
    /// assert!(catalog.default_dxvk().is_none());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, CatalogError> {
        let raw: RawCatalog = serde_json::from_slice(bytes).map_err(CatalogError::Malformed)?;
        Self::try_from(raw)
    }

    /// Verify `signature` over the exact `manifest_json` bytes against `keys`, in order, then parse.
    ///
    /// Returns the catalog and which key admitted it. The signature is checked first, so no pin is
    /// trusted before authenticity is established, and it covers the byte string as handed in:
    /// a manifest reformatted after signing no longer verifies. Nothing else about the contents is
    /// authenticated, and the manifest carries no expiry or counter, so a stale file that was
    /// properly signed still verifies.
    ///
    /// Raw 32-byte keys, the shape [`CATALOG_PUBLIC_KEYS`] is compiled in as, rather than a type
    /// from the signature crate, which would put that crate's major version in this one's surface
    /// for nothing. Passing the keys in rather than reading the constant lets a test drive the gate
    /// with a key it signs with; nothing about that weakens it, since a caller cannot verify against
    /// keys it does not have and the launcher passes the ones compiled into it (see
    /// [`Catalog::verify_trusted`]).
    ///
    /// # Errors
    ///
    /// [`CatalogError::TrustedKeyUnusable`] if one of `keys` is not a usable ed25519 key,
    /// [`CatalogError::BadSignature`] if `signature` is not exactly 64 bytes or verifies against
    /// none of `keys` (an empty `keys` therefore admits nothing), then anything
    /// [`Catalog::from_json_bytes`] raises.
    pub fn parse_and_verify(
        manifest_json: &[u8],
        signature: &[u8],
        keys: &[[u8; 32]],
    ) -> Result<(Self, TrustedKey), CatalogError> {
        let keys = trusted_keys(keys)?;
        let sig = Signature::from_slice(signature).map_err(|_| CatalogError::BadSignature)?;
        let position = keys
            .iter()
            .position(|key| key.verify_strict(manifest_json, &sig).is_ok())
            .ok_or(CatalogError::BadSignature)?;
        Ok((
            Self::from_json_bytes(manifest_json)?,
            TrustedKey::at(position),
        ))
    }

    /// [`Catalog::parse_and_verify`] against the keys compiled into this build.
    ///
    /// # Errors
    ///
    /// [`CatalogError::TrustedKeyUnusable`] if this build's own key list is malformed, then anything
    /// [`Catalog::parse_and_verify`] raises.
    ///
    /// # Examples
    ///
    /// ```
    /// # use apogee_runtime::{Catalog, CatalogError};
    /// # fn demo(manifest_json: &[u8], signature: &[u8]) -> Result<Catalog, CatalogError> {
    /// let (catalog, trusted) = Catalog::verify_trusted(manifest_json, signature)?;
    /// if !trusted.is_current() {
    ///     // Still signed by a key that is being retired: the re-sign has not happened.
    ///     let needs_resign = true;
    /// #   let _ = needs_resign;
    /// }
    /// # Ok(catalog)
    /// # }
    /// ```
    pub fn verify_trusted(
        manifest_json: &[u8],
        signature: &[u8],
    ) -> Result<(Self, TrustedKey), CatalogError> {
        Self::parse_and_verify(manifest_json, signature, default_keys())
    }

    /// Resolve a runner by name and version, both of which must match.
    ///
    /// `None` is what the caller maps to
    /// [`RuntimeError::RunnerUnavailable`](crate::RuntimeError::RunnerUnavailable).
    #[must_use]
    pub fn runner(&self, name: &str, version: &str) -> Option<&Runner> {
        self.runners
            .iter()
            .find(|r| r.name == name && r.version == version)
    }

    /// Resolve a supporting tool by name (`umu-launcher` is the only one published today).
    #[must_use]
    pub fn tool(&self, name: &str) -> Option<&ToolEntry> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// The DXVK build to install when nothing names a particular one.
    ///
    /// The first row, so which build that is stays the publisher's decision and moves by re-ordering
    /// the manifest rather than by changing a caller. `None` is a catalog that publishes none, which
    /// a caller reads as nothing to install rather than as a failure.
    #[must_use]
    pub fn default_dxvk(&self) -> Option<&DxvkEntry> {
        self.dxvk.first()
    }
}

// ---- raw deserialization + validation -------------------------------------------------------

/// The manifest as it is spelled on the wire. Every list defaults to empty, so a manifest may
/// publish only some of the three kinds of row.
#[derive(Deserialize)]
struct RawCatalog {
    version: u32,
    #[serde(default)]
    runners: Vec<RawRunner>,
    #[serde(default)]
    dxvk: Vec<RawDxvk>,
    #[serde(default)]
    tools: Vec<RawTool>,
}

/// A `runners` row. The pin may be spelled either way, and a row that carries neither is refused.
#[derive(Deserialize)]
struct RawRunner {
    name: String,
    version: String,
    kind: String,
    url: String,
    #[serde(default)]
    blake3: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    archive: RawArchive,
    /// Absent in a row written before the key existed, and absent is meaningful (see
    /// [`Runner::uses_ntsync`]), so it stays an `Option` rather than defaulting to a bool.
    #[serde(default)]
    ntsync: Option<bool>,
}

/// A `tools` row, laid out like a runner row minus the kind and the sync key.
#[derive(Deserialize)]
struct RawTool {
    name: String,
    version: String,
    url: String,
    #[serde(default)]
    blake3: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    archive: RawArchive,
}

/// A `dxvk` row. The `nvapi_*` keys describe the companion and are all-or-nothing; the archive is a
/// bare `format` rather than a whole layout, because the install path finds the per-architecture DLL
/// directories in the extracted tree instead of stripping a prefix.
#[derive(Deserialize)]
struct RawDxvk {
    version: String,
    url: String,
    #[serde(default)]
    blake3: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    nvapi_url: Option<String>,
    #[serde(default)]
    nvapi_blake3: Option<String>,
    #[serde(default)]
    nvapi_sha256: Option<String>,
    #[serde(default)]
    nvapi_format: Option<String>,
}

/// An `archive` object: the container, and optionally the top directory to strip from it.
#[derive(Deserialize)]
struct RawArchive {
    format: String,
    #[serde(default)]
    strip_prefix: Option<String>,
}

impl TryFrom<RawCatalog> for Catalog {
    type Error = CatalogError;

    /// Check the schema version, then build every row.
    ///
    /// # Errors
    ///
    /// [`CatalogError::UnsupportedVersion`] before any row is looked at, then whatever the row
    /// builders raise: [`CatalogError::UnknownRunnerKind`], [`CatalogError::UnknownArchiveFormat`],
    /// [`CatalogError::BadPin`], [`CatalogError::BadUrl`].
    fn try_from(raw: RawCatalog) -> Result<Self, CatalogError> {
        if raw.version != CATALOG_MANIFEST_VERSION {
            return Err(CatalogError::UnsupportedVersion {
                found: raw.version,
                expected: CATALOG_MANIFEST_VERSION,
            });
        }
        let runners = raw
            .runners
            .into_iter()
            .map(build_runner)
            .collect::<Result<Vec<_>, _>>()?;
        let tools = raw
            .tools
            .into_iter()
            .map(build_tool)
            .collect::<Result<Vec<_>, _>>()?;
        let dxvk = raw
            .dxvk
            .into_iter()
            .map(build_dxvk)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            version: raw.version,
            runners,
            dxvk,
            tools,
        })
    }
}

/// Validate a runner row: a known kind, a parseable archive, one usable pin, an absolute URL.
///
/// # Errors
///
/// [`CatalogError::UnknownRunnerKind`], [`CatalogError::UnknownArchiveFormat`],
/// [`CatalogError::BadPin`] or [`CatalogError::BadUrl`], each naming the row.
fn build_runner(r: RawRunner) -> Result<Runner, CatalogError> {
    let kind = match r.kind.as_str() {
        "proton_umu" => RunnerKind::ProtonUmu,
        "wine" => RunnerKind::Wine,
        "custom" => RunnerKind::Custom,
        _ => return Err(CatalogError::UnknownRunnerKind { kind: r.kind }),
    };
    let archive = build_archive(r.archive)?;
    let pin = DigestPin::from_hex(HexPins {
        blake3: r.blake3.as_deref(),
        sha256: r.sha256.as_deref(),
    })
    .ok_or_else(|| CatalogError::BadPin {
        name: r.name.clone(),
        version: r.version.clone(),
    })?;
    let url = Url::parse(&r.url).map_err(|_| CatalogError::BadUrl {
        name: r.name.clone(),
        version: r.version.clone(),
    })?;
    Ok(Runner {
        name: r.name,
        version: r.version,
        kind,
        url,
        pin,
        archive,
        ntsync: r.ntsync,
    })
}

/// Validate a tool row, on the same rules as a runner row minus the kind.
///
/// # Errors
///
/// [`CatalogError::UnknownArchiveFormat`], [`CatalogError::BadPin`] or [`CatalogError::BadUrl`].
fn build_tool(t: RawTool) -> Result<ToolEntry, CatalogError> {
    let archive = build_archive(t.archive)?;
    let pin = DigestPin::from_hex(HexPins {
        blake3: t.blake3.as_deref(),
        sha256: t.sha256.as_deref(),
    })
    .ok_or_else(|| CatalogError::BadPin {
        name: t.name.clone(),
        version: t.version.clone(),
    })?;
    let url = Url::parse(&t.url).map_err(|_| CatalogError::BadUrl {
        name: t.name.clone(),
        version: t.version.clone(),
    })?;
    Ok(ToolEntry {
        name: t.name,
        version: t.version,
        url,
        pin,
        archive,
    })
}

/// Validate a DXVK row and its optional companion, both pinned or the row is refused.
///
/// # Errors
///
/// [`CatalogError::UnknownArchiveFormat`], [`CatalogError::BadPin`] (also for a companion given as a
/// URL without a pin or a pin without a URL) or [`CatalogError::BadUrl`], named `dxvk` or
/// `dxvk-nvapi` after the half that failed.
fn build_dxvk(d: RawDxvk) -> Result<DxvkEntry, CatalogError> {
    let pin = DigestPin::from_hex(HexPins {
        blake3: d.blake3.as_deref(),
        sha256: d.sha256.as_deref(),
    })
    .ok_or_else(|| CatalogError::BadPin {
        name: "dxvk".to_owned(),
        version: d.version.clone(),
    })?;
    let url = Url::parse(&d.url).map_err(|_| CatalogError::BadUrl {
        name: "dxvk".to_owned(),
        version: d.version.clone(),
    })?;
    let format = parse_format(d.format.as_deref())?;
    // dxvk-nvapi is all-or-nothing: both its URL and its pin, or neither. A lone URL or lone pin is a
    // malformed row (an unpinned download would violate the verify-before-trust rule).
    let nvapi_pin = DigestPin::from_hex(HexPins {
        blake3: d.nvapi_blake3.as_deref(),
        sha256: d.nvapi_sha256.as_deref(),
    });
    let nvapi = match (d.nvapi_url, nvapi_pin) {
        (None, None) => None,
        (Some(nvapi_url), Some(pin)) => {
            let url = Url::parse(&nvapi_url).map_err(|_| CatalogError::BadUrl {
                name: "dxvk-nvapi".to_owned(),
                version: d.version.clone(),
            })?;
            Some(NvapiRef {
                url,
                pin,
                format: parse_format(d.nvapi_format.as_deref())?,
            })
        }
        _ => {
            return Err(CatalogError::BadPin {
                name: "dxvk-nvapi".to_owned(),
                version: d.version.clone(),
            });
        }
    };
    Ok(DxvkEntry {
        version: d.version,
        url,
        pin,
        format,
        nvapi,
    })
}

/// Validate an archive object. Unlike a DXVK row, `format` is required here.
///
/// # Errors
///
/// [`CatalogError::UnknownArchiveFormat`] for a format outside the fixed set.
fn build_archive(a: RawArchive) -> Result<ArchiveLayout, CatalogError> {
    Ok(ArchiveLayout {
        format: parse_format(Some(&a.format))?,
        strip_prefix: a.strip_prefix,
    })
}

/// Map an archive-format string to [`ArchiveFormat`], `None` defaulting to `tar.gz`.
///
/// The default is the DXVK and nvapi convention, so those rows can omit the key.
///
/// # Errors
///
/// [`CatalogError::UnknownArchiveFormat`] carrying the unrecognized value.
fn parse_format(format: Option<&str>) -> Result<ArchiveFormat, CatalogError> {
    match format.unwrap_or("tar.gz") {
        "tar.gz" => Ok(ArchiveFormat::TarGz),
        "tar.xz" => Ok(ArchiveFormat::TarXz),
        "tar.zst" => Ok(ArchiveFormat::TarZst),
        "zip" => Ok(ArchiveFormat::Zip),
        other => Err(CatalogError::UnknownArchiveFormat {
            format: other.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_test_support::catalog_sign::{sign_manifest, test_verifying_key_bytes};

    /// A key nothing here signs with, for the positions in a list that must not be the one that
    /// admits a catalog.
    fn other_key() -> [u8; 32] {
        ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes()
    }

    /// The hosted catalog and its detached signature, embedded at build time.
    const fn hosted() -> (&'static [u8], &'static [u8]) {
        (
            include_bytes!("../../../site/runners/manifest.json"),
            include_bytes!("../../../site/runners/manifest.json.sig"),
        )
    }

    /// A well-formed single-runner manifest with the given hex pin, spelled `sha256`.
    fn manifest(pin: &str) -> String {
        format!(
            r#"{{
              "version": 1,
              "runners": [
                {{ "name": "UMU-Proton", "version": "9-20", "kind": "proton_umu",
                   "url": "https://example.invalid/UMU-Proton-9-20.tar.gz", "sha256": "{pin}",
                   "archive": {{ "format": "tar.gz", "strip_prefix": "UMU-Proton-9-20" }} }}
              ],
              "tools": [
                {{ "name": "umu-launcher", "version": "1.2.5",
                   "url": "https://example.invalid/umu-1.2.5.tar.gz", "sha256": "{pin}",
                   "archive": {{ "format": "tar.gz" }} }}
              ]
            }}"#
        )
    }

    /// A pin of the accepted shape: 32 hex bytes, all zero.
    const GOOD_PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// A manifest signed by a listed key parses, and its rows survive the trip intact.
    #[test]
    fn signature_accepts_a_valid_manifest() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        let (cat, trusted) =
            Catalog::parse_and_verify(json.as_bytes(), &sig, &[test_verifying_key_bytes()])
                .expect("valid signature");
        assert!(trusted.is_current());
        let runner = cat.runner("UMU-Proton", "9-20").expect("runner present");
        assert_eq!(runner.kind, RunnerKind::ProtonUmu);
        assert_eq!(runner.archive.format, ArchiveFormat::TarGz);
        assert_eq!(
            runner.archive.strip_prefix.as_deref(),
            Some("UMU-Proton-9-20")
        );
        assert!(cat.tool("umu-launcher").is_some());
    }

    /// One flipped byte in the body is refused, so the signature covers the manifest and not just
    /// its shape.
    #[test]
    fn signature_rejects_a_tampered_manifest() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        let mut tampered = json.into_bytes();
        // Flip a byte in the body; the detached signature no longer matches.
        tampered[40] ^= 0x01;
        let err = Catalog::parse_and_verify(&tampered, &sig, &[test_verifying_key_bytes()])
            .expect_err("tampered body");
        assert!(matches!(err, CatalogError::BadSignature));
    }

    /// A signer on none of the trusted positions is refused, however many are listed: the list is an
    /// overlap window and never a widening of who may sign.
    #[test]
    fn signature_rejects_a_key_on_no_position() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        // Neither the compiled-in key nor the successor below is the test signer.
        let keys = [CATALOG_PUBLIC_KEYS[0], other_key()];
        let err =
            Catalog::parse_and_verify(json.as_bytes(), &sig, &keys).expect_err("no listed signer");
        assert!(matches!(err, CatalogError::BadSignature));
    }

    /// Anything that is not a 64-byte signature is refused as a bad signature rather than reaching
    /// the verifier.
    #[test]
    fn signature_rejects_absent_or_short() {
        let json = manifest(GOOD_PIN);
        for sig in [b"".as_slice(), b"too-short".as_slice()] {
            let err =
                Catalog::parse_and_verify(json.as_bytes(), sig, &[test_verifying_key_bytes()])
                    .expect_err("non-64-byte signature");
            assert!(matches!(err, CatalogError::BadSignature));
        }
    }

    /// The property the overlap window buys. Without the second half a rotation nobody finished
    /// looks exactly like one that is done, right up until the retiring release.
    #[test]
    fn a_retired_key_still_admits_a_catalog_and_says_it_did() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        let keys = [other_key(), test_verifying_key_bytes()];

        let (_, trusted) = Catalog::parse_and_verify(json.as_bytes(), &sig, &keys)
            .expect("a key inside its overlap window still admits the catalog");
        assert_eq!(trusted, TrustedKey::Retired { position: 1 });
        assert!(!trusted.is_current());
    }

    /// The order is the whole design: position zero is what the publisher signs with today, and a
    /// retired key must never be reported as the current one.
    #[test]
    fn the_first_accepted_key_is_the_current_one() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        let keys = [test_verifying_key_bytes(), other_key()];

        let (_, trusted) =
            Catalog::parse_and_verify(json.as_bytes(), &sig, &keys).expect("valid signature");
        assert!(trusted.is_current());
    }

    /// An empty accepted list admits nothing. It cannot be reached from a shipping build (a const
    /// assertion refuses one), so what this pins is that the loop does not fall through to success.
    #[test]
    fn a_build_that_trusts_no_key_admits_nothing() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        assert!(matches!(
            Catalog::parse_and_verify(json.as_bytes(), &sig, &[]),
            Err(CatalogError::BadSignature)
        ));
    }

    /// Reported as a bad signature it would send whoever hits it to go and check the hosted file,
    /// which is the one thing that cannot be at fault. The position matters too: with a list,
    /// "which entry" is the only part of the message that locates the typo.
    #[test]
    fn a_key_that_is_not_a_key_is_a_build_problem_rather_than_a_bad_signature() {
        // Not a decompressable compressed Edwards point, so it can never verify anything.
        let mut unusable = [0u8; 32];
        unusable[0] = 0x02;

        assert!(matches!(
            trusted_keys(&[test_verifying_key_bytes(), unusable]),
            Err(CatalogError::TrustedKeyUnusable { position: 1 })
        ));
    }

    /// A kind outside the fixed set is a typed refusal, not a runner the launch path cannot drive.
    #[test]
    fn schema_rejects_unknown_runner_kind() {
        let json = manifest(GOOD_PIN).replace("proton_umu", "proton_flatpak");
        let err = Catalog::from_json_bytes(json.as_bytes()).expect_err("unknown kind");
        assert!(matches!(err, CatalogError::UnknownRunnerKind { .. }));
    }

    /// Every kind of row takes either spelling, and one that pins nothing at all is refused rather
    /// than becoming an unverified download. Checked per row kind because each has its own builder,
    /// and the nvapi companion has its own pair of keys besides.
    #[test]
    fn every_row_may_spell_its_pin_either_way_but_must_carry_one() {
        let blake3 = manifest(GOOD_PIN).replace("\"sha256\"", "\"blake3\"");
        let cat = Catalog::from_json_bytes(blake3.as_bytes()).expect("parse");
        assert_eq!(
            cat.runner("UMU-Proton", "9-20").expect("runner").pin,
            DigestPin::Blake3([0u8; 32])
        );
        assert_eq!(
            cat.tool("umu-launcher").expect("tool").pin,
            DigestPin::Blake3([0u8; 32])
        );

        let nvapi = format!(
            r#", "nvapi_url": "https://example.invalid/nvapi.tar.gz", "nvapi_blake3": "{GOOD_PIN}""#
        );
        let dxvk = dxvk_manifest(&nvapi).replace("\"sha256\"", "\"blake3\"");
        let cat = Catalog::from_json_bytes(dxvk.as_bytes()).expect("parse");
        let entry = cat.dxvk.first().expect("dxvk row");
        assert_eq!(entry.pin, DigestPin::Blake3([0u8; 32]));
        assert_eq!(
            entry.nvapi.as_ref().expect("nvapi").pin,
            DigestPin::Blake3([0u8; 32])
        );

        // Neither key present is a row with no pin, not a row to download unverified.
        let unpinned = manifest(GOOD_PIN).replace("\"sha256\"", "\"md5\"");
        assert!(matches!(
            Catalog::from_json_bytes(unpinned.as_bytes()),
            Err(CatalogError::BadPin { .. })
        ));
    }

    /// A pin that is not 32 hex bytes is refused at parse time, not at download time.
    #[test]
    fn schema_rejects_a_bad_pin() {
        let err = Catalog::from_json_bytes(manifest("not-hex").as_bytes()).expect_err("bad pin");
        assert!(matches!(err, CatalogError::BadPin { .. }));
    }

    /// A DXVK row, with `extra` raw JSON fields appended (an nvapi pair, a `format`, and so on).
    fn dxvk_manifest(extra: &str) -> String {
        format!(
            r#"{{ "version": 1, "dxvk": [
                {{ "version": "2.4.1", "url": "https://example.invalid/dxvk-2.4.1.tar.gz",
                   "sha256": "{GOOD_PIN}"{extra} }} ] }}"#
        )
    }

    /// A URL and a pin together are the companion, so it rides the DXVK row rather than needing a
    /// row of its own.
    #[test]
    fn dxvk_parses_a_pinned_nvapi_pair() {
        let nvapi = format!(
            r#", "nvapi_url": "https://example.invalid/nvapi.tar.gz", "nvapi_sha256": "{GOOD_PIN}""#
        );
        let cat = Catalog::from_json_bytes(dxvk_manifest(&nvapi).as_bytes()).expect("parse");
        let entry = cat.dxvk.first().expect("dxvk row");
        assert_eq!(entry.version, "2.4.1");
        assert!(entry.nvapi.is_some(), "nvapi companion parsed");
    }

    /// Omitting the companion is a row with no companion, not a malformed row.
    #[test]
    fn dxvk_without_nvapi_parses_and_has_none() {
        let cat = Catalog::from_json_bytes(dxvk_manifest("").as_bytes()).expect("parse");
        assert!(cat.dxvk.first().expect("dxvk row").nvapi.is_none());
    }

    /// A DXVK row may omit its format and get `tar.gz`, and naming one still moves the container
    /// without a code change.
    #[test]
    fn dxvk_format_defaults_to_tar_gz_and_honors_an_override() {
        let default = Catalog::from_json_bytes(dxvk_manifest("").as_bytes()).expect("parse");
        assert_eq!(default.dxvk[0].format, ArchiveFormat::TarGz);
        let xz = Catalog::from_json_bytes(dxvk_manifest(r#", "format": "tar.xz""#).as_bytes())
            .expect("parse xz");
        assert_eq!(xz.dxvk[0].format, ArchiveFormat::TarXz);
    }

    /// A format nothing can unpack is refused at parse time rather than after the download.
    #[test]
    fn dxvk_rejects_an_unknown_format() {
        let err = Catalog::from_json_bytes(dxvk_manifest(r#", "format": "tar.brotli""#).as_bytes())
            .expect_err("bad format");
        assert!(matches!(err, CatalogError::UnknownArchiveFormat { .. }));
    }

    /// Half a companion is a malformed row: the all-or-nothing rule is what keeps every download
    /// pinned.
    #[test]
    fn dxvk_rejects_an_unpinned_nvapi_url() {
        // An nvapi URL without a pin would be an unauthenticated download.
        let nvapi = r#", "nvapi_url": "https://example.invalid/nvapi.tar.gz""#;
        let err = Catalog::from_json_bytes(dxvk_manifest(nvapi).as_bytes()).expect_err("unpinned");
        assert!(matches!(err, CatalogError::BadPin { .. }));
    }

    /// The version gate is equality, and the error names both numbers so the mismatch is readable
    /// without the file in hand.
    #[test]
    fn schema_rejects_an_unsupported_version() {
        let json = manifest(GOOD_PIN).replace("\"version\": 1", "\"version\": 999");
        let err = Catalog::from_json_bytes(json.as_bytes()).expect_err("bad version");
        assert!(matches!(
            err,
            CatalogError::UnsupportedVersion {
                found: 999,
                expected: 1
            }
        ));
    }

    /// A runner row's archive goes through the same fixed set as a DXVK row's.
    #[test]
    fn schema_rejects_an_unknown_archive_format() {
        let json = manifest(GOOD_PIN).replace("tar.gz", "tar.brotli");
        let err = Catalog::from_json_bytes(json.as_bytes()).expect_err("bad format");
        assert!(matches!(err, CatalogError::UnknownArchiveFormat { .. }));
    }

    /// The parser is total over untrusted bytes, which is what the fuzz target depends on: empty,
    /// non-JSON and truncated input are all typed errors.
    #[test]
    fn malformed_json_is_a_typed_error_not_a_panic() {
        for bytes in [
            b"".as_slice(),
            b"not json".as_slice(),
            b"{\"version\":".as_slice(),
        ] {
            let err = Catalog::from_json_bytes(bytes).expect_err("malformed");
            assert!(matches!(err, CatalogError::Malformed(_)));
        }
    }

    /// Every key this build would accept has to be usable, or it can admit nothing and the build
    /// says so as a signature failure on a user's machine instead.
    #[test]
    fn every_compiled_in_key_parses() {
        trusted_keys(default_keys())
            .expect("every trusted key in this build is a usable ed25519 key");
    }

    /// The rotation failure an accepted-key list otherwise hides.
    ///
    /// A new key added and released while the hosted file was never re-signed works everywhere
    /// until the retired key is dropped, and then works nowhere. Its own test, so a failure names
    /// the unfinished rotation rather than the rows.
    #[test]
    fn the_hosted_manifest_is_signed_by_the_key_in_use_today() {
        let (manifest, signature) = hosted();
        let (_, trusted) = Catalog::verify_trusted(manifest, signature)
            .expect("the hosted manifest verifies and parses against a trusted key");
        assert_eq!(
            trusted,
            TrustedKey::Current,
            "the hosted catalog is still signed by a retired key: finish the rotation by re-signing it"
        );
    }

    /// The hosted manifest and its detached signature, embedded at build time, must verify against
    /// the compiled-in keys and expose the runner and tool the managed launch path resolves. This
    /// catches a mistyped key, a manifest reformatted after signing, or a dropped entry.
    #[test]
    fn the_hosted_manifest_verifies_against_the_compiled_in_key() {
        let (manifest, signature) = hosted();
        let (catalog, _) = Catalog::verify_trusted(manifest, signature)
            .expect("hosted manifest verifies and parses against a compiled-in key");
        let runner = catalog
            .runner("GE-Proton", "11-1")
            .expect("proton runner present");
        assert_eq!(runner.kind, RunnerKind::ProtonUmu);
        // Every hosted row publishes both spellings, so a build that predates BLAKE3 keeps reading
        // this file; what a build that understands both takes is the newer one.
        assert!(
            matches!(runner.pin, DigestPin::Blake3(_)),
            "the hosted rows resolve to the preferred function"
        );
        assert!(runner.uses_ntsync(), "the proton row declares ntsync");
        assert!(catalog.tool("umu-launcher").is_some());

        // The wine build the injection path steers to. It predates ntsync, and saying so in the row
        // is what keeps a launch through it on fsync instead of on nothing.
        let wine = catalog
            .runner("wine-xiv", "10.8.r0.a2ca9e4")
            .expect("wine runner present");
        assert_eq!(wine.kind, RunnerKind::Wine);
        assert_eq!(wine.archive.format, ArchiveFormat::TarXz);
        assert!(!wine.uses_ntsync());
        // The archive's own top directory carries the build flavour but not the distribution the
        // asset was built on, so the strip prefix and the file name legitimately disagree.
        assert_eq!(
            wine.archive.strip_prefix.as_deref(),
            Some("wine-xiv-staging-fsync-git-10.8.r0.a2ca9e4-nolsc")
        );

        // The graphics translation a prepared prefix installs. Its companion is pinned alongside it
        // so turning that on later is a setting rather than another manifest edit.
        let dxvk = catalog.default_dxvk().expect("a dxvk row is published");
        assert_eq!(dxvk.version, "3.0.2");
        assert!(dxvk.nvapi.is_some(), "the companion is pinned too");
    }

    /// Which build a launch installs is the publisher's ordering, so the resolver is that rule and
    /// not a search. A catalog that publishes none is nothing to install rather than an error.
    #[test]
    fn the_first_dxvk_row_is_the_one_a_launch_installs() {
        let empty = Catalog::from_json_bytes(br#"{ "version": 1 }"#).expect("parses");
        assert!(empty.default_dxvk().is_none());

        let two = format!(
            r#"{{ "version": 1, "dxvk": [
                {{ "version": "first", "url": "https://example.invalid/a.tar.gz", "sha256": "{GOOD_PIN}" }},
                {{ "version": "second", "url": "https://example.invalid/b.tar.gz", "sha256": "{GOOD_PIN}" }} ] }}"#
        );
        let cat = Catalog::from_json_bytes(two.as_bytes()).expect("parses");
        assert_eq!(
            cat.default_dxvk().map(|d| d.version.as_str()),
            Some("first")
        );
    }

    /// A row written before the key existed still parses, and reads as no rather than as absent
    /// support the launcher then acts on.
    #[test]
    fn a_runner_row_without_the_sync_key_still_parses() {
        let cat = Catalog::from_json_bytes(manifest(GOOD_PIN).as_bytes()).expect("parses");
        let runner = cat.runner("UMU-Proton", "9-20").expect("runner present");
        assert_eq!(runner.ntsync, None);
        assert!(!runner.uses_ntsync());
    }
}
