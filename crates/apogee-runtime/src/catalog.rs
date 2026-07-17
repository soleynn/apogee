//! The signed runner catalog: a JSON manifest whose Ed25519 signature is verified against a
//! compiled-in key *before* any `sha256` pin inside is trusted.
//!
//! [`Catalog::from_json_bytes`] is a pure, total parser over untrusted input (the fuzz entry point);
//! [`Catalog::parse_and_verify`] gates it behind the signature check.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use url::Url;

use crate::error::CatalogError;

/// The manifest schema version this build understands.
pub const CATALOG_MANIFEST_VERSION: u32 = 1;

/// The compiled-in public key runner catalogs are authenticated against.
///
/// PLACEHOLDER — a throwaway key whose private half was generated and discarded. The real key and
/// where the catalog is hosted are settled before the first real-catalog download; replacing this
/// constant is the only change that takes.
pub const CATALOG_PUBLIC_KEY: [u8; 32] = [
    0x02, 0x12, 0x6d, 0xf0, 0xd3, 0xed, 0x62, 0xc6, 0x71, 0xdc, 0x1f, 0x34, 0x12, 0x9f, 0x62, 0x20,
    0x06, 0x36, 0x52, 0x97, 0x8c, 0x38, 0x7c, 0x0d, 0xcd, 0x3f, 0x81, 0xa6, 0xab, 0xca, 0x2a, 0xd1,
];

/// The three runner kinds the launch path understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RunnerKind {
    ProtonUmu,
    Wine,
    Custom,
}

/// The archive container a runner/tool ships in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ArchiveFormat {
    TarGz,
    TarXz,
    TarZst,
}

/// How to lay a downloaded archive onto disk.
#[derive(Debug, Clone)]
pub struct ArchiveLayout {
    pub format: ArchiveFormat,
    /// A leading path component stripped from every entry (upstream tarballs wrap their content in a
    /// versioned top directory).
    pub strip_prefix: Option<String>,
}

/// A Wine/Proton runner: an installable, pinned artifact.
#[derive(Debug, Clone)]
pub struct Runner {
    pub name: String,
    pub version: String,
    pub kind: RunnerKind,
    pub url: Url,
    pub sha256: [u8; 32],
    pub archive: ArchiveLayout,
}

/// A supporting tool managed as data (currently `umu-launcher`), installed like a runner.
#[derive(Debug, Clone)]
pub struct ToolEntry {
    pub name: String,
    pub version: String,
    pub url: Url,
    pub sha256: [u8; 32],
    pub archive: ArchiveLayout,
}

/// A DXVK build. Parsed at 0.1 but not installed until the environment matrix lands.
#[derive(Debug, Clone)]
pub struct DxvkEntry {
    pub version: String,
    pub url: Url,
    pub sha256: [u8; 32],
    pub nvapi_url: Option<Url>,
}

/// A verified runner catalog.
#[derive(Debug, Clone)]
pub struct Catalog {
    pub version: u32,
    pub runners: Vec<Runner>,
    pub dxvk: Vec<DxvkEntry>,
    pub tools: Vec<ToolEntry>,
}

impl Catalog {
    /// Parse a catalog from untrusted JSON. Pure and total: any byte sequence yields a `Catalog` or a
    /// typed [`CatalogError`], never a panic or an unbounded allocation. This is the fuzz target and
    /// carries **no** authenticity guarantee on its own — callers must have verified the signature
    /// (see [`parse_and_verify`](Self::parse_and_verify)).
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, CatalogError> {
        let raw: RawCatalog = serde_json::from_slice(bytes).map_err(CatalogError::Malformed)?;
        Self::try_from(raw)
    }

    /// Verify `signature` over the exact `manifest_json` bytes against `key`, then parse. The
    /// signature is checked **first**, so no `sha256` pin is trusted before authenticity is
    /// established. A signature that is not exactly 64 bytes, or does not verify, is
    /// [`CatalogError::BadSignature`].
    pub fn parse_and_verify(
        manifest_json: &[u8],
        signature: &[u8],
        key: &VerifyingKey,
    ) -> Result<Self, CatalogError> {
        let sig = Signature::from_slice(signature).map_err(|_| CatalogError::BadSignature)?;
        key.verify_strict(manifest_json, &sig)
            .map_err(|_| CatalogError::BadSignature)?;
        Self::from_json_bytes(manifest_json)
    }

    /// Resolve a runner by identity. `None` → the caller maps to
    /// [`RuntimeError::RunnerUnavailable`](crate::RuntimeError::RunnerUnavailable).
    #[must_use]
    pub fn runner(&self, name: &str, version: &str) -> Option<&Runner> {
        self.runners
            .iter()
            .find(|r| r.name == name && r.version == version)
    }

    /// Resolve a supporting tool by name (e.g. `umu-launcher`).
    #[must_use]
    pub fn tool(&self, name: &str) -> Option<&ToolEntry> {
        self.tools.iter().find(|t| t.name == name)
    }
}

// ---- raw deserialization + validation -------------------------------------------------------

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

#[derive(Deserialize)]
struct RawRunner {
    name: String,
    version: String,
    kind: String,
    url: String,
    sha256: String,
    archive: RawArchive,
}

#[derive(Deserialize)]
struct RawTool {
    name: String,
    version: String,
    url: String,
    sha256: String,
    archive: RawArchive,
}

#[derive(Deserialize)]
struct RawDxvk {
    version: String,
    url: String,
    sha256: String,
    #[serde(default)]
    nvapi_url: Option<String>,
}

#[derive(Deserialize)]
struct RawArchive {
    format: String,
    #[serde(default)]
    strip_prefix: Option<String>,
}

impl TryFrom<RawCatalog> for Catalog {
    type Error = CatalogError;

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

fn build_runner(r: RawRunner) -> Result<Runner, CatalogError> {
    let kind = match r.kind.as_str() {
        "proton_umu" => RunnerKind::ProtonUmu,
        "wine" => RunnerKind::Wine,
        "custom" => RunnerKind::Custom,
        _ => return Err(CatalogError::UnknownRunnerKind { kind: r.kind }),
    };
    let archive = build_archive(r.archive)?;
    let sha256 = decode_sha256_hex(&r.sha256).ok_or_else(|| CatalogError::BadPin {
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
        sha256,
        archive,
    })
}

fn build_tool(t: RawTool) -> Result<ToolEntry, CatalogError> {
    let archive = build_archive(t.archive)?;
    let sha256 = decode_sha256_hex(&t.sha256).ok_or_else(|| CatalogError::BadPin {
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
        sha256,
        archive,
    })
}

fn build_dxvk(d: RawDxvk) -> Result<DxvkEntry, CatalogError> {
    let sha256 = decode_sha256_hex(&d.sha256).ok_or_else(|| CatalogError::BadPin {
        name: "dxvk".to_owned(),
        version: d.version.clone(),
    })?;
    let url = Url::parse(&d.url).map_err(|_| CatalogError::BadUrl {
        name: "dxvk".to_owned(),
        version: d.version.clone(),
    })?;
    let nvapi_url = match d.nvapi_url {
        Some(u) => Some(Url::parse(&u).map_err(|_| CatalogError::BadUrl {
            name: "dxvk-nvapi".to_owned(),
            version: d.version.clone(),
        })?),
        None => None,
    };
    Ok(DxvkEntry {
        version: d.version,
        url,
        sha256,
        nvapi_url,
    })
}

fn build_archive(a: RawArchive) -> Result<ArchiveLayout, CatalogError> {
    let format = match a.format.as_str() {
        "tar.gz" => ArchiveFormat::TarGz,
        "tar.xz" => ArchiveFormat::TarXz,
        "tar.zst" => ArchiveFormat::TarZst,
        _ => return Err(CatalogError::UnknownArchiveFormat { format: a.format }),
    };
    Ok(ArchiveLayout {
        format,
        strip_prefix: a.strip_prefix,
    })
}

/// Decode exactly 64 lowercase/uppercase hex digits into 32 bytes; any other length or a non-hex
/// digit is `None`.
fn decode_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_test_support::catalog_sign::{sign_manifest, test_verifying_key};

    /// A well-formed single-runner manifest with the given sha256 hex pin.
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

    const GOOD_PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn signature_accepts_a_valid_manifest() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        let cat = Catalog::parse_and_verify(json.as_bytes(), &sig, &test_verifying_key())
            .expect("valid signature");
        let runner = cat.runner("UMU-Proton", "9-20").expect("runner present");
        assert_eq!(runner.kind, RunnerKind::ProtonUmu);
        assert_eq!(runner.archive.format, ArchiveFormat::TarGz);
        assert_eq!(
            runner.archive.strip_prefix.as_deref(),
            Some("UMU-Proton-9-20")
        );
        assert!(cat.tool("umu-launcher").is_some());
    }

    #[test]
    fn signature_rejects_a_tampered_manifest() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        let mut tampered = json.into_bytes();
        // Flip a byte in the body; the detached signature no longer matches.
        tampered[40] ^= 0x01;
        let err = Catalog::parse_and_verify(&tampered, &sig, &test_verifying_key())
            .expect_err("tampered body");
        assert!(matches!(err, CatalogError::BadSignature));
    }

    #[test]
    fn signature_rejects_the_wrong_key() {
        let json = manifest(GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());
        // The compiled-in placeholder key is a different key than the test signer.
        let other = VerifyingKey::from_bytes(&CATALOG_PUBLIC_KEY).expect("placeholder key parses");
        let err = Catalog::parse_and_verify(json.as_bytes(), &sig, &other).expect_err("wrong key");
        assert!(matches!(err, CatalogError::BadSignature));
    }

    #[test]
    fn signature_rejects_absent_or_short() {
        let json = manifest(GOOD_PIN);
        for sig in [b"".as_slice(), b"too-short".as_slice()] {
            let err = Catalog::parse_and_verify(json.as_bytes(), sig, &test_verifying_key())
                .expect_err("non-64-byte signature");
            assert!(matches!(err, CatalogError::BadSignature));
        }
    }

    #[test]
    fn schema_rejects_unknown_runner_kind() {
        let json = manifest(GOOD_PIN).replace("proton_umu", "proton_flatpak");
        let err = Catalog::from_json_bytes(json.as_bytes()).expect_err("unknown kind");
        assert!(matches!(err, CatalogError::UnknownRunnerKind { .. }));
    }

    #[test]
    fn schema_rejects_a_bad_pin() {
        let err = Catalog::from_json_bytes(manifest("not-hex").as_bytes()).expect_err("bad pin");
        assert!(matches!(err, CatalogError::BadPin { .. }));
    }

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

    #[test]
    fn schema_rejects_an_unknown_archive_format() {
        let json = manifest(GOOD_PIN).replace("tar.gz", "tar.brotli");
        let err = Catalog::from_json_bytes(json.as_bytes()).expect_err("bad format");
        assert!(matches!(err, CatalogError::UnknownArchiveFormat { .. }));
    }

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

    #[test]
    fn the_compiled_in_key_parses() {
        assert!(VerifyingKey::from_bytes(&CATALOG_PUBLIC_KEY).is_ok());
    }
}
