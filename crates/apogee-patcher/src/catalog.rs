//! The signed index catalog: a JSON manifest of per-repo-and-version `.apzi` block-index pins, whose
//! Ed25519 signature is verified against a compiled-in key *before* any `sha256` pin inside is
//! trusted.
//!
//! The index is derived (reproducible from the same patch chain), so authenticity rests on the pin;
//! the pin, in turn, is trustworthy only once the manifest carrying it is authenticated. This is the
//! patcher's own signed catalog, separate from the runner and component catalogs (its production
//! signing ceremony is its own), matching the "each domain crate verifies its own manifest" model.
//!
//! [`IndexCatalog::from_json_bytes`] is a pure, total parser over untrusted input (the fuzz entry
//! point); [`IndexCatalog::parse_and_verify`] gates it behind the signature check. A resolved
//! [`IndexEntry`] hands back the [`IndexSource`] a repair fetches under.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use crate::Repo;
use crate::request::IndexSource;

/// The manifest schema version this build understands.
pub const INDEX_CATALOG_MANIFEST_VERSION: u32 = 1;

/// The compiled-in public key index catalogs are authenticated against.
///
/// Separate from the runner catalog's key: this is the patcher's own signed manifest. The matching
/// private seed is held offline by the maintainer; it signs the hosted `manifest.json` and only these
/// public bytes are committed. Rotating the key is a change to this constant plus a re-sign.
pub const INDEX_CATALOG_PUBLIC_KEY: [u8; 32] = [
    0xb0, 0x60, 0x39, 0xaa, 0x1a, 0x8b, 0x96, 0x54, 0x1d, 0x8c, 0xd7, 0x5a, 0x23, 0x68, 0xec, 0x94,
    0x38, 0x2c, 0x1e, 0x97, 0xfd, 0x32, 0xed, 0x43, 0xd4, 0x33, 0x11, 0x25, 0x88, 0xb5, 0xe1, 0x37,
];

/// One repo-and-version block index: which repo and version it describes, where its `.apzi` is
/// served, and the `sha256` pin authenticating the fetched bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub repo: Repo,
    pub version: String,
    pub url: Url,
    pub sha256: [u8; 32],
}

impl IndexEntry {
    /// The [`IndexSource`] a repair uses to fetch this index under its pin.
    #[must_use]
    pub fn source(&self) -> IndexSource {
        IndexSource::Pinned {
            url: self.url.clone(),
            sha256: self.sha256,
        }
    }
}

/// A verified index catalog.
#[derive(Debug, Clone)]
pub struct IndexCatalog {
    pub version: u32,
    pub indexes: Vec<IndexEntry>,
}

impl IndexCatalog {
    /// Parse a catalog from untrusted JSON. Pure and total: any byte sequence yields an
    /// [`IndexCatalog`] or a typed [`IndexCatalogError`], never a panic or an unbounded allocation.
    /// This is the fuzz target and carries **no** authenticity guarantee on its own; callers must have
    /// verified the signature (see [`parse_and_verify`](Self::parse_and_verify)).
    ///
    /// # Errors
    /// [`IndexCatalogError`] for malformed JSON, an unsupported version, or a bad repo/pin/url.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, IndexCatalogError> {
        let raw: RawCatalog =
            serde_json::from_slice(bytes).map_err(IndexCatalogError::Malformed)?;
        Self::try_from(raw)
    }

    /// Verify `signature` over the exact `manifest_json` bytes against `key`, then parse. The
    /// signature is checked **first**, so no `sha256` pin is trusted before authenticity is
    /// established. A signature that is not exactly 64 bytes, or does not verify, is
    /// [`IndexCatalogError::BadSignature`].
    ///
    /// # Errors
    /// [`IndexCatalogError::BadSignature`] if the signature is absent, malformed, or does not verify;
    /// otherwise any parse error from [`from_json_bytes`](Self::from_json_bytes).
    pub fn parse_and_verify(
        manifest_json: &[u8],
        signature: &[u8],
        key: &VerifyingKey,
    ) -> Result<Self, IndexCatalogError> {
        let sig = Signature::from_slice(signature).map_err(|_| IndexCatalogError::BadSignature)?;
        key.verify_strict(manifest_json, &sig)
            .map_err(|_| IndexCatalogError::BadSignature)?;
        Self::from_json_bytes(manifest_json)
    }

    /// Resolve the index entry for `repo` at `version`, or `None` when the catalog has no such row.
    #[must_use]
    pub fn resolve(&self, repo: Repo, version: &str) -> Option<&IndexEntry> {
        self.indexes
            .iter()
            .find(|e| e.repo == repo && e.version == version)
    }
}

/// Index-catalog parse/verification failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum IndexCatalogError {
    #[error("manifest is not valid JSON or violates the schema")]
    Malformed(#[source] serde_json::Error),
    #[error("manifest signature did not verify against the trusted key")]
    BadSignature,
    #[error("unsupported manifest version {found} (expected {expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("unknown repo {repo:?}")]
    UnknownRepo { repo: String },
    #[error("{repo} {version}: sha256 pin is not 32 hex bytes")]
    BadPin { repo: String, version: String },
    #[error("{repo} {version}: not a valid absolute url")]
    BadUrl { repo: String, version: String },
}

// ---- raw deserialization + validation -------------------------------------------------------

#[derive(Deserialize)]
struct RawCatalog {
    version: u32,
    #[serde(default)]
    indexes: Vec<RawIndex>,
}

#[derive(Deserialize)]
struct RawIndex {
    repo: String,
    version: String,
    url: String,
    sha256: String,
}

impl TryFrom<RawCatalog> for IndexCatalog {
    type Error = IndexCatalogError;

    fn try_from(raw: RawCatalog) -> Result<Self, IndexCatalogError> {
        if raw.version != INDEX_CATALOG_MANIFEST_VERSION {
            return Err(IndexCatalogError::UnsupportedVersion {
                found: raw.version,
                expected: INDEX_CATALOG_MANIFEST_VERSION,
            });
        }
        let indexes = raw
            .indexes
            .into_iter()
            .map(build_entry)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            version: raw.version,
            indexes,
        })
    }
}

fn build_entry(r: RawIndex) -> Result<IndexEntry, IndexCatalogError> {
    let repo = parse_repo(&r.repo).ok_or_else(|| IndexCatalogError::UnknownRepo {
        repo: r.repo.clone(),
    })?;
    let sha256 = decode_sha256_hex(&r.sha256).ok_or_else(|| IndexCatalogError::BadPin {
        repo: r.repo.clone(),
        version: r.version.clone(),
    })?;
    let url = Url::parse(&r.url).map_err(|_| IndexCatalogError::BadUrl {
        repo: r.repo.clone(),
        version: r.version.clone(),
    })?;
    Ok(IndexEntry {
        repo,
        version: r.version,
        url,
        sha256,
    })
}

/// Map a manifest repo label to a [`Repo`]: `boot`, `game`, or `ex{n}` (an expansion, `n` a `u8`).
fn parse_repo(label: &str) -> Option<Repo> {
    match label {
        "boot" => Some(Repo::Boot),
        "game" => Some(Repo::Game),
        other => other
            .strip_prefix("ex")
            .and_then(|n| n.parse::<u8>().ok())
            .map(Repo::Expansion),
    }
}

/// Decode exactly 64 hex digits into 32 bytes; any other length or a non-hex digit is `None`.
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

    /// A well-formed single-index manifest with the given repo label and sha256 hex pin.
    fn manifest(repo: &str, pin: &str) -> String {
        format!(
            r#"{{
              "version": 1,
              "indexes": [
                {{ "repo": "{repo}", "version": "2024.03.28.0000.0000",
                   "url": "https://example.invalid/indexes/{repo}-2024.03.28.0000.0000.apzi",
                   "sha256": "{pin}" }}
              ]
            }}"#
        )
    }

    const GOOD_PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn parses_and_resolves_each_repo_label() {
        for (label, repo) in [
            ("boot", Repo::Boot),
            ("game", Repo::Game),
            ("ex1", Repo::Expansion(1)),
            ("ex4", Repo::Expansion(4)),
        ] {
            let cat =
                IndexCatalog::from_json_bytes(manifest(label, GOOD_PIN).as_bytes()).expect("parse");
            let entry = cat
                .resolve(repo, "2024.03.28.0000.0000")
                .expect("resolve the entry");
            assert_eq!(entry.repo, repo);
            assert_eq!(entry.sha256, [0u8; 32]);
            // The resolved entry hands back a pinned source ready for repair.
            assert!(matches!(entry.source(), IndexSource::Pinned { .. }));
        }
    }

    #[test]
    fn resolve_misses_an_absent_repo_or_version() {
        let cat = IndexCatalog::from_json_bytes(manifest("game", GOOD_PIN).as_bytes()).unwrap();
        assert!(cat.resolve(Repo::Boot, "2024.03.28.0000.0000").is_none());
        assert!(cat.resolve(Repo::Game, "1999.01.01.0000.0000").is_none());
    }

    #[test]
    fn signature_accepts_a_valid_manifest_and_rejects_tampering() {
        use apogee_test_support::catalog_sign::{sign_manifest, test_verifying_key};
        let json = manifest("game", GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());

        let cat =
            IndexCatalog::parse_and_verify(json.as_bytes(), &sig, &test_verifying_key()).unwrap();
        assert_eq!(cat.indexes.len(), 1);

        // A flipped body byte no longer matches the detached signature.
        let mut tampered = json.into_bytes();
        tampered[40] ^= 0x01;
        assert!(matches!(
            IndexCatalog::parse_and_verify(&tampered, &sig, &test_verifying_key()),
            Err(IndexCatalogError::BadSignature)
        ));
    }

    #[test]
    fn signature_rejects_the_wrong_key_and_a_short_signature() {
        use apogee_test_support::catalog_sign::{sign_manifest, test_verifying_key};
        let json = manifest("game", GOOD_PIN);
        let sig = sign_manifest(json.as_bytes());

        // The compiled-in key is a different key than the test signer.
        let other =
            VerifyingKey::from_bytes(&INDEX_CATALOG_PUBLIC_KEY).expect("compiled-in parses");
        assert!(matches!(
            IndexCatalog::parse_and_verify(json.as_bytes(), &sig, &other),
            Err(IndexCatalogError::BadSignature)
        ));
        for bad in [b"".as_slice(), b"too-short".as_slice()] {
            assert!(matches!(
                IndexCatalog::parse_and_verify(json.as_bytes(), bad, &test_verifying_key()),
                Err(IndexCatalogError::BadSignature)
            ));
        }
    }

    #[test]
    fn schema_rejects_bad_repo_pin_version_and_url() {
        assert!(matches!(
            IndexCatalog::from_json_bytes(manifest("ex999", GOOD_PIN).as_bytes()),
            Err(IndexCatalogError::UnknownRepo { .. })
        ));
        assert!(matches!(
            IndexCatalog::from_json_bytes(manifest("game", "not-hex").as_bytes()),
            Err(IndexCatalogError::BadPin { .. })
        ));
        let bad_ver = manifest("game", GOOD_PIN).replace("\"version\": 1", "\"version\": 999");
        assert!(matches!(
            IndexCatalog::from_json_bytes(bad_ver.as_bytes()),
            Err(IndexCatalogError::UnsupportedVersion {
                found: 999,
                expected: 1
            })
        ));
        let bad_url = manifest("game", GOOD_PIN).replace("https://example.invalid", "not a url");
        assert!(matches!(
            IndexCatalog::from_json_bytes(bad_url.as_bytes()),
            Err(IndexCatalogError::BadUrl { .. })
        ));
    }

    #[test]
    fn malformed_json_is_a_typed_error_not_a_panic() {
        for bytes in [
            b"".as_slice(),
            b"not json".as_slice(),
            b"{\"version\":".as_slice(),
        ] {
            assert!(matches!(
                IndexCatalog::from_json_bytes(bytes),
                Err(IndexCatalogError::Malformed(_))
            ));
        }
    }

    #[test]
    fn the_compiled_in_key_parses() {
        assert!(VerifyingKey::from_bytes(&INDEX_CATALOG_PUBLIC_KEY).is_ok());
    }

    /// The hosted staging manifest and its detached signature, embedded at build time, must verify
    /// against the compiled-in key and resolve the sample index; the resolved pin must match the
    /// committed `.apzi` byte-for-byte. This catches a mistyped key, a manifest reformatted after
    /// signing, or an artifact regenerated without re-signing.
    #[test]
    fn the_hosted_manifest_verifies_against_the_compiled_in_key() {
        let manifest = include_bytes!("../../../site/indexes/manifest.json");
        let signature = include_bytes!("../../../site/indexes/manifest.json.sig");
        let key = VerifyingKey::from_bytes(&INDEX_CATALOG_PUBLIC_KEY).expect("compiled-in parses");
        let catalog = IndexCatalog::parse_and_verify(manifest, signature, &key)
            .expect("hosted manifest verifies and parses against the compiled-in key");

        let entry = catalog
            .resolve(Repo::Game, "2024.03.28.0000.0000")
            .expect("the sample game index entry resolves");
        let artifact =
            include_bytes!("../../../site/indexes/artifacts/game-2024.03.28.0000.0000.apzi");
        assert_eq!(
            entry.sha256,
            apogee_test_support::chaos::sha256_of(artifact),
            "the manifest pin must match the committed artifact",
        );
    }
}
