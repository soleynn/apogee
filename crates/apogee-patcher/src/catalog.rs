//! The signed index catalog: a JSON manifest of per-repo-and-version `.apzi` block-index pins, whose
//! Ed25519 signature is verified against a compiled-in key *before* any pin inside is trusted.
//!
//! The index is derived (reproducible from the same patch chain), so authenticity rests on the pin;
//! the pin, in turn, is trustworthy only once the manifest carrying it is authenticated. This is the
//! patcher's own signed catalog, separate from the runner and component catalogs (its production
//! signing ceremony is its own), matching the "each domain crate verifies its own manifest" model.
//!
//! [`IndexCatalog::from_json_bytes`] is a pure, total parser over untrusted input (the fuzz entry
//! point); [`IndexCatalog::parse_and_verify`] gates it behind the signature check. A resolved
//! [`IndexEntry`] hands back the [`IndexSource`] a repair fetches under, and the base its source
//! patches are served under ([`IndexEntry::source_base`]) when the row names one.

use apogee_fetch::{DigestPin, HexPins};
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
/// served, the digest pin authenticating the fetched bytes, and where the source patches that index
/// references are served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub repo: Repo,
    pub version: String,
    pub url: Url,
    /// The whole-file digest, carrying which function a row pinned it under.
    pub pin: DigestPin,
    /// The base the repo's source patches are served under, so a repair forms each source's URL as
    /// `{base}/{name}` with no patch cache to draw on. `None` leaves the caller on whatever it knows.
    ///
    /// This is here because the base is not derivable from the repo alone. Square Enix serves each
    /// repo under an opaque path id (`game/ex1/6b936f08/`), and only the boot and base-game ids hold
    /// still enough to compile in; an expansion's is read off that expansion's patchlist URLs, which
    /// a repair never fetches (it registers no session, and needs none). So the id travels with the
    /// row that already has to exist for this repo and version, under the same signature.
    pub source_base: Option<Url>,
}

impl IndexEntry {
    /// The [`IndexSource`] a repair uses to fetch this index under its pin.
    #[must_use]
    pub fn source(&self) -> IndexSource {
        IndexSource::Pinned {
            url: self.url.clone(),
            pin: self.pin,
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
    /// [`IndexCatalogError`] for malformed JSON, an unsupported version, or a bad
    /// repo/pin/url/source base.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, IndexCatalogError> {
        let raw: RawCatalog =
            serde_json::from_slice(bytes).map_err(IndexCatalogError::Malformed)?;
        Self::try_from(raw)
    }

    /// Verify `signature` over the exact `manifest_json` bytes against `key`, then parse. The
    /// signature is checked **first**, so no pin is trusted before authenticity is established. A
    /// signature that is not exactly 64 bytes, or does not verify, is
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

    /// Verify and parse a hosted catalog against the compiled-in [`INDEX_CATALOG_PUBLIC_KEY`]. The
    /// convenience the composition root calls so it never handles the key or the `ed25519` type: it
    /// fetches the manifest and signature bytes (transport is its job) and hands them here for the
    /// crypto (the patcher's job).
    ///
    /// # Errors
    /// [`IndexCatalogError::BadSignature`] if the compiled-in key is unbuildable, or the signature is
    /// absent, malformed, or does not verify; otherwise any parse error from
    /// [`from_json_bytes`](Self::from_json_bytes).
    pub fn verify_default(
        manifest_json: &[u8],
        signature: &[u8],
    ) -> Result<Self, IndexCatalogError> {
        let key = VerifyingKey::from_bytes(&INDEX_CATALOG_PUBLIC_KEY)
            .map_err(|_| IndexCatalogError::BadSignature)?;
        Self::parse_and_verify(manifest_json, signature, &key)
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
    #[error("{repo} {version}: no blake3 or sha256 pin of 32 hex bytes")]
    BadPin { repo: String, version: String },
    #[error("{repo} {version}: not a valid absolute url")]
    BadUrl { repo: String, version: String },
    #[error("{repo} {version}: source base is not an absolute http(s) url ending in `/`")]
    BadSourceBase { repo: String, version: String },
}

// ---- raw deserialization + validation -------------------------------------------------------

#[derive(Deserialize)]
struct RawCatalog {
    version: u32,
    #[serde(default)]
    indexes: Vec<RawIndex>,
}

/// A row's pin is spelled by the function that produced it, and either spelling is accepted so a
/// hosted catalog stays readable while it is re-signed onto the newer one. A row carrying both is
/// read as BLAKE3 (see [`DigestPin::from_hex`]).
#[derive(Deserialize)]
struct RawIndex {
    repo: String,
    version: String,
    url: String,
    #[serde(default)]
    blake3: Option<String>,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    source_base: Option<String>,
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
    let repo = Repo::from_label(&r.repo).ok_or_else(|| IndexCatalogError::UnknownRepo {
        repo: r.repo.clone(),
    })?;
    let pin = DigestPin::from_hex(HexPins {
        blake3: r.blake3.as_deref(),
        sha256: r.sha256.as_deref(),
    })
    .ok_or_else(|| IndexCatalogError::BadPin {
        repo: r.repo.clone(),
        version: r.version.clone(),
    })?;
    let url = Url::parse(&r.url).map_err(|_| IndexCatalogError::BadUrl {
        repo: r.repo.clone(),
        version: r.version.clone(),
    })?;
    let source_base = r
        .source_base
        .as_deref()
        .map(parse_source_base)
        .transpose()
        .map_err(|()| IndexCatalogError::BadSourceBase {
            repo: r.repo.clone(),
            version: r.version.clone(),
        })?;
    Ok(IndexEntry {
        repo,
        version: r.version,
        url,
        pin,
        source_base,
    })
}

/// Parse a row's source base, which must be an absolute `http`/`https` URL whose path ends in `/`.
///
/// The trailing slash is the whole of the check worth having, and it is refused rather than repaired.
/// `Url::join` replaces the last path segment, so a base written without one silently drops the very
/// path id it exists to carry: `.../game/ex1/6b936f08` joined with `D2024.patch` addresses
/// `.../game/ex1/D2024.patch`. That URL is well-formed and 404s, so the repair reads as a repo whose
/// patches are gone rather than as a manifest with a typo in it.
///
/// The scheme is bounded because patch delivery is plain HTTP (see `apogee_core`'s trust module on
/// why there is no handshake there to constrain), so anything else in this field is a mistake in a
/// manifest we signed rather than a deployment anyone runs.
fn parse_source_base(raw: &str) -> Result<Url, ()> {
    let url = Url::parse(raw).map_err(|_| ())?;
    let usable = !url.cannot_be_a_base()
        && matches!(url.scheme(), "http" | "https")
        && url.path().ends_with('/');
    usable.then_some(url).ok_or(())
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

    /// The same manifest with a `source_base` field carrying `base` on its single row.
    fn manifest_based(repo: &str, base: &str) -> String {
        manifest(repo, GOOD_PIN).replace(
            &format!("\"sha256\": \"{GOOD_PIN}\""),
            &format!("\"sha256\": \"{GOOD_PIN}\", \"source_base\": \"{base}\""),
        )
    }

    const GOOD_PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// An expansion's live base, in the shape the patchlist gives it: the opaque path id is the part
    /// that cannot be compiled in, and is the whole reason the row carries this.
    const EX1_BASE: &str = "http://patch-dl.ffxiv.com/game/ex1/6b936f08/";

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
            assert_eq!(entry.pin, DigestPin::Sha256([0u8; 32]));
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

    /// The schema takes either spelling and a row that pins nothing is refused, so a catalog can be
    /// re-signed onto the newer function one row at a time and a row that forgot its pin cannot pass
    /// as an unpinned download.
    #[test]
    fn a_row_may_spell_its_pin_either_way_but_must_carry_one() {
        let blake3 = manifest("game", GOOD_PIN).replace("\"sha256\"", "\"blake3\"");
        let cat = IndexCatalog::from_json_bytes(blake3.as_bytes()).expect("parse");
        let entry = cat
            .resolve(Repo::Game, "2024.03.28.0000.0000")
            .expect("resolve");
        assert_eq!(entry.pin, DigestPin::Blake3([0u8; 32]));

        let unpinned = manifest("game", GOOD_PIN).replace("\"sha256\"", "\"md5\"");
        assert!(matches!(
            IndexCatalog::from_json_bytes(unpinned.as_bytes()),
            Err(IndexCatalogError::BadPin { .. })
        ));
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

    /// A row names where its source patches are served, and a row that does not says so as `None`
    /// rather than as some invented default. The join is asserted rather than the field alone,
    /// because forming `{base}/{name}` is the only thing a repair does with it.
    #[test]
    fn a_row_carries_the_base_its_source_patches_are_served_under() {
        let cat = IndexCatalog::from_json_bytes(manifest_based("ex1", EX1_BASE).as_bytes())
            .expect("parse");
        let entry = cat
            .resolve(Repo::Expansion(1), "2024.03.28.0000.0000")
            .expect("resolve");
        let base = entry.source_base.as_ref().expect("the row named a base");
        assert_eq!(
            base.join("D2024.03.28.0000.0000.patch")
                .expect("the base forms a source url")
                .as_str(),
            "http://patch-dl.ffxiv.com/game/ex1/6b936f08/D2024.03.28.0000.0000.patch",
        );

        let bare =
            IndexCatalog::from_json_bytes(manifest("ex1", GOOD_PIN).as_bytes()).expect("parse");
        assert_eq!(
            bare.resolve(Repo::Expansion(1), "2024.03.28.0000.0000")
                .expect("resolve")
                .source_base,
            None,
            "a row that names no base must not be read as naming one",
        );
    }

    /// A base written without its trailing slash is refused, and this is the case the check exists
    /// for: `Url::join` replaces the last segment, so such a base drops the path id it is here to
    /// carry and addresses a well-formed URL that 404s. The control is the join itself, computed
    /// here, so the test states what the accepted form would have done rather than asserting a rule
    /// whose consequence is left off-screen.
    #[test]
    fn a_source_base_that_would_drop_its_path_id_is_refused() {
        let no_slash = EX1_BASE.trim_end_matches('/');
        assert_eq!(
            Url::parse(no_slash)
                .expect("it parses; being well-formed is the problem")
                .join("D2024.03.28.0000.0000.patch")
                .expect("and it joins")
                .as_str(),
            "http://patch-dl.ffxiv.com/game/ex1/D2024.03.28.0000.0000.patch",
            "the id-dropping join this refusal exists to prevent no longer happens",
        );
        assert!(matches!(
            IndexCatalog::from_json_bytes(manifest_based("ex1", no_slash).as_bytes()),
            Err(IndexCatalogError::BadSourceBase { .. })
        ));
    }

    /// The field takes an absolute http(s) base and nothing else: a relative path has no host to
    /// resolve against, and another scheme is a manifest we signed with a mistake in it rather than
    /// anything patch delivery serves.
    #[test]
    fn a_source_base_must_be_an_absolute_http_base() {
        for base in [
            "/game/ex1/6b936f08/",
            "patch-dl.ffxiv.com/game/ex1/6b936f08/",
            "file:///srv/patches/",
            "mailto:patches@example.invalid",
            "",
        ] {
            assert!(
                matches!(
                    IndexCatalog::from_json_bytes(manifest_based("ex1", base).as_bytes()),
                    Err(IndexCatalogError::BadSourceBase { .. })
                ),
                "{base:?} was accepted as a source base",
            );
        }
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

    #[test]
    fn verify_default_uses_the_compiled_in_key() {
        let manifest = include_bytes!("../../../site/indexes/manifest.json");
        let signature = include_bytes!("../../../site/indexes/manifest.json.sig");
        let catalog = IndexCatalog::verify_default(manifest, signature)
            .expect("hosted manifest verifies against the compiled-in key");
        assert!(
            catalog
                .resolve(Repo::Game, "2026.08.05.0000.0000")
                .is_some()
        );
        // A one-byte flip breaks the signature under the same key.
        let mut tampered = manifest.to_vec();
        tampered[40] ^= 0x01;
        assert!(matches!(
            IndexCatalog::verify_default(&tampered, signature),
            Err(IndexCatalogError::BadSignature)
        ));
    }

    /// The hosted staging manifest and its detached signature, embedded at build time, must verify
    /// against the compiled-in key and carry a row for every repo a repair plans; the resolved pin
    /// must match the committed `.apzi` byte-for-byte. This catches a mistyped key, a manifest
    /// reformatted after signing, an artifact regenerated without re-signing, and a patch-day
    /// re-author that moved some repos to the new version and left others behind.
    #[test]
    fn the_hosted_manifest_verifies_against_the_compiled_in_key() {
        let manifest = include_bytes!("../../../site/indexes/manifest.json");
        let signature = include_bytes!("../../../site/indexes/manifest.json.sig");
        let key = VerifyingKey::from_bytes(&INDEX_CATALOG_PUBLIC_KEY).expect("compiled-in parses");
        let catalog = IndexCatalog::parse_and_verify(manifest, signature, &key)
            .expect("hosted manifest verifies and parses against the compiled-in key");

        // A repair plans every installed repo at once and refuses on the first it cannot resolve, so
        // a row missing here is a repair that cannot run at all rather than one that runs narrower.
        for (repo, version) in [
            (Repo::Boot, "2026.07.13.0000.0001"),
            (Repo::Game, "2026.08.05.0000.0000"),
            (Repo::Expansion(1), "2026.07.03.0000.0000"),
            (Repo::Expansion(2), "2026.07.06.0000.0000"),
            (Repo::Expansion(3), "2026.08.05.0000.0000"),
            (Repo::Expansion(4), "2026.08.05.0000.0000"),
            (Repo::Expansion(5), "2026.08.05.0000.0000"),
        ] {
            assert!(
                catalog.resolve(repo, version).is_some(),
                "the hosted catalog must carry {repo:?} {version}",
            );
        }

        // Pinned against boot's artifact rather than a larger repo's: the property is that a row's
        // digest describes the bytes it was taken over, and the smallest artifact proves it without
        // embedding tens of megabytes in the test binary. The artifacts are published as release
        // assets rather than committed, so this one is kept as a fixture beside the test; a row
        // regenerated without re-signing fails here, and a release asset that does not match the row
        // describing it fails against the pin at download time.
        let entry = catalog
            .resolve(Repo::Boot, "2026.07.13.0000.0001")
            .expect("the boot index entry resolves");
        let artifact = include_bytes!("../tests/fixtures/boot-2026.07.13.0000.0001.apzi");
        // The row publishes both spellings so a build that predates BLAKE3 can still read it, and
        // the pin taken here is the preferred one, checked against the artifact it describes.
        assert_eq!(
            entry.pin,
            DigestPin::Blake3(apogee_test_support::chaos::blake3_of(artifact)),
            "the manifest pin must match the artifact it was taken over",
        );

        // The base survived the signing ceremony in a form that forms source URLs. A row reformatted
        // by hand is the way this comes back wrong, and the trailing slash is what it loses. Checked
        // on an expansion, the only repo whose base nothing else can supply.
        assert_eq!(
            catalog
                .resolve(Repo::Expansion(1), "2026.07.03.0000.0000")
                .expect("the ex1 index entry resolves")
                .source_base
                .as_ref()
                .expect("the hosted row names where its source patches are served")
                .join("D2026.07.03.0000.0000.patch")
                .expect("the hosted base forms a source url")
                .as_str(),
            "http://patch-dl.ffxiv.com/game/ex1/6b936f08/D2026.07.03.0000.0000.patch",
        );
    }
}
