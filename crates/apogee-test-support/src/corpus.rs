//! Download-by-URL + SHA256 corpus fetch into a content-addressed cache.
//!
//! Large reference inputs (the boot patch corpus) are never checked in; they are fetched once into a
//! cache directory, keyed by digest, and verified against a pinned SHA256 before any test reads them.
//! Boot patches are served over plain HTTP and carry no upstream per-file hash, so the pin is a
//! trust-on-first-download digest the maintainer records once (§the milestone runbook).
//!
//! The fetch reuses [`apogee_fetch`]'s verified downloader rather than a second HTTP client: the pin
//! then covers the on-wire bytes (that client disables transparent gzip/deflate), and resume, retry,
//! atomic publish, and cache-hit-skips-the-network all come for free. A cache hit re-hashes the
//! digest-named file already on disk and makes no request.

use std::path::{Path, PathBuf};

use apogee_fetch::{DownloadSpec, FetchError, Fetcher, SpecError, Validator};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::golden::from_hex;

/// One corpus input: a source URL, its expected lowercase-hex SHA256, and a human-readable name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusEntry {
    pub url: String,
    pub sha256: String,
    pub name: String,
}

/// A set of corpus inputs, committed as `corpus/manifest.json` (URLs + pins, never the bytes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub entries: Vec<CorpusEntry>,
}

impl CorpusManifest {
    /// Parse a manifest from JSON.
    ///
    /// # Errors
    /// The `serde_json` error when the input is not a valid manifest.
    pub fn from_json(json: &str) -> serde_json::Result<Self> {
        serde_json::from_str(json)
    }
}

/// A corpus fetch failure, always naming the offending entry.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CorpusError {
    #[error("invalid sha256 pin for {name}: {sha256}")]
    BadPin { name: String, sha256: String },
    #[error("invalid url for {name}: {url}")]
    BadUrl { name: String, url: String },
    #[error("preparing the cache dir {path} failed")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("building the download for {name} failed")]
    Spec {
        name: String,
        #[source]
        source: SpecError,
    },
    #[error("fetching {name} failed")]
    Fetch {
        name: String,
        // Boxed: `FetchError` is large, and this keeps `CorpusError` small enough for a `Result`.
        #[source]
        source: Box<FetchError>,
    },
}

/// The default cache directory: `$APOGEE_CORPUS_CACHE` if set, else `./.corpus-cache` (gitignored).
#[must_use]
pub fn default_cache_dir() -> PathBuf {
    std::env::var_os("APOGEE_CORPUS_CACHE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".corpus-cache"))
}

/// Fetch `entry` into `cache_dir`, keyed by its digest and verified against the pin, returning the
/// cached path. A cache hit (the digest-named file already present and matching) makes no request.
///
/// # Errors
/// A [`CorpusError`] for a bad pin/URL, a cache-dir I/O failure, or a download/verification failure.
pub async fn fetch_cached(
    entry: &CorpusEntry,
    cache_dir: &Path,
    fetcher: &Fetcher,
) -> Result<PathBuf, CorpusError> {
    let digest = decode_pin(&entry.name, &entry.sha256)?;
    let url = Url::parse(&entry.url).map_err(|_| CorpusError::BadUrl {
        name: entry.name.clone(),
        url: entry.url.clone(),
    })?;
    std::fs::create_dir_all(cache_dir).map_err(|source| CorpusError::Io {
        path: cache_dir.to_path_buf(),
        source,
    })?;
    let dest = cache_dir.join(entry.sha256.to_ascii_lowercase());
    let spec = DownloadSpec::builder(url, dest, Validator::Sha256(digest))
        .build()
        .map_err(|source| CorpusError::Spec {
            name: entry.name.clone(),
            source,
        })?;
    let verified = fetcher
        .download(&spec, None, CancellationToken::new())
        .await
        .map_err(|source| CorpusError::Fetch {
            name: entry.name.clone(),
            source: Box::new(source),
        })?;
    Ok(verified.path().to_path_buf())
}

/// Fetch every entry of `manifest` into `cache_dir`, returning the cached paths in order.
///
/// # Errors
/// The first entry's [`CorpusError`].
pub async fn fetch_all(
    manifest: &CorpusManifest,
    cache_dir: &Path,
    fetcher: &Fetcher,
) -> Result<Vec<PathBuf>, CorpusError> {
    let mut paths = Vec::with_capacity(manifest.entries.len());
    for entry in &manifest.entries {
        paths.push(fetch_cached(entry, cache_dir, fetcher).await?);
    }
    Ok(paths)
}

fn decode_pin(name: &str, hex: &str) -> Result<[u8; 32], CorpusError> {
    from_hex(hex)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| CorpusError::BadPin {
            name: name.to_owned(),
            sha256: hex.to_owned(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chaos::{ChaosServer, sha256_of};
    use crate::golden::to_hex;

    #[tokio::test]
    async fn fetches_verifies_and_then_hits_the_cache() {
        let bytes = b"boot patch fixture bytes".to_vec();
        let server = ChaosServer::serving(bytes.clone()).start().await.unwrap();
        let cache = tempfile::tempdir().unwrap();
        let fetcher = Fetcher::builder().build().unwrap();
        let entry = CorpusEntry {
            url: server.url("boot.patch").to_string(),
            sha256: to_hex(&sha256_of(&bytes)),
            name: "boot".into(),
        };

        let path = fetch_cached(&entry, cache.path(), &fetcher).await.unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(server.stats().requests(), 1);

        // A second fetch re-hashes the cached file and makes no new request.
        let again = fetch_cached(&entry, cache.path(), &fetcher).await.unwrap();
        assert_eq!(again, path);
        assert_eq!(server.stats().requests(), 1);
    }

    #[tokio::test]
    async fn a_wrong_pin_is_a_fetch_error() {
        let server = ChaosServer::serving(b"real bytes".to_vec())
            .start()
            .await
            .unwrap();
        let cache = tempfile::tempdir().unwrap();
        let fetcher = Fetcher::builder().build().unwrap();
        let entry = CorpusEntry {
            url: server.url("f.patch").to_string(),
            sha256: to_hex(&sha256_of(b"different bytes")),
            name: "f".into(),
        };
        let err = fetch_cached(&entry, cache.path(), &fetcher)
            .await
            .unwrap_err();
        assert!(matches!(err, CorpusError::Fetch { .. }), "got {err:?}");
    }

    #[test]
    fn a_malformed_pin_is_rejected_before_any_fetch() {
        assert!(decode_pin("x", "not-hex").is_err());
        assert!(decode_pin("x", "00").is_err()); // too short for 32 bytes
    }

    #[test]
    fn manifest_json_round_trips() {
        let manifest = CorpusManifest {
            entries: vec![CorpusEntry {
                url: "http://example.test/a.patch".into(),
                sha256: to_hex(&sha256_of(b"a")),
                name: "a".into(),
            }],
        };
        let json = serde_json::to_string_pretty(&manifest).unwrap();
        assert_eq!(CorpusManifest::from_json(&json).unwrap(), manifest);
    }

    #[test]
    fn the_committed_manifest_is_well_formed() {
        let manifest =
            CorpusManifest::from_json(include_str!("../corpus/manifest.json")).expect("parse");
        assert!(!manifest.entries.is_empty(), "corpus manifest is empty");
        for entry in &manifest.entries {
            assert!(
                decode_pin(&entry.name, &entry.sha256).is_ok(),
                "bad pin for {}",
                entry.name
            );
            assert!(
                entry.url.starts_with("http://") || entry.url.starts_with("https://"),
                "bad url for {}",
                entry.name
            );
        }
    }
}
