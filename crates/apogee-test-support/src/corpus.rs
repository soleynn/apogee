//! Download-by-URL + SHA256 corpus fetch into a content-addressed cache.
//!
//! Large reference inputs (the boot patch corpus) are never checked in; they are fetched once into a
//! cache directory, keyed by digest, and verified against a pinned SHA256 before any test reads them.
//! Boot patches are served over plain HTTP and carry no upstream per-file hash, so the pin is a
//! trust-on-first-download digest the maintainer records once.
//!
//! The fetch reuses [`apogee_fetch`]'s verified downloader rather than a second HTTP client: the pin
//! then covers the on-wire bytes (that client disables transparent gzip/deflate), and resume, retry,
//! atomic publish, and cache-hit-skips-the-network all come for free. A cache hit re-hashes the
//! digest-named file already on disk and makes no request.
//!
//! Fetching lives behind the `corpus` feature, so the plain `--workspace` build never pulls the
//! download transport in. [`readiness`] does not: it is filesystem and environment only, and the
//! gates that consult it are in a crate that has no business depending on an HTTP client to ask
//! whether a file is on disk.

use std::path::{Path, PathBuf};

#[cfg(feature = "corpus")]
use apogee_fetch::{DownloadSpec, FetchError, Fetcher, SpecError, Validator};
use serde::{Deserialize, Serialize};
#[cfg(feature = "corpus")]
use thiserror::Error;
#[cfg(feature = "corpus")]
use tokio_util::sync::CancellationToken;
#[cfg(feature = "corpus")]
use url::Url;

#[cfg(feature = "corpus")]
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
#[cfg(feature = "corpus")]
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
#[cfg(feature = "corpus")]
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
#[cfg(feature = "corpus")]
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

/// Whether the source still serves this entry at all.
///
/// Square Enix retires a boot patch once a newer one supersedes it: the pinned URL starts answering
/// `404`, and no retry, mirror or pin correction brings it back. That is a fact about their retention
/// rather than a fault in this repository, so it is worth naming apart from every other fetch failure
/// (a CDN hiccup, a proxy, a pin that no longer matches the bytes), which are all still faults.
#[cfg(feature = "corpus")]
#[must_use]
pub fn is_retired(error: &CorpusError) -> bool {
    matches!(
        error,
        CorpusError::Fetch { source, .. }
            if matches!(**source, FetchError::Http { status: 404 | 410, .. })
    )
}

/// The environment variable a caller sets to say the corpus must really be present, so an unprimed
/// cache is a failure rather than a skip.
pub const REQUIRED_ENV: &str = "APOGEE_CORPUS_REQUIRED";

/// Whether a corpus-backed gate may run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Every entry is cached: run the gate.
    Primed,
    /// Nothing is cached and nothing demanded it be: a no-network run, so skip.
    Unprimed,
}

/// A corpus that cannot back a gate, and cannot be excused as a no-network run either.
///
/// Implemented by hand rather than derived: `thiserror` is optional here and rides the `corpus`
/// feature, and this type has to exist without it.
#[derive(Debug)]
pub struct CorpusUnusable {
    pub cache: PathBuf,
    pub missing: Vec<String>,
    pub detail: &'static str,
}

impl std::fmt::Display for CorpusUnusable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the boot corpus under {} is unusable: {} of its entries are absent ({}). {}",
            self.cache.display(),
            self.missing.len(),
            self.missing.join(", "),
            self.detail,
        )
    }
}

impl std::error::Error for CorpusUnusable {}

/// Decide whether a gate needing every digest in `entries` can run, skip, or must fail.
///
/// Three states rather than two, and the third is the point. Both boot gates used to skip whenever
/// *any* entry was missing, which is right for a contributor with no network and silently wrong
/// everywhere else: the day the source retired one patch of a two-patch chain, a tolerant fetch would
/// have left the gates reporting success while applying nothing. A gate that cannot run must not be
/// able to pass.
///
/// So a *partial* cache is never a no-network run: some entry downloaded, which means the network was
/// there and the corpus is broken. And an *empty* cache is a skip only until a caller sets
/// [`REQUIRED_ENV`], which the scheduled job that primes the corpus first does, so a priming step that
/// silently delivered nothing cannot be absorbed downstream as "no network".
///
/// # Errors
/// [`CorpusUnusable`] when the cache is partial, or empty while [`REQUIRED_ENV`] is set.
pub fn readiness(cache_dir: &Path, digests: &[&str]) -> Result<Readiness, CorpusUnusable> {
    let missing: Vec<String> = digests
        .iter()
        .filter(|digest| !cache_dir.join(digest).exists())
        .map(|digest| (*digest).to_owned())
        .collect();
    decide(
        cache_dir,
        missing,
        digests.len(),
        std::env::var_os(REQUIRED_ENV).is_some(),
    )
}

/// The rule itself, with the cache already inspected and the requirement already read.
///
/// Split from [`readiness`] so it can be exercised directly: the requirement arrives as a process
/// environment variable, which a test in this crate cannot set (`set_var` is unsafe, and this crate
/// forbids unsafe), and which would be shared mutable state across concurrent tests if it could.
fn decide(
    cache_dir: &Path,
    missing: Vec<String>,
    total: usize,
    required: bool,
) -> Result<Readiness, CorpusUnusable> {
    let detail = match missing.len() {
        0 => return Ok(Readiness::Primed),
        n if n < total => {
            "part of the chain is cached, so this is a broken corpus rather than a run without \
             network; a gate cannot apply a chain it only half has"
        }
        _ if required => {
            "the corpus was declared required, so an empty cache is a priming failure rather than \
             a run without network"
        }
        _ => return Ok(Readiness::Unprimed),
    };
    Err(CorpusUnusable {
        cache: cache_dir.to_path_buf(),
        missing,
        detail,
    })
}

#[cfg(feature = "corpus")]
fn decode_pin(name: &str, hex: &str) -> Result<[u8; 32], CorpusError> {
    from_hex(hex)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| CorpusError::BadPin {
            name: name.to_owned(),
            sha256: hex.to_owned(),
        })
}

#[cfg(test)]
mod readiness_tests {
    use super::*;

    fn missing(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    /// The whole point of the three-state rule: a gate that cannot run must not be able to report
    /// success. Both boot gates skipped on *any* absence, so the day the upstream retired one patch of
    /// a two-patch chain, tolerating that fetch would have turned them green over an empty apply.
    #[test]
    fn a_half_cached_chain_is_a_failure_and_never_a_skip() {
        let cache = Path::new("/nonexistent");
        // Missing some but not all, with and without the requirement: broken either way, because
        // something did download, so the network was there.
        for required in [false, true] {
            let err = decide(cache, missing(&["b"]), 2, required)
                .expect_err("a partial chain must not be usable");
            assert!(
                err.to_string().contains("half"),
                "the message must say why a partial cache is not a no-network run: {err}",
            );
        }
    }

    /// An empty cache is the contributor-with-no-network case, and stays a skip, until a caller says
    /// it primed the corpus first. That is what stops a priming step which delivered nothing from
    /// being absorbed downstream as "no network".
    #[test]
    fn an_empty_cache_skips_until_it_is_declared_required() {
        let cache = Path::new("/nonexistent");
        assert_eq!(
            decide(cache, missing(&["a", "b"]), 2, false).ok(),
            Some(Readiness::Unprimed),
        );
        assert!(decide(cache, missing(&["a", "b"]), 2, true).is_err());
    }

    #[test]
    fn a_complete_cache_runs_the_gate() {
        for required in [false, true] {
            assert_eq!(
                decide(Path::new("/nonexistent"), Vec::new(), 2, required).ok(),
                Some(Readiness::Primed),
            );
        }
    }

    /// The failure has to name the entries, since the caller's next move is re-recording exactly
    /// those pins.
    #[test]
    fn the_failure_names_the_absent_entries() {
        let err =
            decide(Path::new("/cache"), missing(&["deadbeef"]), 2, false).expect_err("partial");
        let shown = err.to_string();
        assert!(shown.contains("deadbeef"), "{shown}");
        assert!(shown.contains("/cache"), "{shown}");
    }
}

#[cfg(all(test, feature = "corpus"))]
mod fetch_tests {
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
