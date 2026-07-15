//! Download-by-URL + SHA256 corpus fetch. Large reference inputs (e.g. the boot patchlist) are
//! never checked in; they are fetched once into a content-addressed cache and verified against a
//! pinned digest before any test reads them.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Corpus fetch failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CorpusError {
    #[error("request to {url} failed")]
    Request {
        url: String,
        #[source]
        source: reqwest::Error,
    },
    #[error("http {status} for {url}")]
    Http { url: String, status: u16 },
    #[error("digest mismatch for {url}: expected {expected}, got {got}")]
    DigestMismatch {
        url: String,
        expected: String,
        got: String,
    },
    #[error("io error at {path}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Fetch `url` into `cache_dir` keyed by its `sha256_hex`, verifying the digest before returning.
///
/// A cache hit (a file already present under the digest key, still matching) skips the network.
/// Bytes are written atomically (temp-then-rename) so a killed run never leaves a partial file.
pub fn fetch_cached(url: &str, sha256_hex: &str, cache_dir: &Path) -> Result<PathBuf, CorpusError> {
    let expected = sha256_hex.to_ascii_lowercase();
    let dest = cache_dir.join(&expected);

    if let Ok(bytes) = fs::read(&dest)
        && sha256_hex_of(&bytes) == expected
    {
        return Ok(dest);
    }

    fs::create_dir_all(cache_dir).map_err(|source| CorpusError::Io {
        path: cache_dir.to_path_buf(),
        source,
    })?;

    let resp = reqwest::blocking::get(url).map_err(|source| CorpusError::Request {
        url: url.to_owned(),
        source,
    })?;
    let status = resp.status();
    if !status.is_success() {
        return Err(CorpusError::Http {
            url: url.to_owned(),
            status: status.as_u16(),
        });
    }
    let bytes = resp.bytes().map_err(|source| CorpusError::Request {
        url: url.to_owned(),
        source,
    })?;

    let got = sha256_hex_of(&bytes);
    if got != expected {
        return Err(CorpusError::DigestMismatch {
            url: url.to_owned(),
            expected,
            got,
        });
    }

    write_atomic(cache_dir, &dest, &bytes)?;
    Ok(dest)
}

fn sha256_hex_of(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    crate::golden::to_hex(&digest)
}

fn write_atomic(dir: &Path, dest: &Path, bytes: &[u8]) -> Result<(), CorpusError> {
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|source| CorpusError::Io {
        path: dir.to_path_buf(),
        source,
    })?;
    tmp.write_all(bytes).map_err(|source| CorpusError::Io {
        path: tmp.path().to_path_buf(),
        source,
    })?;
    tmp.persist(dest).map_err(|e| CorpusError::Io {
        path: dest.to_path_buf(),
        source: e.error,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_skips_the_network() {
        // A bogus URL proves no request is made when the cached file already matches its digest.
        let dir = tempfile::tempdir().expect("tempdir");
        let bytes = b"cached corpus bytes";
        let digest = sha256_hex_of(bytes);
        fs::write(dir.path().join(&digest), bytes).expect("seed cache");

        let got = fetch_cached("http://0.0.0.0:1/never", &digest, dir.path()).expect("cache hit");
        assert_eq!(got, dir.path().join(&digest));
    }
}
