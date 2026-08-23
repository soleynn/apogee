//! Read-only inspection of a download's durable resume state.

use crate::{DownloadSpec, FetchError, download, journal};

/// Durable bytes belonging to the exact request described by a [`DownloadSpec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeReading {
    /// Total bytes covered by intact journal intervals whose data is present in the part file.
    pub durable_bytes: u64,
}

/// Inspect an existing part file and journal without changing either one.
///
/// `Ok(None)` means there is no usable progress for this exact source, declared length, and
/// validator. Corrupt, obsolete, mismatched, empty, or incomplete sidecars are intentionally read
/// as no progress. Genuine filesystem failures remain errors.
pub async fn resume_reading(spec: &DownloadSpec) -> Result<Option<ResumeReading>, FetchError> {
    if !spec.resume() {
        return Ok(None);
    }
    let part = download::sidecar(spec.dest(), ".part");
    let apdl = download::sidecar(spec.dest(), ".apdl");
    let Some(loaded) = journal::load(&apdl)
        .await
        .map_err(|source| FetchError::io(&apdl, source))?
    else {
        return Ok(None);
    };
    let expected = download::base_identity(spec, spec.expected_len());
    if !expected.matches(&loaded.identity) {
        return Ok(None);
    }
    let metadata = match tokio::fs::metadata(&part).await {
        Ok(metadata) if metadata.is_file() => metadata,
        Ok(_) => return Ok(None),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(FetchError::io(&part, source)),
    };
    let durable_bytes = loaded.intervals.covered_len();
    if durable_bytes == 0 || loaded.intervals.highest_end() > metadata.len() {
        return Ok(None);
    }
    Ok(Some(ResumeReading { durable_bytes }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Validator, journal::Journal};
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    fn spec(path: &std::path::Path, digest: [u8; 32]) -> DownloadSpec {
        DownloadSpec::builder(
            "https://example.invalid/file".parse().unwrap(),
            path,
            Validator::Sha256(digest),
        )
        .expected_len(16)
        .build()
        .unwrap()
    }

    async fn write_resume(spec: &DownloadSpec, bytes: usize) {
        let part = download::sidecar(spec.dest(), ".part");
        let apdl = download::sidecar(spec.dest(), ".apdl");
        let mut file = tokio::fs::File::create(part).await.unwrap();
        file.write_all(&vec![0; bytes]).await.unwrap();
        file.sync_data().await.unwrap();
        let identity = download::base_identity(spec, spec.expected_len());
        let mut journal = Journal::create(&apdl, &identity).await.unwrap().unwrap();
        journal.commit_interval(0, 8).await.unwrap();
    }

    #[tokio::test]
    async fn reports_only_progress_for_the_exact_request() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("file");
        let original = spec(&path, [1; 32]);
        write_resume(&original, 8).await;

        assert_eq!(
            resume_reading(&original).await.unwrap(),
            Some(ResumeReading { durable_bytes: 8 })
        );
        assert_eq!(resume_reading(&spec(&path, [2; 32])).await.unwrap(), None);
    }

    #[tokio::test]
    async fn rejects_intervals_beyond_the_part_file() {
        let dir = tempdir().unwrap();
        let request = spec(&dir.path().join("file"), [1; 32]);
        write_resume(&request, 4).await;
        assert_eq!(resume_reading(&request).await.unwrap(), None);
    }
}
