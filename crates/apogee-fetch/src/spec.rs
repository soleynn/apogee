//! The download request and its validating constructor.

use std::path::{Path, PathBuf};

use url::Url;

use crate::error::SpecError;
use crate::headers::HeaderPolicy;
use crate::scheduler::Priority;
use crate::validator::Validator;

/// A single download: where to fetch, where to land it, how to verify it, whether to resume, and its
/// scheduling priority. Built through [`DownloadSpec::builder`], whose
/// [`build`](DownloadSpecBuilder::build) is the one place the source-safety rules are enforced, so an
/// unsafe request cannot be represented.
#[derive(Debug, Clone)]
pub struct DownloadSpec {
    url: Url,
    mirrors: Vec<Url>,
    dest: PathBuf,
    expected_len: Option<u64>,
    validator: Validator,
    resume: bool,
    priority: Priority,
    header_policy: Option<HeaderPolicy>,
}

impl DownloadSpec {
    /// Start building a download of `url` to `dest`, verified by `validator`. Resuming is on by
    /// default.
    #[must_use]
    pub fn builder(
        url: Url,
        dest: impl Into<PathBuf>,
        validator: Validator,
    ) -> DownloadSpecBuilder {
        DownloadSpecBuilder {
            url,
            mirrors: Vec::new(),
            dest: dest.into(),
            expected_len: None,
            validator,
            resume: true,
            priority: Priority::default(),
            allow_unverified: false,
            header_policy: None,
        }
    }

    /// The primary source URL. Also the resume identity key, so rotating to a mirror never invalidates
    /// journaled progress.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The alternate source URLs, tried in order when a block repeatedly fails from the primary.
    #[must_use]
    pub fn mirrors(&self) -> &[Url] {
        &self.mirrors
    }

    /// The primary URL followed by each mirror, the source list a transfer rotates through.
    pub(crate) fn sources(&self) -> Vec<Url> {
        let mut sources = Vec::with_capacity(1 + self.mirrors.len());
        sources.push(self.url.clone());
        sources.extend(self.mirrors.iter().cloned());
        sources
    }

    /// The per-request header policy, if any.
    #[must_use]
    pub fn header_policy(&self) -> Option<&HeaderPolicy> {
        self.header_policy.as_ref()
    }

    /// The final path the verified file lands at.
    #[must_use]
    pub fn dest(&self) -> &Path {
        &self.dest
    }

    /// The caller-declared expected length, if any.
    #[must_use]
    pub fn expected_len(&self) -> Option<u64> {
        self.expected_len
    }

    /// The verification policy.
    #[must_use]
    pub fn validator(&self) -> &Validator {
        &self.validator
    }

    /// Whether an interrupted transfer may resume from a sidecar journal.
    #[must_use]
    pub fn resume(&self) -> bool {
        self.resume
    }

    /// The scheduling priority: how this job is admitted relative to others in flight.
    #[must_use]
    pub fn priority(&self) -> Priority {
        self.priority
    }
}

/// Builds a [`DownloadSpec`], enforcing the source-safety rules in [`build`](Self::build).
#[derive(Debug)]
pub struct DownloadSpecBuilder {
    url: Url,
    mirrors: Vec<Url>,
    dest: PathBuf,
    expected_len: Option<u64>,
    validator: Validator,
    resume: bool,
    priority: Priority,
    allow_unverified: bool,
    header_policy: Option<HeaderPolicy>,
}

impl DownloadSpecBuilder {
    /// Declare the expected byte length; a server `Content-Length` that disagrees fails the download
    /// before any bytes are written.
    #[must_use]
    pub fn expected_len(mut self, len: u64) -> Self {
        self.expected_len = Some(len);
        self
    }

    /// Enable or disable resuming from a sidecar journal (on by default).
    #[must_use]
    pub fn resume(mut self, on: bool) -> Self {
        self.resume = on;
        self
    }

    /// Set the scheduling priority (defaults to [`Priority::Normal`]). Boot patches are admitted
    /// ahead of game data, which is admitted ahead of optional assets.
    #[must_use]
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Add one alternate source URL, tried after the primary when a block repeatedly fails.
    #[must_use]
    pub fn mirror(mut self, url: Url) -> Self {
        self.mirrors.push(url);
        self
    }

    /// Add alternate source URLs, tried in order after the primary when a block repeatedly fails.
    #[must_use]
    pub fn mirrors(mut self, urls: impl IntoIterator<Item = Url>) -> Self {
        self.mirrors.extend(urls);
        self
    }

    /// Set the per-request header policy (defaults to none).
    #[must_use]
    pub fn header_policy(mut self, policy: HeaderPolicy) -> Self {
        self.header_policy = Some(policy);
        self
    }

    /// Acknowledge that `Validator::None` leaves the bytes unverified. Required for an unverified
    /// download, and still rejected over plain HTTP.
    #[must_use]
    pub fn allow_unverified(mut self) -> Self {
        self.allow_unverified = true;
        self
    }

    /// Finish the spec, enforcing the source-safety and block-layout rules.
    ///
    /// # Errors
    /// [`SpecError::UnsupportedScheme`] for a non-http(s) primary or mirror URL;
    /// [`SpecError::UnverifiedOverPlainHttp`] for `Validator::None` over `http://`;
    /// [`SpecError::UnverifiedNotAcknowledged`] for `Validator::None` over `https://` without
    /// [`allow_unverified`](Self::allow_unverified); [`SpecError::ExternalRequiresLength`] for a
    /// `Validator::External` with no declared length; [`SpecError::BlockLayout`] for a
    /// `Validator::BlockSha1` whose block map is inconsistent with the declared length.
    pub fn build(self) -> Result<DownloadSpec, SpecError> {
        for url in std::iter::once(&self.url).chain(self.mirrors.iter()) {
            match url.scheme() {
                "http" | "https" => {}
                other => {
                    return Err(SpecError::UnsupportedScheme {
                        scheme: other.to_owned(),
                    });
                }
            }
        }
        if matches!(self.validator, Validator::None) {
            // Plain HTTP + no validator is refused outright: opting in cannot override it.
            if self.url.scheme() == "http" {
                return Err(SpecError::UnverifiedOverPlainHttp { url: self.url });
            }
            if !self.allow_unverified {
                return Err(SpecError::UnverifiedNotAcknowledged);
            }
        }
        // `External` is allowed over plain HTTP (it names a downstream gate), but the length check is
        // then the sole fetch-side guarantee, so a declared length is mandatory.
        if matches!(self.validator, Validator::External) && self.expected_len.is_none() {
            return Err(SpecError::ExternalRequiresLength);
        }
        if let Validator::BlockSha1 { block_size, hashes } = &self.validator {
            // A block map that disagrees with the length would mis-address a block on verify.
            if *block_size == 0 {
                return Err(SpecError::BlockLayout {
                    reason: "block size is zero",
                });
            }
            if hashes.is_empty() {
                return Err(SpecError::BlockLayout {
                    reason: "hash list is empty",
                });
            }
            let Some(len) = self.expected_len else {
                return Err(SpecError::BlockLayout {
                    reason: "block-hash validation requires a declared length",
                });
            };
            if hashes.len() as u64 != len.div_ceil(u64::from(*block_size)) {
                return Err(SpecError::BlockLayout {
                    reason: "hash count does not match the length and block size",
                });
            }
        }
        Ok(DownloadSpec {
            url: self.url,
            mirrors: self.mirrors,
            dest: self.dest,
            expected_len: self.expected_len,
            validator: self.validator,
            resume: self.resume,
            priority: self.priority,
            header_policy: self.header_policy,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn a_sha256_download_over_https_builds() {
        let spec = DownloadSpec::builder(
            url("https://host.invalid/f"),
            "/tmp/f",
            Validator::Sha256([0; 32]),
        )
        .expected_len(10)
        .build()
        .unwrap();
        assert_eq!(spec.expected_len(), Some(10));
        assert!(spec.resume());
    }

    #[test]
    fn unverified_over_plain_http_is_refused_even_when_acknowledged() {
        let err = DownloadSpec::builder(url("http://host.invalid/f"), "/tmp/f", Validator::None)
            .allow_unverified()
            .build()
            .unwrap_err();
        assert!(matches!(err, SpecError::UnverifiedOverPlainHttp { .. }));
    }

    #[test]
    fn unverified_https_must_be_acknowledged() {
        let err = DownloadSpec::builder(url("https://host.invalid/f"), "/tmp/f", Validator::None)
            .build()
            .unwrap_err();
        assert!(matches!(err, SpecError::UnverifiedNotAcknowledged));
    }

    #[test]
    fn acknowledged_unverified_https_builds() {
        DownloadSpec::builder(url("https://host.invalid/f"), "/tmp/f", Validator::None)
            .allow_unverified()
            .build()
            .unwrap();
    }

    #[test]
    fn external_over_plain_http_builds_with_a_declared_length() {
        // The boot-patch shape: no fetch-side hash, plain HTTP, length-checked, downstream-verified.
        let spec = DownloadSpec::builder(
            url("http://patch.invalid/boot.patch"),
            "/tmp/b",
            Validator::External,
        )
        .expected_len(300)
        .build()
        .unwrap();
        assert!(matches!(spec.validator(), Validator::External));
        assert_eq!(spec.expected_len(), Some(300));
    }

    #[test]
    fn external_without_a_declared_length_is_refused() {
        let err = DownloadSpec::builder(
            url("http://patch.invalid/boot.patch"),
            "/tmp/b",
            Validator::External,
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, SpecError::ExternalRequiresLength));
    }

    #[test]
    fn a_non_http_scheme_is_refused() {
        let err = DownloadSpec::builder(
            url("ftp://host.invalid/f"),
            "/tmp/f",
            Validator::Sha256([0; 32]),
        )
        .build()
        .unwrap_err();
        assert!(matches!(err, SpecError::UnsupportedScheme { scheme } if scheme == "ftp"));
    }

    fn block_validator(blocks: usize) -> Validator {
        Validator::BlockSha1 {
            block_size: 16,
            hashes: vec![[0u8; 20]; blocks],
        }
    }

    #[test]
    fn a_well_formed_block_download_builds_with_mirrors() {
        let spec =
            DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", block_validator(3))
                .expected_len(40) // 40.div_ceil(16) == 3 blocks
                .mirror(url("http://mirror.invalid/f"))
                .build()
                .unwrap();
        assert_eq!(spec.mirrors().len(), 1);
        assert_eq!(spec.sources().len(), 2);
        assert_eq!(spec.sources()[0], *spec.url());
    }

    #[test]
    fn block_validation_requires_a_declared_length() {
        let err =
            DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", block_validator(3))
                .build()
                .unwrap_err();
        assert!(matches!(err, SpecError::BlockLayout { .. }));
    }

    #[test]
    fn a_hash_count_that_disagrees_with_the_length_is_refused() {
        let err =
            DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", block_validator(2))
                .expected_len(40) // needs 3 blocks, not 2
                .build()
                .unwrap_err();
        assert!(matches!(err, SpecError::BlockLayout { .. }));
    }

    #[test]
    fn an_empty_block_hash_list_is_refused() {
        let err =
            DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", block_validator(0))
                .expected_len(0)
                .build()
                .unwrap_err();
        assert!(matches!(err, SpecError::BlockLayout { .. }));
    }

    #[test]
    fn a_zero_block_size_is_refused() {
        let v = Validator::BlockSha1 {
            block_size: 0,
            hashes: vec![[0u8; 20]],
        };
        let err = DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", v)
            .expected_len(10)
            .build()
            .unwrap_err();
        assert!(matches!(err, SpecError::BlockLayout { .. }));
    }

    #[test]
    fn a_mirror_with_a_bad_scheme_is_refused() {
        let err = DownloadSpec::builder(
            url("https://host.invalid/f"),
            "/tmp/f",
            Validator::Sha256([0; 32]),
        )
        .mirror(url("ftp://mirror.invalid/f"))
        .build()
        .unwrap_err();
        assert!(matches!(err, SpecError::UnsupportedScheme { scheme } if scheme == "ftp"));
    }
}
