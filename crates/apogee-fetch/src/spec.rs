//! The download request and its validating constructor.

use std::path::{Path, PathBuf};

use url::Url;

use crate::error::SpecError;
use crate::scheduler::Priority;
use crate::validator::Validator;

/// A single download: where to fetch, where to land it, how to verify it, whether to resume, and its
/// scheduling priority. Built through [`DownloadSpec::builder`], whose
/// [`build`](DownloadSpecBuilder::build) is the one place the source-safety rules are enforced, so an
/// unsafe request cannot be represented.
#[derive(Debug, Clone)]
pub struct DownloadSpec {
    url: Url,
    dest: PathBuf,
    expected_len: Option<u64>,
    validator: Validator,
    resume: bool,
    priority: Priority,
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
            dest: dest.into(),
            expected_len: None,
            validator,
            resume: true,
            priority: Priority::default(),
            allow_unverified: false,
        }
    }

    /// The source URL.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
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
    dest: PathBuf,
    expected_len: Option<u64>,
    validator: Validator,
    resume: bool,
    priority: Priority,
    allow_unverified: bool,
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

    /// Acknowledge that `Validator::None` leaves the bytes unverified. Required for an unverified
    /// download, and still rejected over plain HTTP.
    #[must_use]
    pub fn allow_unverified(mut self) -> Self {
        self.allow_unverified = true;
        self
    }

    /// Finish the spec, enforcing the source-safety rules.
    ///
    /// # Errors
    /// [`SpecError::UnsupportedScheme`] for a non-http(s) URL; [`SpecError::UnverifiedOverPlainHttp`]
    /// for `Validator::None` over `http://`; [`SpecError::UnverifiedNotAcknowledged`] for
    /// `Validator::None` over `https://` without [`allow_unverified`](Self::allow_unverified).
    pub fn build(self) -> Result<DownloadSpec, SpecError> {
        match self.url.scheme() {
            "http" | "https" => {}
            other => {
                return Err(SpecError::UnsupportedScheme {
                    scheme: other.to_owned(),
                });
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
        Ok(DownloadSpec {
            url: self.url,
            dest: self.dest,
            expected_len: self.expected_len,
            validator: self.validator,
            resume: self.resume,
            priority: self.priority,
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
}
