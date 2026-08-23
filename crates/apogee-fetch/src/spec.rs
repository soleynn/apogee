//! The download request and its validating constructor.

use std::path::{Path, PathBuf};

use url::Url;

use crate::error::SpecError;
use crate::headers::HeaderPolicy;
use crate::scheduler::Priority;
use crate::validator::Validator;

/// A single download: where to fetch, where to land it, how to verify it, whether to resume, and its
/// scheduling priority.
///
/// Built through [`DownloadSpec::builder`], whose [`build`](DownloadSpecBuilder::build) is the one
/// place the source-safety rules are enforced, so an unsafe request cannot be represented.
#[derive(Debug, Clone)]
pub struct DownloadSpec {
    url: Url,
    mirrors: Vec<Url>,
    dest: PathBuf,
    expected_len: Option<u64>,
    max_len: Option<u64>,
    allowed_content_types: Vec<String>,
    validator: Validator,
    resume: bool,
    overwrite: bool,
    priority: Priority,
    header_policy: Option<HeaderPolicy>,
}

impl DownloadSpec {
    /// Start building a download of `url` to `dest`, verified by `validator`; resuming is on by
    /// default.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_fetch::{DownloadSpec, Validator};
    ///
    /// let spec = DownloadSpec::builder(
    ///     "https://example.invalid/patch.zip".parse().unwrap(),
    ///     "/tmp/patch.zip",
    ///     Validator::Sha256([0; 32]),
    /// )
    /// .expected_len(1024)
    /// .build()
    /// .unwrap();
    /// assert_eq!(spec.expected_len(), Some(1024));
    /// assert!(spec.resume());
    /// ```
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
            max_len: None,
            allowed_content_types: Vec::new(),
            validator,
            resume: true,
            overwrite: false,
            priority: Priority::default(),
            allow_unverified: false,
            header_policy: None,
        }
    }

    /// The primary source URL. Also the resume identity key, so rotating to a mirror never
    /// invalidates journaled progress.
    #[must_use]
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The alternate source URLs, tried in turn when work repeatedly fails from the primary.
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

    /// The largest response body the transfer may accept, if one was configured.
    ///
    /// Unlike [`expected_len`](Self::expected_len), this is an upper bound rather than an exact
    /// length. It also protects responses without a `Content-Length`: the streaming path stops
    /// before a byte beyond this limit reaches disk.
    #[must_use]
    pub fn max_len(&self) -> Option<u64> {
        self.max_len
    }

    /// The normalized MIME types an HTTP response may carry.
    ///
    /// An empty slice accepts any response type. Parameters on a response header, such as a charset,
    /// do not participate in the comparison.
    #[must_use]
    pub fn allowed_content_types(&self) -> &[String] {
        &self.allowed_content_types
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

    /// Whether an existing destination is re-fetched rather than served back.
    #[must_use]
    pub fn overwrite(&self) -> bool {
        self.overwrite
    }

    /// The scheduling priority: how this job is admitted relative to others in flight.
    #[must_use]
    pub fn priority(&self) -> Priority {
        self.priority
    }

    /// Check the response metadata that is common to both transfer engines before its body is read.
    pub(crate) fn validate_response(
        &self,
        response: &reqwest::Response,
        url: &Url,
        total_len: Option<u64>,
    ) -> Result<(), crate::error::FetchError> {
        if let (Some(max), Some(got)) = (self.max_len, total_len)
            && got > max
        {
            return Err(crate::error::FetchError::ResponseTooLarge {
                url: url.clone(),
                max,
                got,
            });
        }
        if !self.allowed_content_types.is_empty() {
            let raw = response
                .headers()
                .get(reqwest::header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok());
            let normalized = raw
                .and_then(|value| value.split(';').next())
                .and_then(normalize_content_type);
            if normalized
                .as_ref()
                .is_none_or(|value| !self.allowed_content_types.contains(value))
            {
                return Err(crate::error::FetchError::ContentTypeRejected {
                    url: url.clone(),
                    content_type: raw.map(str::to_owned),
                });
            }
        }
        Ok(())
    }

    /// Check a streaming high-water mark when no trustworthy length was available up front.
    pub(crate) fn validate_stream_len(
        &self,
        url: &Url,
        got: u64,
    ) -> Result<(), crate::error::FetchError> {
        if let Some(max) = self.max_len
            && got > max
        {
            return Err(crate::error::FetchError::ResponseTooLarge {
                url: url.clone(),
                max,
                got,
            });
        }
        Ok(())
    }

    /// Fingerprint every policy that decides whether journaled bytes remain acceptable.
    pub(crate) fn resume_identity_digest(&self) -> [u8; 32] {
        let validator = self.validator.config_digest();
        if self.max_len.is_none() && self.allowed_content_types.is_empty() {
            return validator;
        }
        let mut digest = blake3::Hasher::new();
        digest.update(b"apogee-fetch-response-policy-v1\0");
        digest.update(&validator);
        match self.max_len {
            Some(max) => {
                digest.update(&[1]);
                digest.update(&max.to_le_bytes());
            }
            None => {
                digest.update(&[0]);
            }
        }
        for content_type in &self.allowed_content_types {
            digest.update(&(content_type.len() as u64).to_le_bytes());
            digest.update(content_type.as_bytes());
        }
        *digest.finalize().as_bytes()
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
    overwrite: bool,
    priority: Priority,
    allow_unverified: bool,
    header_policy: Option<HeaderPolicy>,
    max_len: Option<u64>,
    allowed_content_types: Vec<String>,
}

impl DownloadSpecBuilder {
    /// Declare the expected byte length; a server `Content-Length` that disagrees fails the download
    /// before any bytes are written.
    #[must_use]
    pub fn expected_len(mut self, len: u64) -> Self {
        self.expected_len = Some(len);
        self
    }

    /// Set the largest response body the transfer may accept.
    ///
    /// A declared or advertised length over this bound is rejected before preallocation. A response
    /// without a length is capped while streaming.
    #[must_use]
    pub fn max_len(mut self, len: u64) -> Self {
        self.max_len = Some(len);
        self
    }

    /// Allow one response MIME type.
    ///
    /// Types are ASCII case-insensitive and must be MIME essences such as `image/png`, without
    /// parameters. Calling this method opts the request into MIME enforcement.
    #[must_use]
    pub fn allowed_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.allowed_content_types.push(content_type.into());
        self
    }

    /// Allow a set of response MIME types; see [`allowed_content_type`](Self::allowed_content_type).
    #[must_use]
    pub fn allowed_content_types(
        mut self,
        content_types: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.allowed_content_types
            .extend(content_types.into_iter().map(Into::into));
        self
    }

    /// Enable or disable resuming from a sidecar journal (on by default).
    #[must_use]
    pub fn resume(mut self, on: bool) -> Self {
        self.resume = on;
        self
    }

    /// Re-fetch even when the destination already satisfies the request, replacing it on success
    /// (off by default).
    ///
    /// Needed for a mutable artifact (a signed catalog, a manifest) fetched to a fixed path: with no
    /// digest or declared length to check against, an unpinned download otherwise treats any existing
    /// file as already satisfying the request and serves it back forever. Either way, publication is
    /// the same atomic rename, so a failed or truncated transfer never disturbs the existing file.
    #[must_use]
    pub fn overwrite(mut self) -> Self {
        self.overwrite = true;
        self
    }

    /// Set the scheduling priority (defaults to [`Priority::Normal`]). Boot patches are admitted
    /// ahead of game data, which is admitted ahead of optional assets.
    #[must_use]
    pub fn priority(mut self, priority: Priority) -> Self {
        self.priority = priority;
        self
    }

    /// Add one alternate source URL, tried after the primary when work repeatedly fails.
    ///
    /// A mirror can serve any part of the transfer the primary won't, from a single dying segment up
    /// to a whole single-connection transfer, and steps in only after the failing source gets one
    /// more try (so a transient blip doesn't give up a warm connection). A mirror that won't serve
    /// ranges drops out of a segmented transfer's rotation but stays in a single-connection one. No
    /// mirror is ever sent the primary's validator, so it's the downloaded file's own validator, not
    /// the source, that proves a transfer assembled from more than one URL.
    #[must_use]
    pub fn mirror(mut self, url: Url) -> Self {
        self.mirrors.push(url);
        self
    }

    /// Add alternate source URLs, tried in turn after the primary when work repeatedly fails; see
    /// [`mirror`](Self::mirror) for how each is used.
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

    /// Acknowledge that [`Validator::None`] leaves the bytes unverified. Required for an unverified
    /// download, and still rejected over plain HTTP.
    #[must_use]
    pub fn allow_unverified(mut self) -> Self {
        self.allow_unverified = true;
        self
    }

    /// Finish the spec, enforcing the source-safety and block-layout rules.
    ///
    /// # Errors
    ///
    /// [`SpecError::UnsupportedScheme`] for a non-http(s) primary or mirror URL;
    /// [`SpecError::UnverifiedOverPlainHttp`] for [`Validator::None`] over `http://`;
    /// [`SpecError::UnverifiedNotAcknowledged`] for [`Validator::None`] over `https://` without
    /// [`allow_unverified`](Self::allow_unverified); [`SpecError::ExternalRequiresLength`] for a
    /// [`Validator::External`] with no declared length; [`SpecError::BlockLayout`] for a
    /// [`Validator::BlockSha1`] whose block map is inconsistent with the declared length;
    /// [`SpecError::ExpectedLengthExceedsMaximum`] when the exact length exceeds the response cap;
    /// or [`SpecError::InvalidAllowedContentType`] for a malformed MIME allowlist entry.
    pub fn build(self) -> Result<DownloadSpec, SpecError> {
        if let (Some(expected), Some(max)) = (self.expected_len, self.max_len)
            && expected > max
        {
            return Err(SpecError::ExpectedLengthExceedsMaximum { expected, max });
        }
        let mut allowed_content_types = self
            .allowed_content_types
            .into_iter()
            .map(|value| {
                normalize_content_type(&value).ok_or(SpecError::InvalidAllowedContentType {
                    content_type: value,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        allowed_content_types.sort_unstable();
        allowed_content_types.dedup();
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
            max_len: self.max_len,
            allowed_content_types,
            validator: self.validator,
            resume: self.resume,
            overwrite: self.overwrite,
            priority: self.priority,
            header_policy: self.header_policy,
        })
    }
}

/// Normalize a MIME essence for policy comparison. Parameters belong on response headers, not in a
/// configured allowlist.
pub(crate) fn normalize_content_type(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.contains(';') || !value.is_ascii() {
        return None;
    }
    let (kind, subtype) = value.split_once('/')?;
    if subtype.contains('/') || !mime_token(kind) || !mime_token(subtype) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

fn mime_token(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    /// The happy path: a verified https download builds with resume on by default.
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

    /// `allow_unverified` cannot override the plain-http refusal.
    #[test]
    fn unverified_over_plain_http_is_refused_even_when_acknowledged() {
        let err = DownloadSpec::builder(url("http://host.invalid/f"), "/tmp/f", Validator::None)
            .allow_unverified()
            .build()
            .unwrap_err();
        assert!(matches!(err, SpecError::UnverifiedOverPlainHttp { .. }));
    }

    /// `Validator::None` over https is refused unless acknowledged.
    #[test]
    fn unverified_https_must_be_acknowledged() {
        let err = DownloadSpec::builder(url("https://host.invalid/f"), "/tmp/f", Validator::None)
            .build()
            .unwrap_err();
        assert!(matches!(err, SpecError::UnverifiedNotAcknowledged));
    }

    /// Acknowledging the risk lets an unverified https download build.
    #[test]
    fn acknowledged_unverified_https_builds() {
        DownloadSpec::builder(url("https://host.invalid/f"), "/tmp/f", Validator::None)
            .allow_unverified()
            .build()
            .unwrap();
    }

    /// `Validator::External` is allowed over plain http when a length is declared.
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

    /// `Validator::External` requires a declared length.
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

    /// A non-http(s) primary URL is refused.
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

    /// A consistent block layout builds, and a mirror is counted in `sources()`.
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

    /// Block-hash validation needs a declared length to check the hash count against.
    #[test]
    fn block_validation_requires_a_declared_length() {
        let err =
            DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", block_validator(3))
                .build()
                .unwrap_err();
        assert!(matches!(err, SpecError::BlockLayout { .. }));
    }

    /// The hash count must match the length and block size.
    #[test]
    fn a_hash_count_that_disagrees_with_the_length_is_refused() {
        let err =
            DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", block_validator(2))
                .expected_len(40) // needs 3 blocks, not 2
                .build()
                .unwrap_err();
        assert!(matches!(err, SpecError::BlockLayout { .. }));
    }

    /// An empty hash list is refused even with a matching length.
    #[test]
    fn an_empty_block_hash_list_is_refused() {
        let err =
            DownloadSpec::builder(url("http://patch.invalid/f"), "/tmp/f", block_validator(0))
                .expected_len(0)
                .build()
                .unwrap_err();
        assert!(matches!(err, SpecError::BlockLayout { .. }));
    }

    /// A zero block size is refused.
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

    /// A mirror URL is held to the same scheme rule as the primary.
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

    /// An exact length cannot contradict the request's own upper bound.
    #[test]
    fn an_expected_length_over_the_maximum_is_refused() {
        let err = DownloadSpec::builder(
            url("https://host.invalid/f"),
            "/tmp/f",
            Validator::Sha256([0; 32]),
        )
        .expected_len(11)
        .max_len(10)
        .build()
        .unwrap_err();
        assert!(matches!(
            err,
            SpecError::ExpectedLengthExceedsMaximum {
                expected: 11,
                max: 10
            }
        ));
    }

    /// MIME entries are normalized, sorted and deduplicated so equivalent policies share an
    /// identity and callers see the exact enforced set.
    #[test]
    fn content_type_allowlists_are_canonical() {
        let spec = DownloadSpec::builder(
            url("https://host.invalid/f"),
            "/tmp/f",
            Validator::Sha256([0; 32]),
        )
        .max_len(1024)
        .allowed_content_types(["image/webp", "IMAGE/PNG", "image/png"])
        .build()
        .unwrap();
        assert_eq!(spec.max_len(), Some(1024));
        assert_eq!(
            spec.allowed_content_types(),
            &["image/png".to_owned(), "image/webp".to_owned()]
        );
    }

    /// Parameters describe a particular response and are not a MIME essence suitable for an
    /// allowlist.
    #[test]
    fn a_parameterized_allowed_content_type_is_refused() {
        let err = DownloadSpec::builder(
            url("https://host.invalid/f"),
            "/tmp/f",
            Validator::Sha256([0; 32]),
        )
        .allowed_content_type("image/png; charset=binary")
        .build()
        .unwrap_err();
        assert!(matches!(err, SpecError::InvalidAllowedContentType { .. }));
    }

    /// Any policy difference changes the journal fingerprint, while allowlist ordering does not.
    #[test]
    fn response_policy_is_part_of_the_resume_identity() {
        let build = |max, types: &[&str]| {
            DownloadSpec::builder(
                url("https://host.invalid/f"),
                "/tmp/f",
                Validator::Sha256([7; 32]),
            )
            .max_len(max)
            .allowed_content_types(types.iter().copied())
            .build()
            .unwrap()
        };
        let a = build(1024, &["image/png", "image/webp"]);
        let reordered = build(1024, &["IMAGE/WEBP", "image/png"]);
        let different_max = build(1025, &["image/png", "image/webp"]);
        let different_type = build(1024, &["image/jpeg"]);
        assert_eq!(
            a.resume_identity_digest(),
            reordered.resume_identity_digest()
        );
        assert_ne!(
            a.resume_identity_digest(),
            different_max.resume_identity_digest()
        );
        assert_ne!(
            a.resume_identity_digest(),
            different_type.resume_identity_digest()
        );
    }
}
