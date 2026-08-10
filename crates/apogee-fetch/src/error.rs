//! Download failures and the reasons a download request is refused.
//!
//! Two surfaces. [`SpecError`] rejects a request that must never be attempted (an unverified
//! plain-HTTP source, an unacknowledged skip of verification, an unsupported scheme) at the single
//! construction site, so an unsafe request is unrepresentable rather than merely unchecked.
//! [`FetchError`] is the runtime taxonomy for a transfer that was attempted and failed; expected,
//! recoverable situations are values in the result types, not variants here.
//!
//! # Stability
//!
//! Every variant of both enums has a construction site in this crate. A variant naming a situation
//! the crate cannot produce is dead code in whoever matches it, so there are none, and neither the
//! variants nor their fields change without a major version.
//!
//! Two situations deliberately have no variant, because both are recoveries rather than failures: a
//! server that will not serve byte ranges demotes the transfer to a single streaming connection, and
//! a journal that will not decode restarts the download from zero. Neither can reach a caller.
//!
//! Both enums stay `#[non_exhaustive]`, so matching one needs a `_` arm. [`Validator`](crate::Validator)
//! is open for the same reason: a failure shape a server has not shown us yet earns a variant rather
//! than widening an existing one into vagueness. The transient cases are listed positively in
//! [`FetchError::is_transient`] and `_` reads there as "permanent, do not retry", so a variant added
//! here cannot become a retry loop by default, and cannot silently change the answer a consumer gets
//! from a crate that never saw it added.

use std::path::PathBuf;

use thiserror::Error;
use url::Url;

use crate::retry::{Class, classify_status};

/// A download request that must not be attempted, rejected when the
/// [`DownloadSpec`](crate::DownloadSpec) is built. Distinct from [`FetchError`]: these are caller or
/// configuration mistakes caught before any network contact, not transfer failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpecError {
    /// An unverified download (`Validator::None`) over a plain-`http://` source. Plain HTTP is
    /// allowed only when an out-of-band validator authenticates the bytes.
    #[error("refusing an unverified download over plain http: {url}")]
    UnverifiedOverPlainHttp { url: Url },

    /// `Validator::None` was requested without the explicit opt-in acknowledging the bytes go
    /// unverified.
    #[error("unverified downloads must be acknowledged explicitly")]
    UnverifiedNotAcknowledged,

    /// The source scheme is neither `http` nor `https`.
    #[error("unsupported url scheme: {scheme}")]
    UnsupportedScheme { scheme: String },

    /// A `Validator::External` download without a declared length. The length check is the only
    /// fetch-side guarantee for externally-verified bytes, so it is required rather than optional.
    #[error("externally-verified downloads require a declared length")]
    ExternalRequiresLength,

    /// A `Validator::BlockSha1` whose block layout is inconsistent: no declared length, a zero block
    /// size, an empty hash list, or a hash count that disagrees with the block count the length and
    /// block size imply. Caught before any request so a mis-specified block map cannot start a transfer.
    #[error("invalid block-hash layout: {reason}")]
    BlockLayout { reason: &'static str },
}

/// Download failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The connection could not be established.
    #[error("connect to {host} failed")]
    Connect {
        host: String,
        #[source]
        source: std::io::Error,
    },

    /// The transfer failed after the connection was established: a dropped connection, a read error,
    /// or a TLS error while streaming the response body. Distinct from [`Connect`](FetchError::Connect)
    /// so a mid-stream drop is not mistaken for an unreachable host.
    #[error("transport error for {url}")]
    Transport {
        url: Url,
        #[source]
        source: std::io::Error,
    },

    /// The server answered with a status the download cannot accept.
    #[error("http {status} for {url}")]
    Http { status: u16, url: Url },

    /// A redirect the client's policy would not follow: a chain past the hop cap, a hop leaving
    /// `https` for plaintext, or a hop to a scheme that is not HTTP. Distinct from
    /// [`Connect`](FetchError::Connect) because the host answered perfectly well, and because a
    /// refusal is a verdict on the source rather than a transient fault, so it is never retried.
    #[error("refused a redirect while fetching {url}: {detail}")]
    RedirectRefused { url: Url, detail: &'static str },

    /// The transfer made no progress for too long, with no other source to try.
    #[error("stalled at {at_bytes} bytes: {url}")]
    Stalled { url: Url, at_bytes: u64 },

    /// One range failed on every source in turn until its attempt budget ran out. Distinct from
    /// [`Stalled`](FetchError::Stalled), which is a lone source going quiet with nowhere to fail over
    /// to: the fact worth triaging here is that failover itself was exhausted, so `sources` and
    /// `attempts` say how wide and how hard the transfer tried. `url` names the primary, the source
    /// list's head and the transfer's identity.
    #[error("all {sources} sources failed {url} after {attempts} attempt(s), {at_bytes} bytes in")]
    AllSourcesFailed {
        url: Url,
        sources: usize,
        attempts: u32,
        at_bytes: u64,
    },

    /// The server's advertised length disagreed with the caller's expectation before bytes flowed.
    #[error("length mismatch: expected {expected}, got {got}")]
    LengthMismatch { expected: u64, got: u64 },

    /// The source changed underneath an in-flight resume in a way the transfer could not absorb.
    #[error("server file changed mid-resume: {validator}")]
    ServerFileChanged { validator: String },

    /// A block failed its hash after exhausting its retry budget.
    #[error("block {block} at offset {offset} failed verification after {attempts} attempt(s)")]
    BlockVerifyFailed {
        block: u32,
        offset: u64,
        attempts: u32,
    },

    /// The finished file's whole-file hash did not match the expected digest.
    #[error("file verification failed: expected {expected}, got {got}")]
    FileVerifyFailed { expected: String, got: String },

    /// A filesystem operation failed. Disk-full carries its own [`std::io::ErrorKind`], which
    /// [`into_out_of_space`](FetchError::into_out_of_space) is the way to route on.
    #[error("io error at {path:?}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The HTTP client could not be constructed (the TLS backend failed to initialize).
    #[error("http client setup failed")]
    Client {
        #[source]
        source: std::io::Error,
    },

    /// A multi-range response could not be parsed or did not answer what was asked: a malformed
    /// `multipart/byteranges` body, a part whose `Content-Range` fell outside the requested ranges, or
    /// a boundary the `Content-Type` never declared.
    #[error("malformed range response for {url}: {detail}")]
    MalformedRangeResponse { url: Url, detail: &'static str },

    /// A source shape the streaming path cannot handle: the multi-range transport, and the defensive
    /// guard for a block validator that somehow reached the engine without a declared length (the spec
    /// builder normally rejects that first).
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },

    /// The caller cancelled the transfer; the partial file and its journal survive for a resume.
    #[error("cancelled")]
    Cancelled,
}

impl FetchError {
    /// Whether asking again could succeed: the network faults, plus the two cases only this crate can
    /// answer.
    ///
    /// An [`Http`](FetchError::Http) status is transient exactly when the crate's own backoff treats
    /// it as such, the throttle-and-overload set (`408`, `429`, `500`, `502`, `503`, `504`). A
    /// transfer with a single source hands that status back verbatim once its internal budget is
    /// spent, so a caller reading the variant alone stops on a throttling `503` that a longer pause
    /// would have cleared. [`ServerFileChanged`](FetchError::ServerFileChanged) is raised only after
    /// the journal is deleted, so what it asks for is a clean restart rather than a resume against
    /// bytes that moved underneath one.
    ///
    /// Everything else is permanent, `_` included: a consumer restating this list has to be re-edited
    /// whenever a variant is added, from a crate that cannot see it being added, and until then
    /// classifies the new failure by whichever way its own `_` arm happened to fall. Answered beside
    /// the code that constructs these, where the conservative default is also the local one.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Connect { .. }
            | Self::Transport { .. }
            | Self::Stalled { .. }
            | Self::AllSourcesFailed { .. }
            | Self::ServerFileChanged { .. } => true,
            Self::Http { status, .. } => classify_status(*status) == Class::Retryable,
            _ => false,
        }
    }

    /// Build an [`Io`](FetchError::Io) at `path`, the single tidy build site for the crate's
    /// filesystem failures.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Take this failure apart as a full disk: the path the filesystem refused and the `ENOSPC` it
    /// raised. `Err(self)` hands the failure back untouched when it is not one.
    ///
    /// Answered here rather than by each caller, because which variants can carry `ENOSPC` is this
    /// crate's knowledge and it is not obvious from the outside: preallocation raises it before a
    /// payload byte streams, and a write into a `.part` raises it mid-transfer on a filesystem with
    /// no reservation support, but both arrive as [`Io`](FetchError::Io) while a network fault with
    /// its own `io::Error` inside does not. A caller matching the enum itself would have to know
    /// that, and would silently stop covering the case if a later variant ever carried it too.
    ///
    /// This is the whole distinction between a full disk and any other filesystem fault, so a caller
    /// that routes on it gets a typed answer instead of walking the source chain for an
    /// [`ErrorKind`](std::io::ErrorKind). It yields the pair rather than the whole error because
    /// those two are all a disk-full [`Io`](FetchError::Io) holds: a caller re-wrapping the original
    /// beside a path it just read out of it would be storing the path twice.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_fetch::FetchError;
    ///
    /// let full = FetchError::Io {
    ///     path: "/tmp/game.patch.part".into(),
    ///     source: std::io::ErrorKind::StorageFull.into(),
    /// };
    /// let (path, source) = full.into_out_of_space().expect("a full disk");
    /// assert_eq!(path, std::path::Path::new("/tmp/game.patch.part"));
    /// assert_eq!(source.kind(), std::io::ErrorKind::StorageFull);
    ///
    /// let denied = FetchError::Io {
    ///     path: "/tmp/game.patch.part".into(),
    ///     source: std::io::ErrorKind::PermissionDenied.into(),
    /// };
    /// assert!(denied.into_out_of_space().is_err());
    /// ```
    ///
    /// # Errors
    /// The failure itself, unchanged, when it is not a full disk.
    pub fn into_out_of_space(self) -> Result<(PathBuf, std::io::Error), Self> {
        match self {
            Self::Io { path, source } if source.kind() == std::io::ErrorKind::StorageFull => {
                Ok((path, source))
            }
            other => Err(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn io(kind: std::io::ErrorKind) -> FetchError {
        FetchError::io("/dest/out.part", kind.into())
    }

    #[test]
    fn a_disk_full_io_failure_yields_its_path_and_kind() {
        let (path, source) = io(std::io::ErrorKind::StorageFull)
            .into_out_of_space()
            .map_err(|e| format!("{e:?}"))
            .expect("a full disk");
        assert_eq!(path, Path::new("/dest/out.part"));
        assert_eq!(source.kind(), std::io::ErrorKind::StorageFull);
    }

    #[test]
    fn another_io_failure_at_the_same_path_is_not_a_full_disk() {
        // The path alone cannot be the signal: the same `.part` raises permission and not-found
        // faults that a caller must not report as "free up space". Each is handed back whole, so a
        // caller can go on routing it.
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::FileTooLarge,
        ] {
            let returned = io(kind).into_out_of_space().err().ok_or(kind);
            assert!(
                matches!(returned, Ok(FetchError::Io { .. })),
                "{kind:?} was taken for a full disk",
            );
        }
    }

    #[test]
    fn a_transport_failure_carrying_an_io_error_is_not_a_full_disk() {
        // Connect/Transport wrap an `io::Error` of their own, so a caller matching on "has an
        // io::Error inside" would misread a network fault as a disk one.
        let err = FetchError::Transport {
            url: Url::parse("https://example.invalid/f.bin").expect("static url"),
            source: std::io::ErrorKind::StorageFull.into(),
        };
        assert!(err.into_out_of_space().is_err());
        assert!(FetchError::Cancelled.into_out_of_space().is_err());
    }
}

#[cfg(test)]
mod tests {
    use std::io::ErrorKind;

    use super::*;

    fn io(kind: ErrorKind) -> std::io::Error {
        std::io::Error::from(kind)
    }

    /// The faults a second attempt exists for: reaching the host, streaming from it, a source that
    /// went quiet, a failover that ran out of sources, and a source that stopped honoring ranges
    /// mid-transfer (whose journal is already gone, so the retry starts clean).
    #[test]
    fn the_network_faults_and_a_changed_source_are_transient() {
        let url = Url::parse("https://example.test/artifact.bin").unwrap();
        for error in [
            FetchError::Connect {
                host: "example.test".to_owned(),
                source: io(ErrorKind::ConnectionRefused),
            },
            FetchError::Transport {
                url: url.clone(),
                source: io(ErrorKind::ConnectionReset),
            },
            FetchError::Stalled {
                url: url.clone(),
                at_bytes: 4096,
            },
            FetchError::AllSourcesFailed {
                url: url.clone(),
                sources: 3,
                attempts: 8,
                at_bytes: 4096,
            },
            FetchError::ServerFileChanged {
                validator: "range ignored mid-transfer".to_owned(),
            },
        ] {
            assert!(error.is_transient(), "{error:?}");
        }
    }

    /// Bytes that failed a check, a request shape the source refused, a local fault, and a caller
    /// that asked to stop: none of them become a success by being asked again.
    #[test]
    fn a_failed_check_a_refusal_and_a_cancellation_are_permanent() {
        let url = Url::parse("https://example.test/artifact.bin").unwrap();
        for error in [
            FetchError::RedirectRefused {
                url: url.clone(),
                detail: "left https for plaintext",
            },
            FetchError::LengthMismatch {
                expected: 100,
                got: 99,
            },
            FetchError::BlockVerifyFailed {
                block: 2,
                offset: 262_144,
                attempts: 8,
            },
            FetchError::FileVerifyFailed {
                expected: "aa".to_owned(),
                got: "bb".to_owned(),
            },
            FetchError::io("/tmp/out.bin.part", io(ErrorKind::StorageFull)),
            FetchError::Client {
                source: io(ErrorKind::Other),
            },
            FetchError::MalformedRangeResponse {
                url: url.clone(),
                detail: "part outside the requested ranges",
            },
            FetchError::Unsupported {
                what: "multi-range transport",
            },
            FetchError::Cancelled,
        ] {
            assert!(!error.is_transient(), "{error:?}");
        }
    }

    /// A status reads the same to a consumer as it does to the crate's own backoff, over the whole
    /// range a server can send. Restating the set instead would let the two drift, which is how a
    /// throttling `503` that outlasts the internal budget stops an outer retry loop dead.
    #[test]
    fn a_status_is_transient_exactly_when_the_backoff_would_retry_it() {
        let url = Url::parse("https://example.test/artifact.bin").unwrap();
        for status in 100..=599u16 {
            let error = FetchError::Http {
                status,
                url: url.clone(),
            };
            assert_eq!(
                error.is_transient(),
                classify_status(status) == Class::Retryable,
                "{status}",
            );
        }
    }
}
