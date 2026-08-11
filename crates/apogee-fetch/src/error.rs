//! Download failures and the reasons a download request is refused.
//!
//! [`SpecError`] rejects a request that must never be attempted (an unverified plain-HTTP source, an
//! unacknowledged skip of verification, an unsupported scheme) at the single construction site, so an
//! unsafe request is unrepresentable rather than merely unchecked. [`FetchError`] is the runtime
//! taxonomy for a transfer that was attempted and failed; expected, recoverable situations are values
//! in the result types, not variants here.
//!
//! # Stability
//!
//! Every variant of both enums has a construction site in this crate. Two situations that could look
//! like failures have none, because both are recoveries handled internally: a server that refuses byte
//! ranges demotes the transfer to a single connection, and a journal that fails to decode restarts the
//! download from zero. Neither reaches a caller.
//!
//! Both enums are `#[non_exhaustive]`, so matching either needs a `_` arm; [`Validator`](crate::Validator)
//! is open for the same reason. The transient cases are listed positively in
//! [`FetchError::is_transient`], so `_` there reads as "permanent, do not retry": a variant added later
//! cannot become a retry loop by default.
//!
//! Openness is also decided per variant. A variant no consumer has reason to construct is itself
//! `#[non_exhaustive]`, so it can gain a field (a cause, a URL, an offset) without a major version. The
//! variants consumers build directly or take apart field by field ([`FetchError::Io`],
//! [`FetchError::LengthMismatch`], [`FetchError::FileVerifyFailed`], [`FetchError::BlockVerifyFailed`],
//! and the field-less [`FetchError::Cancelled`]) stay open instead: their field lists are the
//! commitment.

use std::path::PathBuf;

use thiserror::Error;
use url::Url;

use crate::retry::{Class, classify_status};

/// A download request that must not be attempted, rejected when the
/// [`DownloadSpec`](crate::DownloadSpec) is built. Distinct from [`FetchError`]: these are
/// configuration mistakes caught before any network contact, not transfer failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpecError {
    /// An unverified download (`Validator::None`) over a plain-`http://` source. Plain HTTP is
    /// allowed only when an out-of-band validator authenticates the bytes.
    #[error("refusing an unverified download over plain http: {url}")]
    #[non_exhaustive]
    UnverifiedOverPlainHttp {
        /// The plain-`http://` source that was refused.
        url: Url,
    },

    /// `Validator::None` was requested without the explicit opt-in acknowledging the bytes go
    /// unverified.
    #[error("unverified downloads must be acknowledged explicitly")]
    UnverifiedNotAcknowledged,

    /// The source scheme is neither `http` nor `https`.
    #[error("unsupported url scheme: {scheme}")]
    #[non_exhaustive]
    UnsupportedScheme {
        /// The scheme the URL carried.
        scheme: String,
    },

    /// A `Validator::External` download without a declared length.
    #[error("externally-verified downloads require a declared length")]
    ExternalRequiresLength,

    /// A `Validator::BlockSha1` block layout that is inconsistent: no declared length, a zero block
    /// size, an empty hash list, or a hash count that disagrees with what the length and block size
    /// imply.
    #[error("invalid block-hash layout: {reason}")]
    #[non_exhaustive]
    BlockLayout {
        /// Which consistency rule the block map broke.
        reason: &'static str,
    },
}

/// Download failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FetchError {
    /// The connection could not be established.
    #[error("connect to {host} failed")]
    #[non_exhaustive]
    Connect {
        /// The host that could not be reached.
        host: String,
        /// The underlying connect fault.
        #[source]
        source: std::io::Error,
    },

    /// The transfer failed after the connection was established: a dropped connection, a read error,
    /// or a TLS error while streaming the response body. Distinct from [`Connect`](FetchError::Connect)
    /// so a mid-stream drop is not mistaken for an unreachable host.
    #[error("transport error for {url}")]
    #[non_exhaustive]
    Transport {
        /// The source that was streaming when the transport failed.
        url: Url,
        /// The underlying stream fault.
        #[source]
        source: std::io::Error,
    },

    /// The server answered with a status the download cannot accept.
    #[error("http {status} for {url}")]
    #[non_exhaustive]
    Http {
        /// The status the server answered with.
        status: u16,
        /// The source that answered it.
        url: Url,
    },

    /// A redirect the client's policy would not follow: a chain past the hop cap, a hop leaving
    /// `https` for plaintext, or a hop to a scheme that is not HTTP. Never retried: the host answered
    /// fine, so this is a verdict on the source rather than a transient fault.
    #[error("refused a redirect while fetching {url}: {detail}")]
    #[non_exhaustive]
    RedirectRefused {
        /// The source whose redirect was refused.
        url: Url,
        /// Which floor rule the hop broke.
        detail: &'static str,
    },

    /// The transfer made no progress for too long, with no other source to try.
    #[error("stalled at {at_bytes} bytes: {url}")]
    #[non_exhaustive]
    Stalled {
        /// The lone source that went quiet.
        url: Url,
        /// How far the transfer had come when it did.
        at_bytes: u64,
    },

    /// One range failed on every source in turn until its attempt budget ran out. Distinct from
    /// [`Stalled`](FetchError::Stalled): the fact worth triaging here is that failover itself was
    /// exhausted, so `sources` and `attempts` say how wide and how hard the transfer tried.
    #[error("all {sources} sources failed {url} after {attempts} attempt(s), {at_bytes} bytes in")]
    #[non_exhaustive]
    AllSourcesFailed {
        /// The primary: the source list's head and the transfer's identity.
        url: Url,
        /// How many sources the rotation covered.
        sources: usize,
        /// How many attempts the stuck range spent.
        attempts: u32,
        /// How far the transfer had come when the budget ran out.
        at_bytes: u64,
    },

    /// The server's advertised length disagreed with the caller's expectation before bytes flowed.
    #[error("length mismatch: expected {expected}, got {got}")]
    LengthMismatch {
        /// The caller's declared length.
        expected: u64,
        /// The length the server advertised.
        got: u64,
    },

    /// The source changed underneath an in-flight resume in a way the transfer could not absorb.
    #[error("server file changed mid-resume for {url}: {detail}")]
    #[non_exhaustive]
    ServerFileChanged {
        /// The primary, whose validator the resume presented.
        url: Url,
        /// What the source did that reads as a change.
        detail: &'static str,
    },

    /// A block failed its hash after exhausting its retry budget.
    #[error("block {block} at offset {offset} failed verification after {attempts} attempt(s)")]
    BlockVerifyFailed {
        /// The block's index in the validator's hash list.
        block: u32,
        /// The block's byte offset in the file.
        offset: u64,
        /// How many attempts its re-fetches spent.
        attempts: u32,
    },

    /// The finished file's whole-file hash did not match the expected digest.
    #[error("file verification failed: expected {expected}, got {got}")]
    FileVerifyFailed {
        /// The pinned digest, in hex.
        expected: String,
        /// The digest the finished file hashed to, in hex.
        got: String,
    },

    /// A filesystem operation failed. Disk-full carries its own [`std::io::ErrorKind`]; see
    /// [`into_out_of_space`](FetchError::into_out_of_space) for the routed form.
    #[error("io error at {path:?}")]
    Io {
        /// The path the filesystem refused.
        path: PathBuf,
        /// The underlying fault; disk-full rides its `ErrorKind`.
        #[source]
        source: std::io::Error,
    },

    /// The HTTP client could not be constructed (the TLS backend failed to initialize).
    #[error("http client setup failed")]
    #[non_exhaustive]
    Client {
        /// What the TLS backend reported.
        #[source]
        source: std::io::Error,
    },

    /// A multi-range response could not be parsed or did not answer what was asked: a malformed
    /// `multipart/byteranges` body, a part whose `Content-Range` fell outside the requested ranges, or
    /// a boundary the `Content-Type` never declared.
    #[error("malformed range response for {url}: {detail}")]
    #[non_exhaustive]
    MalformedRangeResponse {
        /// The source whose response could not be honored.
        url: Url,
        /// Which shape rule the response broke.
        detail: &'static str,
    },

    /// A source shape the streaming path cannot handle: the multi-range transport, or a block
    /// validator that reached the engine without a declared length (the spec builder normally rejects
    /// that first).
    #[error("unsupported: {what}")]
    #[non_exhaustive]
    Unsupported {
        /// The shape the path cannot handle.
        what: &'static str,
    },

    /// A fetcher configuration the engine cannot serve, refused by
    /// [`FetcherBuilder::build`](crate::FetcherBuilder::build) before any client exists.
    #[error("fetcher configuration rejected: {detail}")]
    #[non_exhaustive]
    Config {
        /// The caps that were asked for and why they cannot run.
        detail: String,
    },

    /// The engine itself failed: a transfer task panicked or the runtime tore it down. A defect in
    /// this crate rather than a property of the source, the disk, or the caller's request.
    #[error("internal engine failure: {detail}")]
    #[non_exhaustive]
    Internal {
        /// What the engine was doing when it failed.
        detail: &'static str,
        /// What the runtime reported.
        #[source]
        source: std::io::Error,
    },

    /// The caller cancelled the transfer; the partial file and its journal survive for a resume.
    #[error("cancelled")]
    Cancelled,
}

impl FetchError {
    /// Whether asking again could succeed: the network faults, plus an [`Http`](FetchError::Http)
    /// status in the crate's own retryable set, plus [`ServerFileChanged`](FetchError::ServerFileChanged)
    /// (raised only after the journal is deleted, so what it asks for is a clean restart). Everything
    /// else, `_` included, is permanent.
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

    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }

    /// Take this failure apart as a full disk: the path the filesystem refused and the `ENOSPC` it
    /// raised.
    ///
    /// Only [`Io`](FetchError::Io) can carry it: preallocation and a `.part` write both raise
    /// `StorageFull` through that variant, while a network fault's own `io::Error` never does. A
    /// caller matching the enum directly would have to know that boundary, and would silently stop
    /// covering it if a later variant carried `StorageFull` too.
    ///
    /// # Errors
    /// The failure itself, unchanged, when it is not a full disk.
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
    use std::io::ErrorKind;
    use std::path::Path;

    use super::*;

    fn io(kind: ErrorKind) -> std::io::Error {
        std::io::Error::from(kind)
    }

    // The transience every variant is committed to, as an exhaustive match: adding a variant fails
    // this compile until it is classified here and sampled in the tests below, so a new failure
    // cannot fall into `is_transient`'s `_` arm unexamined. `None` is status-dependent (`Http`),
    // swept over every status in its own test.
    fn expected_transience(error: &FetchError) -> Option<bool> {
        match error {
            FetchError::Connect { .. }
            | FetchError::Transport { .. }
            | FetchError::Stalled { .. }
            | FetchError::AllSourcesFailed { .. }
            | FetchError::ServerFileChanged { .. } => Some(true),
            FetchError::Http { .. } => None,
            FetchError::RedirectRefused { .. }
            | FetchError::LengthMismatch { .. }
            | FetchError::BlockVerifyFailed { .. }
            | FetchError::FileVerifyFailed { .. }
            | FetchError::Io { .. }
            | FetchError::Client { .. }
            | FetchError::MalformedRangeResponse { .. }
            | FetchError::Unsupported { .. }
            | FetchError::Config { .. }
            | FetchError::Internal { .. }
            | FetchError::Cancelled => Some(false),
        }
    }

    // Which variants a full disk can arrive in, as an exhaustive match: `Io` alone. A variant added
    // later must take a row here, which is the prompt to decide whether `into_out_of_space` has to
    // start looking inside it too.
    fn may_carry_a_full_disk(error: &FetchError) -> bool {
        match error {
            FetchError::Io { .. } => true,
            FetchError::Connect { .. }
            | FetchError::Transport { .. }
            | FetchError::Http { .. }
            | FetchError::RedirectRefused { .. }
            | FetchError::Stalled { .. }
            | FetchError::AllSourcesFailed { .. }
            | FetchError::ServerFileChanged { .. }
            | FetchError::LengthMismatch { .. }
            | FetchError::BlockVerifyFailed { .. }
            | FetchError::FileVerifyFailed { .. }
            | FetchError::Client { .. }
            | FetchError::MalformedRangeResponse { .. }
            | FetchError::Unsupported { .. }
            | FetchError::Config { .. }
            | FetchError::Internal { .. }
            | FetchError::Cancelled => false,
        }
    }

    /// Network faults, a stalled source, exhausted failover, and a mid-resume source change are all
    /// transient.
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
                url: url.clone(),
                detail: "range ignored mid-transfer",
            },
        ] {
            assert!(error.is_transient(), "{error:?}");
            assert_eq!(expected_transience(&error), Some(true), "{error:?}");
        }
    }

    /// A failed check, a refusal, a local fault, and a cancellation are all permanent.
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
            FetchError::Config {
                detail: "5 files x 6 connections per file exceeds the global cap of 24".to_owned(),
            },
            FetchError::Internal {
                detail: "transfer task panicked",
                source: io(ErrorKind::Other),
            },
            FetchError::Cancelled,
        ] {
            assert!(!error.is_transient(), "{error:?}");
            assert_eq!(expected_transience(&error), Some(false), "{error:?}");
        }
    }

    /// `is_transient` for `Http` agrees with the crate's own backoff classification across every
    /// status 100..=599, so an outer retry loop never disagrees with the internal one.
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

    fn io_failure(kind: ErrorKind) -> FetchError {
        FetchError::io("/dest/out.part", io(kind))
    }

    #[test]
    fn a_disk_full_io_failure_yields_its_path_and_kind() {
        let (path, source) = io_failure(std::io::ErrorKind::StorageFull)
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
            let returned = io_failure(kind).into_out_of_space().err().ok_or(kind);
            assert!(
                matches!(returned, Ok(FetchError::Io { .. })),
                "{kind:?} was taken for a full disk",
            );
        }
    }

    #[test]
    fn a_transport_failure_carrying_an_io_error_is_not_a_full_disk() {
        // Connect/Transport/Internal wrap an `io::Error` of their own, so a caller matching on "has
        // an io::Error inside" would misread a network fault or an engine defect as a disk one.
        for err in [
            FetchError::Transport {
                url: Url::parse("https://example.invalid/f.bin").expect("static url"),
                source: std::io::ErrorKind::StorageFull.into(),
            },
            FetchError::Internal {
                detail: "transfer task panicked",
                source: std::io::ErrorKind::StorageFull.into(),
            },
            FetchError::Cancelled,
        ] {
            assert!(!may_carry_a_full_disk(&err), "{err:?}");
            assert!(err.into_out_of_space().is_err());
        }
        assert!(may_carry_a_full_disk(&io_failure(ErrorKind::StorageFull)));
    }
}
