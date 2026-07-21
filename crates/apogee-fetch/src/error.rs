//! Download failures and the reasons a download request is refused.
//!
//! Two surfaces. [`SpecError`] rejects a request that must never be attempted (an unverified
//! plain-HTTP source, an unacknowledged skip of verification, an unsupported scheme) at the single
//! construction site, so an unsafe request is unrepresentable rather than merely unchecked.
//! [`FetchError`] is the runtime taxonomy for a transfer that was attempted and failed; expected,
//! recoverable situations are values in the result types, not variants here.

use std::path::PathBuf;

use thiserror::Error;
use url::Url;

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

    /// A resume needed byte ranges the server would not serve.
    #[error("server does not support byte ranges: {url}")]
    RangesUnsupported { url: Url },

    /// The transfer made no progress for too long.
    #[error("stalled at {at_bytes} bytes: {url}")]
    Stalled { url: Url, at_bytes: u64 },

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

    /// The resume journal could not be read as a journal at all (as opposed to being merely stale,
    /// which silently restarts the download).
    #[error("download journal corrupt: {path:?}")]
    JournalCorrupt { path: PathBuf },

    /// A filesystem operation failed. Disk-full carries its own [`std::io::ErrorKind`].
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
    /// Build an [`Io`](FetchError::Io) at `path`, the single tidy build site for the crate's
    /// filesystem failures.
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
