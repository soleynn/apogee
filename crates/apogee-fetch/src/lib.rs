#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Resumable, verified HTTP downloads.
//!
//! A download streams to a sidecar `.part` file, is checked against its [`Validator`], and is
//! published to its final path by an atomic rename only once verification passes, so a file present
//! at the destination is verified by construction. An interrupted transfer resumes from a CRC-framed
//! journal; progress is a stream of [`Progress`] events over a caller-owned channel, and cancellation
//! is a single token.
//!
//! What a transfer had to recover from on the way (a retry, a stall, a dropped mirror, a demotion, a
//! block re-fetched after a bad hash) rides the same events as [`Recoveries`], and each of those
//! sites also emits a `tracing` event with the source, offset and cause behind it. None of them
//! reaches the caller as an error, so without the two a transfer that fought for every byte and one
//! that sailed through are indistinguishable.
//!
//! # Stability
//!
//! The crate's version commitment covers the default feature set. `testing` and `fuzzing` are
//! development seams, compiled only into test and fuzz builds; what they expose can change without
//! a major version.
//!
//! One foreign seam is load-bearing: [`HttpRangeSource`] implements `apogee-zipatch`'s
//! `RangeSource`, so that trait's signature, `PatchId`, and the `Error::Io`/`Error::Corrupt`
//! variants this adapter constructs are part of this crate's public surface. A breaking change to
//! that seam is a breaking change here: the two crates version together across it, and the seam's
//! side of the commitment is recorded beside those items in `apogee-zipatch`.

mod block;
mod download;
mod error;
mod fetcher;
mod hash;
mod headers;
mod intervals;
mod job;
mod journal;
mod limiter;
mod multipart;
mod prealloc;
mod probe;
mod progress;
mod range_source;
mod ranges;
mod redirect;
mod retry;
mod scheduler;
mod segmented;
mod spec;
mod util;
mod validator;

pub use error::{FetchError, SpecError};
pub use fetcher::{Fetcher, FetcherBuilder};
pub use hash::{DigestPin, HexPins};
pub use headers::HeaderPolicy;
pub use job::Job;
pub use limiter::LimitHandle;
pub use progress::{Phase, Progress, Recoveries};
pub use range_source::{HttpRangeSource, HttpSource};
pub use ranges::RangePacking;
pub use retry::RetryPolicy;
pub use scheduler::Priority;
pub use spec::{DownloadSpec, DownloadSpecBuilder};
pub use validator::{Validator, VerifiedFile};

/// Unstable surface for fuzz targets only; gated to the `fuzzing` feature and never part of the
/// public contract.
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub use crate::journal::fuzz_decode;
    pub use crate::multipart::fuzz_multipart;
}
