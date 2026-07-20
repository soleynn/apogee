#![forbid(unsafe_code)]
//! Resumable, verified HTTP downloads.
//!
//! A download streams to a sidecar `.part` file, is checked against its [`Validator`], and is
//! published to its final path by an atomic rename only once verification passes, so a file present
//! at the destination is verified by construction. An interrupted transfer resumes from a CRC-framed
//! journal; progress is a stream of [`Progress`] events over a caller-owned channel, and cancellation
//! is a single token.

mod download;
mod error;
mod fetcher;
mod intervals;
mod job;
mod journal;
mod limiter;
mod prealloc;
mod probe;
mod progress;
mod scheduler;
mod segmented;
mod spec;
mod validator;

pub use error::{FetchError, SpecError};
pub use fetcher::{Fetcher, FetcherBuilder};
pub use job::Job;
pub use limiter::LimitHandle;
pub use progress::{Phase, Progress};
pub use scheduler::Priority;
pub use spec::{DownloadSpec, DownloadSpecBuilder};
pub use validator::{Validator, VerifiedFile};

/// Unstable surface for fuzz targets only; gated to the `fuzzing` feature and never part of the
/// public contract.
#[cfg(feature = "fuzzing")]
pub mod fuzzing {
    pub use crate::journal::fuzz_decode;
}
