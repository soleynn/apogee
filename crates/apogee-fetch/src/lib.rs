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
//! # Layout
//!
//! - [`Fetcher`] is the entry point: build one with [`Fetcher::builder`], then
//!   [`Fetcher::download`] or [`Fetcher::submit`] a [`DownloadSpec`].
//! - [`DownloadSpec`] describes one request; build it with [`DownloadSpec::builder`], which enforces
//!   the safety rules a [`SpecError`] reports when broken.
//! - [`Validator`] states how the bytes are checked; a passing check mints a [`VerifiedFile`], the
//!   only way to name a downloaded file as trustworthy.
//! - [`Progress`] and [`Recoveries`] are the two things every transfer reports: how far along, and
//!   what it recovered from (a retry, a stall, a dropped mirror, a block re-fetched after a bad
//!   hash) on the way there. Neither reaches the caller as an error, so without them a transfer that
//!   fought for every byte and one that sailed through are indistinguishable.
//! - [`Job`] is the handle [`Fetcher::submit`] returns for a transfer running on its own task.
//! - [`HttpRangeSource`] and [`Fetcher::fetch_ranges`] are the scatter-gather primitive behind
//!   repair.
//! - [`RetryPolicy`], [`HeaderPolicy`], [`LimitHandle`], and [`Priority`] configure backoff, request
//!   headers, a shared speed cap, and job ordering.
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
//!
//! # Examples
//!
//! Building a request:
//!
//! ```
//! use apogee_fetch::{DownloadSpec, Validator};
//!
//! let spec = DownloadSpec::builder(
//!     "https://example.invalid/patch.zip".parse().unwrap(),
//!     "/tmp/patch.zip",
//!     Validator::Sha256([0; 32]),
//! )
//! .expected_len(1024)
//! .build()
//! .unwrap();
//! assert_eq!(spec.expected_len(), Some(1024));
//! ```
//!
//! Running it:
//!
//! ```
//! # async fn demo(
//! #     fetcher: &apogee_fetch::Fetcher,
//! #     spec: &apogee_fetch::DownloadSpec,
//! # ) -> Result<(), apogee_fetch::FetchError> {
//! use tokio_util::sync::CancellationToken;
//!
//! let verified = fetcher.download(spec, None, CancellationToken::new()).await?;
//! let _path = verified.path();
//! # Ok(())
//! # }
//! ```

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
