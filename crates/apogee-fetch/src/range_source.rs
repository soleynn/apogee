//! [`HttpRangeSource`]: an [`apogee_zipatch::RangeSource`] that answers repair's byte-range requests
//! over HTTP, one source patch file at a time, via [`Fetcher::fetch_ranges`].

use std::ops::Range;

use tokio_util::sync::CancellationToken;
use url::Url;

use crate::error::FetchError;
use crate::fetcher::Fetcher;
use crate::headers::HeaderPolicy;
use crate::ranges::RangePacking;

/// One source patch a [`HttpRangeSource`] can fetch ranges of, keyed by its position in the chain:
/// `sources[i]` serves `PatchId(i)`, matching [`apogee_zipatch::Index::source_refs`] order.
///
/// `#[non_exhaustive]` and built only through [`new`](Self::new): a per-source input added later
/// widens the constructor rather than breaking every literal built elsewhere.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpSource {
    /// Where the patch file is served.
    pub url: Url,
    /// The patch file's length, cross-checked against each response's `Content-Range` total.
    pub expected_len: u64,
    /// The request header policy; `None` for no extra headers.
    pub policy: Option<HeaderPolicy>,
}

impl HttpSource {
    /// A source serving `url`, whose file is `expected_len` bytes long, with no extra request
    /// headers.
    #[must_use]
    pub fn new(url: Url, expected_len: u64) -> Self {
        Self {
            url,
            expected_len,
            policy: None,
        }
    }

    /// Set the request header policy.
    #[must_use]
    pub fn policy(mut self, policy: HeaderPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// An [`apogee_zipatch::RangeSource`] that fetches repair's requested byte ranges over HTTP, backing
/// each `PatchId(i)` with `sources[i]`.
#[derive(Debug)]
pub struct HttpRangeSource {
    fetcher: Fetcher,
    handle: tokio::runtime::Handle,
    sources: Vec<HttpSource>,
    packing: RangePacking,
    cancel: CancellationToken,
}

impl HttpRangeSource {
    /// Build a source over `fetcher`, reusing its pooled client, limiter, scheduler cap, and
    /// capability cache for every fetch, and bridging its async calls to this synchronous seam with
    /// `handle` (capture it on a runtime thread via `Handle::current()`). See
    /// [`read_ranges`](apogee_zipatch::RangeSource::read_ranges) for the resulting constraint on
    /// where repair may run.
    ///
    /// # Examples
    ///
    /// ```
    /// # fn demo(
    /// #     fetcher: apogee_fetch::Fetcher,
    /// #     handle: tokio::runtime::Handle,
    /// #     sources: Vec<apogee_fetch::HttpSource>,
    /// # ) -> Result<(), apogee_fetch::FetchError> {
    /// use apogee_fetch::HttpRangeSource;
    ///
    /// let range_source = HttpRangeSource::new(fetcher, handle, sources);
    /// # let _ = range_source;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn new(fetcher: Fetcher, handle: tokio::runtime::Handle, sources: Vec<HttpSource>) -> Self {
        Self {
            fetcher,
            handle,
            sources,
            packing: RangePacking::default(),
            cancel: CancellationToken::new(),
        }
    }

    /// Override the range-packing policy (default [`RangePacking::default`]).
    #[must_use]
    pub fn with_packing(mut self, packing: RangePacking) -> Self {
        self.packing = packing;
        self
    }

    /// Watch `cancel` while fetching, so repair driven through this adapter is interruptible
    /// mid-transfer rather than only between the planner's requests. A cancelled fetch surfaces to
    /// the planner as an i/o read fault, ending the repair with an error; there is no progress
    /// counterpart, since only the repair planner's own callback knows what a delivered span means to
    /// the file it is mending. Default: a token nothing cancels.
    #[must_use]
    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }
}

impl apogee_zipatch::RangeSource for HttpRangeSource {
    /// Fetches `ranges` of `sources[patch.0]` over HTTP, driving the fetch to completion on the
    /// calling thread via `Handle::block_on`.
    ///
    /// # Panics
    ///
    /// Panics if called from inside the async runtime `handle` belongs to. Drive
    /// [`apogee_zipatch::Index::repair`] from `tokio::task::spawn_blocking` or a dedicated thread,
    /// never directly inside an async task.
    fn read_ranges(
        &mut self,
        patch: apogee_zipatch::PatchId,
        ranges: &[Range<u64>],
        out: &mut dyn FnMut(u64, &[u8]) -> apogee_zipatch::Result<()>,
    ) -> apogee_zipatch::Result<()> {
        let source = self
            .sources
            .get(patch.0 as usize)
            .ok_or(apogee_zipatch::Error::Corrupt {
                offset: 0,
                detail: "http range source patch id out of range",
            })?;

        // The planner's `out` returns a zipatch error; capture it so the async fetch can be aborted and
        // the real error re-surfaced afterward (the sink's own return value never reaches the caller).
        let mut captured: Option<apogee_zipatch::Error> = None;
        let fetch = self.fetcher.fetch_ranges(
            source,
            ranges,
            self.packing,
            self.cancel.clone(),
            |off, bytes| match out(off, bytes) {
                Ok(()) => Ok(()),
                Err(err) => {
                    captured = Some(err);
                    Err(sink_abort())
                }
            },
        );
        match self.handle.block_on(fetch) {
            Ok(()) => Ok(()),
            Err(fetch_err) => Err(captured
                .take()
                .unwrap_or_else(|| fetch_to_zipatch(&fetch_err))),
        }
    }
}

/// A throwaway error the sink returns to abort a fetch after the planner's callback failed; its
/// contents never surface, since the captured zipatch error wins.
fn sink_abort() -> FetchError {
    FetchError::Internal {
        detail: "range sink aborted",
        source: std::io::Error::other("range sink aborted"),
    }
}

// A hard error here tells `Index::repair` the source is broken; its own retry policy owns recovery
// from there.
/// Maps a transport failure to the zipatch error taxonomy: a malformed range response is corrupt
/// source data, everything else an i/o read fault.
fn fetch_to_zipatch(err: &FetchError) -> apogee_zipatch::Error {
    match err {
        FetchError::MalformedRangeResponse { detail, .. } => {
            apogee_zipatch::Error::Corrupt { offset: 0, detail }
        }
        other => apogee_zipatch::Error::Io {
            source: std::io::Error::other(other.to_string()),
            target: None,
            during: apogee_zipatch::Op::Read,
        },
    }
}
