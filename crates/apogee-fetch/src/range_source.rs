//! [`HttpRangeSource`]: the HTTP implementor of `apogee-zipatch`'s `RangeSource` seam.
//!
//! `apogee-zipatch`'s repair planner asks a `RangeSource` for byte ranges of one source patch file
//! at a time; this adapter answers those over HTTP via [`Fetcher::fetch_ranges`]. It maps each
//! `PatchId` to a URL (the chain order `Index::source_refs` names), then packs and fetches the
//! requested ranges, handing each fetched span back to the planner's callback.
//!
//! **Sync-over-async bridge.** `RangeSource::read_ranges` is synchronous, but the fetcher is async.
//! The adapter holds a [`tokio::runtime::Handle`] and drives each fetch with `Handle::block_on`,
//! reusing the one `Fetcher` (its pooled client, limiter, scheduler cap, capability cache). Because
//! `Handle::block_on` panics inside an async execution context, **repair must run off the runtime** —
//! a caller drives `Index::repair` from `tokio::task::spawn_blocking` or a dedicated thread, never
//! directly inside an async task.

use std::ops::Range;

use tokio_util::sync::CancellationToken;
use url::Url;

use crate::error::FetchError;
use crate::fetcher::Fetcher;
use crate::headers::HeaderPolicy;
use crate::ranges::RangePacking;

/// One source patch a [`HttpRangeSource`] can fetch ranges of, keyed by its position in the chain
/// (`sources[i]` serves `PatchId(i)`, matching `Index::source_refs` order).
///
/// `#[non_exhaustive]`: built through [`new`](Self::new) and read through its public fields, so a
/// per-source input added later (the way the patch token question could land) widens the
/// constructor set rather than breaking every literal.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpSource {
    /// Where the patch file is served.
    pub url: Url,
    /// The patch file's length, cross-checked against each response's `Content-Range` total.
    pub expected_len: u64,
    /// The request header policy (e.g. the Square Enix patch `User-Agent`); `None` for no extra headers.
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

    /// Set the request header policy (e.g. the Square Enix patch `User-Agent`).
    #[must_use]
    pub fn policy(mut self, policy: HeaderPolicy) -> Self {
        self.policy = Some(policy);
        self
    }
}

/// An `apogee-zipatch` `RangeSource` that pulls broken byte ranges over HTTP. Built from a `Fetcher`,
/// a runtime handle, and the per-patch source table; see the module docs for the off-runtime rule.
#[derive(Debug)]
pub struct HttpRangeSource {
    fetcher: Fetcher,
    handle: tokio::runtime::Handle,
    sources: Vec<HttpSource>,
    packing: RangePacking,
    cancel: CancellationToken,
}

impl HttpRangeSource {
    /// Back each `PatchId(i)` with `sources[i]`, fetching through `fetcher` and bridging to it with
    /// `handle`. Capture `handle` on a runtime thread (`Handle::current()`); `read_ranges` must then be
    /// called off the runtime (see the module docs).
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

    /// Watch `cancel` while fetching, so a repair pass driven through this adapter is interruptible
    /// mid-transfer rather than only between the planner's requests. A cancelled fetch surfaces to
    /// the planner as an i/o read fault (the seam's taxonomy has no cancel of its own), which ends
    /// the repair with an error exactly as the caller asked. Default: a token nothing cancels.
    ///
    /// No progress counterpart, deliberately: only the repair planner knows what a delivered span
    /// means to the file it is mending, so per-file progress belongs to its report callback rather
    /// than to a byte tally here.
    #[must_use]
    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = cancel;
        self
    }
}

impl apogee_zipatch::RangeSource for HttpRangeSource {
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
/// contents never surface (the captured zipatch error wins), so only its role matters.
fn sink_abort() -> FetchError {
    FetchError::Internal {
        detail: "range sink aborted",
        source: std::io::Error::other("range sink aborted"),
    }
}

/// Map a transport failure into the zipatch error taxonomy: a malformed range response is corrupt
/// source data, everything else an i/o read fault. A hard error here tells `Index::repair` the source
/// is broken, and its retry policy owns recovery.
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
