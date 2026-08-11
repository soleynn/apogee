//! Pins the public API surface ahead of the version commitment: every public item, the exact
//! signature of every public method, and the auto-traits consumers rely on.
//!
//! Signatures are pinned by coercing each method to a function pointer of its written-out type, so
//! a changed parameter, return type, or receiver fails this compile rather than surfacing as a
//! consumer break after the fact. Additive change (a new method, a new variant on a
//! `#[non_exhaustive]` enum, a new field on a sealed variant) passes untouched, which is the point:
//! only the commitments break.
//!
//! Async methods do not coerce to `fn` pointers, so each is pinned by a monomorphic wrapper whose
//! own signature restates the method's; a drifted method fails to typecheck inside the wrapper.

use std::ops::Range;
use std::path::{Path, PathBuf};

use apogee_fetch::{
    DigestPin, DownloadSpec, DownloadSpecBuilder, FetchError, Fetcher, FetcherBuilder,
    HeaderPolicy, HexPins, HttpRangeSource, HttpSource, Job, LimitHandle, Phase, Priority,
    Progress, RangePacking, Recoveries, RetryPolicy, SpecError, Validator, VerifiedFile,
};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};
use tokio_util::sync::CancellationToken;
use url::Url;

/// Every non-async public signature, as function-pointer coercions. Never called; compiling is the
/// assertion.
#[allow(dead_code)]
fn signatures() {
    // Fetcher
    let _: fn() -> FetcherBuilder = Fetcher::builder;
    let _: fn(&Fetcher, DownloadSpec) -> Job = Fetcher::submit;

    // FetcherBuilder
    let _: fn(FetcherBuilder, usize) -> FetcherBuilder = FetcherBuilder::max_files;
    let _: fn(FetcherBuilder, usize) -> FetcherBuilder = FetcherBuilder::max_connections_per_file;
    let _: fn(FetcherBuilder, usize) -> FetcherBuilder = FetcherBuilder::max_connections_total;
    let _: fn(FetcherBuilder, LimitHandle) -> FetcherBuilder = FetcherBuilder::speed_limit;
    let _: fn(FetcherBuilder, std::time::Duration) -> FetcherBuilder = FetcherBuilder::stall_timeout;
    let _: fn(FetcherBuilder, RetryPolicy) -> FetcherBuilder = FetcherBuilder::retry_policy;
    let _: fn(FetcherBuilder) -> Result<Fetcher, FetchError> = FetcherBuilder::build;

    // DownloadSpec. `builder` takes `impl Into<PathBuf>`, which cannot coerce to a fn pointer, so
    // it is pinned by a monomorphic wrapper like the async methods below.
    fn builder(url: Url, dest: PathBuf, validator: Validator) -> DownloadSpecBuilder {
        DownloadSpec::builder(url, dest, validator)
    }
    let _: fn(Url, PathBuf, Validator) -> DownloadSpecBuilder = builder;
    let _: fn(&DownloadSpec) -> &Url = DownloadSpec::url;
    let _: fn(&DownloadSpec) -> &[Url] = DownloadSpec::mirrors;
    let _: fn(&DownloadSpec) -> Option<&HeaderPolicy> = DownloadSpec::header_policy;
    let _: fn(&DownloadSpec) -> &Path = DownloadSpec::dest;
    let _: fn(&DownloadSpec) -> Option<u64> = DownloadSpec::expected_len;
    let _: fn(&DownloadSpec) -> &Validator = DownloadSpec::validator;
    let _: fn(&DownloadSpec) -> bool = DownloadSpec::resume;
    let _: fn(&DownloadSpec) -> Priority = DownloadSpec::priority;

    // DownloadSpecBuilder
    let _: fn(DownloadSpecBuilder, u64) -> DownloadSpecBuilder = DownloadSpecBuilder::expected_len;
    let _: fn(DownloadSpecBuilder, bool) -> DownloadSpecBuilder = DownloadSpecBuilder::resume;
    let _: fn(DownloadSpecBuilder, Priority) -> DownloadSpecBuilder = DownloadSpecBuilder::priority;
    let _: fn(DownloadSpecBuilder, Url) -> DownloadSpecBuilder = DownloadSpecBuilder::mirror;
    fn mirrors(b: DownloadSpecBuilder, urls: Vec<Url>) -> DownloadSpecBuilder {
        b.mirrors(urls)
    }
    let _: fn(DownloadSpecBuilder, Vec<Url>) -> DownloadSpecBuilder = mirrors;
    let _: fn(DownloadSpecBuilder, HeaderPolicy) -> DownloadSpecBuilder =
        DownloadSpecBuilder::header_policy;
    let _: fn(DownloadSpecBuilder) -> DownloadSpecBuilder = DownloadSpecBuilder::allow_unverified;
    let _: fn(DownloadSpecBuilder) -> Result<DownloadSpec, SpecError> = DownloadSpecBuilder::build;

    // Job
    let _: fn(&mut Job) -> UnboundedReceiver<Progress> = Job::progress;
    let _: fn(&Job) = Job::cancel;
    let _: fn(&Job) -> CancellationToken = Job::cancel_token;

    // HeaderPolicy
    let _: fn(Option<String>) -> HeaderPolicy = HeaderPolicy::se_patch;

    // HttpSource / HttpRangeSource
    let _: fn(Url, u64) -> HttpSource = HttpSource::new;
    let _: fn(HttpSource, HeaderPolicy) -> HttpSource = HttpSource::policy;
    let _: fn(Fetcher, tokio::runtime::Handle, Vec<HttpSource>) -> HttpRangeSource =
        HttpRangeSource::new;
    let _: fn(HttpRangeSource, RangePacking) -> HttpRangeSource = HttpRangeSource::with_packing;
    let _: fn(HttpRangeSource, CancellationToken) -> HttpRangeSource = HttpRangeSource::with_cancel;

    // RangePacking
    let _: fn(RangePacking, usize) -> RangePacking = RangePacking::max_ranges;
    let _: fn(RangePacking, usize) -> RangePacking = RangePacking::max_range_header_bytes;

    // DigestPin / HexPins
    let _: fn(HexPins<'_>) -> Option<DigestPin> = DigestPin::from_hex;
    let _: fn(&DigestPin) -> [u8; 32] = DigestPin::bytes;
    let _: fn(DigestPin) -> Validator = Validator::from;

    // Errors
    let _: fn(&FetchError) -> bool = FetchError::is_transient;
    let _: fn(FetchError) -> Result<(PathBuf, std::io::Error), FetchError> =
        FetchError::into_out_of_space;

    // Progress family
    let _: fn(&Recoveries) -> bool = Recoveries::is_clean;

    // VerifiedFile
    let _: fn(&VerifiedFile) -> &Path = VerifiedFile::path;
}

/// The async methods, pinned by monomorphic wrappers: a drifted signature fails to typecheck here.
#[allow(dead_code, clippy::too_many_arguments)]
mod async_signatures {
    use super::*;

    async fn download(
        f: &Fetcher,
        spec: &DownloadSpec,
        progress: Option<UnboundedSender<Progress>>,
        cancel: CancellationToken,
    ) -> Result<VerifiedFile, FetchError> {
        f.download(spec, progress, cancel).await
    }

    async fn download_external(
        f: &Fetcher,
        spec: &DownloadSpec,
        progress: Option<UnboundedSender<Progress>>,
        cancel: CancellationToken,
    ) -> Result<PathBuf, FetchError> {
        f.download_external(spec, progress, cancel).await
    }

    async fn fetch_ranges(
        f: &Fetcher,
        source: &HttpSource,
        ranges: &[Range<u64>],
        packing: RangePacking,
        cancel: CancellationToken,
        sink: fn(u64, &[u8]) -> Result<(), FetchError>,
    ) -> Result<(), FetchError> {
        f.fetch_ranges(source, ranges, packing, cancel, sink).await
    }

    async fn wait(job: Job) -> Result<VerifiedFile, FetchError> {
        job.wait().await
    }

    /// `Job` is awaitable directly.
    async fn into_future(job: Job) -> Result<VerifiedFile, FetchError> {
        job.await
    }
}

/// The auto-traits and standard traits consumers rely on; losing one is a breaking change no
/// signature pin sees.
#[test]
fn public_types_keep_their_trait_obligations() {
    fn send_sync<T: Send + Sync>() {}
    fn debuggable<T: std::fmt::Debug>() {}
    fn cloneable<T: Clone>() {}
    fn copyable<T: Copy>() {}
    fn defaulted<T: Default>() {}
    fn error<T: std::error::Error>() {}

    send_sync::<Fetcher>();
    send_sync::<Job>();
    send_sync::<DownloadSpec>();
    send_sync::<LimitHandle>();
    send_sync::<HttpRangeSource>();
    send_sync::<FetchError>();
    send_sync::<SpecError>();

    debuggable::<Fetcher>();
    debuggable::<FetcherBuilder>();
    debuggable::<DownloadSpec>();
    debuggable::<DownloadSpecBuilder>();
    debuggable::<Job>();
    debuggable::<HttpSource>();
    debuggable::<HttpRangeSource>();
    debuggable::<HeaderPolicy>();
    debuggable::<Validator>();
    debuggable::<VerifiedFile>();
    debuggable::<Progress>();
    debuggable::<Phase>();
    debuggable::<Recoveries>();
    debuggable::<RangePacking>();
    debuggable::<RetryPolicy>();
    debuggable::<Priority>();
    debuggable::<DigestPin>();
    debuggable::<HexPins<'_>>();
    debuggable::<LimitHandle>();
    debuggable::<FetchError>();
    debuggable::<SpecError>();

    cloneable::<Fetcher>();
    cloneable::<DownloadSpec>();
    cloneable::<HttpSource>();
    cloneable::<HeaderPolicy>();
    cloneable::<Validator>();
    cloneable::<Progress>();
    cloneable::<LimitHandle>();

    copyable::<Phase>();
    copyable::<Recoveries>();
    copyable::<RangePacking>();
    copyable::<RetryPolicy>();
    copyable::<Priority>();
    copyable::<DigestPin>();
    copyable::<HexPins<'_>>();

    defaulted::<Progress>();
    defaulted::<Phase>();
    defaulted::<Recoveries>();
    defaulted::<RangePacking>();
    defaulted::<RetryPolicy>();
    defaulted::<Priority>();
    defaulted::<HexPins<'_>>();

    error::<FetchError>();
    error::<SpecError>();
}
