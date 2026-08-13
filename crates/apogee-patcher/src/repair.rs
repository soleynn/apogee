//! The repair pipeline: verify a repo against its block index, re-fetch only the broken byte ranges,
//! reconstruct zero/empty regions locally, and quarantine strays.
//!
//! Both lower crates do the work; this module owns only the policy between them. `apogee-zipatch`
//! verifies and reconstructs (it reports broken parts and heals them from a [`RangeSource`]);
//! `apogee-fetch` moves bytes (`HttpRangeSource` pulls ranges over the wire). The patcher decides the
//! order (local patch files trusted on the first attempt, HTTP after), the reattempt budget, the
//! version cross-check, and the stray-quarantine, and it finalizes `.ver` after a clean heal.
//!
//! The verify/repair core is synchronous and `HttpRangeSource` bridges to the async fetcher with
//! `Handle::block_on`, so the whole per-repo pass runs on a blocking worker off the runtime (the
//! `RangeSource` off-runtime rule, `apogee-fetch`'s `range_source` docs).

use std::collections::HashMap;
use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use apogee_fetch::{
    DownloadSpec, FetchError, Fetcher, HeaderPolicy, HttpRangeSource, HttpSource, Validator,
};
use apogee_zipatch::{
    Index, LocalPatchSource, RangeSource, RepairOutcome as ZipRepair, VerifyOptions, VerifyReport,
};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::elevated::Executor;
use crate::request::{IndexSource, RepairRepo, RepairRequest};
use crate::{PartRef, PatchError, PatchProgress, PatcherConfig, Repo, preflight, recycler, store};

/// One repo's repair result: the version it now verifies clean against, the counts healed, the bytes
/// pulled over HTTP, and the strays moved to the recycler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairedRepo {
    pub repo: Repo,
    /// The version the repo verifies against after the heal (its `.ver` was advanced to this).
    pub version: String,
    /// Broken parts rewritten in place across all passes.
    pub repaired_parts: usize,
    /// Missing files recreated.
    pub recreated: usize,
    /// Wrong-length files resized.
    pub resized: usize,
    /// Bytes pulled over HTTP for this repo (zero when local patches sufficed).
    pub bytes_refetched: u64,
    /// Strays moved to the recycler (install-root-relative paths), never deleted.
    pub quarantined: Vec<PathBuf>,
}

/// The outcome of a [`Patcher::repair`](crate::Patcher::repair): one entry per repo plus the
/// aggregate byte count and quarantine list, the proof a repair pulled only broken ranges and
/// deleted nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairOutcome {
    pub repos: Vec<RepairedRepo>,
    /// Total bytes pulled over HTTP across every repo.
    pub bytes_refetched: u64,
    /// Every stray quarantined across every repo (install-root-relative), never deleted.
    pub quarantined: Vec<PathBuf>,
}

/// Run a repair across every requested repo.
pub(crate) async fn run(
    fetcher: Fetcher,
    config: PatcherConfig,
    request: RepairRequest,
    progress: mpsc::UnboundedSender<PatchProgress>,
    cancel: CancellationToken,
) -> Result<RepairOutcome, PatchError> {
    let RepairRequest { game_root, repos } = request;
    // Asked once for the request rather than per repo: a repair rewrites files in place, and a client
    // that is running holds them whichever repo it was launched from.
    preflight::game_not_running(&config, &game_root)?;
    // One batch directory for the whole request, so strays from several repos land together.
    let batch = recycler::batch_name(SystemTime::now());
    let handle = Handle::current();
    let mut outcome = RepairOutcome::default();

    // Where the writes happen, decided once before the first verify. Every repo subtree the request
    // names, plus the install root itself, because a stray is quarantined into a recycler beside
    // those subtrees rather than inside one.
    let mut roots: Vec<PathBuf> = repos
        .iter()
        .map(|repo_req| store::repo_root(&game_root, repo_req.repo))
        .collect();
    roots.push(game_root.clone());
    let mut executor = Executor::open_unbound(&config, &roots).await?;
    let staging = StagingFile::under(&config.patch_store)?;

    for repo_req in repos {
        if cancel.is_cancelled() {
            return Err(PatchError::Cancelled);
        }
        // Acquire the index bytes (an async fetch for a pinned source), then hand the sync verify and
        // repair to a blocking worker: `HttpRangeSource` uses `Handle::block_on`, which must not run
        // inside an async task.
        let index_path = acquire_index(&fetcher, &config, &repo_req, &cancel).await?;
        let ctx = RepoCtx {
            fetcher: fetcher.clone(),
            handle: handle.clone(),
            game_root: game_root.clone(),
            index_path,
            batch: batch.clone(),
            staging: staging.path.clone(),
            reattempts: config.repair_reattempts.max(1),
            progress: progress.clone(),
            cancel: cancel.clone(),
        };
        // The executor rides onto the blocking worker and back: the repair sink drives it from
        // there, exactly as the range source drives the fetcher from there.
        let carried = executor;
        let (result, returned) = tokio::task::spawn_blocking(move || {
            let mut executor = carried;
            let result = repair_repo(&repo_req, &ctx, &mut executor);
            (result, executor)
        })
        .await
        .map_err(join_to_io)?;
        executor = returned;
        let repaired = result?;

        outcome.bytes_refetched = outcome
            .bytes_refetched
            .saturating_add(repaired.bytes_refetched);
        outcome
            .quarantined
            .extend(repaired.quarantined.iter().cloned());
        outcome.repos.push(repaired);
    }
    executor.finish().await;
    Ok(outcome)
}

/// The file a privileged repair stages its bytes in, removed when the run ends.
///
/// Named per process and per run rather than fixed, so two repairs at once do not read each other's
/// batches, and removed on the way out however the run ended: a staging file left behind is bytes
/// nothing will ever read again.
struct StagingFile {
    path: PathBuf,
}

impl StagingFile {
    /// The staging path beneath `patch_store`. Nothing is created here; a repair that stays in
    /// process never touches it.
    fn under(patch_store: &Path) -> Result<Self, PatchError> {
        let stamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let path = patch_store
            .join("repair")
            .join(format!("staged-{}-{stamp:x}.bin", std::process::id()));
        // Absolute because the worker refuses a relative path, and this process's working directory
        // is not the one an elevated child inherits.
        std::path::absolute(&path)
            .map(|path| Self { path })
            .map_err(|source| PatchError::Io { path, source })
    }
}

impl Drop for StagingFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        // Only if this run left it empty; a concurrent repair's file keeps it.
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::remove_dir(parent);
        }
    }
}

/// The per-repo inputs threaded onto the blocking worker.
struct RepoCtx {
    fetcher: Fetcher,
    handle: Handle,
    game_root: PathBuf,
    index_path: PathBuf,
    batch: String,
    staging: PathBuf,
    reattempts: usize,
    progress: mpsc::UnboundedSender<PatchProgress>,
    cancel: CancellationToken,
}

/// Obtain the repo's `.apzi` on local disk: a local source is used in place, a pinned source is
/// fetched under its digest pin (allowed over plain HTTP because the pin authenticates the bytes).
async fn acquire_index(
    fetcher: &Fetcher,
    config: &PatcherConfig,
    repo_req: &RepairRepo,
    cancel: &CancellationToken,
) -> Result<PathBuf, PatchError> {
    let repo = repo_req.repo;
    match &repo_req.index {
        IndexSource::LocalFile(path) => Ok(path.clone()),
        IndexSource::Pinned { url, pin } => {
            let dest = config
                .patch_store
                .join("indexes")
                .join(index_filename(repo, &repo_req.target_version));
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent).map_err(|source| PatchError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
            let spec = DownloadSpec::builder(url.clone(), dest, Validator::from(*pin))
                .build()
                .map_err(|e| index_unavailable(repo, e))?;
            let verified = fetcher
                .download(&spec, None, cancel.clone())
                .await
                .map_err(|e| index_acquire_err(e, repo))?;
            Ok(verified.path().to_path_buf())
        }
    }
}

/// Map a fetch failure taken while pulling the block index into the patcher taxonomy: a cancellation
/// stays [`PatchError::Cancelled`], a full disk becomes [`PatchError::OutOfSpace`], everything else
/// says the index is unavailable.
///
/// The disk-full arm is here for the same reason [`install::acquire_err`](crate::install) has one:
/// the index lands in the patch store like any other download, so the store filling is a failure
/// this call can produce, and it is not the index being unreachable. Reported that way it sends a
/// caller looking at the catalog and the network instead of at free space.
///
/// Named rather than written inline at the one call site so the routing can be asserted directly:
/// the arms are hand-written, and dropping either one leaves a `match` that still compiles and an
/// end-to-end suite that still passes.
fn index_acquire_err(err: FetchError, repo: Repo) -> PatchError {
    if matches!(err, FetchError::Cancelled) {
        return PatchError::Cancelled;
    }
    match err.into_out_of_space() {
        Ok((path, source)) => PatchError::OutOfSpace { path, source },
        Err(other) => index_unavailable(repo, other),
    }
}

/// The cached filename for a fetched index: distinct per repo and version so expansions and versions
/// do not collide under `indexes/`.
fn index_filename(repo: Repo, target_version: &str) -> String {
    let tag = match repo {
        Repo::Boot => "boot".to_owned(),
        Repo::Game => "game".to_owned(),
        Repo::Expansion(n) => format!("ex{n}"),
    };
    format!("{tag}-{}.apzi", store::bare_version(target_version))
}

/// Verify one repo against its index and heal it. Synchronous and off the runtime.
fn repair_repo(
    repo_req: &RepairRepo,
    ctx: &RepoCtx,
    executor: &mut Executor,
) -> Result<RepairedRepo, PatchError> {
    let repo = repo_req.repo;
    let index = read_index(&ctx.index_path, repo)?;

    // Version cross-check, made loud: the index must describe the version we mean to heal to, or a
    // wrong-version index could rewrite bytes to the wrong contents. Compared on the bare form so a
    // list-prefix letter does not spuriously mismatch.
    let wanted = store::bare_version(&repo_req.target_version);
    let have = store::bare_version(index.repo_version());
    if wanted != have {
        return Err(PatchError::VersionCrossCheck {
            repo,
            index_version: index.repo_version().to_owned(),
            wanted: repo_req.target_version.clone(),
        });
    }

    let root = store::repo_root(&ctx.game_root, repo);

    // The initial full pass: broken parts, wrong lengths, missing files, and strays.
    let _ = ctx
        .progress
        .send(PatchProgress::Verifying { repo, attempt: 0 });
    let report = index
        .verify(&root, &VerifyOptions::default())
        .map_err(PatchError::Apply)?;

    // Quarantine strays up front (they are independent of the block heal and always safe to relocate),
    // so even a heal that later fails still moves them out of the tree rather than deleting them.
    let quarantined = if report.stray_files.is_empty() {
        Vec::new()
    } else {
        let _ = ctx.progress.send(PatchProgress::Quarantining {
            repo,
            count: report.stray_files.len(),
        });
        ctx.handle.block_on(executor.quarantine(
            &ctx.game_root,
            repo,
            &ctx.batch,
            &report.stray_files,
        ))?
    };

    // From here on every write is inside the repo subtree, so that is what the executor is pointed
    // at: the quarantine above is the only phase whose two ends are not both in it.
    ctx.handle.block_on(executor.bind(&root))?;

    // Addressing the chain's source patches is deferred until the verify says something has to be
    // pulled from one. A repo can reference sources this request cannot form a URL for (no cached copy
    // and no base to derive one under), and that is only a failure when a broken part actually has to
    // come from one: a repo that verifies clean has nothing to fetch and must not fail for want of a
    // source it never reads. Resolving up front made one unaddressable repo abort the whole run,
    // healthy or not, which on an install whose patch cache is gone is every repo the base URL does
    // not cover.
    let (local_files, http_sources) = if has_work(&report) {
        resolve_sources(&index, repo_req)?
    } else {
        (None, Vec::new())
    };

    // The reattempt loop: pass 0 trusts local patch files when the whole chain is cached, every pass
    // after re-fetches over HTTP (the reference's corrupt-local insurance). Each pass re-verifies only
    // the parts it touched (zipatch's refine), so a retry never re-hashes a healthy tree. A pass that
    // raises a hard fault (a corrupt local file, or a transient transport error) does not abort the
    // repair: it is spent like a soft miss, so the budget covers both. `pending` is left unchanged on a
    // fault, so the next pass redoes the same work (zipatch's positioned writes are idempotent).
    let mut agg = RepairAgg::default();
    let mut pending = report;
    let mut residue: Vec<apogee_zipatch::PartRef> = Vec::new();
    let mut last_fault: Option<PatchError> = None;
    let mut healed = false;
    let mut attempt = 0u32;
    while (attempt as usize) < ctx.reattempts && has_work(&pending) {
        if ctx.cancel.is_cancelled() {
            return Err(PatchError::Cancelled);
        }
        // Pass 0 reads local patch files when the whole chain is cached; every other pass pulls over
        // HTTP. Only the HTTP passes count toward `bytes_refetched` (the network byte-accounting) and
        // toward the `Refetching` progress; a local pass delivers bytes but fetches nothing.
        let over_network = !(attempt == 0 && local_files.is_some());
        let mut source = compose_source(ctx, attempt, &local_files, &http_sources);
        let mut sink = executor.repair_sink(&root, &ctx.staging, ctx.handle.clone(), &ctx.cancel);
        match index.repair_into(&root, &pending, source.as_mut(), &mut *sink) {
            Ok(outcome) => {
                last_fault = None;
                agg.absorb(&outcome, over_network);
                if over_network {
                    let _ = ctx.progress.send(PatchProgress::Refetching {
                        repo,
                        attempt,
                        bytes: outcome.bytes_fetched,
                    });
                }
                if outcome.is_complete() {
                    healed = true;
                    break;
                }
                residue = outcome.still_broken.clone();
                pending = VerifyReport {
                    broken: outcome.still_broken,
                    ..VerifyReport::default()
                };
            }
            // A sink that writes somewhere this process cannot reach unwinds through zipatch's error
            // type, which has no room for what actually failed; it kept that and hands it back here.
            Err(fault) => {
                let fault = sink.fault().unwrap_or(PatchError::Apply(fault));
                if ends_the_repair(&fault) {
                    return Err(fault);
                }
                last_fault = Some(fault);
            }
        }
        attempt += 1;
    }

    // Failure only if the tree is not healed and work remains: a hard fault that outlived the budget
    // surfaces as itself; an otherwise-clean pass that could not source some parts surfaces as `Verify`.
    if !healed && has_work(&pending) {
        if let Some(fault) = last_fault {
            return Err(fault);
        }
        if let Some(first) = residue.first() {
            return Err(PatchError::Verify {
                repo,
                broken: residue.len(),
                first: PartRef {
                    repo,
                    path: first.path.clone(),
                    offset: first.target_off,
                },
            });
        }
    }

    // Clean: record the healed version exactly as an install would (bare, then `.bck`), through
    // whichever side did the writing, since the version file lives in the tree that needed it.
    ctx.handle
        .block_on(executor.advance_ver(&ctx.game_root, repo, &wanted))?;
    ctx.handle
        .block_on(executor.backup_ver(&ctx.game_root, repo))?;
    let _ = ctx.progress.send(PatchProgress::Repaired {
        repo,
        version: wanted.clone(),
    });

    Ok(RepairedRepo {
        repo,
        version: wanted,
        repaired_parts: agg.repaired,
        recreated: agg.recreated,
        resized: agg.resized,
        bytes_refetched: agg.bytes,
        quarantined,
    })
}

/// Whether a pass's failure ends the repo's repair rather than spending one of its reattempts.
///
/// Almost nothing does. The budget exists for exactly the faults a second pass can get past, and a
/// privileged pass fails the same ways an in-process one does: a write that was refused, bytes that
/// did not match, a transport that dropped. Those are spent, so the two arms give a broken repo the
/// same number of chances.
///
/// The two that end it are the ones no later pass can improve on. A run the user stopped is not
/// worth re-fetching for. And a worker that could not start, or that stopped answering, has taken
/// the only thing that can write the tree with it: every later pass would pull the same ranges over
/// the network again and then find nothing on the other end. Written out rather than folded into the
/// `match` above so the routing can be asserted directly; both arms are hand-written, and widening
/// either one leaves a repair that still compiles and an end-to-end suite that still passes.
fn ends_the_repair(fault: &PatchError) -> bool {
    match fault {
        PatchError::Cancelled => true,
        PatchError::Worker { kind, .. } => matches!(
            kind,
            crate::WorkerErrorKind::Spawn | crate::WorkerErrorKind::Protocol
        ),
        _ => false,
    }
}

/// Whether a verify report still names something to heal (strays are handled separately).
fn has_work(report: &VerifyReport) -> bool {
    !report.broken.is_empty()
        || !report.missing_files.is_empty()
        || !report.size_mismatches.is_empty()
}

/// The range source for `attempt`: pass 0 reads from the local patch cache when the whole chain is
/// present, every later pass (and pass 0 with an incomplete cache) fetches over HTTP.
fn compose_source(
    ctx: &RepoCtx,
    attempt: u32,
    local_files: &Option<Vec<PathBuf>>,
    http_sources: &[HttpSource],
) -> Box<dyn RangeSource> {
    match (attempt, local_files) {
        (0, Some(files)) => Box::new(LocalPatchSource::new(files.clone())),
        _ => Box::new(HttpRangeSource::new(
            ctx.fetcher.clone(),
            ctx.handle.clone(),
            http_sources.to_vec(),
        )),
    }
}

/// Resolve the index's source patches, in its chain order, to an HTTP source per patch and (when the
/// whole chain is cached locally) a local file per patch. A source the index references is taken from
/// the request's explicit [`patch_sources`](RepairRepo::patch_sources) when listed there, else formed
/// as `{source_base_url}/{name}` when a base is set (an HTTP-only source, no local copy). A source that
/// neither supplies is a hard [`PatchError::IndexUnavailable`]: a repair that has bytes to pull cannot
/// proceed missing a source the index depends on. Called only once the verify has found work, so an
/// unaddressable source costs nothing on a repo that turns out to be healthy.
type ResolvedSources = (Option<Vec<PathBuf>>, Vec<HttpSource>);

fn resolve_sources(index: &Index, repo_req: &RepairRepo) -> Result<ResolvedSources, PatchError> {
    let repo = repo_req.repo;
    let by_name: HashMap<&str, &crate::request::RepairPatchSource> = repo_req
        .patch_sources
        .iter()
        .map(|s| (s.name.as_str(), s))
        .collect();

    let refs = index.source_refs();
    let mut http = Vec::with_capacity(refs.len());
    let mut locals = Vec::with_capacity(refs.len());
    let mut whole_chain_local = true;
    for sref in &refs {
        // An explicit source (with an optional local copy) wins; otherwise derive the URL from the base
        // (index-only heal, no local). A source the request cannot form at all is a hard error.
        let (url, local) = match by_name.get(sref.name) {
            Some(src) => (src.url.clone(), src.local.clone()),
            None => match &repo_req.source_base_url {
                Some(base) => {
                    let url = base.join(sref.name).map_err(|e| {
                        index_unavailable(
                            repo,
                            std::io::Error::other(format!(
                                "cannot form a source url for {:?} under {base}: {e}",
                                sref.name
                            )),
                        )
                    })?;
                    (url, None)
                }
                None => {
                    return Err(index_unavailable(
                        repo,
                        std::io::Error::other(format!(
                            "index references source patch {:?} the repair did not provide",
                            sref.name
                        )),
                    ));
                }
            },
        };
        // The index's own length is authoritative; each HTTP response's `Content-Range` total is
        // cross-checked against it by the fetcher.
        http.push(
            HttpSource::new(url, sref.expected_len)
                .policy(HeaderPolicy::se_patch(repo_req.headers.unique_id.clone())),
        );
        // Trust a local copy for the first attempt only if it is present *and* the right length: the
        // patch store keeps partial/interrupted downloads for later resume, and a truncated file would
        // fail its range reads. A same-length-but-corrupt copy still slips through here, but its bytes
        // fail their CRC on the first attempt and the HTTP passes heal it (the reattempt loop treats a
        // hard local fault as retryable), so it never corrupts the tree.
        match &local {
            Some(path) if local_len_matches(path, sref.expected_len) => locals.push(path.clone()),
            _ => whole_chain_local = false,
        }
    }
    let local_files = (whole_chain_local && !locals.is_empty()).then_some(locals);
    Ok((local_files, http))
}

/// Whether `path` is a file of exactly `expected` bytes (a partial/truncated cache copy is not).
fn local_len_matches(path: &std::path::Path, expected: u64) -> bool {
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.len() == expected)
}

/// Read and parse a repo's `.apzi` from disk; either fault is [`PatchError::IndexUnavailable`].
fn read_index(path: &std::path::Path, repo: Repo) -> Result<Index, PatchError> {
    let file = std::fs::File::open(path).map_err(|e| index_unavailable(repo, e))?;
    Index::read_apzi(BufReader::new(file)).map_err(|e| index_unavailable(repo, e))
}

/// Sum the per-pass repair counts into one repo total.
#[derive(Default)]
struct RepairAgg {
    repaired: usize,
    recreated: usize,
    resized: usize,
    bytes: u64,
}

impl RepairAgg {
    /// Fold one pass's counts in. `over_network` gates the byte total: bytes a local pass delivered
    /// were read from disk, not refetched, so they do not count toward the network accounting.
    fn absorb(&mut self, outcome: &ZipRepair, over_network: bool) {
        self.repaired += outcome.repaired.len();
        self.recreated += outcome.recreated.len();
        self.resized += outcome.resized.len();
        if over_network {
            self.bytes = self.bytes.saturating_add(outcome.bytes_fetched);
        }
    }
}

/// Wrap any error into [`PatchError::IndexUnavailable`] for `repo`.
fn index_unavailable(
    repo: Repo,
    source: impl std::error::Error + Send + Sync + 'static,
) -> PatchError {
    PatchError::IndexUnavailable {
        repo,
        source: Box::new(source),
    }
}

/// A blocking-task join failure surfaces as an i/o fault, matching the install path's panic handling.
fn join_to_io(join: tokio::task::JoinError) -> PatchError {
    PatchError::Io {
        path: PathBuf::new(),
        source: std::io::Error::other(join),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An `ENOSPC` taken while pulling the index keeps the path the filesystem refused instead of
    /// being reported as an unreachable index.
    ///
    /// The end-to-end proof that fetch really raises this shape is `tests/disk_space.rs`; this
    /// covers the mapping itself, on every target rather than only where a memory-backed filesystem
    /// exists.
    #[test]
    fn a_disk_full_index_fetch_is_routed_out_of_the_unavailable_arm() {
        let err = index_acquire_err(
            FetchError::Io {
                path: PathBuf::from("/store/indexes/game-2024.01.02.0000.0000.apzi.part"),
                source: std::io::ErrorKind::StorageFull.into(),
            },
            Repo::Game,
        );
        let PatchError::OutOfSpace { path, source } = &err else {
            panic!("a full disk must not arrive as an unavailable index, got {err:?}");
        };
        assert_eq!(
            path,
            std::path::Path::new("/store/indexes/game-2024.01.02.0000.0000.apzi.part"),
        );
        assert_eq!(source.kind(), std::io::ErrorKind::StorageFull);
    }

    /// A worker that is gone ends the repair; a worker that refused one pass does not.
    ///
    /// The pair is what carries the claim. Ending on any worker failure at all still passes the
    /// first case and quietly halves the reattempt budget a repair gets whenever it is privileged:
    /// bytes that failed their digest, or a write the filesystem refused, are exactly the faults the
    /// budget exists for, and an in-process repair spends a pass on them rather than giving up.
    #[test]
    fn only_a_worker_that_cannot_write_again_ends_the_repair() {
        let worker = |kind| PatchError::Worker {
            kind,
            failed_file: None,
            detail: String::new(),
        };
        for kind in [
            crate::WorkerErrorKind::Spawn,
            crate::WorkerErrorKind::Protocol,
        ] {
            assert!(
                ends_the_repair(&worker(kind)),
                "{kind:?} leaves nothing that can write the tree",
            );
        }
        assert!(ends_the_repair(&PatchError::Cancelled));

        for kind in [
            crate::WorkerErrorKind::Verify,
            crate::WorkerErrorKind::Apply,
        ] {
            assert!(
                !ends_the_repair(&worker(kind)),
                "{kind:?} is a pass that failed, not a worker that is gone",
            );
        }
        assert!(!ends_the_repair(&PatchError::Io {
            path: PathBuf::new(),
            source: std::io::ErrorKind::PermissionDenied.into(),
        }));
        assert!(!ends_the_repair(&PatchError::Apply(
            apogee_zipatch::Error::BadMagic
        )));
    }

    /// Only disk-full leaves the index arm, and a cancelled repair is not dressed up as either.
    ///
    /// The pair is what carries the claim: delete the `into_out_of_space` guard and the test above
    /// still passes, so the routing has to be pinned to the `ErrorKind` and not to "any i/o
    /// failure". The cancel case is the one that must not move at all: a repair the user stopped is
    /// re-runnable, and reporting it as a missing index says the opposite.
    #[test]
    fn a_cancel_and_every_other_fault_keep_their_existing_arms() {
        assert!(matches!(
            index_acquire_err(FetchError::Cancelled, Repo::Game),
            PatchError::Cancelled
        ));
        let denied = index_acquire_err(
            FetchError::Io {
                path: PathBuf::from("/store/indexes/boot-2024.01.02.0000.0000.apzi.part"),
                source: std::io::ErrorKind::PermissionDenied.into(),
            },
            Repo::Boot,
        );
        assert!(
            matches!(
                denied,
                PatchError::IndexUnavailable {
                    repo: Repo::Boot,
                    ..
                }
            ),
            "a permission fault is not a space fault, got {denied:?}",
        );
        let bad_pin = index_acquire_err(
            FetchError::FileVerifyFailed {
                expected: "00".repeat(32),
                got: "ff".repeat(32),
            },
            Repo::Expansion(1),
        );
        assert!(
            matches!(
                bad_pin,
                PatchError::IndexUnavailable {
                    repo: Repo::Expansion(1),
                    ..
                }
            ),
            "got {bad_pin:?}",
        );
    }
}
