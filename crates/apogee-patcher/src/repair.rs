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
use std::path::PathBuf;
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

use crate::request::{IndexSource, RepairRepo, RepairRequest};
use crate::{PartRef, PatchError, PatchProgress, PatcherConfig, Repo, recycler, store};

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
    // One batch directory for the whole request, so strays from several repos land together.
    let batch = recycler::batch_name(SystemTime::now());
    let handle = Handle::current();
    let mut outcome = RepairOutcome::default();

    for repo_req in repos {
        if cancel.is_cancelled() {
            return Err(PatchError::Cancelled);
        }
        // Acquire the index bytes (an async fetch for a pinned source), then hand the sync verify and
        // repair to a blocking worker: `HttpRangeSource` uses `Handle::block_on`, which must not run
        // inside an async task.
        let index_path = acquire_index(&fetcher, &config, &repo_req, &cancel).await?;
        let repaired = {
            let ctx = RepoCtx {
                fetcher: fetcher.clone(),
                handle: handle.clone(),
                game_root: game_root.clone(),
                index_path,
                batch: batch.clone(),
                reattempts: config.repair_reattempts.max(1),
                progress: progress.clone(),
                cancel: cancel.clone(),
            };
            tokio::task::spawn_blocking(move || repair_repo(&repo_req, &ctx))
                .await
                .map_err(join_to_io)??
        };
        outcome.bytes_refetched = outcome
            .bytes_refetched
            .saturating_add(repaired.bytes_refetched);
        outcome
            .quarantined
            .extend(repaired.quarantined.iter().cloned());
        outcome.repos.push(repaired);
    }
    Ok(outcome)
}

/// The per-repo inputs threaded onto the blocking worker.
struct RepoCtx {
    fetcher: Fetcher,
    handle: Handle,
    game_root: PathBuf,
    index_path: PathBuf,
    batch: String,
    reattempts: usize,
    progress: mpsc::UnboundedSender<PatchProgress>,
    cancel: CancellationToken,
}

/// Obtain the repo's `.apzi` on local disk: a local source is used in place, a pinned source is
/// fetched under its `sha256` (allowed over plain HTTP because the pin authenticates the bytes).
async fn acquire_index(
    fetcher: &Fetcher,
    config: &PatcherConfig,
    repo_req: &RepairRepo,
    cancel: &CancellationToken,
) -> Result<PathBuf, PatchError> {
    let repo = repo_req.repo;
    match &repo_req.index {
        IndexSource::LocalFile(path) => Ok(path.clone()),
        IndexSource::Pinned { url, sha256 } => {
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
            let spec = DownloadSpec::builder(url.clone(), dest, Validator::Sha256(*sha256))
                .build()
                .map_err(|e| index_unavailable(repo, e))?;
            let verified = fetcher
                .download(&spec, None, cancel.clone())
                .await
                .map_err(|e| match e {
                    FetchError::Cancelled => PatchError::Cancelled,
                    other => index_unavailable(repo, other),
                })?;
            Ok(verified.path().to_path_buf())
        }
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
fn repair_repo(repo_req: &RepairRepo, ctx: &RepoCtx) -> Result<RepairedRepo, PatchError> {
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
    let (local_files, http_sources) = resolve_sources(&index, repo_req)?;

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
        recycler::quarantine(&ctx.game_root, repo, &ctx.batch, &report.stray_files)?
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
        match index.repair(&root, &pending, source.as_mut()) {
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
            Err(fault) => last_fault = Some(PatchError::Apply(fault)),
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

    // Clean: record the healed version exactly as an install would (bare, then `.bck`).
    store::write_ver(&ctx.game_root, repo, &wanted)?;
    store::backup_ver(&ctx.game_root, repo)?;
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
/// whole chain is cached locally) a local file per patch. A patch the index references but the request
/// does not name is a hard [`PatchError::IndexUnavailable`]: a repair cannot proceed missing a source
/// the index depends on.
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
        let src = by_name.get(sref.name).ok_or_else(|| {
            index_unavailable(
                repo,
                std::io::Error::other(format!(
                    "index references source patch {:?} the repair did not provide",
                    sref.name
                )),
            )
        })?;
        http.push(HttpSource {
            url: src.url.clone(),
            // The index's own length is authoritative; each HTTP response's `Content-Range` total is
            // cross-checked against it by the fetcher.
            expected_len: sref.expected_len,
            policy: Some(HeaderPolicy::SePatch {
                unique_id: repo_req.headers.unique_id.clone(),
            }),
        });
        // Trust a local copy for the first attempt only if it is present *and* the right length: the
        // patch store keeps partial/interrupted downloads for later resume, and a truncated file would
        // fail its range reads. A same-length-but-corrupt copy still slips through here, but its bytes
        // fail their CRC on the first attempt and the HTTP passes heal it (the reattempt loop treats a
        // hard local fault as retryable), so it never corrupts the tree.
        match &src.local {
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
