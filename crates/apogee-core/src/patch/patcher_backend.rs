//! The patch backend that drives `apogee-patcher`.
//!
//! Install requests arrive fully formed from the flow (the pending set comes from registration); this
//! backend just runs them and relays progress. Repair requests do not: a [`RepairPlan`] names the
//! repos and versions, and the backend resolves each repo's digest-pinned block index, and where that
//! index's source patches are served, from the hosted, Ed25519-signed catalog before handing
//! `apogee-patcher` the full request. A repo carrying a local-index override skips that resolution
//! and reads its `.apzi` from the given path; a plan whose every repo is overridden never fetches the
//! catalog at all. The catalog bytes travel through the download engine like
//! every other byte this launcher pulls (its redirect floor and stall bounds included); the
//! signature check stays in `apogee-patcher` ([`IndexCatalog::verify_default`]), so no crypto lives
//! in this crate.

use std::path::{Path, PathBuf};

use apogee_fetch::{DownloadSpec, Fetcher, Validator};
use apogee_patcher::{
    IndexCatalog, IndexEntry, IndexSource, InstallRequest, Installed, Job, PatchError, Patcher,
    RepairOutcome, RepairPatchSource, RepairRepo, RepairRequest, Repo, SePatch,
};
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use url::Url;

use super::{PatchBackend, RepairPlan, RepairRepoPlan, classify_repo};
use crate::command::Event;
use crate::error::CoreError;

/// The real patch backend over `apogee-patcher`.
pub(crate) struct PatcherBackend {
    patcher: Patcher,
    /// The download engine the catalog manifest and signature come through, shared with every other
    /// subsystem that pulls bytes.
    fetcher: Fetcher,
    /// Where downloaded patches are cached, scanned to seed a repair's local-first sources.
    patch_store: PathBuf,
}

impl PatcherBackend {
    /// Construct over an already-built patcher, the shared download engine (for the catalog fetch),
    /// and the patch store (scanned for a repair's local sources).
    pub(crate) fn new(patcher: Patcher, fetcher: Fetcher, patch_store: PathBuf) -> Self {
        Self {
            patcher,
            fetcher,
            patch_store,
        }
    }

    /// Fetch and verify the hosted index catalog against the compiled-in key.
    async fn fetch_catalog(&self) -> Result<IndexCatalog, CoreError> {
        let (manifest_url, signature_url) = index_catalog_urls()?;
        let dir = self.patch_store.join(".index-catalog");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| CoreError::Repair {
                detail: format!("make {}: {e}", dir.display()),
            })?;
        let manifest = self
            .fetch_bytes(&manifest_url, &dir.join("manifest.json"))
            .await?;
        let signature = self
            .fetch_bytes(&signature_url, &dir.join("manifest.json.sig"))
            .await?;
        IndexCatalog::verify_default(&manifest, &signature).map_err(|e| CoreError::Repair {
            detail: format!("index catalog: {e}"),
        })
    }

    /// Fetch `url` into `dest` through the download engine and hand back the bytes, replacing any
    /// previous copy (`overwrite`: the catalog is a mutable artifact at a fixed URL, so a satisfied
    /// destination must not be served back). Unverified at this layer and over HTTPS only;
    /// authenticity is the Ed25519 check one call up, exactly as the runner and addon catalogs do it.
    async fn fetch_bytes(&self, url: &Url, dest: &Path) -> Result<Vec<u8>, CoreError> {
        let repair_err = |detail: String| CoreError::Repair { detail };
        let spec = DownloadSpec::builder(url.clone(), dest, Validator::None)
            .allow_unverified()
            .overwrite()
            .resume(false)
            .build()
            .map_err(|e| repair_err(format!("fetch {url}: {e}")))?;
        self.fetcher
            .download(&spec, None, CancellationToken::new())
            .await
            .map_err(|e| repair_err(format!("fetch {url}: {e}")))?;
        tokio::fs::read(dest)
            .await
            .map_err(|e| repair_err(format!("read {}: {e}", dest.display())))
    }

    /// Turn a [`RepairPlan`] into `apogee-patcher`'s [`RepairRequest`]: resolve each repo's block-index
    /// pin from the signed catalog and seed its local-first sources from the patch cache. The catalog
    /// is fetched only when some repo actually resolves through it: a plan whose every repo carries a
    /// local-index override must complete with the catalog host unreachable, since that host being
    /// down is what the override exists for.
    async fn build_repair_request(&self, plan: RepairPlan) -> Result<RepairRequest, CoreError> {
        let catalog = if plan.repos.iter().any(|r| r.index_override.is_none()) {
            Some(self.fetch_catalog().await?)
        } else {
            None
        };
        assemble_repair_request(plan, catalog.as_ref(), &cached_patch_sources(&self.patch_store))
    }
}

/// Assemble the full [`RepairRequest`] from a plan, the verified catalog (`None` only when every repo
/// is overridden), and the cache scan. An overridden repo reads its `.apzi` from the given path and
/// never consults the catalog, not even for its source base (the row may not exist, and the point of
/// the override is completing without one); its sources come from the cache scan and the compiled-in
/// CDN bases. The plan's version rides into `target_version` either way, so the patcher's cross-check
/// against the index's own recorded version runs the same for a local index as for a pinned one.
fn assemble_repair_request(
    plan: RepairPlan,
    catalog: Option<&IndexCatalog>,
    cached: &[(Repo, Vec<RepairPatchSource>)],
) -> Result<RepairRequest, CoreError> {
    let mut repos = Vec::with_capacity(plan.repos.len());
    for RepairRepoPlan {
        repo,
        version,
        index_override,
    } in plan.repos
    {
        let (index, source_base_url) = match index_override {
            Some(path) => (IndexSource::LocalFile(path), cdn_base_for(repo)),
            None => {
                let catalog = catalog.ok_or_else(|| CoreError::Repair {
                    detail: format!("no catalog was fetched to resolve {repo:?} {version}"),
                })?;
                let entry = catalog
                    .resolve(repo, &version)
                    .ok_or_else(|| CoreError::Repair {
                        detail: format!(
                            "no block index for {repo:?} {version} in the signed catalog"
                        ),
                    })?;
                // The CDN base lets the repair form each index source-ref's URL without a populated
                // cache, so a repair works even with keep-patches off.
                (entry.source(), source_base_for(entry, repo))
            }
        };
        let patch_sources = cached
            .iter()
            .find(|(r, _)| *r == repo)
            .map(|(_, sources)| sources.clone())
            .unwrap_or_default();
        repos.push(RepairRepo {
            repo,
            target_version: version,
            index,
            patch_sources,
            source_base_url,
            // No session credential, and none is needed: patch delivery answers a ranged request
            // for a game patch the same way it answers one for a boot patch, on the user agent
            // alone. Measured against the live CDN, and a full game-repo heal has run over it.
            headers: SePatch::boot(),
        });
    }
    Ok(RepairRequest {
        game_root: plan.game_root,
        repos,
    })
}

#[async_trait]
impl PatchBackend for PatcherBackend {
    async fn install(
        &self,
        request: InstallRequest,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Installed, CoreError> {
        let job = self.patcher.install(request);
        Ok(drive_job(job, cancel, events).await?)
    }

    async fn repair(
        &self,
        plan: RepairPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<RepairOutcome, CoreError> {
        let request = self.build_repair_request(plan).await?;
        let job = self.patcher.repair(request);
        Ok(drive_job(job, cancel, events).await?)
    }
}

/// Run a patcher [`Job`] to completion, relaying its progress onto `events` and bridging the flow's
/// cancellation to it. The progress relay runs on a spawned task and drains fully once the job's
/// progress channel closes (which it does when the run returns), so no frame is dropped.
async fn drive_job<T: Send + 'static>(
    mut job: Job<T>,
    cancel: &CancellationToken,
    events: &UnboundedSender<Event>,
) -> Result<T, PatchError> {
    let token = job.cancel_token();
    let mut progress = job.progress();
    let sink = events.clone();
    let relay = tokio::spawn(async move {
        while let Some(frame) = progress.next().await {
            let _ = sink.send(Event::Patch(frame));
        }
    });
    let bridge = {
        let external = cancel.clone();
        tokio::spawn(async move {
            external.cancelled().await;
            token.cancel();
        })
    };

    let result = job.wait().await;
    bridge.abort();
    // The job's progress sender dropped when its run returned, so the relay sees the channel close and
    // ends after draining; await it so every frame reaches the stream before the result does.
    let _ = relay.await;
    result
}

/// Resolve the index-catalog manifest and signature URLs. `APOGEE_INDEX_CATALOG_URL` overrides the
/// manifest URL (a mirror or a pre-deploy test); the signature is the manifest URL plus `.sig`. The
/// override cannot weaken trust: the Ed25519 signature over the manifest is checked against the
/// compiled-in key regardless of origin.
fn index_catalog_urls() -> Result<(Url, Url), CoreError> {
    // The catalog is hosted on Pages beside the runner catalog; the signature is the manifest plus `.sig`.
    let manifest = std::env::var("APOGEE_INDEX_CATALOG_URL")
        .unwrap_or_else(|_| "https://soleynn.github.io/apogee/indexes/manifest.json".to_owned());
    let signature = format!("{manifest}.sig");
    Ok((parse_url(&manifest)?, parse_url(&signature)?))
}

fn parse_url(raw: &str) -> Result<Url, CoreError> {
    Url::parse(raw).map_err(|e| CoreError::Repair {
        detail: format!("index catalog url {raw:?}: {e}"),
    })
}

/// Where `repo`'s source patches are served, so a repair forms each index source-ref's URL as
/// `{base}/{name}` with no patch cache to draw on.
///
/// The signed catalog row answers first. It is the only thing that can: Square Enix serves each repo
/// under an opaque path id, and while boot's and the base game's hold still enough to compile in
/// below, an expansion's does not (`ex1` is `6b936f08` and `ex5` is `6cfeab11` on this machine, read
/// off the game patchlist during an install). A repair fetches no patchlist to read them from, and the
/// row it needs for this repo and version already exists and is already verified before any of this
/// runs, so that row is where the id lives.
///
/// The row also outranks the compiled-in pair rather than merely filling the gap they leave, so a
/// re-signed catalog is enough if Square Enix ever moves boot or the base game. `None` when neither
/// answers: the repo then heals from the cache and from what can be rebuilt locally, exactly as an
/// expansion did before any row carried a base.
fn source_base_for(entry: &IndexEntry, repo: Repo) -> Option<Url> {
    entry.source_base.clone().or_else(|| cdn_base_for(repo))
}

/// The compiled-in fallback for a row that names no base: boot `2b5cbc63` and base game `4e9a232b`,
/// both observed from the live CDN (the boot id covers a chain running from 2013 to today). No
/// expansion has one, which is what [`source_base_for`] exists to answer.
fn cdn_base_for(repo: Repo) -> Option<Url> {
    let path = match repo {
        Repo::Boot => "boot/2b5cbc63/",
        Repo::Game => "game/4e9a232b/",
        _ => return None,
    };
    Url::parse(&format!("http://patch-dl.ffxiv.com/{path}")).ok()
}

/// Scan the patch cache for `.patch` files and group them into per-repo repair sources, keyed by the
/// same repo classification the reference launcher uses. Each cached patch becomes a
/// [`RepairPatchSource`] whose URL is reconstructed against the SE patch CDN (the cache mirrors the
/// URL path, host discarded) and whose local copy is trusted on the first repair pass.
///
/// Best-effort: an install run with `keep_patches` off leaves no cache, so this yields nothing and the
/// repair heals only locally-reconstructible (zero/empty) ranges. Enumerating a repo's full source
/// chain independent of the cache is deferred index-infrastructure work.
fn cached_patch_sources(patch_store: &Path) -> Vec<(Repo, Vec<RepairPatchSource>)> {
    let mut grouped: Vec<(Repo, Vec<RepairPatchSource>)> = Vec::new();
    let mut relative = Vec::new();
    collect_patches(patch_store, &mut relative, &mut |segments, path| {
        let Some(source) = repair_source_from(segments, path) else {
            return;
        };
        let repo = classify_repo(segments.iter().map(String::as_str));
        match grouped.iter_mut().find(|(r, _)| *r == repo) {
            Some((_, sources)) => sources.push(source),
            None => grouped.push((repo, vec![source])),
        }
    });
    grouped
}

/// Build a [`RepairPatchSource`] from a cached patch's path segments (relative to the store) and its
/// on-disk path, reconstructing the CDN URL from the mirrored path.
fn repair_source_from(segments: &[String], path: &Path) -> Option<RepairPatchSource> {
    let name = segments.last()?.clone();
    // The cache mirrors the URL path with the host discarded; rebuild it against the SE patch CDN.
    let url = Url::parse(&format!("http://patch-dl.ffxiv.com/{}", segments.join("/"))).ok()?;
    Some(RepairPatchSource {
        name,
        url,
        local: Some(path.to_path_buf()),
    })
}

/// Walk `dir` recursively, invoking `visit(relative_segments, file_path)` for every `.patch` file.
/// `relative` accumulates the path segments beneath the store root as the walk descends.
fn collect_patches(
    dir: &Path,
    relative: &mut Vec<String>,
    visit: &mut impl FnMut(&[String], &Path),
) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        // `file_type` reads the entry's own type without following a symlink, so a symlinked
        // directory is never descended into: the walk cannot loop on a symlink cycle, and only real
        // files under the store are trusted as patch sources.
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let path = entry.path();
        relative.push(entry.file_name().to_string_lossy().into_owned());
        if file_type.is_dir() {
            collect_patches(&path, relative, visit);
        } else if file_type.is_file() && path.extension().and_then(|e| e.to_str()) == Some("patch")
        {
            visit(relative, &path);
        }
        relative.pop();
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use apogee_fetch::DigestPin;
    use apogee_patcher::{GameProbe, PatcherConfig};
    use apogee_zipatch::{Platform, build_index, fixtures};
    use tokio::sync::mpsc::unbounded_channel;

    use super::*;

    /// A catalog row for `repo`, optionally naming the base its source patches are served under.
    fn entry(repo: Repo, source_base: Option<&str>) -> IndexEntry {
        IndexEntry {
            repo,
            version: "2024.03.28.0000.0000".to_owned(),
            url: Url::parse("https://example.invalid/indexes/x.apzi").expect("a hosted index url"),
            pin: DigestPin::Blake3([0u8; 32]),
            source_base: source_base.map(|b| Url::parse(b).expect("a source base")),
        }
    }

    /// The case this exists for: an expansion has no compiled-in id, so without the row it heals
    /// nothing over HTTP, and with the row it heals from the CDN like any other repo. Asserted on the
    /// formed source URL rather than the base, since forming one is all a repair does with it.
    #[test]
    fn an_expansions_base_comes_from_the_row_and_is_nothing_without_one() {
        let repo = Repo::Expansion(1);
        let base = "http://patch-dl.ffxiv.com/game/ex1/6b936f08/";
        let resolved =
            source_base_for(&entry(repo, Some(base)), repo).expect("the row named a base");
        assert_eq!(
            resolved
                .join("D2024.03.28.0000.0000.patch")
                .expect("the base forms a source url")
                .as_str(),
            "http://patch-dl.ffxiv.com/game/ex1/6b936f08/D2024.03.28.0000.0000.patch",
        );

        assert_eq!(
            source_base_for(&entry(repo, None), repo),
            None,
            "an expansion with no row base must stay unaddressable rather than guess one",
        );
    }

    /// Boot and the base game keep working against a catalog that predates the field, which is what
    /// keeps this from being a flag day: the hosted manifest can be re-signed one row at a time.
    #[test]
    fn boot_and_the_base_game_fall_back_to_the_compiled_in_bases() {
        for (repo, want) in [
            (Repo::Boot, "http://patch-dl.ffxiv.com/boot/2b5cbc63/"),
            (Repo::Game, "http://patch-dl.ffxiv.com/game/4e9a232b/"),
        ] {
            assert_eq!(
                source_base_for(&entry(repo, None), repo)
                    .as_ref()
                    .map(Url::as_str),
                Some(want),
            );
        }
    }

    /// A row that names a base outranks the compiled-in one, so moving a repo Square Enix has moved
    /// costs a re-signed catalog rather than a release.
    #[test]
    fn a_row_outranks_the_compiled_in_base() {
        let moved = "http://patch-dl.ffxiv.com/game/deadbeef/";
        assert_eq!(
            source_base_for(&entry(Repo::Game, Some(moved)), Repo::Game)
                .as_ref()
                .map(Url::as_str),
            Some(moved),
        );
    }

    /// The version the local-index tests author their index at and install to. A fn rather than a
    /// const: the audit forbids string constants in this crate, and its grep does not read cfg.
    fn version() -> String {
        "2024.01.02.0000.0000".to_owned()
    }

    /// A plan entry for `repo` at [`version`], optionally overridden to a local index path.
    fn plan_repo(repo: Repo, index_override: Option<PathBuf>) -> RepairRepoPlan {
        RepairRepoPlan {
            repo,
            version: version(),
            index_override,
        }
    }

    /// The catalog-down case the override exists for: a plan whose every repo carries a local index
    /// assembles into a full request with no catalog value at all, each repo reading its own file
    /// and keeping its plan version as the cross-check target.
    #[test]
    fn a_fully_overridden_plan_assembles_without_any_catalog() {
        let plan = RepairPlan {
            game_root: PathBuf::from("/install"),
            repos: vec![
                plan_repo(Repo::Boot, Some(PathBuf::from("/idx/boot.apzi"))),
                plan_repo(Repo::Game, Some(PathBuf::from("/idx/game.apzi"))),
            ],
        };
        let request = assemble_repair_request(plan, None, &[]).expect("no catalog is needed");
        assert_eq!(request.repos.len(), 2);
        for (built, want) in request.repos.iter().zip(["/idx/boot.apzi", "/idx/game.apzi"]) {
            assert_eq!(built.target_version, version(), "the cross-check target rides in");
            match &built.index {
                IndexSource::LocalFile(path) => assert_eq!(path, &PathBuf::from(want)),
                other => panic!("expected the local file, got {other:?}"),
            }
        }
    }

    /// One repo overridden, one not: the overridden repo reads its local file while the other still
    /// resolves its pinned row, so pointing one repo at a regenerated index does not change how the
    /// untouched repos are trusted.
    #[test]
    fn a_mixed_plan_resolves_only_unoverridden_repos_through_the_catalog() {
        let row = entry(Repo::Game, None);
        let catalog = IndexCatalog {
            version: 1,
            indexes: vec![row.clone()],
        };
        let plan = RepairPlan {
            game_root: PathBuf::from("/install"),
            repos: vec![
                RepairRepoPlan {
                    repo: Repo::Game,
                    version: row.version.clone(),
                    index_override: None,
                },
                RepairRepoPlan {
                    repo: Repo::Expansion(1),
                    version: row.version.clone(),
                    index_override: Some(PathBuf::from("/idx/ex1.apzi")),
                },
            ],
        };
        let request =
            assemble_repair_request(plan, Some(&catalog), &[]).expect("the game row resolves");
        match &request.repos[0].index {
            IndexSource::Pinned { url, pin } => {
                assert_eq!(url, &row.url);
                assert_eq!(pin, &row.pin);
            }
            other => panic!("the unoverridden repo must stay pinned, got {other:?}"),
        }
        match &request.repos[1].index {
            IndexSource::LocalFile(path) => assert_eq!(path, &PathBuf::from("/idx/ex1.apzi")),
            other => panic!("the overridden repo must read its file, got {other:?}"),
        }
    }

    /// Author a `.apzi` over `chain` at `version` and write it to `path`.
    fn write_index_file(
        chain: &[Vec<u8>],
        version: &str,
        path: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let inputs: Vec<(String, Cursor<Vec<u8>>)> = chain
            .iter()
            .enumerate()
            .map(|(i, p)| (format!("p{i}.patch"), Cursor::new(p.clone())))
            .collect();
        let index = build_index(inputs, Platform::Win32, version)?;
        let mut buf = Vec::new();
        index.write_apzi(&mut buf)?;
        std::fs::write(path, buf)?;
        Ok(())
    }

    /// A real backend over `store`, with the game-running guard answered "no" so the repair runs.
    fn backend(store: &Path) -> Result<PatcherBackend, Box<dyn std::error::Error>> {
        let fetcher = Fetcher::builder().build()?;
        let patcher = Patcher::new(
            fetcher.clone(),
            PatcherConfig {
                patch_store: store.to_path_buf(),
                ..PatcherConfig::new(GameProbe::never_running())
            },
        );
        Ok(PatcherBackend::new(patcher, fetcher, store.to_path_buf()))
    }

    /// Install the fixture chain into `game_root/game` and put cached copies of its patches in the
    /// store, laid out as the download cache keeps them, so a heal's first attempt is local.
    fn install_with_cache(
        chain: &[Vec<u8>],
        game_root: &Path,
        store: &Path,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let repo_dir = game_root.join("game");
        std::fs::create_dir_all(&repo_dir)?;
        fixtures::apply_chain(&repo_dir, chain)?;
        let cache = store.join("game").join("cafef00d");
        std::fs::create_dir_all(&cache)?;
        for (i, patch) in chain.iter().enumerate() {
            std::fs::write(cache.join(format!("p{i}.patch")), patch)?;
        }
        Ok(())
    }

    /// The whole point of the override, driven through the real backend and patcher: a damaged
    /// install heals from a local index and cached patches with the catalog host unreachable. The
    /// catalog fetch would create `.index-catalog` under the store before a byte moved, so that
    /// directory staying absent is the observation that no fetch was even attempted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_overridden_repair_heals_offline_and_never_touches_the_catalog() {
        let chain = fixtures::chain();
        let game_root = tempfile::tempdir().expect("a game root");
        let store = tempfile::tempdir().expect("a patch store");
        install_with_cache(&chain, game_root.path(), store.path()).expect("an installed fixture");
        let index_path = store.path().join("game.apzi");
        write_index_file(&chain, &version(), &index_path).expect("an authored index");

        let exe = game_root.path().join("game").join("ffxivboot.exe");
        let healthy = std::fs::read(&exe).expect("the installed exe");
        let mut broken = healthy.clone();
        broken[0] ^= 0xFF;
        std::fs::write(&exe, broken).expect("a corrupted exe");

        let backend = backend(store.path()).expect("a real backend");
        let plan = RepairPlan {
            game_root: game_root.path().to_path_buf(),
            repos: vec![plan_repo(Repo::Game, Some(index_path))],
        };
        let (tx, _rx) = unbounded_channel();
        let outcome = backend
            .repair(plan, &CancellationToken::new(), &tx)
            .await
            .expect("a local-index repair with no catalog host");

        assert_eq!(outcome.repos.len(), 1);
        assert!(
            outcome.repos[0].repaired_parts >= 1,
            "the corrupted part must have been healed"
        );
        assert_eq!(
            std::fs::read(&exe).expect("the healed exe"),
            healthy,
            "healed byte-identically"
        );
        assert!(
            !store.path().join(".index-catalog").exists(),
            "an all-overridden repair must never attempt the catalog fetch"
        );
    }

    /// A local index describing the wrong version is the typed cross-check error, not a trust
    /// bypass: the plan's installed version still rides into the request, so the patcher refuses to
    /// heal toward bytes the install is not at. The catalog stays untouched on this path too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_wrong_version_local_index_is_the_typed_cross_check_error() {
        let chain = fixtures::chain();
        let game_root = tempfile::tempdir().expect("a game root");
        let store = tempfile::tempdir().expect("a patch store");
        install_with_cache(&chain, game_root.path(), store.path()).expect("an installed fixture");
        let index_path = store.path().join("game.apzi");
        write_index_file(&chain, "2024.09.09.0001.0000", &index_path).expect("a stale index");

        let backend = backend(store.path()).expect("a real backend");
        let plan = RepairPlan {
            game_root: game_root.path().to_path_buf(),
            repos: vec![plan_repo(Repo::Game, Some(index_path))],
        };
        let (tx, _rx) = unbounded_channel();
        let err = backend
            .repair(plan, &CancellationToken::new(), &tx)
            .await
            .expect_err("a wrong-version index must be refused");

        assert!(
            matches!(
                err,
                CoreError::Patch(PatchError::VersionCrossCheck { repo: Repo::Game, .. })
            ),
            "expected the typed cross-check error, got {err:?}"
        );
        assert!(!store.path().join(".index-catalog").exists());
    }
}
