//! The patch backend that drives `apogee-patcher`.
//!
//! Install requests arrive fully formed from the flow (the pending set comes from registration); this
//! backend just runs them and relays progress. Repair requests do not: a [`RepairPlan`] names the
//! repos and versions, and the backend resolves each repo's digest-pinned block index, and where that
//! index's source patches are served, from the hosted, Ed25519-signed catalog before handing
//! `apogee-patcher` the full request. The catalog bytes are fetched here (transport is the composition
//! root's job); the signature check stays in `apogee-patcher`
//! ([`IndexCatalog::verify_default`]), so no crypto lives in this crate.

use std::path::{Path, PathBuf};

use apogee_patcher::{
    IndexCatalog, IndexEntry, InstallRequest, Installed, Job, PatchError, Patcher, RepairOutcome,
    RepairPatchSource, RepairRepo, RepairRequest, Repo, SePatch,
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
    /// The HTTP client used to fetch the signed catalog manifest and signature.
    http: reqwest::Client,
    /// Where downloaded patches are cached, scanned to seed a repair's local-first sources.
    patch_store: PathBuf,
}

impl PatcherBackend {
    /// Construct over an already-built patcher, an HTTP client for the catalog fetch, and the patch
    /// store (scanned for a repair's local sources).
    pub(crate) fn new(patcher: Patcher, http: reqwest::Client, patch_store: PathBuf) -> Self {
        Self {
            patcher,
            http,
            patch_store,
        }
    }

    /// Fetch and verify the hosted index catalog against the compiled-in key.
    async fn fetch_catalog(&self) -> Result<IndexCatalog, CoreError> {
        let (manifest_url, signature_url) = index_catalog_urls()?;
        let manifest = self.get_bytes(&manifest_url).await?;
        let signature = self.get_bytes(&signature_url).await?;
        IndexCatalog::verify_default(&manifest, &signature).map_err(|e| CoreError::Repair {
            detail: format!("index catalog: {e}"),
        })
    }

    /// GET `url` and return its body bytes, mapping any transport or status failure to a repair error.
    async fn get_bytes(&self, url: &Url) -> Result<Vec<u8>, CoreError> {
        let fetch_err = |e: reqwest::Error| CoreError::Repair {
            detail: format!("fetch {url}: {e}"),
        };
        let response = self
            .http
            .get(url.clone())
            .send()
            .await
            .map_err(fetch_err)?
            .error_for_status()
            .map_err(fetch_err)?;
        Ok(response.bytes().await.map_err(fetch_err)?.to_vec())
    }

    /// Turn a [`RepairPlan`] into `apogee-patcher`'s [`RepairRequest`]: resolve each repo's block-index
    /// pin from the signed catalog and seed its local-first sources from the patch cache.
    async fn build_repair_request(&self, plan: RepairPlan) -> Result<RepairRequest, CoreError> {
        let catalog = self.fetch_catalog().await?;
        let cached = cached_patch_sources(&self.patch_store);
        let mut repos = Vec::with_capacity(plan.repos.len());
        for RepairRepoPlan { repo, version } in plan.repos {
            let entry = catalog
                .resolve(repo, &version)
                .ok_or_else(|| CoreError::Repair {
                    detail: format!("no block index for {repo:?} {version} in the signed catalog"),
                })?;
            let patch_sources = cached
                .iter()
                .find(|(r, _)| *r == repo)
                .map(|(_, sources)| sources.clone())
                .unwrap_or_default();
            repos.push(RepairRepo {
                repo,
                target_version: version,
                index: entry.source(),
                patch_sources,
                // The CDN base lets the repair form each index source-ref's URL without a populated
                // cache, so a repair works even with keep-patches off.
                source_base_url: source_base_for(entry, repo),
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
    use apogee_fetch::DigestPin;

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
}
