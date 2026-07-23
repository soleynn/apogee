//! The install request and its result, and the repair request and its inputs.

use std::path::PathBuf;

use sqex_proto::PatchListEntry;
use url::Url;

use crate::Repo;

/// The per-download SE request headers. Every patch request carries the `FFXIV PATCH CLIENT`
/// user-agent; a game patch additionally carries the session's `X-Patch-Unique-Id` credential, while
/// a boot patch (fetched before login) carries none. `#[non_exhaustive]` so later phases can add
/// header inputs without a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SePatch {
    /// The `X-Patch-Unique-Id` credential from session registration, absent for boot patches.
    pub unique_id: Option<String>,
}

impl SePatch {
    /// Game-patch headers carrying the given session patch-download credential.
    #[must_use]
    pub fn new(unique_id: impl Into<String>) -> Self {
        Self {
            unique_id: Some(unique_id.into()),
        }
    }

    /// Boot-patch headers: the patch-client user-agent only, no session credential (boot patching
    /// runs before there is a session).
    #[must_use]
    pub fn boot() -> Self {
        Self { unique_id: None }
    }
}

/// One repo's install: its ordered pending patch set, the game root to apply into, and the SE
/// headers to fetch with. A single request is always single-repo; the composition root drives
/// boot-before-game by calling [`Patcher::install`](crate::Patcher::install) per repo.
#[derive(Debug, Clone)]
pub struct InstallRequest {
    /// Which repo these patches belong to (sets fetch priority and the `.ver` target).
    pub repo: Repo,
    /// The install root holding `boot/` and `game/`; patches apply into the repo's subtree beneath.
    pub game_root: PathBuf,
    /// The pending patches, already in SE apply order (index `k` applies only after `0..k`).
    pub patches: Vec<PatchListEntry>,
    /// The SE request headers for the patch downloads.
    pub headers: SePatch,
}

/// The outcome of a clean [`Patcher::install`](crate::Patcher::install): the per-repo version now on
/// disk, so the caller's re-registration loop knows what to report to SE next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Installed {
    /// The repo that was installed.
    pub repo: Repo,
    /// The version written to the repo's `.ver` (the last applied patch, prefix-stripped).
    pub new_version: String,
}

/// How a repair obtains a repo's `.apzi` block index.
///
/// The index is derived (reproducible from the same patch chain), so its authenticity rests on a
/// `sha256` pin: [`Pinned`](Self::Pinned) fetches it over HTTP(S) under that pin, and
/// [`LocalFile`](Self::LocalFile) reads one already on disk (a local regeneration, or a cached
/// download). The `sha256`-pinned rows come from a signed index catalog the caller resolves; the
/// catalog's Ed25519 authenticity check and hosting are the adjacent index-infrastructure, not this
/// crate's runtime path (it consumes a resolved pin).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IndexSource {
    /// Read the `.apzi` from a local path (a regeneration, or a prior download).
    LocalFile(PathBuf),
    /// Fetch the `.apzi` over HTTP(S), authenticated by its whole-file `sha256` pin.
    Pinned {
        /// Where the `.apzi` is served.
        url: Url,
        /// The pin the fetched bytes must hash to.
        sha256: [u8; 32],
    },
}

/// One source patch a repair can pull broken ranges from, named as the index records it. The patcher
/// resolves each of the index's source patches to one of these by name and pulls only the broken
/// ranges: from [`local`](Self::local) on the first (trusted) attempt when the whole chain is present,
/// then from [`url`](Self::url) over HTTP after.
#[derive(Debug, Clone)]
pub struct RepairPatchSource {
    /// The source patch file name, matching the index's recorded name for it.
    pub name: String,
    /// Where the patch file is served, for the HTTP range fetches.
    pub url: Url,
    /// A local copy of the patch file to trust on the first attempt, if one is cached.
    pub local: Option<PathBuf>,
}

/// One repo to repair: how to get its index, the version that index must describe, the source patches
/// its ranges come from, and the SE headers for the HTTP range fetches.
#[derive(Debug, Clone)]
pub struct RepairRepo {
    /// Which repo to verify and heal.
    pub repo: Repo,
    /// The version the install should be at; cross-checked against the index's own version.
    pub target_version: String,
    /// How to obtain the repo's block index.
    pub index: IndexSource,
    /// Explicit sources for the patches the index references, matched by name (order irrelevant). Use
    /// this to supply a local copy for a first-attempt local heal, or a per-patch URL. A source the
    /// index references that is not listed here is served from [`source_base_url`](Self::source_base_url)
    /// instead; if neither supplies it, the repair fails with [`IndexUnavailable`](crate::PatchError::IndexUnavailable).
    pub patch_sources: Vec<RepairPatchSource>,
    /// The base URL under which every source patch this index references is served, so a source not in
    /// [`patch_sources`](Self::patch_sources) is fetched from `{base}/{name}` over HTTP (no local copy).
    /// This lets a repair heal from the index alone, without a populated patch cache. `None` requires
    /// every source to be listed explicitly.
    pub source_base_url: Option<Url>,
    /// The SE request headers for the HTTP range fetches (`FFXIV PATCH CLIENT`, optional unique id).
    pub headers: SePatch,
}

/// A repair across one or more repos: verify each against its block index and re-fetch only the broken
/// byte ranges. The game root travels with the request, as for [`InstallRequest`].
#[derive(Debug, Clone)]
pub struct RepairRequest {
    /// The install root holding `boot/` and `game/`; each repo is verified in its subtree beneath.
    pub game_root: PathBuf,
    /// The repos to check, each with its index and source patches.
    pub repos: Vec<RepairRepo>,
}
