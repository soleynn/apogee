//! The install request and its result.

use std::path::PathBuf;

use sqex_proto::PatchListEntry;

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
