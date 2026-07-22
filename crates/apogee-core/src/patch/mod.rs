//! The patch/repair seam: driving `apogee-patcher` through an injectable backend.
//!
//! The flow drives install and repair through [`PatchBackend`] rather than `apogee-patcher` directly,
//! so a headless test can substitute a fake and assert the patch-branch event streams without a
//! network, a patch corpus, or a real index catalog. The real backend
//! ([`patcher_backend::PatcherBackend`]) wraps `apogee-patcher`, relays its [`Job`] progress onto the
//! event stream as [`Event::Patch`], and resolves a repair's signed block-index pins from the hosted
//! catalog. Install requests are fully determined by the flow (the pending patch set comes from
//! registration); a repair request is not (its index pins come from the catalog), so repair takes a
//! lighter [`RepairPlan`] the backend resolves.
//!
//! [`Job`]: apogee_patcher::Job

use std::path::{Path, PathBuf};

use apogee_patcher::{InstallRequest, Installed, RepairOutcome, Repo};
use async_trait::async_trait;
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use crate::command::Event;
use crate::error::CoreError;

pub(crate) mod patcher_backend;

/// One repo to repair: which repo and the installed version its block index must describe (the
/// cross-check target).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepairRepoPlan {
    pub(crate) repo: Repo,
    pub(crate) version: String,
}

/// A repair across a profile's installed repos. The backend resolves each repo's `sha256`-pinned
/// block index from the signed catalog and hands `apogee-patcher` the full request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RepairPlan {
    /// The install root holding `boot/` and `game/`.
    pub(crate) game_root: PathBuf,
    /// The repos to verify and heal, each with the version its index must describe.
    pub(crate) repos: Vec<RepairRepoPlan>,
}

/// Classify a patch location into its repo by the reference launcher's rule
/// (`PatchListEntry.GetRepo`, `PatchListEntry.cs:29-52`): the first `ex{n}` path segment (1..=5) is
/// expansion `n`, a `boot` segment is boot, and everything else is the base game. The game patchlist
/// mixes the base game and every expansion; the segment identifies which repo each entry applies to
/// (and which `.ver` advances). Boot patches arrive on their own patchlist, so the `boot` case only
/// matters for the repair cache scan.
pub(crate) fn classify_repo<'a>(segments: impl IntoIterator<Item = &'a str>) -> Repo {
    for seg in segments {
        if seg == "boot" {
            return Repo::Boot;
        }
        if let Some(n) = seg.strip_prefix("ex").and_then(|d| d.parse::<u8>().ok())
            && (1..=5).contains(&n)
        {
            return Repo::Expansion(n);
        }
    }
    Repo::Game
}

/// The `.ver` path for `repo` beneath `game_root`, in the standard install layout the patcher writes
/// and `sqex_proto::InstallPaths` reads (`boot/ffxivboot.ver`, `game/ffxivgame.ver`,
/// `game/sqpack/ex{n}/ex{n}.ver`). `None` for a repo with no fixed on-disk location. The flow reads
/// it (for a repair plan) and the test fake writes it, so the mapping lives in one place on this side
/// of the seam.
pub(crate) fn repo_ver_path(game_root: &Path, repo: Repo) -> Option<PathBuf> {
    Some(match repo {
        Repo::Boot => game_root.join("boot").join("ffxivboot.ver"),
        Repo::Game => game_root.join("game").join("ffxivgame.ver"),
        Repo::Expansion(n) => game_root
            .join("game")
            .join("sqpack")
            .join(format!("ex{n}"))
            .join(format!("ex{n}.ver")),
        _ => return None,
    })
}

/// Drives `apogee-patcher` for install and repair, relaying progress onto the core event stream.
#[async_trait]
pub(crate) trait PatchBackend: Send + Sync {
    /// Install one repo's ordered patch set, relaying each `apogee-patcher` progress frame onto
    /// `events` as [`Event::Patch`]. Returns the per-repo installed version.
    async fn install(
        &self,
        request: InstallRequest,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<Installed, CoreError>;

    /// Verify and repair the planned repos, relaying each progress frame onto `events` as
    /// [`Event::Patch`]. Returns the aggregate repair outcome.
    async fn repair(
        &self,
        plan: RepairPlan,
        cancel: &CancellationToken,
        events: &UnboundedSender<Event>,
    ) -> Result<RepairOutcome, CoreError>;
}

#[cfg(test)]
pub(crate) mod fake {
    //! An in-memory patch backend for the headless flow tests. It records each request, advances the
    //! install's on-disk `.ver` files (and lays down the boot EXEs on a boot install, so a subsequent
    //! sentinel version report can hash them), emits a representative progress frame, and returns a
    //! scripted result. This makes the patch-branch event sequences assertable without a real
    //! download or apply.

    use std::path::Path;
    use std::sync::{Mutex, PoisonError};

    use apogee_patcher::{
        InstallRequest, Installed, PatchProgress, RepairOutcome, RepairedRepo, Repo,
    };

    use super::{
        CancellationToken, CoreError, Event, PatchBackend, RepairPlan, UnboundedSender, async_trait,
    };

    /// A fake backend recording every install request and repair plan it is handed.
    #[derive(Default)]
    pub(crate) struct FakePatchBackend {
        installs: Mutex<Vec<InstallRequest>>,
        repairs: Mutex<Vec<RepairPlan>>,
    }

    impl FakePatchBackend {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// The install requests received, in order.
        pub(crate) fn installs(&self) -> Vec<InstallRequest> {
            self.installs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// The repos installed, in order (one entry per install request).
        pub(crate) fn installed_repos(&self) -> Vec<Repo> {
            self.installs().iter().map(|r| r.repo).collect()
        }

        /// The repair plans received, in order.
        pub(crate) fn repairs(&self) -> Vec<RepairPlan> {
            self.repairs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl PatchBackend for FakePatchBackend {
        async fn install(
            &self,
            request: InstallRequest,
            _cancel: &CancellationToken,
            events: &UnboundedSender<Event>,
        ) -> Result<Installed, CoreError> {
            let repo = request.repo;
            // The version the last patch advances the repo to (the same bare form the real store writes).
            let new_version = request
                .patches
                .last()
                .map(|p| bare_version(&p.version_id))
                .unwrap_or_default();

            materialize(&request.game_root, repo, &new_version);

            let index = u32::try_from(request.patches.len().saturating_sub(1)).unwrap_or(0);
            let _ = events.send(Event::Patch(PatchProgress::Applied {
                repo,
                index,
                version: new_version.clone(),
            }));

            self.installs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request);
            Ok(Installed { repo, new_version })
        }

        async fn repair(
            &self,
            plan: RepairPlan,
            _cancel: &CancellationToken,
            events: &UnboundedSender<Event>,
        ) -> Result<RepairOutcome, CoreError> {
            let mut outcome = RepairOutcome::default();
            for repo_plan in &plan.repos {
                let repo = repo_plan.repo;
                let _ = events.send(Event::Patch(PatchProgress::Verifying { repo, attempt: 0 }));
                let version = bare_version(&repo_plan.version);
                let _ = events.send(Event::Patch(PatchProgress::Repaired {
                    repo,
                    version: version.clone(),
                }));
                outcome.repos.push(RepairedRepo {
                    repo,
                    version,
                    repaired_parts: 0,
                    recreated: 0,
                    resized: 0,
                    bytes_refetched: 0,
                    quarantined: Vec::new(),
                });
            }
            self.repairs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(plan);
            Ok(outcome)
        }
    }

    /// Advance the repo's `.ver` on disk to `version`, mirroring the real store layout. A boot install
    /// also lays down the four boot EXEs (in version-report hash order), so a sentinel version report
    /// over a from-nothing install can hash them on the next round.
    fn materialize(game_root: &Path, repo: Repo, version: &str) {
        let Some(ver_path) = super::repo_ver_path(game_root, repo) else {
            return;
        };
        if repo == Repo::Boot {
            let boot = game_root.join("boot");
            let _ = std::fs::create_dir_all(&boot);
            for name in [
                "ffxivboot.exe",
                "ffxivboot64.exe",
                "ffxivlauncher64.exe",
                "ffxivupdater64.exe",
            ] {
                let _ = std::fs::write(boot.join(name), name.as_bytes());
            }
        }
        if let Some(parent) = ver_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if !version.is_empty() {
            let _ = std::fs::write(&ver_path, version);
        }
    }

    /// Strip a patchlist version's leading list-prefix letter, matching the real store's `.ver` form.
    fn bare_version(version_id: &str) -> String {
        version_id
            .trim_start_matches(|c: char| c.is_ascii_alphabetic())
            .to_owned()
    }
}
