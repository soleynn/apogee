//! Curated programs: deciding which enabled ones may start, and building them once the game is up.
//!
//! A program reaches a launch in two halves, split by the game's spawn. Before it,
//! [`Addons::program_gates`](crate::Addons::program_gates) decides which enabled programs pass every
//! gate and returns a [`ProgramPlan`]; nothing in it needs the game, so it takes no
//! [`GameContext`]. After it, [`ProgramPlan::companions`] turns the plan into the
//! [`ExternalAddon`] entries the ordinary companion start runs, against the game's own context, so a
//! program can only ever be started into the prefix the game is running in.
//!
//! A program that fails a gate is said on the setup stream, named in the plan's skipped list, and
//! not started. The game always starts.
//!
//! # Examples
//!
//! ```
//! # use apogee_addons::{Addons, AddonEvents, GameContext, SetupEvents, VerifiedManifest};
//! # use apogee_runtime::{Prefix, RunnerRef};
//! # async fn demo(
//! #     addons: &Addons,
//! #     manifest: &VerifiedManifest,
//! #     prefix: &Prefix,
//! #     runner: &RunnerRef,
//! #     game: &GameContext,
//! #     user_addons: &[apogee_addons::ExternalAddon],
//! # ) -> apogee_addons::Result<()> {
//! let enabled = ["act"];
//! let plan = addons.program_gates(
//!     manifest,
//!     prefix,
//!     &enabled,
//!     "2026.11.03.0000.0000",
//!     runner,
//!     &SetupEvents::none(),
//! );
//!
//! // ... the game is spawned, and its pid resolved into `game` ...
//!
//! let mut companions = plan.companions(game)?;
//! companions.extend_from_slice(user_addons);
//! let session = addons.start_external(&companions, game, &AddonEvents::none()).await;
//! let evidence = plan.load_evidence(std::time::SystemTime::now());
//! # Ok(())
//! # }
//! ```

mod paths;
pub(crate) mod record;
#[cfg(test)]
#[cfg(unix)]
mod tests;
mod updater;

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use apogee_runtime::{InstalledComponent, Prefix, RunnerRef};

use crate::manifest::{ComponentManifest, ProgramEntry, RunnerPin};
use crate::{
    AddonError, ExternalAddon, GameContext, LoadEvidence, Result, RunIn, SetupEvent, SetupEvents,
};

pub(crate) use paths::{under_drive_c, walk_dirs};
pub use updater::UpdaterState;

/// Why an enabled program is not in a [`ProgramPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SkipReason {
    /// The catalog carries no row for it.
    NoRow,
    /// The catalog's row for it is one this build cannot read.
    #[non_exhaustive]
    UnreadableRow {
        /// Why, as one line.
        reason: String,
    },
    /// It has not been validated on this game version.
    #[non_exhaustive]
    GameVersion {
        /// The game version this launch is on.
        game_version: String,
    },
    /// It has not been validated on the runner this prefix is built with.
    #[non_exhaustive]
    Runner {
        /// The runner the prefix records.
        runner: RunnerRef,
        /// The runners it has been validated on, one of which the prefix would need.
        validated: Vec<RunnerPin>,
    },
    /// The prefix does not record this version of it as installed.
    #[non_exhaustive]
    NotInstalled {
        /// The version the prefix records, if any.
        recorded: Option<String>,
    },
    /// What its steps placed cannot be checked.
    #[non_exhaustive]
    NoInstallRecord {
        /// Why, as one line.
        reason: String,
    },
    /// A file its steps placed is no longer what was placed.
    #[non_exhaustive]
    Changed {
        /// The file, relative to the prefix's `C:`.
        path: String,
    },
    /// One of its self-updaters is not switched off.
    #[non_exhaustive]
    UpdaterOn {
        /// The setting.
        key: String,
        /// What it holds, or `None` when the setting or its file could not be found or read.
        value: Option<String>,
    },
    /// It claims a fixed name another enabled program already holds.
    #[non_exhaustive]
    Conflict {
        /// The program that holds it.
        with: String,
        /// The name both claim.
        claim: String,
    },
    /// A path its row names cannot be resolved inside this prefix.
    #[non_exhaustive]
    UnresolvedPath {
        /// Why, as one line.
        reason: String,
    },
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoRow => f.write_str("the catalog carries no row for it"),
            Self::UnreadableRow { reason } => {
                write!(
                    f,
                    "this build cannot read the catalog's row for it: {reason}"
                )
            }
            Self::GameVersion { game_version } => write!(
                f,
                "it has not been validated on game version {game_version}, so it is not started"
            ),
            Self::Runner { runner, validated } => {
                let names: Vec<String> = validated
                    .iter()
                    .map(|pin| format!("{} {}", pin.name, pin.version))
                    .collect();
                write!(
                    f,
                    "it has not been validated on {} {}; it runs on {}",
                    runner.name,
                    runner.version,
                    names.join(", ")
                )
            }
            Self::NotInstalled { recorded: None } => {
                f.write_str("it is not installed in this prefix yet")
            }
            Self::NotInstalled {
                recorded: Some(version),
            } => write!(
                f,
                "this prefix has version {version} installed, not the one the catalog pins"
            ),
            Self::NoInstallRecord { reason } => {
                write!(f, "what it installed cannot be checked: {reason}")
            }
            Self::Changed { path } => write!(
                f,
                "{path} changed outside Apogee since it was installed; reinstall it to run it again"
            ),
            Self::UpdaterOn {
                key,
                value: Some(value),
            } => write!(
                f,
                "its self-updater setting {key} is {value:?}; turn it off to run it"
            ),
            Self::UpdaterOn { key, value: None } => write!(
                f,
                "its self-updater setting {key} cannot be read as off, so it is not started"
            ),
            Self::Conflict { with, claim } => write!(
                f,
                "it cannot run in the same session as {with}: both hold {claim}"
            ),
            Self::UnresolvedPath { reason } => f.write_str(reason),
        }
    }
}

/// An enabled program that is not in a plan, and why.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SkippedProgram {
    /// The program, by its row's name.
    pub name: String,
    /// Why it is not started.
    pub reason: SkipReason,
}

/// A program that passed every gate and is started with the game.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PlannedProgram {
    /// The program, by its row's name.
    pub name: String,
    /// The row version that was checked.
    pub version: String,
    /// The executable, relative to the prefix's `C:`.
    program: PathBuf,
    args: Vec<String>,
    trigger: crate::Trigger,
    env: BTreeMap<String, String>,
    evidence: Option<(PathBuf, Duration)>,
}

/// The enabled programs that may start with this launch, decided before the game is spawned.
///
/// Built by [`Addons::program_gates`](crate::Addons::program_gates). Holds the prefix it was gated
/// against, so the companions it builds afterwards can only go into that prefix.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProgramPlan {
    prefix: PathBuf,
    planned: Vec<PlannedProgram>,
    skipped: Vec<SkippedProgram>,
}

impl ProgramPlan {
    /// The programs that passed, in the catalog's row order.
    #[must_use]
    pub fn planned(&self) -> &[PlannedProgram] {
        &self.planned
    }

    /// The enabled programs that did not, each with why.
    #[must_use]
    pub fn skipped(&self) -> &[SkippedProgram] {
        &self.skipped
    }

    /// Whether nothing is to be started.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.planned.is_empty()
    }

    /// One companion entry per planned program, to start ahead of the user's own.
    ///
    /// Taken after the game is spawned, from the context built for it, and never from a fresh
    /// prefix handle: a program must join the game's wine session, and the game's context is the only
    /// thing that names it. Each entry runs inside the prefix, with the game, and stops with it, and
    /// is marked as curated, so one found already running is reported as running and unverified
    /// rather than as the pinned program.
    ///
    /// # Errors
    /// [`AddonError::PrefixRequired`] if `game` has no prefix and anything is planned, and
    /// [`AddonError::ProgramPrefixMismatch`] if its prefix is not the one this plan was gated against.
    pub fn companions(&self, game: &GameContext) -> Result<Vec<ExternalAddon>> {
        let Some(first) = self.planned.first() else {
            return Ok(Vec::new());
        };
        let Some(prefix) = game.prefix() else {
            return Err(AddonError::PrefixRequired {
                program: first.program.clone(),
            });
        };
        if prefix.path() != self.prefix {
            return Err(AddonError::ProgramPrefixMismatch {
                program: first.name.clone(),
                gated: self.prefix.clone(),
                game: prefix.path().to_path_buf(),
            });
        }
        let drive_c = prefix.drive_c();
        self.planned
            .iter()
            .map(|program| {
                Ok(ExternalAddon::new(
                    drive_c.join(&program.program),
                    program.args.clone(),
                    RunIn::Prefix,
                    program.trigger,
                )?
                .with_env(program.env.clone())
                .curated_as(&program.name))
            })
            .collect()
    }

    /// What to watch for each planned program's proof that it came up, counting writes after `since`.
    ///
    /// A program whose row names no proof contributes nothing. One that was found already running
    /// rather than started is not proof of the pinned program, so a caller should not watch for it.
    #[must_use]
    pub fn load_evidence(&self, since: SystemTime) -> Vec<LoadEvidence> {
        self.planned
            .iter()
            .filter_map(|program| {
                let (path, window) = program.evidence.as_ref()?;
                Some(LoadEvidence::new(&program.name, path, since).within(*window))
            })
            .collect()
    }
}

/// The gates, in order, for every enabled program the manifest carries a row for.
pub(crate) fn gates(
    manifest: &ComponentManifest,
    addons_root: &Path,
    prefix: &Prefix,
    enabled: &[&str],
    game_version: &str,
    runner: &RunnerRef,
    events: &SetupEvents,
) -> ProgramPlan {
    let mut plan = ProgramPlan {
        prefix: prefix.path().to_path_buf(),
        planned: Vec::new(),
        skipped: Vec::new(),
    };
    let installed = prefix.components().unwrap_or_default();
    let records = record::records_dir(addons_root, prefix.path());
    // A fixed name is held by the first program in row order that passes every other gate.
    let mut claimed: BTreeMap<&str, &str> = BTreeMap::new();

    let skip = |plan: &mut ProgramPlan, name: &str, reason: SkipReason| {
        let note = reason.to_string();
        // A conflict is a refusal between two things the user asked for, so it is a failure; every
        // other gate is a caveat about a program that is simply not ready to run here.
        events.emit(if matches!(reason, SkipReason::Conflict { .. }) {
            SetupEvent::Failed {
                what: name.to_owned(),
                reason: note,
            }
        } else {
            SetupEvent::Caveat {
                what: name.to_owned(),
                note,
            }
        });
        plan.skipped.push(SkippedProgram {
            name: name.to_owned(),
            reason,
        });
    };

    for name in requested(manifest, enabled, |name, reason| {
        skip(&mut plan, name, reason);
    }) {
        let Some(row) = manifest.program(name) else {
            continue;
        };
        if let Some(note) = row.tier.note() {
            events.emit(SetupEvent::Caveat {
                what: row.name.clone(),
                note: note.to_owned(),
            });
        }
        match gate(row, prefix, &installed, &records, game_version, runner) {
            Err(reason) => skip(&mut plan, &row.name, reason),
            Ok(planned) => {
                if let Some((claim, holder)) = row
                    .claims
                    .iter()
                    .find_map(|claim| claimed.get(claim.as_str()).map(|h| (claim, *h)))
                {
                    let reason = SkipReason::Conflict {
                        with: holder.to_owned(),
                        claim: claim.clone(),
                    };
                    skip(&mut plan, &row.name, reason);
                    continue;
                }
                for claim in &row.claims {
                    claimed.insert(claim, &row.name);
                }
                plan.planned.push(planned);
            }
        }
    }
    plan
}

/// The enabled names in the manifest's row order, reporting each one that has no usable row.
///
/// Row order rather than the caller's, so two launches enabling the same programs install and start
/// them the same way whatever order a profile lists them in.
pub(crate) fn requested<'m>(
    manifest: &'m ComponentManifest,
    enabled: &[&str],
    mut missing: impl FnMut(&str, SkipReason),
) -> Vec<&'m str> {
    for name in enabled {
        if manifest.program(name).is_some() {
            continue;
        }
        let reason = manifest
            .refused_program(name)
            .map_or(SkipReason::NoRow, |refused| SkipReason::UnreadableRow {
                reason: refused.reason.clone(),
            });
        missing(name, reason);
    }
    manifest
        .programs
        .iter()
        .filter(|row| enabled.contains(&row.name.as_str()))
        .map(|row| row.name.as_str())
        .collect()
}

/// Every gate one program must pass, cheapest first, so a program that would be refused on its
/// version is not hashed.
fn gate(
    row: &ProgramEntry,
    prefix: &Prefix,
    installed: &[InstalledComponent],
    records: &Path,
    game_version: &str,
    runner: &RunnerRef,
) -> std::result::Result<PlannedProgram, SkipReason> {
    if !row.supports_game(game_version) {
        return Err(SkipReason::GameVersion {
            game_version: game_version.to_owned(),
        });
    }
    if !row.supports_runner(runner) {
        return Err(SkipReason::Runner {
            runner: runner.clone(),
            validated: row.runners.clone(),
        });
    }
    let recorded = installed
        .iter()
        .find(|c| c.name() == row.name)
        .map(|c| c.version().map(str::to_owned));
    if recorded.as_ref().and_then(Option::as_deref) != Some(row.version.as_str()) {
        return Err(SkipReason::NotInstalled {
            recorded: recorded.flatten(),
        });
    }

    let unresolved = |err: AddonError| SkipReason::UnresolvedPath {
        reason: err.chain(),
    };
    let start = under_drive_c(prefix, &row.start.program, &row.name).map_err(unresolved)?;
    let pinned: Vec<&str> = row
        .steps
        .iter()
        .filter(|step| !step.seeded)
        .map(|step| step.verb.name.as_str())
        .collect();
    let expected = record::expected(records, &row.name, &row.version, &pinned)
        .map_err(|reason| SkipReason::NoInstallRecord { reason })?;
    let start_key = start
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect::<Vec<_>>()
        .join("/");
    if !expected.contains_key(&start_key) {
        return Err(SkipReason::NoInstallRecord {
            reason: format!("{start_key} is not a file its steps placed"),
        });
    }
    let drive_c = prefix.drive_c();
    if let Some(path) = record::first_changed(&drive_c, &expected) {
        return Err(SkipReason::Changed { path });
    }

    for key in &row.updater_keys {
        let state = under_drive_c(prefix, &key.file, &row.name)
            .ok()
            .and_then(|rel| paths::open_regular(&drive_c, &rel).ok())
            .and_then(|file| {
                use std::io::Read as _;
                let mut bytes = Vec::new();
                file.take(updater::MAX_SETTINGS_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .ok()?;
                Some(key.state_in(&bytes))
            });
        match state {
            Some(UpdaterState::Off) => {}
            Some(UpdaterState::On { value }) => {
                return Err(SkipReason::UpdaterOn {
                    key: key.key.clone(),
                    value: Some(value),
                });
            }
            _ => {
                return Err(SkipReason::UpdaterOn {
                    key: key.key.clone(),
                    value: None,
                });
            }
        }
    }

    let evidence = match &row.evidence {
        Some(evidence) => Some((
            drive_c.join(under_drive_c(prefix, &evidence.path, &row.name).map_err(unresolved)?),
            evidence.window,
        )),
        None => None,
    };
    Ok(PlannedProgram {
        name: row.name.clone(),
        version: row.version.clone(),
        program: start,
        args: row.start.args.clone(),
        trigger: row.start.trigger,
        env: row.start.env.clone(),
        evidence,
    })
}
