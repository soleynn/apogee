//! Running the user's own tools alongside the game.
//!
//! One pass over the configured list starts everything that runs with the game and hands back an
//! [`AddonSession`] that owns them. The launch is never blocked by a helper: an entry that cannot be
//! run is recorded against its own index and reported, and the game still starts.
//!
//! # Examples
//!
//! ```
//! # use apogee_addons::{AddonEvents, ExternalAddon, GameContext};
//! # use apogee_runtime::Runtime;
//! # use tokio_util::sync::CancellationToken;
//! # async fn demo(
//! #     runtime: &Runtime,
//! #     tools: &[ExternalAddon],
//! #     cancel: &CancellationToken,
//! # ) -> apogee_addons::Result<()> {
//! let events = AddonEvents::none();
//! let game = GameContext::new(4321)?;
//! let session = apogee_addons::external::start(runtime, tools, &game, &events).await;
//!
//! // ... the game runs ...
//!
//! let report = session.game_closed(cancel, &events).await;
//!
//! // What each entry came to, one line per tool, already narrated onto `events`.
//! let lines: Vec<String> = report
//!     .outcomes
//!     .iter()
//!     .map(|entry| format!("{}: {}", entry.program.display(), entry.outcome))
//!     .collect();
//! # Ok(())
//! # }
//! ```

mod addon;
mod event;
mod identity;
mod session;

use std::path::PathBuf;
use std::time::Duration;

use apogee_runtime::{CompanionSpec, Prefix, Runtime};

pub use addon::{ExternalAddon, RunIn, Trigger};
pub use event::{AddonEvent, AddonEvents};
// Not public: every function that produces one is crate-private, so a caller outside could name the
// type and never obtain one.
pub(crate) use identity::Running;
pub use session::{AddonOutcome, AddonReport, AddonSession, Outcome};

use crate::{AddonError, Result};
use session::Held;

/// How long an after-game tool runs before the wait is reported as still going.
const STILL_WAITING_AFTER: Duration = Duration::from_secs(30);

/// The running game, as plain values: its process id, and the prefix it was launched into.
///
/// Not the runtime's own session type, whose constructor is private to that crate: a lifecycle test
/// living outside it could then build no game at all to start companions against.
///
/// # Examples
///
/// ```
/// # fn main() -> apogee_addons::Result<()> {
/// use apogee_addons::GameContext;
///
/// let game = GameContext::new(4321)?;
/// assert_eq!(game.game_pid(), 4321);
/// assert!(game.prefix().is_none());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct GameContext {
    pid: i32,
    prefix: Option<Prefix>,
}

impl GameContext {
    /// A launch with no prefix. A prefix tool against this context fails that entry.
    ///
    /// # Errors
    ///
    /// Returns [`AddonError::InvalidAddon`] if `game_pid` is not positive. The pid is handed to the
    /// child so a wrapper can signal it, and zero means "my whole process group" while minus one
    /// means "everything this user owns".
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::{AddonError, GameContext};
    ///
    /// assert!(matches!(
    ///     GameContext::new(0),
    ///     Err(AddonError::InvalidAddon { .. })
    /// ));
    /// ```
    pub fn new(game_pid: i32) -> Result<Self> {
        if game_pid <= 0 {
            return Err(AddonError::InvalidAddon {
                program: PathBuf::new(),
                index: 0,
                reason: "the game process id must be positive",
            });
        }
        Ok(Self {
            pid: game_pid,
            prefix: None,
        })
    }

    /// A launch into `prefix`, which is what a prefix tool is run through.
    ///
    /// # Errors
    ///
    /// As [`Self::new`].
    ///
    /// # Examples
    ///
    /// ```
    /// # use apogee_addons::GameContext;
    /// # use apogee_runtime::Prefix;
    /// # fn demo(prefix: &Prefix) -> apogee_addons::Result<()> {
    /// let game = GameContext::in_prefix(4321, prefix)?;
    /// assert!(game.prefix().is_some());
    /// # Ok(())
    /// # }
    /// ```
    pub fn in_prefix(game_pid: i32, prefix: &Prefix) -> Result<Self> {
        Ok(Self {
            prefix: Some(prefix.clone()),
            ..Self::new(game_pid)?
        })
    }

    /// The process id of the game when the companions started.
    ///
    /// A hint for reporting, not a handle to attach to: a runner renames a short-lived loader to the
    /// executable's own name and hands off, so this can be the pre-handoff loader, correct when it
    /// was read and expected to die.
    #[must_use]
    pub fn game_pid(&self) -> i32 {
        self.pid
    }

    /// The prefix, if the launch has one.
    #[must_use]
    pub fn prefix(&self) -> Option<&Prefix> {
        self.prefix.as_ref()
    }
}

/// Start every companion that runs with the game.
///
/// Entries are considered in order. Each one that fails is recorded against its own index and the
/// rest continue, so one bad entry costs the user that tool rather than the launch. An entry that
/// runs after the game is validated here too, then kept for the returned [`AddonSession`].
///
/// # Examples
///
/// ```
/// # use apogee_addons::{AddonEvents, AddonSession, ExternalAddon, GameContext};
/// # use apogee_runtime::Runtime;
/// # async fn demo(
/// #     runtime: &Runtime,
/// #     tools: &[ExternalAddon],
/// #     game: &GameContext,
/// #     events: &AddonEvents,
/// # ) -> AddonSession {
/// let session = apogee_addons::external::start(runtime, tools, game, events).await;
///
/// // The launch carries on regardless; the report says what each entry came to.
/// let started = session.report().outcomes.len();
/// session
/// # }
/// ```
pub async fn start(
    runtime: &Runtime,
    addons: &[ExternalAddon],
    game: &GameContext,
    events: &AddonEvents,
) -> AddonSession {
    let mut held = Vec::new();
    let mut on_close = Vec::new();
    let mut report = AddonReport::default();

    for (index, addon) in addons.iter().enumerate() {
        let program = addon.program().to_path_buf();
        if !addon.enabled() {
            report.outcomes.push(AddonOutcome {
                index,
                program,
                outcome: Outcome::Disabled,
            });
            continue;
        }
        if let Err(err) = addon.validate(index, game.prefix().is_some()) {
            report.outcomes.push(AddonOutcome {
                index,
                program: program.clone(),
                outcome: fail(&err, &program, events),
            });
            continue;
        }
        if addon.trigger() == Trigger::OnClose {
            // Nothing to do until the game exits, but the entry is validated now so a broken one is
            // reported while the user is still looking at the launch.
            on_close.push((index, addon.clone()));
            continue;
        }

        if let Some(running) = already_running(addon, game).await {
            events.emit(AddonEvent::AlreadyRunning {
                program: program.clone(),
                pid: running.pid,
            });
            report.outcomes.push(AddonOutcome {
                index,
                program,
                outcome: Outcome::AlreadyRunning { pid: running.pid },
            });
            continue;
        }

        match spawn(runtime, addon, game) {
            Ok(companion) => {
                let pid = companion.pid();
                events.emit(AddonEvent::Started {
                    program: program.clone(),
                    pid,
                });
                report.outcomes.push(AddonOutcome {
                    index,
                    program: program.clone(),
                    outcome: Outcome::Started { pid },
                });
                held.push(Held::new(index, program, companion, addon.trigger()));
            }
            Err(err) => {
                report.outcomes.push(AddonOutcome {
                    index,
                    program: program.clone(),
                    outcome: fail(&err, &program, events),
                });
            }
        }
    }

    AddonSession::new(
        runtime.clone(),
        game.prefix().map(|p| p.path().to_path_buf()),
        held,
        on_close,
        report,
    )
}

/// Report a failure and turn it into an outcome, so the two never disagree.
fn fail(err: &AddonError, program: &std::path::Path, events: &AddonEvents) -> Outcome {
    // Both reported and returned rather than swallowed: the launcher this takes its cues from drops
    // the failure and then logs that it launched, which is how a missing interpreter comes to look
    // exactly like a working tool.
    let reason = err.chain();
    events.emit(AddonEvent::Failed {
        program: program.to_path_buf(),
        reason: reason.clone(),
    });
    Outcome::Failed { reason }
}

/// Whether this tool is already running, by whichever relation fits where it runs.
async fn already_running(addon: &ExternalAddon, game: &GameContext) -> Option<Running> {
    match (addon.run_in(), game.prefix()) {
        (RunIn::Host, _) => identity::find_host(addon.program()),
        (RunIn::Prefix, Some(prefix)) => {
            let name = addon.program().file_name()?.to_str()?;
            // A candidate set keyed on a truncated name, narrowed by the full path below.
            let candidates = apogee_runtime::prefix_processes(prefix, name).await.ok()?;
            identity::find_in_prefix(&candidates, addon.program(), prefix, game.game_pid())
        }
        (RunIn::Prefix, None) => None,
    }
}

/// Build and spawn one companion.
fn spawn(
    runtime: &Runtime,
    addon: &ExternalAddon,
    game: &GameContext,
) -> Result<apogee_runtime::Companion> {
    let args = addon.args().to_vec();
    let mut spec = match (addon.run_in(), game.prefix()) {
        (RunIn::Host, _) => CompanionSpec::host(addon.program(), args),
        (RunIn::Prefix, Some(prefix)) => CompanionSpec::in_prefix(addon.program(), args, prefix),
        (RunIn::Prefix, None) => {
            return Err(AddonError::PrefixRequired {
                program: addon.program().to_path_buf(),
            });
        }
    };
    spec = spec.env(child_env(game));
    // A tool that keeps its configuration beside its own binary needs to be started from there.
    if let Some(dir) = addon.program().parent() {
        spec = spec.working_dir(dir);
    }
    runtime
        .spawn_companion(&spec)
        .map_err(|source| AddonError::ExternalSpawn {
            program: addon.program().to_path_buf(),
            source: Box::new(source),
        })
}

/// What a companion is told about the launch: the game's process id, and the prefix if there is one.
///
/// Deliberately small and named, so a tool can find the game without the launcher inventing a
/// substitution language in the argument vector.
fn child_env(game: &GameContext) -> std::collections::BTreeMap<String, String> {
    let mut env = std::collections::BTreeMap::new();
    env.insert("APOGEE_GAME_PID".to_owned(), game.game_pid().to_string());
    if let Some(prefix) = game.prefix() {
        env.insert(
            "APOGEE_GAME_PREFIX".to_owned(),
            prefix.path().to_string_lossy().into_owned(),
        );
    }
    env
}

/// Run one after-game tool to completion, reporting once the wait is long enough that a launcher
/// still sitting there would otherwise look stuck.
///
/// `cancel` is the only thing that bounds this: the tool is somebody else's program and may never
/// exit. A cancelled wait stops the tool rather than walking away from it, because the launcher is
/// what started it and nothing else is left that knows it is there.
pub(crate) async fn run_to_completion(
    runtime: &Runtime,
    game_prefix: Option<&std::path::Path>,
    addon: &ExternalAddon,
    cancel: &tokio_util::sync::CancellationToken,
    events: &AddonEvents,
) -> Outcome {
    let program = addon.program().to_path_buf();
    let args = addon.args().to_vec();
    let mut spec = CompanionSpec::host(&program, args);
    // The prefix travels but the game's process id does not: it has already exited, so handing it
    // over would name a process that is gone or, worse, one that has reused the number.
    let mut env = std::collections::BTreeMap::new();
    if let Some(prefix) = game_prefix {
        env.insert(
            "APOGEE_GAME_PREFIX".to_owned(),
            prefix.to_string_lossy().into_owned(),
        );
    }
    spec = spec.env(env);
    if let Some(dir) = program.parent() {
        spec = spec.working_dir(dir);
    }
    // An after-game tool runs on the host: the prefix it would have used is being torn down.
    let mut companion = match runtime.spawn_companion(&spec) {
        Ok(companion) => companion,
        Err(source) => {
            let err = AddonError::ExternalSpawn {
                program: program.clone(),
                source: Box::new(source),
            };
            return fail(&err, &program, events);
        }
    };

    // Scoped so the wait's borrow of the companion ends before the tool is stopped below.
    let waited = {
        let wait = companion.wait_group();
        tokio::pin!(wait);
        let mut elapsed = 0_u64;
        loop {
            tokio::select! {
                result = &mut wait => break Some(result),
                () = cancel.cancelled() => break None,
                () = tokio::time::sleep(STILL_WAITING_AFTER) => {
                    elapsed += STILL_WAITING_AFTER.as_secs();
                    events.emit(AddonEvent::StillWaiting {
                        program: program.clone(),
                        seconds: elapsed,
                    });
                }
            }
        }
    };

    match waited {
        Some(Ok(exit)) => Outcome::Completed { code: exit.code },
        Some(Err(err)) => Outcome::Failed {
            reason: crate::chain_of(&err),
        },
        // Stopped rather than left behind, and the failure to stop it is dropped: what a caller asked
        // for is to stop waiting, and a tool that ignores a signal is not something to report as a
        // teardown failure to somebody who is already quitting.
        None => {
            let _ = companion.stop(session::STOP_GRACE).await;
            Outcome::Cancelled
        }
    }
}
