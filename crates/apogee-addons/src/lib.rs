#![forbid(unsafe_code)]
//! Companion tool and component injection.
//!
//! STUB: public shape only (error taxonomy, the [`Injectable`] seam this crate owns, the
//! [`ComponentKind`] catalog, and the [`Addons`] handle the composition root constructs); install,
//! injection, and companion lifecycle are not yet built.

use std::path::PathBuf;

use async_trait::async_trait;
use thiserror::Error;

use apogee_fetch::{FetchError, Fetcher};
use apogee_runtime::{GameSession, LaunchPlan, Prefix, Progress, Runtime};

pub mod backup;
pub mod external;

pub use backup::{BackupError, Selection};
pub use external::{
    AddonEvent, AddonEvents, AddonOutcome, AddonReport, AddonSession, ExternalAddon, GameContext,
    Outcome, RunIn, Running, Trigger,
};

/// Crate result over [`AddonError`].
pub type Result<T> = std::result::Result<T, AddonError>;

/// How well a component is supported.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SupportTier {
    FirstClass,
    BestEffort { note: String },
}

/// Component install / injection failures.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AddonError {
    #[error("component download failed")]
    Download(#[from] FetchError),
    #[error("integrity mismatch for {component}: expected {expected}, got {got}")]
    IntegrityMismatch {
        component: String,
        expected: String,
        got: String,
    },
    #[error("install of {component} failed at step {step}")]
    Install {
        component: String,
        step: &'static str,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("injection of {injectable} failed ({tier:?})")]
    Inject {
        injectable: String,
        tier: SupportTier,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("verb {verb} failed")]
    VerbFailed {
        verb: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    #[error("addon {index} ({program:?}) cannot be run: {reason}")]
    InvalidAddon {
        program: PathBuf,
        index: usize,
        reason: &'static str,
    },
    #[error("{program:?} runs inside a prefix, but this launch has no prefix")]
    PrefixRequired { program: PathBuf },
    #[error("{program:?} asks for {field:?}, which this launcher does not support")]
    UnsupportedField { program: PathBuf, field: String },
    #[error("failed to start {program:?}")]
    ExternalSpawn {
        program: PathBuf,
        /// Boxed because the runtime's own taxonomy is wide, and this error type is carried in the
        /// error half of results all over this crate.
        #[source]
        source: Box<apogee_runtime::RuntimeError>,
    },
    #[error("config backup failed")]
    Backup(#[from] BackupError),
    #[error("unsupported: {what}")]
    Unsupported { what: &'static str },
}

/// A component that installs into a prefix and hooks the launch / attach lifecycle.
#[async_trait]
pub trait Injectable: Send + Sync {
    fn name(&self) -> &str;
    fn support_tier(&self) -> SupportTier;

    /// Install or update the component into `prefix` (opt-in).
    async fn ensure(&self, prefix: &Prefix, p: &Progress) -> Result<()>;

    /// Wrap or mutate the launch before spawn. Default: no-op.
    fn prepare_launch(&self, _plan: &mut LaunchPlan) -> Result<()> {
        Ok(())
    }

    /// Attach after the game process is resolved. Default: no-op.
    async fn attach(&self, _game: &GameSession) -> Result<()> {
        Ok(())
    }
}

/// The kinds of component the manager drives.
pub enum ComponentKind {
    Injectable(Box<dyn Injectable>),
    PrefixTool,
    Verb,
    ExternalNative,
}

/// A signed catalog of installable components.
#[derive(Debug, Clone, Default)]
pub struct ComponentManifest {/* signed rows not yet modeled */}

/// Companion / component manager (`apogee-core`'s `addons` field).
///
/// A cheap handle: clone it to share. Every field it holds is itself a handle.
#[derive(Debug, Clone)]
pub struct Addons {
    runtime: Runtime,
    #[expect(dead_code, reason = "component downloads are a later concern")]
    fetcher: Fetcher,
    #[expect(dead_code, reason = "the signed component catalog is a later concern")]
    manifest: ComponentManifest,
}

impl Addons {
    /// Construct over the runtime, fetcher, and component manifest (composition root).
    #[must_use]
    pub fn new(runtime: Runtime, fetcher: Fetcher, manifest: ComponentManifest) -> Self {
        Self {
            runtime,
            fetcher,
            manifest,
        }
    }

    /// Start the companions that run alongside a game that is already up.
    ///
    /// Never fails as a whole: an entry that cannot be run is recorded in the session's report and
    /// the rest continue, because a helper tool must not fail a launch that has already succeeded.
    pub async fn start_external(
        &self,
        addons: &[ExternalAddon],
        game: &GameContext,
        events: &AddonEvents,
    ) -> AddonSession {
        external::start(&self.runtime, addons, game, events).await
    }
}
