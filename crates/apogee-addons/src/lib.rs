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
    #[error("failed to spawn {path:?}")]
    ExternalSpawn {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("backup of {path:?} failed")]
    Backup {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
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

/// An externally-run companion tool.
#[derive(Debug, Clone)]
pub struct ExternalAddon {
    pub path: PathBuf,
}

/// The kinds of component the manager drives.
pub enum ComponentKind {
    Injectable(Box<dyn Injectable>),
    PrefixTool,
    Verb,
    External(ExternalAddon),
}

/// A signed catalog of installable components.
#[derive(Debug, Clone, Default)]
pub struct ComponentManifest {/* signed rows not yet modeled */}

/// Companion / component manager (`apogee-core`'s `addons` field).
#[derive(Debug)]
pub struct Addons;

impl Addons {
    /// Construct over the runtime, fetcher, and component manifest (composition root).
    pub fn new(_runtime: Runtime, _fetcher: Fetcher, _manifest: ComponentManifest) -> Self {
        Self
    }
}
