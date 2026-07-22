//! The launcher's domain model: profiles, accounts, and settings.
//!
//! A profile is a set of fields carrying a stable [`Uuid`], so identity never shifts when a field
//! like OTP use is toggled. Credentials never appear here: an account references its password and
//! TOTP material by UUID in the secret store, keeping the model serializable without ever touching
//! plaintext.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A launch configuration: one account, one game path, one runner and prefix, a component set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable identity, minted once and never derived from the other fields.
    pub id: Uuid,
    pub name: String,
    /// The [`Account`] this profile logs in with.
    pub account: Uuid,
    pub game_path: PathBuf,
    pub runner: RunnerSelection,
    pub prefix: PrefixSelection,
    pub components: Vec<ComponentSelection>,
    pub launch: LaunchSettings,
}

impl Profile {
    /// A new profile with a freshly minted identity and empty selections.
    #[must_use]
    pub fn new(name: impl Into<String>, account: Uuid, game_path: PathBuf) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            account,
            game_path,
            runner: RunnerSelection::SystemWine,
            prefix: PrefixSelection::default(),
            components: Vec::new(),
            launch: LaunchSettings::default(),
        }
    }
}

/// A Square Enix account: its login name, kind, and whether it carries a one-time password. The
/// password and TOTP secret are not fields: they live in the secret store, keyed by [`Account::id`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub sqex_id: String,
    pub kind: AccountKind,
    pub use_otp: bool,
}

impl Account {
    /// A new account with a freshly minted identity and no one-time password.
    #[must_use]
    pub fn new(sqex_id: impl Into<String>, kind: AccountKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            sqex_id: sqex_id.into(),
            kind,
            use_otp: false,
        }
    }
}

/// How an account authenticates and what entitlements it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AccountKind {
    Standard,
    Steam { app_id: u32 },
    FreeTrial,
}

/// Which Wine/Proton runner a profile launches under.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum RunnerSelection {
    /// The Wine already on the host `PATH`.
    SystemWine,
    /// A managed runner pinned by name and version.
    Managed { name: String, version: String },
}

/// Which prefix a profile uses, named within the runtime's prefix set.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PrefixSelection {
    pub name: String,
}

/// A companion component a profile enables, referenced by catalog id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComponentSelection {
    pub id: String,
    pub enabled: bool,
}

/// Region and per-launch overrides applied when the game starts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LaunchSettings {
    pub region: Region,
    pub extra_args: Vec<String>,
    pub extra_env: Vec<(String, String)>,
    pub wrappers: Vec<String>,
}

/// The service region a profile connects to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Region {
    #[default]
    Global,
    Korea,
    China,
}

/// Launcher-wide preferences, independent of any profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub language: String,
    pub close_after_launch: bool,
    /// Keep downloaded patches after a clean apply instead of removing them. Costs disk, but lets a
    /// later repair re-fetch broken ranges from the local patch files first (and a re-apply skip the
    /// download). Read once at construction, so a change takes effect on the next launch.
    pub keep_patches: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
            close_after_launch: false,
            keep_patches: false,
        }
    }
}
