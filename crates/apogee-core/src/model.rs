//! The launcher's domain model: profiles, accounts, and settings.
//!
//! A profile is a set of fields carrying a stable [`Uuid`], so identity never shifts when a field
//! like OTP use is toggled. Credentials never appear here: an account references its password and
//! TOTP material by UUID in the secret store, keeping the model serializable without ever touching
//! plaintext.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use apogee_addons::ExternalAddon;
use apogee_runtime::{Gamescope, GpuSelect, Hud, SyncChoice};

/// A launch configuration: one account, one game path, one runner and prefix, and the tools to run
/// beside the game.
///
/// Not `Eq`: an external addon keeps the keys a newer build might add, and those are arbitrary JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Profile {
    /// Stable identity, minted once and never derived from the other fields.
    pub id: Uuid,
    pub name: String,
    /// The [`Account`] this profile logs in with.
    pub account: Uuid,
    pub game_path: PathBuf,
    pub runner: RunnerSelection,
    pub prefix: PrefixSelection,
    /// The user's own tools, run alongside the game in list order.
    #[serde(default)]
    pub external: Vec<ExternalAddon>,
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
            external: Vec::new(),
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
    /// Keep nothing for this account in the secret store: ask for the password every time. Per
    /// account rather than per launcher, because a shared machine may hold one login worth saving
    /// and one that is not.
    pub never_store: bool,
    /// Where the one-time password comes from when [`Account::use_otp`] is set.
    ///
    /// Persisted because a front end has to choose what to ask for before it calls the core, and
    /// secrets are write-only: "is a secret stored for this account" is not a question a shell may
    /// put to the store. An account file written before this field existed reads as
    /// [`OtpDelivery::Ask`], which is what every account did then.
    #[serde(default)]
    pub otp_delivery: OtpDelivery,
}

impl Account {
    /// A new account with a freshly minted identity, no one-time password, and its secrets kept.
    #[must_use]
    pub fn new(sqex_id: impl Into<String>, kind: AccountKind) -> Self {
        Self {
            id: Uuid::new_v4(),
            sqex_id: sqex_id.into(),
            kind,
            use_otp: false,
            never_store: false,
            otp_delivery: OtpDelivery::default(),
        }
    }
}

/// Where an account's one-time password comes from when it uses one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OtpDelivery {
    /// Ask for a code. What every account did before a secret could be stored.
    #[default]
    Ask,
    /// Derive one from the stored secret, with nothing to type. Set by importing a secret.
    Generate,
    /// A companion pushes one to this machine's listener while the login waits.
    ///
    /// The only call in this crate that sets it is the one that takes the acknowledgment, because
    /// pointing an account here is the decision to open a port on the user's network. That is a rule
    /// about this crate's own callers and not a boundary: the field is public and deserializable, so a
    /// user editing their own configuration to turn on their own feature reaches it, which is theirs
    /// to do.
    Listen,
}

/// How an account authenticates and what entitlements it carries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AccountKind {
    Standard,
    Steam { app_id: u32 },
    FreeTrial,
}

/// The Steam app id the game is licensed under, for an account that bought it there.
pub const STEAM_APP_ID: u32 = 39_210;
/// The Steam app id the free trial is licensed under.
///
/// It decides two things at once, which is why it lives beside the paid one rather than in whichever
/// caller needed it first: the ticket is minted against the app the licence belongs to, and this app
/// is also the one whose login carries the trial flag.
pub const STEAM_FREE_TRIAL_APP_ID: u32 = 312_060;

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

/// Region and per-launch overrides applied when the game starts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LaunchSettings {
    pub region: Region,
    pub extra_args: Vec<String>,
    pub extra_env: Vec<(String, String)>,
    pub wrappers: Vec<String>,
    /// Which synchronization primitive to ask for. The default resolves against what the host and
    /// the selected runner can actually do; naming one is for pinning a comparison or working around
    /// a build, and is honored even where the host cannot back it.
    #[serde(default)]
    pub sync: SyncChoice,
    /// The in-game overlay. One or the other, never both.
    #[serde(default)]
    pub hud: Hud,
    /// Which GPU to run on, where the machine has more than one.
    #[serde(default)]
    pub gpu: GpuSelect,
    /// Install DXVK's `dxvk-nvapi` companion into the prefix and override its nvapi DLLs onto it, so
    /// the game sees the driver features it exposes.
    ///
    /// Off by default and beside [`LaunchSettings::gpu`] rather than launcher-wide, because it is a
    /// property of the card a profile runs on: it does nothing on a prefix whose GPU is not an
    /// NVIDIA one, and a machine with two cards has one profile per card. While it is off, nothing
    /// downloads the companion.
    #[serde(default)]
    pub nvapi: bool,
    /// Run inside a nested compositor, and how. Absent leaves the launch in whatever session started
    /// it.
    #[serde(default)]
    pub gamescope: Option<Gamescope>,
    /// Ask the system to switch to its game performance profile for the duration.
    #[serde(default)]
    pub gamemode: bool,
    /// Load Dalamud into the game.
    ///
    /// Off by default and per profile, because it is third-party code injected into the client and
    /// because one account's raiding profile and another's are not the same decision. While it is off,
    /// nothing here contacts its distribution.
    pub dalamud: bool,
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

/// Where the launcher keeps account secrets on this machine.
///
/// A stored choice rather than something detected at startup. The alternative to the platform store
/// is a file sealed under a passphrase the user has to type, and nothing may put a secret into one
/// the user did not ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SecretBackend {
    /// The credential store this platform provides.
    #[default]
    Platform,
    /// A file sealed under a passphrase, for a session with no credential store to talk to.
    EncryptedFile,
    /// Nothing is written down at all, and a password is asked for every time.
    Nothing,
}

/// Launcher-wide preferences, independent of any profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    pub language: String,
    pub close_after_launch: bool,
    /// Which store account secrets go into. Read once at construction, so a change takes effect on
    /// the next launch, and switching moves nothing: whatever the old backend holds stays there until
    /// it is deleted on purpose.
    pub secret_backend: SecretBackend,
    /// Keep downloaded patches after a clean apply instead of removing them. Costs disk, but lets a
    /// later repair re-fetch broken ranges from the local patch files first (and a re-apply skip the
    /// download). Read once at construction, so a change takes effect on the next launch.
    pub keep_patches: bool,
    /// How many config backups to keep per profile. Nothing is pruned until a backup is taken.
    pub backups_kept: u32,
    /// Capture the game's settings before applying patches. On by default: a capture is tens of
    /// kilobytes, and a patch is the moment settings are most likely to be rewritten.
    pub backup_before_patch: bool,
    /// Where a companion pushes a one-time code, for the accounts set to receive one that way.
    pub otp_listener: ListenerSettings,
}

/// The local endpoint a companion app pushes a one-time code to, and who may reach it.
///
/// Machine facts rather than account facts: which interface faces the phone, which port is free,
/// which device may push, and how patient the user is are all properties of this PC. Two accounts
/// cannot each take the same port, only one login awaits a code at a time by design, and the phone
/// that pushes is one device per household rather than one per Square Enix account.
///
/// Which *login* uses it stays on the account as its delivery mode, and that is also the only switch.
/// There is no separate enable here, because an account's delivery already defaults to asking, and a
/// second flag would be a second thing to keep consistent with the first: it would also make tuning
/// the listener a way to turn it on without the acknowledgment that is supposed to gate exactly that.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerSettings {
    /// The interface to take.
    ///
    /// The unspecified address is every interface this host answers on, which is more than "the LAN":
    /// it includes a VPN tunnel, a container bridge, and on a machine with a public address, the
    /// internet. It is the default because it is what makes the phone app work with no configuration,
    /// and it is a field because a multi-homed host should be able to say which interface it means.
    pub bind: IpAddr,
    /// The port to take. The compatibility port unless something else on this machine holds it.
    pub port: u16,
    /// Which sources may deliver a code.
    pub sources: ListenerSources,
    /// How long a login waits for a push before giving up.
    pub wait_seconds: u64,
}

/// Which sources the listener admits.
///
/// A tagged enum rather than a list whose emptiness carries meaning: an empty list reads as both
/// "admit anything" and "admit nothing", and a round trip through a config file that drops empty
/// collections silently turns one into the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ListenerSources {
    /// Anything that can reach the bound interface.
    Any,
    /// Only these addresses. An empty list admits nothing, and the flow refuses to bind rather than
    /// opening a port no one can use.
    Only { addresses: Vec<IpAddr> },
}

impl Default for ListenerSettings {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: apogee_otp::COMPAT_PORT,
            sources: ListenerSources::Any,
            // Long enough to fetch a phone, unlock it, open the app and tap, which is the whole of
            // what this wait is for. Shorter fails real people; much longer holds a port open on the
            // network past any plausible attention span, and the port being brief is most of what
            // makes the endpoint defensible at all.
            wait_seconds: 90,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: "en".to_string(),
            close_after_launch: false,
            secret_backend: SecretBackend::Platform,
            // On, because a repair re-fetches broken ranges from the patch files first when they are
            // there and from the network when they are not, and the second is hours where the first
            // is minutes. It costs disk, which is why it is a setting and why it is stated.
            keep_patches: true,
            backups_kept: 5,
            backup_before_patch: true,
            // Tuning only. Nothing here opens a port: the listener binds when an account set to
            // receive pushed codes begins a login, and no account is set that way by default.
            otp_listener: ListenerSettings::default(),
        }
    }
}
