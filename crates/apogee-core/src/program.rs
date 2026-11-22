//! The three programs a profile can run with the game, and the consent that turning one on takes.
//!
//! A profile holds one switch per program and nothing else: what each program *is* (its version, the
//! game versions and runners it was validated on, what it costs) is published in the signed component
//! catalog and read from there. This module is where the two meet, so a shell can render a program's
//! switch and its row without knowing which of the three is an injectable and which a companion.

use apogee_addons::manifest::InjectableKind;
use apogee_addons::{ComponentManifest, ExternalAddon, SupportTier};

use crate::model::{LaunchSettings, Profile};

/// One of the programs a profile can switch on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProgramName {
    /// Dalamud, loaded into the game by wrapping its launch.
    Dalamud,
    /// XivAlexander, started beside the game in its wine session.
    Xivalexander,
    /// ACT with the FFXIV parsing plugin, started beside the game in its wine session.
    Act,
}

impl ProgramName {
    /// Every program, in the order a report lists them.
    pub const ALL: [Self; 3] = [Self::Dalamud, Self::Xivalexander, Self::Act];

    /// The name the setting and the catalog row both go by.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Dalamud => "dalamud",
            Self::Xivalexander => "xivalexander",
            Self::Act => "act",
        }
    }

    /// The program a setting or row name names, or `None` for any other.
    #[must_use]
    pub fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|name| name.key() == key)
    }

    /// Whether turning it on takes a [`ProgramConsent`].
    ///
    /// The two companions do: each is a third-party program started in the game's wine session with
    /// the same access to the game, the user's files and their stored sign-in as the launcher.
    /// Dalamud's switch predates the consent value and joins it when the shell can ask.
    #[must_use]
    pub const fn needs_consent(self) -> bool {
        !matches!(self, Self::Dalamud)
    }

    /// Whether `launch` has it on.
    #[must_use]
    pub const fn is_on(self, launch: &LaunchSettings) -> bool {
        match self {
            Self::Dalamud => launch.dalamud,
            Self::Xivalexander => launch.xivalexander,
            Self::Act => launch.act,
        }
    }

    /// Switch it on or off in `launch`.
    pub const fn set(self, launch: &mut LaunchSettings, on: bool) {
        match self {
            Self::Dalamud => launch.dalamud = on,
            Self::Xivalexander => launch.xivalexander = on,
            Self::Act => launch.act = on,
        }
    }
}

/// How well the catalog says a program is supported here.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProgramTier {
    /// It works here as well as it works anywhere.
    FirstClass,
    /// It works with a cost, stated in `note`.
    BestEffort { note: String },
}

/// What the signed catalog says about one program.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProgramRow {
    pub program: ProgramName,
    pub tier: ProgramTier,
    /// What the user should know before enabling it, beyond what the tier says.
    pub caveats: Vec<String>,
    /// The pinned version, for a program the catalog pins. Dalamud follows its own distribution.
    pub version: Option<String>,
    /// The game versions it was validated on. Empty for one the catalog does not gate by version.
    pub game_versions: Vec<String>,
    /// The runners it was validated on, as `(name, version)`. Empty for one not gated by runner.
    pub runners: Vec<(String, String)>,
}

/// One program's switch on a profile, with the catalog's row for it when one could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ProgramSetting {
    pub program: ProgramName,
    pub enabled: bool,
    /// `None` when the catalog was unreadable or carries no row for it.
    pub row: Option<ProgramRow>,
}

/// The user was shown what running a program beside the game grants it and said yes.
///
/// Holds nothing, and is neither `Clone`, `Copy`, `Default`, nor deserializable, with a private field,
/// so it cannot be conjured by a struct literal or produced by parsing a request. Taken by value, so
/// one grant authorizes one write. The constructor is confined to the layers that put the question to
/// a user (a typed command, a native confirmation) and is greppable, so that confinement is checkable.
#[derive(Debug)]
pub struct ProgramConsent(());

impl ProgramConsent {
    /// The user asked for this themselves, knowing what it grants.
    #[must_use]
    pub const fn granted() -> Self {
        Self(())
    }
}

/// Why a profile write needs a [`ProgramConsent`], or `None` when it grants nothing new.
///
/// What needs one is anything that newly lets code run beside the game: a companion program switched
/// on, a companion row of the user's own that is new, changed, or switched on, a launch wrapper that
/// is new, or an environment entry that is new or changed (a variable such as `LD_PRELOAD` or
/// `WINEDLLOVERRIDES` loads code into the game as surely as a companion does). Switching anything off,
/// removing a row, wrapper or variable, and rewriting any of them unchanged need none, so a shell
/// round-tripping a profile it did not touch is never refused.
pub(crate) fn consent_needed(stored: &Profile, next: &Profile) -> Option<String> {
    if let Some(program) = ProgramName::ALL.into_iter().find(|program| {
        program.needs_consent() && program.is_on(&next.launch) && !program.is_on(&stored.launch)
    }) {
        return Some(program.key().to_owned());
    }
    next.external
        .iter()
        .find(|row| row.enabled() && !stored.external.contains(row))
        .map(|row| row.program().to_string_lossy().into_owned())
        .or_else(|| {
            next.launch
                .wrappers
                .iter()
                .find(|wrapper| !stored.launch.wrappers.contains(wrapper))
                .cloned()
        })
        .or_else(|| {
            next.launch
                .extra_env
                .iter()
                .find(|entry| !stored.launch.extra_env.contains(entry))
                .map(|(name, _)| name.clone())
        })
}

/// Whether any companion is configured on `profile`: a curated program switched on, or a row of the
/// user's own that is enabled. A companion has the launcher's access to the session, which is what
/// several launch rules key on.
pub(crate) fn companions_configured(profile: &Profile) -> bool {
    ProgramName::ALL
        .into_iter()
        .any(|program| program.needs_consent() && program.is_on(&profile.launch))
        || profile.external.iter().any(ExternalAddon::enabled)
}

/// The catalog's row for `program`, projected for a report.
pub(crate) fn row(manifest: &ComponentManifest, program: ProgramName) -> Option<ProgramRow> {
    if program == ProgramName::Dalamud {
        let entry = manifest.injectable(InjectableKind::Dalamud)?;
        return Some(ProgramRow {
            program,
            tier: tier(&entry.tier),
            caveats: entry.caveats.clone(),
            version: None,
            game_versions: Vec::new(),
            runners: Vec::new(),
        });
    }
    let entry = manifest.program(program.key())?;
    Some(ProgramRow {
        program,
        tier: tier(&entry.tier),
        caveats: entry.caveats.clone(),
        version: Some(entry.version.clone()),
        game_versions: entry.game_versions.clone(),
        runners: entry
            .runners
            .iter()
            .map(|pin| (pin.name.clone(), pin.version.clone()))
            .collect(),
    })
}

fn tier(tier: &SupportTier) -> ProgramTier {
    match tier.note() {
        Some(note) => ProgramTier::BestEffort {
            note: note.to_owned(),
        },
        None => ProgramTier::FirstClass,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use apogee_addons::{RunIn, Trigger};
    use uuid::Uuid;

    use super::*;

    fn profile() -> Profile {
        Profile::new(
            "Main",
            Uuid::nil(),
            PathBuf::from("/game"),
            crate::RunnerSelection::Unchosen,
        )
    }

    fn tool(path: &str) -> ExternalAddon {
        ExternalAddon::new(
            path,
            Vec::new(),
            RunIn::Prefix,
            Trigger::WithGame {
                keep_after_close: false,
            },
        )
        .unwrap()
    }

    #[test]
    fn a_new_wrapper_or_environment_entry_needs_consent_and_removing_one_does_not() {
        let stored = profile();
        let mut wrapped = stored.clone();
        wrapped.launch.wrappers = vec!["sh".to_owned(), "-c".to_owned()];
        assert_eq!(consent_needed(&stored, &wrapped).as_deref(), Some("sh"));
        assert_eq!(consent_needed(&wrapped, &stored), None);
        assert_eq!(consent_needed(&wrapped, &wrapped), None);

        let mut preload = stored.clone();
        preload
            .launch
            .extra_env
            .push(("LD_PRELOAD".to_owned(), "/tmp/a.so".to_owned()));
        assert_eq!(
            consent_needed(&stored, &preload).as_deref(),
            Some("LD_PRELOAD")
        );
        // A changed value is new code as much as a new name is.
        let mut changed = preload.clone();
        changed.launch.extra_env[0].1 = "/tmp/b.so".to_owned();
        assert_eq!(
            consent_needed(&preload, &changed).as_deref(),
            Some("LD_PRELOAD")
        );
        assert_eq!(consent_needed(&preload, &stored), None);
    }

    #[test]
    fn turning_a_companion_on_needs_consent_and_turning_it_off_does_not() {
        let stored = profile();
        let mut on = stored.clone();
        on.launch.act = true;
        assert_eq!(consent_needed(&stored, &on).as_deref(), Some("act"));
        // Back off again, and a save of what is already stored: neither grants anything.
        assert_eq!(consent_needed(&on, &stored), None);
        assert_eq!(consent_needed(&on, &on), None);
    }

    /// Dalamud's toggle is not gated yet; gating it now would break the one switch a shell already
    /// writes, before the shell has any way to ask.
    #[test]
    fn dalamud_is_not_gated_yet() {
        let stored = profile();
        let mut on = stored.clone();
        on.launch.dalamud = true;
        assert_eq!(consent_needed(&stored, &on), None);
    }

    #[test]
    fn a_new_changed_or_reenabled_row_needs_consent_and_a_removed_or_disabled_one_does_not() {
        let mut stored = profile();
        stored.external.push(tool("/tools/a.exe"));

        let mut added = stored.clone();
        added.external.push(tool("/tools/b.exe"));
        assert!(consent_needed(&stored, &added).is_some());

        let mut changed = stored.clone();
        changed.external[0] = tool("/tools/elsewhere.exe");
        assert!(consent_needed(&stored, &changed).is_some());

        let mut disabled = stored.clone();
        disabled.external[0].set_enabled(false);
        assert_eq!(consent_needed(&stored, &disabled), None);
        assert!(
            consent_needed(&disabled, &stored).is_some(),
            "switching a row back on runs it again"
        );

        let mut removed = stored.clone();
        removed.external.clear();
        assert_eq!(consent_needed(&stored, &removed), None);
    }
}
