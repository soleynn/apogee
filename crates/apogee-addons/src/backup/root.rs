//! A source tree and the rules that carve it up.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::error::BackupError;
use super::rule::{Expect, NameMatch, Rule};

/// The namespace a root's entries live under in the archive, and the unit a restore works in.
// Deliberately exhaustive: it is written into the archive record, so a variant added here changes a
// persisted format and every reader has to be taught it rather than allowed to skip it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootLabel {
    /// The game's own config tree.
    User,
}

impl RootLabel {
    /// The archive path component every entry from this root sits under.
    #[must_use]
    pub fn prefix(self) -> &'static str {
        match self {
            Self::User => "user",
        }
    }
}

/// Whether a root that is absent from disk is a fault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Presence {
    /// Absent fails the backup.
    Required,
    /// Absent is recorded and the backup continues, which is the state of a config directory the
    /// game has been pointed at but has never written into.
    Optional,
}

/// Parts of the game tree that are large, regenerable, or redundant, and are dropped unless asked
/// for. Everything else in the tree is taken without being named.
#[derive(Debug, Clone, Copy, Default)]
pub struct GameConfigOpts {
    /// Keep the per-character `log` directories: chat scrollback, unbounded, and tens of megabytes
    /// on a played account against roughly one megabyte for the settings themselves.
    pub chat_logs: bool,
    /// Keep `screenshots`: user media, and the one directory in the tree with no size bound.
    pub screenshots: bool,
    /// Keep the game's previous-generation shadows, which hold strictly older copies of data the
    /// archive already has.
    pub rotations: bool,
    /// Keep the game's own restore blob, a stale re-encoding of the same character's settings.
    pub game_restore_blob: bool,
}

/// One source tree and the rules that carve it up.
#[derive(Debug, Clone)]
pub struct SelectionRoot {
    label: RootLabel,
    path: PathBuf,
    include: Vec<Rule>,
    prune: Vec<Rule>,
    presence: Presence,
}

impl SelectionRoot {
    /// A root whose immediate children are tested against `include`, with `prune` applied at every
    /// depth.
    ///
    /// # Errors
    /// [`BackupError::DuplicateRule`] if two rules in either list render identically, which would
    /// make their match counts impossible to tell apart in the report.
    pub fn new(
        label: RootLabel,
        path: impl Into<PathBuf>,
        include: Vec<Rule>,
        prune: Vec<Rule>,
        presence: Presence,
    ) -> Result<Self, BackupError> {
        let root = Self::assembled(label, path, include, prune, presence);
        for list in [&root.include, &root.prune] {
            // Compared as the rendered key, folded: two rules that render the same modulo case match
            // the same entries, so keeping both would split one match count across two report rows.
            let mut seen: Vec<String> = Vec::with_capacity(list.len());
            for rule in list {
                let key = rule.to_string().to_ascii_lowercase();
                if seen.contains(&key) {
                    return Err(BackupError::DuplicateRule {
                        rule: rule.to_string(),
                        root: root.path.clone(),
                    });
                }
                seen.push(key);
            }
        }
        Ok(root)
    }

    /// The game's config tree: everything, less the noise `opts` leaves switched off.
    ///
    /// Inclusion names no directory, which is the point. A name that is never spelled cannot be
    /// misspelled, and a directory a future game patch adds is carried by default rather than
    /// dropped by default. That puts every literal in this root on the prune side, where getting one
    /// wrong makes the archive bigger instead of losing settings.
    #[must_use]
    pub fn game_config(path: impl Into<PathBuf>, opts: GameConfigOpts) -> Self {
        let mut prune = Vec::new();
        if !opts.chat_logs {
            prune.push(Rule::dir(NameMatch::Exact("log".into()), Expect::Optional));
        }
        if !opts.screenshots {
            prune.push(Rule::dir(
                NameMatch::Exact("screenshots".into()),
                Expect::Optional,
            ));
        }
        if !opts.game_restore_blob {
            prune.push(Rule::dir(
                NameMatch::Exact("backup".into()),
                Expect::Optional,
            ));
        }
        if !opts.rotations {
            prune.push(Rule::file(
                NameMatch::Suffix(".old".into()),
                Expect::Optional,
            ));
        }
        Self::assembled(
            RootLabel::User,
            path,
            vec![
                Rule::dir(NameMatch::Any, Expect::Optional),
                Rule::file(NameMatch::Any, Expect::Optional),
            ],
            prune,
            Presence::Required,
        )
    }

    /// The namespace this root's entries sit under.
    #[must_use]
    pub fn label(&self) -> RootLabel {
        self.label
    }

    /// The directory this root reads.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Whether an absent root is a fault.
    #[must_use]
    pub fn presence(&self) -> Presence {
        self.presence
    }

    /// The rules tested against the root's immediate children.
    #[must_use]
    pub fn include(&self) -> &[Rule] {
        &self.include
    }

    /// The rules that drop an entry at any depth.
    #[must_use]
    pub fn prune(&self) -> &[Rule] {
        &self.prune
    }

    /// Assemble without the duplicate check, for rule sets built in this module.
    fn assembled(
        label: RootLabel,
        path: impl Into<PathBuf>,
        include: Vec<Rule>,
        prune: Vec<Rule>,
        presence: Presence,
    ) -> Self {
        Self {
            label,
            path: path.into(),
            include,
            prune,
            presence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The presets skip the duplicate check, so it is asserted here instead of trusted.
    #[test]
    fn no_preset_lists_the_same_rule_twice() {
        let all_on = GameConfigOpts {
            chat_logs: true,
            screenshots: true,
            rotations: true,
            game_restore_blob: true,
        };
        for opts in [GameConfigOpts::default(), all_on] {
            let preset = SelectionRoot::game_config("/tmp/x", opts);
            assert!(
                SelectionRoot::new(
                    preset.label,
                    preset.path.clone(),
                    preset.include.clone(),
                    preset.prune.clone(),
                    preset.presence,
                )
                .is_ok()
            );
        }
    }

    /// Two rules that render the same would report one match count between them, so they are
    /// refused rather than merged.
    #[test]
    fn a_rule_listed_twice_is_refused() {
        let twice = vec![
            Rule::file(NameMatch::Suffix(".old".into()), Expect::Optional),
            Rule::file(NameMatch::Suffix(".OLD".into()), Expect::Required),
        ];
        let err = SelectionRoot::new(
            RootLabel::User,
            "/tmp/x",
            vec![Rule::file(NameMatch::Any, Expect::Optional)],
            twice,
            Presence::Required,
        );
        assert!(matches!(err, Err(BackupError::DuplicateRule { .. })));
    }

    /// The game root names no directory to include, so there is no literal on the losing side.
    #[test]
    fn the_game_root_includes_without_naming_anything() {
        let root = SelectionRoot::game_config("/tmp/x", GameConfigOpts::default());
        for rule in root.include() {
            assert_eq!(rule.to_string().split_once(' ').map(|(_, n)| n), Some("*"));
        }
    }
}
