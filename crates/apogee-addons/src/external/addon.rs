//! The user-authored record: what to run, where, and when.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{AddonError, Result};

/// Where an external tool runs.
///
/// Declared by the record, never inferred from the file extension. An extension cannot express a
/// native Linux binary at all and mis-files an extensionless one, which is how a launcher ends up
/// with no way to run the tools a Linux user actually has.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RunIn {
    /// A native binary or script on the host, spawned directly.
    Host,
    /// A Windows program, run inside the game's prefix through that prefix's runner.
    Prefix,
}

/// When the tool runs, and what happens to it when the game exits.
///
/// The stop policy lives only on the arm that has something to stop, so "run after the game closes"
/// and "stop it when the game closes" cannot be asked for together. That pair spells a teardown that
/// starts a process and then immediately kills what it just started.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Trigger {
    /// Starts once the game is running, and is stopped when the game exits unless asked otherwise.
    ///
    /// An absent `keep_after_close` defaults to the policy that terminates, so a truncated record, a
    /// record written by an older build, and a user who never considered the question all yield a
    /// tool that stops with the game. The two wrong defaults do not cost the same: a wrong
    /// default-stop costs a restart, a wrong default-keep costs an orphan the user has to hunt down.
    WithGame {
        /// Leave it running after the game exits.
        #[serde(default)]
        keep_after_close: bool,
    },
    /// Runs once after the game has exited, and is waited on until it finishes.
    OnClose,
}

/// A companion tool the user configured: what to run, what to pass it, where it runs, and when.
///
/// There is no elevation field. Asking for elevation interrupts the launch with a prompt and, in the
/// launcher this takes its shape from, silently disables every teardown branch, so a record that
/// carries one is refused at the point of execution rather than run with the request quietly
/// dropped.
///
/// # Examples
///
/// ```
/// # fn main() -> apogee_addons::Result<()> {
/// use apogee_addons::{ExternalAddon, RunIn, Trigger};
///
/// let tool = ExternalAddon::new(
///     "/home/u/tools/ACT/Advanced Combat Tracker.exe",
///     vec!["-noicon".to_owned()],
///     RunIn::Prefix,
///     Trigger::WithGame {
///         keep_after_close: false,
///     },
/// )?;
///
/// assert_eq!(tool.args(), ["-noicon"]);
/// assert!(tool.enabled());
/// assert!(!tool.keeps_running());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(from = "RawExternalAddon")]
pub struct ExternalAddon {
    program: PathBuf,
    args: Vec<String>,
    run_in: RunIn,
    trigger: Trigger,
    enabled: bool,
    #[serde(flatten)]
    unsupported: BTreeMap<String, serde_json::Value>,
}

impl ExternalAddon {
    /// Build a record.
    ///
    /// # Errors
    ///
    /// Returns [`AddonError::InvalidAddon`] if `program` is empty or relative. A relative path
    /// resolves against whatever directory the launcher happened to start in, so the same
    /// configuration would run a different program depending on how it was started.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::{AddonError, ExternalAddon, RunIn, Trigger};
    ///
    /// let relative = ExternalAddon::new("tools/act.sh", vec![], RunIn::Host, Trigger::OnClose);
    /// assert!(matches!(relative, Err(AddonError::InvalidAddon { .. })));
    ///
    /// let absolute = ExternalAddon::new("/opt/act/act.sh", vec![], RunIn::Host, Trigger::OnClose);
    /// assert!(absolute.is_ok());
    /// ```
    pub fn new(
        program: impl Into<PathBuf>,
        args: Vec<String>,
        run_in: RunIn,
        trigger: Trigger,
    ) -> Result<Self> {
        let addon = Self {
            program: program.into(),
            args,
            run_in,
            trigger,
            enabled: true,
            unsupported: BTreeMap::new(),
        };
        addon.check_program(0)?;
        Ok(addon)
    }

    /// The program to run.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The argument vector, passed to the child verbatim: no shell, so no quoting dialect and no
    /// word splitting.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Host or prefix.
    #[must_use]
    pub fn run_in(&self) -> RunIn {
        self.run_in
    }

    /// When it runs.
    #[must_use]
    pub fn trigger(&self) -> Trigger {
        self.trigger
    }

    /// Whether the launch considers it at all.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Turn it on or off without losing the entry.
    pub fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    /// Whether the game's exit leaves it running.
    #[must_use]
    pub fn keeps_running(&self) -> bool {
        matches!(
            self.trigger,
            Trigger::WithGame {
                keep_after_close: true
            }
        )
    }

    /// Why this record cannot be run as written, or `Ok` when it can.
    ///
    /// Checked when the launch reaches it rather than when it is loaded, so one hand-edited entry
    /// costs the user that entry rather than the whole configuration it lives in.
    ///
    /// # Errors
    ///
    /// [`AddonError::InvalidAddon`] for an empty or relative program, [`AddonError::UnsupportedField`]
    /// for a key this build does not understand, and [`AddonError::PrefixRequired`] for a prefix tool
    /// in a launch that has no prefix.
    /// Why this entry cannot be run, or `None` if it can.
    ///
    /// The same check a launch makes, asked without one, so a caller can show a broken entry while the
    /// user is still editing it rather than at the moment the game starts. `has_prefix` is what the
    /// launch it would join will have: an entry that runs inside a prefix is only a problem for a
    /// launch that has none.
    ///
    /// # Examples
    ///
    /// ```
    /// # use apogee_addons::ExternalAddon;
    /// # fn demo(addons: &[ExternalAddon]) {
    /// let broken: Vec<String> = addons
    ///     .iter()
    ///     .enumerate()
    ///     .filter_map(|(index, addon)| addon.problem(index, true).map(|err| err.chain()))
    ///     .collect();
    /// # }
    /// ```
    #[must_use]
    pub fn problem(&self, index: usize, has_prefix: bool) -> Option<AddonError> {
        self.validate(index, has_prefix).err()
    }

    pub(crate) fn validate(&self, index: usize, has_prefix: bool) -> Result<()> {
        self.check_program(index)?;
        if let Some(field) = self.unsupported.keys().next() {
            // Refused rather than ignored: a key that changes how a program is executed must never be
            // dropped on the floor, and this build cannot know which ones do.
            return Err(AddonError::UnsupportedField {
                program: self.program.clone(),
                field: field.clone(),
            });
        }
        if self.run_in == RunIn::Prefix && !has_prefix {
            return Err(AddonError::PrefixRequired {
                program: self.program.clone(),
            });
        }
        Ok(())
    }

    /// The program-path rule, checked both when a record is built and when it is run.
    fn check_program(&self, index: usize) -> Result<()> {
        if self.program.as_os_str().is_empty() {
            return Err(AddonError::InvalidAddon {
                program: self.program.clone(),
                index,
                reason: "the program path is empty",
            });
        }
        if !self.program.is_absolute() {
            return Err(AddonError::InvalidAddon {
                program: self.program.clone(),
                index,
                reason: "the program path must be absolute",
            });
        }
        Ok(())
    }
}

/// The persisted form, deliberately total over shape-valid input: every rule that could reject a
/// record is checked when it is run instead, because this lives inside the user's configuration and
/// a configuration that will not load is a launcher that will not launch.
#[derive(Deserialize)]
struct RawExternalAddon {
    program: PathBuf,
    #[serde(default)]
    args: Vec<String>,
    run_in: RunIn,
    trigger: Trigger,
    #[serde(default = "enabled_default")]
    enabled: bool,
    /// Keys this build does not understand, kept verbatim so a newer build's field survives an older
    /// build's save, and refused at the point of execution.
    #[serde(flatten)]
    unsupported: BTreeMap<String, serde_json::Value>,
}

/// An entry is considered unless it was explicitly switched off.
const fn enabled_default() -> bool {
    true
}

impl From<RawExternalAddon> for ExternalAddon {
    fn from(raw: RawExternalAddon) -> Self {
        Self {
            program: raw.program,
            args: raw.args,
            run_in: raw.run_in,
            trigger: raw.trigger,
            enabled: raw.enabled,
            unsupported: raw.unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(program: &str) -> Result<ExternalAddon> {
        ExternalAddon::new(
            program,
            vec![],
            RunIn::Host,
            Trigger::WithGame {
                keep_after_close: false,
            },
        )
    }

    /// A relative program would resolve against whatever directory the launcher started in, so the
    /// same configuration would run different code depending on how it was invoked.
    #[test]
    fn a_relative_or_empty_program_is_refused() {
        assert!(matches!(
            host("tools/act.sh"),
            Err(AddonError::InvalidAddon { .. })
        ));
        assert!(matches!(host(""), Err(AddonError::InvalidAddon { .. })));
        assert!(host("/opt/act/act.sh").is_ok());
    }

    /// The absent-field default has to be the policy that stops, because the cost of the two wrong
    /// defaults is not symmetric.
    #[test]
    fn a_record_without_a_stop_policy_stops_with_the_game() {
        let addon: ExternalAddon = serde_json::from_str(
            r#"{"program":"/opt/act/act.sh","run_in":"host","trigger":{"with_game":{}}}"#,
        )
        .expect("parse");
        assert!(!addon.keeps_running());
        assert!(addon.enabled(), "an entry is considered unless disabled");
    }

    /// The combination that starts a process and then immediately kills it has no spelling.
    #[test]
    fn an_on_close_entry_cannot_also_carry_a_stop_policy() {
        let addon: ExternalAddon = serde_json::from_str(
            r#"{"program":"/opt/sync/sync.sh","run_in":"host","trigger":"on_close"}"#,
        )
        .expect("parse");
        assert_eq!(addon.trigger(), Trigger::OnClose);
        assert!(!addon.keeps_running());
        // The only way to ask for a stop policy is on the arm that has something to stop.
        assert!(
            serde_json::from_str::<ExternalAddon>(
                r#"{"program":"/x","run_in":"host","trigger":{"on_close":{"keep_after_close":true}}}"#
            )
            .is_err()
        );
    }

    /// A key this build does not understand may change how the program runs, so it is refused at the
    /// point of execution rather than silently dropped.
    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let addon: ExternalAddon = serde_json::from_str(
            r#"{"program":"/opt/act/act.sh","run_in":"host","trigger":"on_close","run_as_admin":true}"#,
        )
        .expect("an unknown key parses, so the rest of the configuration still loads");

        match addon.validate(0, true) {
            Err(AddonError::UnsupportedField { field, .. }) => assert_eq!(field, "run_as_admin"),
            other => panic!("expected the field to be named, got {other:?}"),
        }
    }

    /// An unknown key survives a load and save by an older build, so a newer build's setting is not
    /// destroyed by opening the launcher once.
    #[test]
    fn an_unknown_key_survives_a_round_trip() {
        let raw = r#"{"program":"/opt/act/act.sh","run_in":"host","trigger":"on_close","future_field":{"a":1}}"#;
        let addon: ExternalAddon = serde_json::from_str(raw).expect("parse");
        let back = serde_json::to_value(&addon).expect("serialize");
        assert_eq!(back["future_field"], serde_json::json!({"a": 1}));
    }

    /// A prefix tool in a launch with no prefix is that entry's failure, named as such.
    #[test]
    fn a_prefix_tool_without_a_prefix_is_refused() -> Result<()> {
        let addon = ExternalAddon::new(
            "/opt/act/Advanced Combat Tracker.exe",
            vec![],
            RunIn::Prefix,
            Trigger::WithGame {
                keep_after_close: false,
            },
        )?;
        assert!(matches!(
            addon.validate(0, false),
            Err(AddonError::PrefixRequired { .. })
        ));
        assert!(addon.validate(0, true).is_ok());
        Ok(())
    }

    /// Arguments are carried as a vector, so a value with spaces is one argument and no quoting
    /// dialect is involved.
    #[test]
    fn arguments_are_a_vector_not_a_command_line() -> Result<()> {
        let addon = ExternalAddon::new(
            "/opt/tool/run",
            vec!["--path".into(), "/home/a b/c".into()],
            RunIn::Host,
            Trigger::OnClose,
        )?;
        assert_eq!(addon.args(), ["--path", "/home/a b/c"]);
        Ok(())
    }
}
