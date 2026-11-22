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

/// A configuration defect visible without resolving a launch environment.
///
/// This intentionally carries no arbitrary field name or parser prose. A shell needs to distinguish
/// an entry it can edit from one this build must preserve unchanged, but it does not need to receive
/// untrusted keys to do that.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExternalAddonProblem {
    /// The configured program is empty or relative.
    InvalidProgram,
    /// The record contains fields this build does not understand and must preserve.
    UnsupportedFields,
    /// The record asks for an environment variable a companion may not set.
    InvalidEnv,
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
/// let program = std::env::temp_dir().join("Advanced Combat Tracker.exe");
/// let tool = ExternalAddon::new(
///     program,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "RawExternalAddon")]
pub struct ExternalAddon {
    program: PathBuf,
    args: Vec<String>,
    run_in: RunIn,
    trigger: Trigger,
    enabled: bool,
    /// Environment the program needs, held to the companion allowlist when it is run. Left out of a
    /// saved record when empty, so a record that never used it saves exactly as an older build wrote
    /// it, and an older build that meets one keeps it as a field it refuses to run.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<String, String>,
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
    /// let program = std::env::temp_dir().join("apogee-act");
    /// let absolute = ExternalAddon::new(program, vec![], RunIn::Host, Trigger::OnClose);
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
            env: BTreeMap::new(),
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
    pub const fn run_in(&self) -> RunIn {
        self.run_in
    }

    /// When it runs.
    #[must_use]
    pub const fn trigger(&self) -> Trigger {
        self.trigger
    }

    /// The same entry with `env` set for the program it runs.
    ///
    /// Only `MONO_PATH` and `WINEDLLOVERRIDES` may be set, the latter as additions that never name a
    /// library the game's own launch decides. Anything else is accepted here, so a configuration
    /// loads, and refused when the entry is run, as [`AddonError::InvalidAddon`].
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> apogee_addons::Result<()> {
    /// use apogee_addons::{ExternalAddon, RunIn, Trigger};
    /// use std::collections::BTreeMap;
    ///
    /// let program = std::env::temp_dir().join("tool.exe");
    /// let trigger = Trigger::WithGame { keep_after_close: false };
    /// let env = BTreeMap::from([("LD_PRELOAD".to_owned(), "/tmp/x.so".to_owned())]);
    /// let tool = ExternalAddon::new(program, vec![], RunIn::Prefix, trigger)?.with_env(env);
    ///
    /// assert!(tool.problem(0, true).is_some());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_env(mut self, env: BTreeMap<String, String>) -> Self {
        self.env = env;
        self
    }

    /// The environment it asks for.
    #[must_use]
    pub const fn env(&self) -> &BTreeMap<String, String> {
        &self.env
    }

    /// Whether the launch considers it at all.
    #[must_use]
    pub const fn enabled(&self) -> bool {
        self.enabled
    }

    /// Turn it on or off without losing the entry.
    pub const fn set_enabled(&mut self, on: bool) {
        self.enabled = on;
    }

    /// A defect in the stored record itself, independent of the launch it may join.
    ///
    /// An unsupported entry remains readable so a newer build's fields survive a round trip, but a
    /// caller must not present it as an ordinary editable entry. The details stay inside the domain
    /// layer: only the safe classification crosses to a shell.
    #[must_use]
    pub fn configuration_problem(&self) -> Option<ExternalAddonProblem> {
        if !self.unsupported.is_empty() {
            Some(ExternalAddonProblem::UnsupportedFields)
        } else if self.program.as_os_str().is_empty() || !self.program.is_absolute() {
            Some(ExternalAddonProblem::InvalidProgram)
        } else if crate::env_rules::check(&self.env, &[]).is_err() {
            Some(ExternalAddonProblem::InvalidEnv)
        } else {
            None
        }
    }

    /// Whether the game's exit leaves it running.
    #[must_use]
    pub const fn keeps_running(&self) -> bool {
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
        self.validate_against(index, has_prefix, &[])
    }

    /// [`Self::validate`], with `game_overrides` naming the libraries the game's launch environment
    /// overrides beyond the fixed set, which an override of this entry's may not name either.
    pub(crate) fn validate_against(
        &self,
        index: usize,
        has_prefix: bool,
        game_overrides: &[String],
    ) -> Result<()> {
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
        crate::env_rules::check(&self.env, game_overrides).map_err(|refused| {
            AddonError::InvalidAddon {
                program: self.program.clone(),
                index,
                reason: refused.reason,
            }
        })?;
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
    #[serde(default)]
    env: BTreeMap<String, String>,
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
            env: raw.env,
            unsupported: raw.unsupported,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fixture path that is absolute in the syntax of the host running the test.
    fn absolute(program: &str) -> PathBuf {
        let path = std::env::temp_dir()
            .join("apogee-external-addon-tests")
            .join(program);
        assert!(path.is_absolute(), "test fixture path must be absolute");
        path
    }

    fn host(program: impl Into<PathBuf>) -> Result<ExternalAddon> {
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
        assert!(host(absolute("act/act")).is_ok());
    }

    /// The absent-field default has to be the policy that stops, because the cost of the two wrong
    /// defaults is not symmetric.
    #[test]
    fn a_record_without_a_stop_policy_stops_with_the_game() {
        let addon: ExternalAddon = serde_json::from_value(serde_json::json!({
            "program": absolute("act/act"),
            "run_in": "host",
            "trigger": {"with_game": {}}
        }))
        .expect("parse");
        assert!(!addon.keeps_running());
        assert!(addon.enabled(), "an entry is considered unless disabled");
    }

    /// The combination that starts a process and then immediately kills it has no spelling.
    #[test]
    fn an_on_close_entry_cannot_also_carry_a_stop_policy() {
        let addon: ExternalAddon = serde_json::from_value(serde_json::json!({
            "program": absolute("sync/sync"),
            "run_in": "host",
            "trigger": "on_close"
        }))
        .expect("parse");
        assert_eq!(addon.trigger(), Trigger::OnClose);
        assert!(!addon.keeps_running());
        // The only way to ask for a stop policy is on the arm that has something to stop.
        assert!(
            serde_json::from_value::<ExternalAddon>(serde_json::json!({
                "program": absolute("sync/invalid"),
                "run_in": "host",
                "trigger": {"on_close": {"keep_after_close": true}}
            }))
            .is_err()
        );
    }

    /// A key this build does not understand may change how the program runs, so it is refused at the
    /// point of execution rather than silently dropped.
    #[test]
    fn an_unknown_key_is_refused_rather_than_ignored() {
        let addon: ExternalAddon = serde_json::from_value(serde_json::json!({
            "program": absolute("act/act"),
            "run_in": "host",
            "trigger": "on_close",
            "run_as_admin": true
        }))
        .expect("an unknown key parses, so the rest of the configuration still loads");

        match addon.validate(0, true) {
            Err(AddonError::UnsupportedField { field, .. }) => assert_eq!(field, "run_as_admin"),
            other => panic!("expected the field to be named, got {other:?}"),
        }
        assert_eq!(
            addon.configuration_problem(),
            Some(ExternalAddonProblem::UnsupportedFields)
        );
    }

    /// Preserving fields this build cannot edit outranks correcting another field on the same row.
    #[test]
    fn unsupported_fields_dominate_an_invalid_program() {
        let addon: ExternalAddon = serde_json::from_value(serde_json::json!({
            "program": "relative/tool",
            "run_in": "host",
            "trigger": "on_close",
            "future_field": true
        }))
        .expect("shape-valid persisted entry");

        assert_eq!(
            addon.configuration_problem(),
            Some(ExternalAddonProblem::UnsupportedFields)
        );
    }

    /// An unknown key survives a load and save by an older build, so a newer build's setting is not
    /// destroyed by opening the launcher once.
    #[test]
    fn an_unknown_key_survives_a_round_trip() {
        let raw = serde_json::json!({
            "program": absolute("act/act"),
            "run_in": "host",
            "trigger": "on_close",
            "future_field": {"a": 1}
        });
        let addon: ExternalAddon = serde_json::from_value(raw).expect("parse");
        let back = serde_json::to_value(&addon).expect("serialize");
        assert_eq!(back["future_field"], serde_json::json!({"a": 1}));
    }

    /// A user's entry is held to the same environment allowlist as a signed row: refused when it is run,
    /// reported as a configuration problem while it is edited, and saved only when it carries some.
    #[test]
    fn an_entry_asking_for_an_environment_outside_the_allowlist_is_refused() -> Result<()> {
        let tool = |key: &str, value: &str| -> Result<ExternalAddon> {
            Ok(host(absolute("act/act"))?
                .with_env(BTreeMap::from([(key.to_owned(), value.to_owned())])))
        };
        for (key, value) in [
            ("PYTHONPATH", "/tmp"),
            ("PROTON_VERB", "run"),
            ("VK_LAYER_PATH", "/tmp"),
            ("LD_PRELOAD", "/tmp/x.so"),
            ("WINEDLLOVERRIDES", "d3d11=n"),
        ] {
            let addon = tool(key, value)?;
            assert!(
                matches!(
                    addon.validate(0, true),
                    Err(AddonError::InvalidAddon { .. })
                ),
                "{key}"
            );
            assert_eq!(
                addon.configuration_problem(),
                Some(ExternalAddonProblem::InvalidEnv)
            );
        }
        let allowed = tool("WINEDLLOVERRIDES", "winhttp=n,b")?;
        assert!(allowed.validate(0, true).is_ok());
        // An override the game's own launch environment adds is refused as well.
        assert!(
            allowed
                .validate_against(0, true, &["winhttp".to_owned()])
                .is_err()
        );

        let saved = serde_json::to_value(&allowed).expect("serialize");
        assert_eq!(saved["env"]["WINEDLLOVERRIDES"], "winhttp=n,b");
        let back: ExternalAddon = serde_json::from_value(saved).expect("parse");
        assert_eq!(back, allowed);
        let plain = serde_json::to_value(host(absolute("act/act"))?).expect("serialize");
        assert!(
            plain.get("env").is_none(),
            "an entry without one saves as before"
        );
        Ok(())
    }

    /// A prefix tool in a launch with no prefix is that entry's failure, named as such.
    #[test]
    fn a_prefix_tool_without_a_prefix_is_refused() -> Result<()> {
        let addon = ExternalAddon::new(
            absolute("act/Advanced Combat Tracker.exe"),
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
            absolute("tool/run"),
            vec!["--path".into(), "a path with spaces".into()],
            RunIn::Host,
            Trigger::OnClose,
        )?;
        assert_eq!(addon.args(), ["--path", "a path with spaces"]);
        Ok(())
    }
}
