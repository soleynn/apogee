//! Writing and removing registry values inside a prefix.
//!
//! An edit composes an argv for `reg`, so there is no shell and no quoting rules, and it writes with
//! `/f`, which overwrites an existing value instead of prompting. That is what makes applying the
//! same edit twice the same as applying it once, with no read-back needed to decide.
//!
//! `/f` is not a nicety. Observed on wine 10.0: without it, `reg add` over a value that already
//! exists asks whether to overwrite, and with stdin closed it re-asks in a tight loop rather than
//! giving up, 36 MB of prompts in twenty seconds. So the flag is part of the composed command rather
//! than a caller's option, and the time budget and output cap every prefix run is held to are what
//! bound that shape if anything else ever produces it.
//!
//! A removal is read rather than reported. `reg delete` exits non-zero both for a value that was not
//! there and for a prefix that cannot answer at all, so a failed removal is followed by two
//! status-only probes: one for the target, one for a key every prefix has. Only "the target is gone
//! while the registry still answers" counts as success, because a removal reported as done is one a
//! caller never retries.

use crate::error::RuntimeError;
use crate::exec::{PrefixRun, ProgramInPrefix};

/// The registry roots this launcher will write under, in both spellings `reg` accepts.
const ROOTS: &[&str] = &[
    "HKCU",
    "HKEY_CURRENT_USER",
    "HKLM",
    "HKEY_LOCAL_MACHINE",
    "HKCR",
    "HKEY_CLASSES_ROOT",
    "HKU",
    "HKEY_USERS",
    "HKCC",
    "HKEY_CURRENT_CONFIG",
];

/// A registry value to write.
///
/// # Examples
///
/// ```
/// use apogee_runtime::{RegistryEdit, RegistryValue};
///
/// let edit = RegistryEdit {
///     key: r"HKCU\Software\Wine\DllOverrides".to_owned(),
///     name: "d3d11".to_owned(),
///     value: RegistryValue::String("native,builtin".to_owned()),
/// };
/// assert!(edit.validate().is_ok());
///
/// let unrooted = RegistryEdit { key: r"Software\Wine".to_owned(), ..edit };
/// assert_eq!(unrooted.validate(), Err("it does not start at a registry root"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEdit {
    /// The key, backslash-separated from a root: `HKCU\Software\Wine\DllOverrides`.
    pub key: String,
    /// The value name within that key.
    pub name: String,
    /// The value.
    pub value: RegistryValue,
}

// The types here are the ones with an unambiguous single-argument encoding. `REG_MULTI_SZ` needs a
// separator convention and `REG_BINARY` a hex one, and a manifest that got either subtly wrong would
// write a plausible-looking wrong value rather than failing, so neither is added until a verb needs
// it.
/// A registry value, in the types a prefix tweak needs.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryValue {
    /// `REG_SZ`. Never empty; [`Self::Disabled`] is how an empty one is spelled.
    String(String),
    /// `REG_EXPAND_SZ`, for a value carrying `%SystemRoot%`-style references.
    ExpandString(String),
    /// `REG_DWORD`, written in decimal.
    Dword(u32),
    /// An empty `REG_SZ`, which under `Wine\DllOverrides` means "load neither the native library nor
    /// the builtin one".
    ///
    /// Its own variant rather than an empty [`Self::String`], so a value that means it says so while
    /// one that went missing is still refused. Those are opposite intentions with the same spelling
    /// otherwise.
    Disabled,
}

impl RegistryValue {
    /// The `/t` type name.
    fn type_name(&self) -> &'static str {
        match self {
            Self::String(_) | Self::Disabled => "REG_SZ",
            Self::ExpandString(_) => "REG_EXPAND_SZ",
            Self::Dword(_) => "REG_DWORD",
        }
    }

    /// The `/d` argument.
    fn data(&self) -> String {
        match self {
            Self::String(s) | Self::ExpandString(s) => s.clone(),
            Self::Dword(n) => n.to_string(),
            Self::Disabled => String::new(),
        }
    }
}

/// The fewest path components below a root a whole-key removal may name.
///
/// `HKLM\Software` and `HKLM\Software\Microsoft` are not keys anything here has business removing,
/// and a row that meant to name something deeper and lost a component would otherwise take the whole
/// subtree with it. Removing a single value is not held to this, since it names exactly what it
/// removes.
const MIN_KEY_DEPTH: usize = 3;

/// A key every initialized prefix has, queried as the control when a removal fails.
///
/// `reg query` on it answers if and only if the prefix's registry can be read at all, which is what
/// makes a "not found" on the target readable as an absence rather than as a prefix that cannot
/// answer anything.
const ALWAYS_PRESENT_KEY: &str = r"HKCU\Software";

/// A registry value or key to remove.
///
/// Its own type rather than a mode of [`RegistryEdit`]: removal is the one registry operation that
/// can destroy something the launcher did not create, and writing one by accident while reaching for
/// a write should not be possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryDelete {
    /// The key, backslash-separated from a root.
    pub key: String,
    /// The value to remove, or `None` to remove the key and everything under it.
    pub name: Option<String>,
}

impl RegistryDelete {
    /// Why this removal is not one this primitive will perform, or `Ok` when it is.
    ///
    /// # Errors
    /// The reason, on the same grounds as [`RegistryEdit::validate`], plus a whole-key removal that
    /// names a key too shallow to be one the launcher put there.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.check()
    }

    /// The invocation that asks whether the thing is still there.
    ///
    /// Asked after a failed removal, not before one: `reg delete` on something absent exits
    /// non-zero, and this crate reads exit status rather than output, so "it was not there" and "it
    /// could not be removed" are otherwise the same answer. Status-only invocations tell them apart
    /// without parsing anything; [`read_failed_delete`] does that reading.
    ///
    /// # Errors
    /// [`RuntimeError::RegistryKey`] if [`Self::validate`] refuses it.
    pub(crate) fn probe(&self) -> Result<ProgramInPrefix, RuntimeError> {
        self.check().map_err(|reason| self.rejected(reason))?;
        let mut args = vec!["query".to_owned(), self.key.clone()];
        if let Some(name) = &self.name {
            args.push("/v".to_owned());
            args.push(name.clone());
        }
        Ok(ProgramInPrefix::new("reg", args))
    }

    /// The invocation that performs the removal.
    ///
    /// # Errors
    /// [`RuntimeError::RegistryKey`] if [`Self::validate`] refuses it.
    pub(crate) fn command(&self) -> Result<ProgramInPrefix, RuntimeError> {
        self.check().map_err(|reason| self.rejected(reason))?;
        let mut args = vec!["delete".to_owned(), self.key.clone()];
        if let Some(name) = &self.name {
            args.push("/v".to_owned());
            args.push(name.clone());
        }
        // No prompt, for the reason the module note gives: it does not merely block, it loops.
        args.push("/f".to_owned());
        Ok(ProgramInPrefix::new("reg", args))
    }

    fn check(&self) -> Result<(), &'static str> {
        check_key(&self.key)?;
        match &self.name {
            Some(name) => check_value_name(name)?,
            None => {
                if self.key.split('\\').skip(1).count() < MIN_KEY_DEPTH {
                    return Err("it removes a key too shallow to be one this launcher created");
                }
            }
        }
        Ok(())
    }

    fn rejected(&self, reason: &'static str) -> RuntimeError {
        RuntimeError::RegistryKey {
            key: match &self.name {
                Some(name) => format!("{}\\{name}", self.key),
                None => self.key.clone(),
            },
            reason,
        }
    }
}

/// The invocation that asks whether the prefix's registry answers at all, by querying a key every
/// prefix has.
pub(crate) fn readable_probe() -> ProgramInPrefix {
    ProgramInPrefix::new(
        "reg",
        vec!["query".to_owned(), ALWAYS_PRESENT_KEY.to_owned()],
    )
}

/// What a failed `reg delete` turned out to mean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeleteVerdict {
    /// The registry answered and does not have it: there was nothing to remove.
    AlreadyAbsent,
    /// The removal did not happen, described by the reading that says so.
    Failed(&'static str),
}

/// Read a failed removal against two status-only probes: `target` asked whether the thing is still
/// there, `control` whether `reg` answers at all.
///
/// The control is what makes an absent answer trustworthy. A non-zero `reg query` is "not found",
/// but it is equally a half-created prefix, a runner whose builtin `reg` will not start, and a wine
/// that aborts on startup. Reading any of those as a completed removal reports success for something
/// that never happened, to a caller that records applied steps and then never retries them.
///
/// The target is read as a raw status rather than as pass/fail, because a probe killed by a signal
/// never reached an answer at all. The control cannot rescue that one: it establishes that the
/// registry is readable, not that this probe finished.
pub(crate) fn read_failed_delete(target: &PrefixRun, control: &PrefixRun) -> DeleteVerdict {
    match (target.code, control.ok()) {
        (Some(0), _) => DeleteVerdict::Failed("it is still in the registry afterwards"),
        (None, _) => DeleteVerdict::Failed(
            "the probe for it was killed before it answered, so whether it is still there is unknown",
        ),
        (Some(_), true) => DeleteVerdict::AlreadyAbsent,
        (Some(_), false) => DeleteVerdict::Failed(
            "the prefix registry answered nothing, so an absent value cannot be told from a prefix that cannot be read",
        ),
    }
}

// Not injection defence: the composed argv has no shell to escape into. The checks are here so a
// typo is a named error at the point of the mistake, rather than an opaque non-zero exit from `reg`
// or, worse, a write that lands somewhere plausible.
/// The key rules both a write and a removal are held to.
fn check_key(key: &str) -> Result<(), &'static str> {
    let root = key
        .split('\\')
        .next()
        .unwrap_or_default()
        .to_ascii_uppercase();
    if !ROOTS.contains(&root.as_str()) {
        return Err("it does not start at a registry root");
    }
    if key.split('\\').skip(1).any(str::is_empty) {
        return Err("it has an empty path component");
    }
    // `reg` reads a leading slash as a flag, so a key that starts with one would be swallowed as an
    // option rather than used.
    if key.starts_with('/') {
        return Err("a leading slash would be read as an option");
    }
    if key.chars().any(char::is_control) {
        return Err("it carries a control character");
    }
    Ok(())
}

/// The rules a value name is held to.
fn check_value_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() {
        return Err("the value name is empty");
    }
    if name.starts_with('/') {
        return Err("a leading slash would be read as an option");
    }
    if name.chars().any(char::is_control) {
        return Err("it carries a control character");
    }
    Ok(())
}

impl RegistryEdit {
    /// Why this edit is not a shape this primitive will write, or `Ok` when it is.
    ///
    /// Public so a manifest that describes registry edits can reject a bad row as it parses it,
    /// naming the row, rather than at the moment of the write. The reason is a string rather than a
    /// [`RuntimeError`] so a caller can report it in its own taxonomy.
    ///
    /// # Errors
    /// The reason, when the key is not rooted at a registry root, a path component or the value name
    /// is empty, a leading slash would be read as an option, the value is empty without saying so
    /// with [`RegistryValue::Disabled`], or anything carries a control character.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.check()
    }

    /// The program invocation that applies this edit.
    ///
    /// # Errors
    /// [`RuntimeError::RegistryKey`] if [`Self::validate`] refuses it.
    pub(crate) fn command(&self) -> Result<ProgramInPrefix, RuntimeError> {
        self.check().map_err(|reason| self.rejected(reason))?;
        Ok(ProgramInPrefix::new(
            "reg",
            vec![
                "add".to_owned(),
                self.key.clone(),
                "/v".to_owned(),
                self.name.clone(),
                "/t".to_owned(),
                self.value.type_name().to_owned(),
                "/d".to_owned(),
                // Passed even when empty. `reg` also treats an omitted `/d` as an empty value, but
                // stating it is one fewer default to depend on.
                self.value.data(),
                // Overwrite instead of asking. See the module note: the prompt does not merely block,
                // it loops.
                "/f".to_owned(),
            ],
        ))
    }

    fn check(&self) -> Result<(), &'static str> {
        check_key(&self.key)?;
        check_value_name(&self.name)?;
        let data = self.value.data();
        if data.is_empty() && self.value != RegistryValue::Disabled {
            return Err("the value is empty");
        }
        if data.chars().any(char::is_control) {
            return Err("it carries a control character");
        }
        Ok(())
    }

    fn rejected(&self, reason: &'static str) -> RuntimeError {
        RuntimeError::RegistryKey {
            key: format!("{}\\{}", self.key, self.name),
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn edit(key: &str, name: &str, value: RegistryValue) -> RegistryEdit {
        RegistryEdit {
            key: key.to_owned(),
            name: name.to_owned(),
            value,
        }
    }

    /// The dll override every prefix tweak is shaped like.
    fn dll_override() -> RegistryEdit {
        edit(
            r"HKCU\Software\Wine\DllOverrides",
            "d3d11",
            RegistryValue::String("native,builtin".to_owned()),
        )
    }

    /// `/f` is what makes a re-apply a no-op instead of a program blocking on a prompt, so it is not
    /// optional, and the flag order is the one `reg` documents.
    #[test]
    fn the_command_overwrites_without_prompting() {
        let command = dll_override().command().expect("valid edit");
        assert_eq!(command.program(), "reg");
        let args = command_args(&command);
        assert_eq!(
            args,
            [
                "add",
                r"HKCU\Software\Wine\DllOverrides",
                "/v",
                "d3d11",
                "/t",
                "REG_SZ",
                "/d",
                "native,builtin",
                "/f",
            ]
        );
    }

    /// Each value type reaches `reg` as its own `/t` name and its own `/d` spelling.
    #[test]
    fn each_value_type_carries_its_own_encoding() {
        let dword = edit(r"HKCU\Software\Apogee", "Flag", RegistryValue::Dword(1))
            .command()
            .expect("valid");
        assert!(command_args(&dword).contains(&"REG_DWORD".to_owned()));
        assert!(command_args(&dword).contains(&"1".to_owned()));

        let expand = edit(
            r"HKCU\Software\Apogee",
            "Path",
            RegistryValue::ExpandString(r"%SystemRoot%\fonts".to_owned()),
        )
        .command()
        .expect("valid");
        assert!(command_args(&expand).contains(&"REG_EXPAND_SZ".to_owned()));
    }

    /// The one value that is legitimately empty. It has to be spelled, because the check that
    /// catches a row whose value went missing would otherwise catch this too.
    #[test]
    fn disabling_a_dll_writes_an_empty_string_value() {
        let command = edit(
            r"HKCU\Software\Wine\DllOverrides",
            "winemenubuilder.exe",
            RegistryValue::Disabled,
        )
        .command()
        .expect("an explicit disable is allowed");
        let args = command_args(&command);
        assert_eq!(
            args,
            [
                "add",
                r"HKCU\Software\Wine\DllOverrides",
                "/v",
                "winemenubuilder.exe",
                "/t",
                "REG_SZ",
                "/d",
                "",
                "/f",
            ]
        );
    }

    /// A key that is not rooted is a manifest mistake, and `reg` would report it as its own opaque
    /// failure. Naming it here points at the row instead.
    #[test]
    fn a_key_that_is_not_rooted_is_refused() {
        for key in ["Software\\Wine", "", "HKEY_MADE_UP\\Software", "/HKCU"] {
            let err = edit(key, "d3d11", RegistryValue::Dword(1))
                .command()
                .expect_err(key);
            assert!(matches!(err, RuntimeError::RegistryKey { .. }), "{key}");
        }
    }

    /// A row that lost a path component, its value name or its value is refused rather than written
    /// somewhere plausible, and a name that begins as an option is refused with it.
    #[test]
    fn an_empty_component_name_or_value_is_refused() {
        let cases = [
            edit(r"HKCU\\Software", "d3d11", RegistryValue::Dword(1)),
            edit(r"HKCU\Software", "", RegistryValue::Dword(1)),
            edit(
                r"HKCU\Software",
                "d3d11",
                RegistryValue::String(String::new()),
            ),
            edit(r"HKCU\Software", "/v", RegistryValue::Dword(1)),
        ];
        for case in cases {
            assert!(
                matches!(case.command(), Err(RuntimeError::RegistryKey { .. })),
                "{case:?}"
            );
        }
    }

    /// A newline in a value would split the argument as far as anything reading the child's output
    /// is concerned, and a NUL truncates it on the way to the syscall.
    #[test]
    fn a_control_character_anywhere_is_refused() {
        let cases = [
            edit("HKCU\\Soft\nware", "d3d11", RegistryValue::Dword(1)),
            edit(r"HKCU\Software", "d3d\x0011", RegistryValue::Dword(1)),
            edit(
                r"HKCU\Software",
                "d3d11",
                RegistryValue::String("native\nbuiltin".to_owned()),
            ),
        ];
        for case in cases {
            assert!(
                matches!(case.command(), Err(RuntimeError::RegistryKey { .. })),
                "{case:?}"
            );
        }
    }

    /// Reads back the argv a [`ProgramInPrefix`] was built with, which is the whole contract here.
    fn command_args(program: &ProgramInPrefix) -> Vec<String> {
        program.args().to_vec()
    }

    /// A run that ended with `code`. Only the status decides anything here.
    fn exited(code: i32) -> PrefixRun {
        PrefixRun {
            code: Some(code),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// A run killed by a signal, which is how a wine that aborts on startup comes back.
    fn signalled() -> PrefixRun {
        PrefixRun {
            code: None,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    /// The reason each failed reading carries, written out here rather than shared with the source.
    /// The text is the whole point of returning a string instead of a bool, and a test that named
    /// the same constant the code names would pass however the readings were wired up.
    const STILL_THERE: &str = "it is still in the registry afterwards";
    const PROBE_KILLED: &str =
        "the probe for it was killed before it answered, so whether it is still there is unknown";
    const UNREADABLE: &str = "the prefix registry answered nothing, so an absent value cannot be told from a prefix that cannot be read";

    /// The distinction the control probe exists for. "Not found", a half-created prefix and a runner
    /// whose `reg` will not start are one and the same non-zero status, so an absence is only an
    /// absence when a key every prefix has still answers.
    #[test]
    fn nothing_to_remove_needs_a_registry_that_still_answers() {
        assert_eq!(
            read_failed_delete(&exited(1), &exited(0)),
            DeleteVerdict::AlreadyAbsent
        );
        assert_eq!(
            read_failed_delete(&exited(1), &exited(1)),
            DeleteVerdict::Failed(UNREADABLE)
        );
    }

    /// The reading a pass/fail on the target cannot express. A killed probe never reached an answer,
    /// and a healthy control does not supply one: it says the registry is readable, not that this
    /// probe finished.
    #[test]
    fn a_probe_that_was_killed_answered_nothing_however_well_the_control_went() {
        assert_eq!(
            read_failed_delete(&signalled(), &exited(0)),
            DeleteVerdict::Failed(PROBE_KILLED)
        );
    }

    /// A target still in the registry after the removal failed is that failure, whatever the control
    /// says: the control only ever rescues an absence.
    #[test]
    fn a_target_that_is_still_there_is_never_read_as_removed() {
        for control in [exited(0), exited(1)] {
            assert_eq!(
                read_failed_delete(&exited(0), &control),
                DeleteVerdict::Failed(STILL_THERE)
            );
        }
    }

    const TEST_KEY: &str = r"HKCU\Software\Apogee\RegistryDeleteTest";

    fn value_delete() -> RegistryDelete {
        RegistryDelete {
            key: TEST_KEY.to_owned(),
            name: Some("Setting".to_owned()),
        }
    }

    /// A prefix whose "runner" is a shell script standing in for `wine`, so the removal path can be
    /// driven end to end without one. The script sees `reg <verb> <key> ...` as its argv and answers
    /// with a status, which is all this path reads.
    #[cfg(target_os = "linux")]
    fn scripted(body: &str) -> (tempfile::TempDir, crate::Runtime, crate::Prefix) {
        let (dir, prefix) = crate::shim::scripted_prefix(body);
        let runtime = crate::Runtime::new(
            apogee_fetch::Fetcher::builder().build().expect("fetcher"),
            crate::RuntimePaths {
                runners: dir.path().join("runners"),
                prefixes: dir.path().join("prefixes"),
            },
        );
        (dir, runtime, prefix)
    }

    /// The message a failure carries, which is where the reading reaches whoever has to act on it.
    #[cfg(target_os = "linux")]
    fn failure_message(err: &RuntimeError) -> String {
        match err {
            RuntimeError::PrefixInit { source, .. } => source.to_string(),
            other => format!("{other:?}"),
        }
    }

    /// The regression: a prefix where nothing answers used to report a successful removal, so a
    /// caller recorded a step that never ran and never came back to it. The message has to say which
    /// of the two failures it was, since the fixes differ: this one is the prefix, not the value.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_prefix_that_answers_nothing_is_a_failure_not_a_removal() {
        let (_dir, runtime, prefix) = scripted("exit 1");
        let err = runtime
            .registry_delete(
                &prefix,
                &value_delete(),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .expect_err("a prefix whose reg never runs cannot have removed anything");
        assert!(matches!(err, RuntimeError::PrefixInit { .. }), "{err:?}");
        let message = failure_message(&err);
        assert!(message.contains(UNREADABLE), "{message}");
    }

    /// The same reading end to end: a probe that dies on its way to an answer is not an absence,
    /// even though the prefix around it is healthy enough to answer the control.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_probe_the_runner_killed_is_a_failure_not_a_removal() {
        let (_dir, runtime, prefix) = scripted(concat!(
            "case \"$3\" in 'HKCU\\Software') exit 0 ;; esac\n",
            "case \"$2\" in 'query') kill -9 $$ ;; esac\n",
            "exit 1"
        ));
        let err = runtime
            .registry_delete(
                &prefix,
                &value_delete(),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .expect_err("a probe that was killed said nothing about what is still there");
        assert!(matches!(err, RuntimeError::PrefixInit { .. }), "{err:?}");
        let message = failure_message(&err);
        assert!(message.contains(PROBE_KILLED), "{message}");
    }

    /// And the case it must stay compatible with: the value really is gone, the registry says so,
    /// and removing it again is success.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn removing_what_is_absent_from_a_working_registry_succeeds() {
        let (_dir, runtime, prefix) = scripted(concat!(
            "case \"$3\" in 'HKCU\\Software') exit 0 ;; esac\n",
            "exit 1"
        ));
        runtime
            .registry_delete(
                &prefix,
                &value_delete(),
                &tokio_util::sync::CancellationToken::new(),
            )
            .await
            .expect("nothing to remove is not a failure");
    }
}
