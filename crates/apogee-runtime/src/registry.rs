//! Writing one registry value inside a prefix.
//!
//! The component layer's prefix tweaks are registry writes, so they get a typed primitive rather than
//! a hand-assembled command line at each call site. Two properties make it usable as the unit of an
//! idempotent setup step. It composes an argv, so there is no shell and no quoting rules. And it
//! writes with `/f`, which overwrites an existing value without prompting, so applying the same edit
//! twice is the same as applying it once and no read-back is needed to decide.
//!
//! `/f` is not a nicety. Observed on wine 10.0: without it, `reg add` over a value that already exists
//! asks whether to overwrite, and with stdin closed it re-asks in a tight loop rather than giving up —
//! 36 MB of prompts in twenty seconds. So the flag is part of the composed command rather than a
//! caller's option, and the time budget and output cap in [`crate::exec`] are what bound that shape if
//! anything else ever produces it.
//!
//! The value types are the ones with an unambiguous single-argument encoding. `REG_MULTI_SZ` needs a
//! separator convention and `REG_BINARY` a hex one, and a manifest that gets either subtly wrong would
//! write a plausible-looking wrong value rather than failing; neither is added until a verb needs it.

use crate::error::RuntimeError;
use crate::exec::ProgramInPrefix;

/// Registry roots this launcher will write under, in both spellings `reg` accepts.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryEdit {
    /// The key, backslash-separated from a root: `HKCU\Software\Wine\DllOverrides`.
    pub key: String,
    /// The value name within that key.
    pub name: String,
    /// The value.
    pub value: RegistryValue,
}

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
    /// Its own variant rather than an empty [`Self::String`] so that a row meaning it says so, while a
    /// row whose value went missing is still refused. Those are opposite intentions with the same
    /// spelling otherwise.
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
/// `HKLM\Software` and `HKLM\Software\Microsoft` are not keys anything here has business removing, and a
/// row that meant to name something deeper and lost a component would otherwise take the whole subtree
/// with it. Removing a single *value* is not held to this, since it names exactly what it removes.
const MIN_KEY_DEPTH: usize = 3;

/// A registry value or key to remove.
///
/// Its own type rather than an option on [`RegistryEdit`], because removal is the one registry operation
/// that can destroy something the launcher did not create, and it is worth being unable to write one by
/// accident while reaching for a write.
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
    /// The reason, as [`RegistryEdit::validate`], plus a whole-key removal that names a key too shallow
    /// to be one the launcher put there.
    pub fn validate(&self) -> Result<(), &'static str> {
        self.check()
    }

    /// The invocation that asks whether there is anything to remove.
    ///
    /// Asked first because `reg delete` on something absent exits non-zero, and this crate reads exit
    /// status rather than output, so "it was not there" and "it could not be removed" are otherwise the
    /// same answer. Two status-only invocations tell them apart without parsing anything.
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
    /// Public because a manifest that describes registry edits wants to reject a bad row when it is
    /// parsed, naming the row, rather than at the moment of the write. Returns the reason rather than a
    /// [`RuntimeError`] so a caller can report it in its own taxonomy.
    ///
    /// Not injection defence: the composed argv has no shell to escape into. It is there so a typo is a
    /// named error at the point of the mistake, rather than a non-zero exit from `reg` or, worse, a
    /// write that lands somewhere plausible.
    ///
    /// # Errors
    /// The reason, when the key is not rooted at a registry root, a path component or the value name is
    /// empty, a leading slash would be read as an option, the value is empty without saying so, or
    /// anything carries a control character.
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

    fn dll_override() -> RegistryEdit {
        edit(
            r"HKCU\Software\Wine\DllOverrides",
            "d3d11",
            RegistryValue::String("native,builtin".to_owned()),
        )
    }

    /// `/f` is what makes a re-apply a no-op instead of a program blocking on a prompt, so it is not
    /// optional and the order of the flags is the one `reg` documents.
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

    /// The one value that is legitimately empty. It has to be spelled, because the check that catches a
    /// row whose value went missing would otherwise catch this too.
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

    /// A newline in a value would split the argument as far as anything reading the child's output is
    /// concerned, and a NUL truncates it on the way to the syscall.
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

    /// Reads back the argv a `ProgramInPrefix` was built with, which is the whole contract here.
    fn command_args(program: &ProgramInPrefix) -> Vec<String> {
        program.args().to_vec()
    }
}
