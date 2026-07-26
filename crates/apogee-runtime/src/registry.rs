//! Writing one registry value inside a prefix.
//!
//! The component layer's prefix tweaks are registry writes, so they get a typed primitive rather than
//! a hand-assembled command line at each call site. Two properties make it usable as the unit of an
//! idempotent setup step. It composes an argv, so there is no shell and no quoting rules. And it
//! writes with `/f`, which overwrites an existing value without prompting, so applying the same edit
//! twice is the same as applying it once and no read-back is needed to decide.
//!
//! The value types are the three with an unambiguous single-argument encoding. `REG_MULTI_SZ` needs a
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
    /// `REG_SZ`. Never empty: the only thing an empty string expresses in the keys a component touches
    /// is "disabled", and switching something off prefix-wide as a side effect of installing a
    /// component is not a thing a component gets to do.
    String(String),
    /// `REG_EXPAND_SZ`, for a value carrying `%SystemRoot%`-style references.
    ExpandString(String),
    /// `REG_DWORD`, written in decimal.
    Dword(u32),
}

impl RegistryValue {
    /// The `/t` type name.
    fn type_name(&self) -> &'static str {
        match self {
            Self::String(_) => "REG_SZ",
            Self::ExpandString(_) => "REG_EXPAND_SZ",
            Self::Dword(_) => "REG_DWORD",
        }
    }

    /// The `/d` argument.
    fn data(&self) -> String {
        match self {
            Self::String(s) | Self::ExpandString(s) => s.clone(),
            Self::Dword(n) => n.to_string(),
        }
    }
}

impl RegistryEdit {
    /// The program invocation that applies this edit.
    ///
    /// # Errors
    /// [`RuntimeError::RegistryKey`] if the key is not rooted at a registry root, or if the key, name,
    /// or value carries something `reg` would reinterpret rather than store.
    pub(crate) fn command(&self) -> Result<ProgramInPrefix, RuntimeError> {
        self.check()?;
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
                self.value.data(),
                // Overwrite an existing value instead of asking, which is what makes a second apply a
                // no-op rather than a program waiting on a prompt nobody can answer.
                "/f".to_owned(),
            ],
        ))
    }

    /// Refuse an edit that is not the shape this primitive promises.
    ///
    /// Not injection defence: the argv has no shell to escape into. It is there so a manifest typo is
    /// a named error at the point of the mistake, rather than a non-zero exit from `reg` or, worse, a
    /// write that lands somewhere plausible.
    fn check(&self) -> Result<(), RuntimeError> {
        let root = self
            .key
            .split('\\')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase();
        if !ROOTS.contains(&root.as_str()) {
            return Err(self.rejected("it does not start at a registry root"));
        }
        if self.key.split('\\').skip(1).any(str::is_empty) {
            return Err(self.rejected("it has an empty path component"));
        }
        if self.name.is_empty() {
            return Err(self.rejected("the value name is empty"));
        }
        // `reg` reads a leading slash as a flag, so a name or key that starts with one would be
        // swallowed as an option rather than used.
        if self.name.starts_with('/') || self.key.starts_with('/') {
            return Err(self.rejected("a leading slash would be read as an option"));
        }
        let data = self.value.data();
        if data.is_empty() {
            return Err(self.rejected("the value is empty"));
        }
        for text in [&self.key, &self.name, &data] {
            if text.chars().any(|c| c.is_control()) {
                return Err(self.rejected("it carries a control character"));
            }
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
