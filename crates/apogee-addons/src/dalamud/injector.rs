//! Composing the injector's command line.
//!
//! Pure, and separate from everything that touches a disk or a network, because this is the part with
//! an external contract: the flags, their spelling and their order are the reference launcher's, and
//! the injector's own parser is not ours to read. A golden test over [`injector_argv`] is what that
//! contract is pinned by.
//!
//! One deliberate difference from the reference launcher. It joins its arguments into a single string
//! that wine splits again, so it wraps every path in literal double quotes to survive that round trip.
//! This builds a real argv, where a quote is just a character, so the quotes are not emitted: a path
//! carrying them would be a path that does not exist.

use std::fmt;

/// How the injector gets Dalamud into the game.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum LoadMode {
    /// Rewrite the original entry point. Loads earlier, and is the mode Dalamud develops against.
    EntryPoint,
    /// Inject once the process is up. The reference launcher's default under wine, and so this one's.
    #[default]
    Inject,
}

impl LoadMode {
    /// The spelling `--mode` takes.
    const fn as_flag_value(self) -> &'static str {
        match self {
            Self::EntryPoint => "entrypoint",
            Self::Inject => "inject",
        }
    }
}

/// Which plugins Dalamud is allowed to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PluginPolicy {
    /// Everything the user has installed.
    #[default]
    All,
    /// Only plugins from the official repository.
    NoThirdParty,
    /// None at all, which is the shape of a "does the game still start?" run.
    None,
}

/// The game's own language ordinal, which the injector takes as a number.
///
/// Numbered explicitly because the wire value is the number and not the name: renaming a variant is
/// free, reordering one is a silent behaviour change.
///
/// # Examples
///
/// ```
/// use apogee_addons::ClientLanguage;
///
/// assert_eq!(ClientLanguage::German.ordinal(), 2);
/// assert_eq!(ClientLanguage::from_ordinal(2), ClientLanguage::German);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum ClientLanguage {
    /// Japanese.
    Japanese = 0,
    /// English.
    #[default]
    English = 1,
    /// German.
    German = 2,
    /// French.
    French = 3,
}

impl ClientLanguage {
    /// The ordinal the injector expects.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::ClientLanguage;
    ///
    /// assert_eq!(ClientLanguage::Japanese.ordinal(), 0);
    /// assert_eq!(ClientLanguage::French.ordinal(), 3);
    /// ```
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// The language an ordinal names, defaulting to [`ClientLanguage::English`] for one this build does
    /// not know.
    ///
    /// Takes the number rather than a name because the number is what the game itself is told, so the
    /// launcher decides the language once and this converts it rather than deciding again.
    ///
    /// # Examples
    ///
    /// ```
    /// use apogee_addons::ClientLanguage;
    ///
    /// assert_eq!(ClientLanguage::from_ordinal(0), ClientLanguage::Japanese);
    /// assert_eq!(ClientLanguage::from_ordinal(200), ClientLanguage::English);
    /// ```
    #[must_use]
    pub const fn from_ordinal(ordinal: u8) -> Self {
        match ordinal {
            0 => Self::Japanese,
            2 => Self::German,
            3 => Self::French,
            _ => Self::English,
        }
    }
}

impl fmt::Display for ClientLanguage {
    /// Formats as the ordinal, which is what the flag carries.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.ordinal())
    }
}

/// Everything one injector invocation needs, with every path already in its Windows form.
///
/// Borrowed rather than owned so the caller keeps the translated strings it just produced; this type
/// exists to be turned straight into argv.
///
/// Internal, because it is a description of somebody else's command line. Every field is a flag
/// upstream chose and may rename, so publishing it would make this launcher's public API a promise
/// about the injector's, and nothing outside this crate composes that command line.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InjectorInvocation<'a> {
    pub mode: LoadMode,
    /// The game executable, as a Windows path.
    pub game: &'a str,
    /// The directory the injector and its libraries sit in.
    pub working_directory: &'a str,
    /// Dalamud's own configuration file.
    pub configuration_path: &'a str,
    /// Where Dalamud writes its logs.
    pub logging_path: &'a str,
    /// Where the user's plugins live.
    pub plugin_directory: &'a str,
    /// The versioned asset tree.
    pub asset_directory: &'a str,
    pub client_language: ClientLanguage,
    pub delay_initialize_ms: u64,
    /// A base64 JSON blob the injector passes through to Dalamud's crash reporting.
    pub troubleshooting_b64: &'a str,
    pub plugins: PluginPolicy,
}

/// The argv tokens that follow the injector executable, ending with the `--` that separates them from
/// the game's own argument string.
///
/// The game argument is *not* included: it stays the launch plan's opaque string, which nothing here is
/// entitled to read or reshape.
///
/// Internal for the same reason as [`InjectorInvocation`].
#[must_use]
pub(crate) fn injector_argv(inv: &InjectorInvocation<'_>) -> Vec<String> {
    let mut argv = vec![
        "launch".to_owned(),
        format!("--mode={}", inv.mode.as_flag_value()),
        format!("--game={}", inv.game),
        format!("--dalamud-working-directory={}", inv.working_directory),
        format!("--dalamud-configuration-path={}", inv.configuration_path),
        format!("--logpath={}", inv.logging_path),
        format!("--dalamud-plugin-directory={}", inv.plugin_directory),
        format!("--dalamud-asset-directory={}", inv.asset_directory),
        format!("--dalamud-client-language={}", inv.client_language),
        format!("--dalamud-delay-initialize={}", inv.delay_initialize_ms),
        format!("--dalamud-tspack-b64={}", inv.troubleshooting_b64),
    ];
    match inv.plugins {
        PluginPolicy::All => {}
        PluginPolicy::NoThirdParty => argv.push("--no-3rd-plugin".to_owned()),
        PluginPolicy::None => argv.push("--no-plugin".to_owned()),
    }
    argv.push("--".to_owned());
    argv
}

#[cfg(test)]
mod tests {
    use super::*;

    fn invocation() -> InjectorInvocation<'static> {
        InjectorInvocation {
            mode: LoadMode::Inject,
            game: r"C:\games\ffxiv\game\ffxiv_dx11.exe",
            working_directory: r"Z:\home\me\dalamud\addon\Hooks\15.0.2.3",
            configuration_path: r"Z:\home\me\dalamud\config\dalamudConfig.json",
            logging_path: r"Z:\home\me\dalamud\logs",
            plugin_directory: r"Z:\home\me\dalamud\config\installedPlugins",
            asset_directory: r"Z:\home\me\dalamud\assets\432",
            client_language: ClientLanguage::English,
            delay_initialize_ms: 0,
            troubleshooting_b64: "e30=",
            plugins: PluginPolicy::All,
        }
    }

    /// The whole contract in one vector. The injector's own parser lives upstream and is not readable
    /// from here, so the only thing standing between a rename and a launch that silently loads nothing
    /// is this list matching the reference launcher's, flag for flag and in order.
    #[test]
    fn the_argv_matches_the_reference_launchers_flags_and_order() {
        assert_eq!(
            injector_argv(&invocation()),
            [
                "launch",
                "--mode=inject",
                r"--game=C:\games\ffxiv\game\ffxiv_dx11.exe",
                r"--dalamud-working-directory=Z:\home\me\dalamud\addon\Hooks\15.0.2.3",
                r"--dalamud-configuration-path=Z:\home\me\dalamud\config\dalamudConfig.json",
                r"--logpath=Z:\home\me\dalamud\logs",
                r"--dalamud-plugin-directory=Z:\home\me\dalamud\config\installedPlugins",
                r"--dalamud-asset-directory=Z:\home\me\dalamud\assets\432",
                "--dalamud-client-language=1",
                "--dalamud-delay-initialize=0",
                "--dalamud-tspack-b64=e30=",
                "--",
            ]
        );
    }

    /// The reference launcher quotes its path arguments because it hands wine one string to re-split.
    /// This passes argv directly, so a quote would be part of the path and every one of these would
    /// name something that does not exist.
    #[test]
    fn no_path_argument_carries_a_literal_quote() {
        for arg in injector_argv(&invocation()) {
            assert!(
                !arg.contains('"'),
                "{arg} carries a quote that would end up in the path"
            );
        }
    }

    /// The ordinals are the wire values. Swapping German and French, or counting from one, changes the
    /// language the game starts in with nothing else to notice it.
    #[test]
    fn the_client_language_is_the_reference_ordinal() {
        assert_eq!(ClientLanguage::Japanese.ordinal(), 0);
        assert_eq!(ClientLanguage::English.ordinal(), 1);
        assert_eq!(ClientLanguage::German.ordinal(), 2);
        assert_eq!(ClientLanguage::French.ordinal(), 3);
    }

    /// A plugin restriction is a flag that is present or absent, never a value. Emitting one
    /// unconditionally would silently stop every plugin the user installed from loading.
    #[test]
    fn the_plugin_flags_appear_only_when_they_are_asked_for() {
        let flags = |plugins| {
            injector_argv(&InjectorInvocation {
                plugins,
                ..invocation()
            })
            .into_iter()
            .filter(|arg| arg.contains("plugin") && !arg.contains("--dalamud-plugin-directory"))
            .collect::<Vec<_>>()
        };
        assert!(flags(PluginPolicy::All).is_empty());
        assert_eq!(flags(PluginPolicy::NoThirdParty), ["--no-3rd-plugin"]);
        assert_eq!(flags(PluginPolicy::None), ["--no-plugin"]);
    }

    /// The separator is last, so everything after it belongs to the game. A flag emitted past it would
    /// reach the game's own argument parser instead of the injector's.
    #[test]
    fn the_separator_is_the_last_token_whatever_else_is_set() {
        for plugins in [
            PluginPolicy::All,
            PluginPolicy::NoThirdParty,
            PluginPolicy::None,
        ] {
            let argv = injector_argv(&InjectorInvocation {
                plugins,
                mode: LoadMode::EntryPoint,
                ..invocation()
            });
            assert_eq!(argv.last().map(String::as_str), Some("--"));
        }
    }

    /// The mode reaches the injector as the word it parses, not as the variant's Rust name.
    #[test]
    fn the_entry_point_mode_is_spelled_as_the_injector_expects() {
        let argv = injector_argv(&InjectorInvocation {
            mode: LoadMode::EntryPoint,
            ..invocation()
        });
        assert!(argv.contains(&"--mode=entrypoint".to_owned()), "{argv:?}");
    }
}
