//! The one rule for what environment a companion may ask for.
//!
//! An exact-key allowlist, shared by a signed program row and a user's own entry, rather than a
//! denylist. Everything that can redirect or load code into the launch chain (the wine loader, umu,
//! `pressure-vessel`, Python, Vulkan layers, `GStreamer`, the dynamic linker, `PATH`, the session bus) is
//! reachable through an environment variable, and that list is open-ended: a denylist is only as good
//! as the last variable somebody remembered. So two keys are admitted and every other one is refused.
//!
//! - `MONO_PATH`, which a managed program needs to find assemblies it does not ship beside itself.
//! - `WINEDLLOVERRIDES`, as **additions** only: an entry may not name a library the game's own launch
//!   overrides, since a companion sharing the game's wine session must not change which renderer or
//!   vendor library the game loads.

use std::collections::BTreeMap;

/// The keys a companion's environment may carry. Anything else is refused.
pub(crate) const ALLOWED_KEYS: [&str; 2] = ["MONO_PATH", "WINEDLLOVERRIDES"];

/// Libraries the game's launch decides and a companion's override may never name, as wine spells
/// them once the `.dll` suffix and any directory are dropped.
///
/// The renderer chain (every Direct3D generation and DXGI, which DXVK and VKD3D replace), the NVIDIA
/// vendor libraries the nvapi option overrides, and the input and loader libraries a proxy-DLL shaped
/// injector would hijack.
const RESERVED_LIBRARIES: [&str; 14] = [
    "d3d8",
    "d3d9",
    "d3d10",
    "d3d10_1",
    "d3d10core",
    "d3d11",
    "d3d12",
    "d3d12core",
    "dxgi",
    "nvapi",
    "nvapi64",
    "nvngx",
    "nvofapi64",
    "dinput8",
];

/// The longest value a companion's variable may hold. Real values are a path or a short override
/// list; this only stops a row from describing an environment no `execve` would take.
const MAX_VALUE_BYTES: usize = 4096;

/// Why one variable was refused, with the key that broke the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EnvRefusal {
    pub key: String,
    pub reason: &'static str,
}

/// What the game's own launch environment says about library overrides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum GameOverrides {
    /// The libraries the game's `WINEDLLOVERRIDES` names, normalized. Empty when it sets none.
    Named(Vec<String>),
    /// The game carries a `WINEDLLOVERRIDES` this module cannot read, so which libraries it decides
    /// is unknown and no companion override can be shown to leave them alone.
    Unreadable,
}

impl GameOverrides {
    /// A launch that overrides nothing beyond the fixed set.
    pub(crate) const fn none() -> Self {
        Self::Named(Vec::new())
    }

    /// Read the game's own `WINEDLLOVERRIDES`, if it has one.
    pub(crate) fn of(value: Option<&str>) -> Self {
        match value.map(override_names) {
            None => Self::none(),
            Some(Ok(names)) => Self::Named(names),
            Some(Err(_)) => Self::Unreadable,
        }
    }
}

/// Check every variable in `env`, refusing the first that breaks a rule.
///
/// `game_overrides` are the libraries the game's own launch environment overrides, beyond the fixed
/// set, so an addition naming one is refused as well. When the game's list could not be read, every
/// `WINEDLLOVERRIDES` is refused: an addition cannot be told from a replacement.
pub(crate) fn check(
    env: &BTreeMap<String, String>,
    game_overrides: &GameOverrides,
) -> Result<(), EnvRefusal> {
    for (key, value) in env {
        let refuse = |reason: &'static str| EnvRefusal {
            key: key.clone(),
            reason,
        };
        if !ALLOWED_KEYS.contains(&key.as_str()) {
            return Err(refuse(
                "only MONO_PATH and WINEDLLOVERRIDES may be set for a companion",
            ));
        }
        if value.len() > MAX_VALUE_BYTES {
            return Err(refuse("its value is longer than any environment needs"));
        }
        // A null byte cannot cross `execve`, and a control character in a value that ends up in a log
        // line or a path is a way to make one say something it does not.
        if value.chars().any(char::is_control) {
            return Err(refuse("its value carries a control character"));
        }
        if key == "WINEDLLOVERRIDES" {
            let GameOverrides::Named(game) = game_overrides else {
                return Err(refuse(
                    "the game's own library overrides could not be read, so none may be added",
                ));
            };
            for library in override_names(value).map_err(refuse)? {
                if RESERVED_LIBRARIES.contains(&library.as_str()) || game.contains(&library) {
                    return Err(refuse(
                        "it overrides a library the game's own launch decides",
                    ));
                }
            }
        } else if value.is_empty() {
            return Err(refuse("its value is empty"));
        }
    }
    Ok(())
}

/// The libraries a `WINEDLLOVERRIDES` value names, normalized the way wine compares them: lowercased,
/// with any directory and a trailing `.dll` dropped.
///
/// Strict about shape, because the value is parsed again by wine and anything this reads differently
/// is an override this check did not see. Each `;`-separated entry is `names=mode`, the names
/// `,`-separated, the mode one or two of `n`, `b`, `native` and `builtin` in any case, `,`-separated
/// (or empty, which disables the library).
pub(crate) fn override_names(value: &str) -> Result<Vec<String>, &'static str> {
    let mut names = Vec::new();
    for entry in value.split(';') {
        if entry.is_empty() {
            continue;
        }
        let Some((libraries, mode)) = entry.split_once('=') else {
            return Err("an override entry names no load order");
        };
        if !is_load_order(mode) {
            return Err("an override entry's load order is not one wine reads");
        }
        for library in libraries.split(',') {
            names.push(normalize(library)?);
        }
    }
    Ok(names)
}

/// Whether `mode` is a load order wine reads the way it is written.
///
/// Wine looks only at the first letter of each `,`-separated word, so `nonsense` would load native.
/// Only the spellings that mean what they say are taken: the letters and the two whole words.
fn is_load_order(mode: &str) -> bool {
    if mode.is_empty() {
        return true;
    }
    let mut words = 0_usize;
    for word in mode.split(',') {
        words += 1;
        let known = ["n", "b", "native", "builtin"]
            .iter()
            .any(|spelling| word.eq_ignore_ascii_case(spelling));
        if !known || words > 2 {
            return false;
        }
    }
    true
}

/// One library name as wine compares it.
fn normalize(raw: &str) -> Result<String, &'static str> {
    let base = raw.rsplit(['\\', '/']).next().unwrap_or(raw);
    let lower = base.to_ascii_lowercase();
    let name = lower.strip_suffix(".dll").unwrap_or(&lower);
    if name.is_empty() {
        return Err("an override entry names an empty library");
    }
    // Wine matches these against module names; anything outside this set is not a module name and
    // is far more likely to be a second entry smuggled past the split above.
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
    {
        return Err("an override entry names something that is not a library");
    }
    Ok(name.to_owned())
}

/// `ours` appended to `game`'s `WINEDLLOVERRIDES`, so the companion inherits the game's overrides
/// and adds its own rather than replacing them.
pub(crate) fn merge_overrides(game: Option<&str>, ours: &str) -> String {
    match game {
        Some(game) if !game.is_empty() => format!("{game};{ours}"),
        _ => ours.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// Every variable that is known to redirect the launch chain is refused by name, and so is one
    /// nobody has thought of yet, because the rule is the allowlist and not a list of these.
    #[test]
    fn every_key_outside_the_allowlist_is_refused() {
        for key in [
            "PYTHONPATH",
            "PYTHONHOME",
            "PROTON_VERB",
            "PRESSURE_VESSEL_FILESYSTEMS_RW",
            "VK_LAYER_PATH",
            "VK_ICD_FILENAMES",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
            "WINEPREFIX",
            "WINESERVER",
            "WINELOADER",
            "GST_PLUGIN_PATH",
            "MONO_ENV_OPTIONS",
            "PATH",
            "HOME",
            "DBUS_SESSION_BUS_ADDRESS",
            "UMU_CONTAINER_NSENTER",
            "APOGEE_GAME_PID",
            "mono_path",
            "MONO_PATH ",
            "",
        ] {
            let refused = check(&env(&[(key, "x")]), &GameOverrides::none()).expect_err(key);
            assert_eq!(refused.key, key);
        }
    }

    /// An override of anything the game's launch decides is refused however it is spelled: case,
    /// suffix, a directory in front, or hidden as the second name of a list.
    #[test]
    fn an_override_of_the_games_libraries_is_refused_in_every_spelling() {
        for value in [
            "d3d11=n",
            "D3D11=n,b",
            "d3d11.dll=b",
            "C:\\windows\\system32\\dxgi.dll=n",
            "mscoree=b;dxgi=",
            "mscoree,nvapi64=n",
            "winhttp=n;DXGI.DLL=n",
        ] {
            assert!(
                check(&env(&[("WINEDLLOVERRIDES", value)]), &GameOverrides::none()).is_err(),
                "{value} must be refused"
            );
        }
        // The launch's own extra overrides join the fixed set.
        assert!(
            check(
                &env(&[("WINEDLLOVERRIDES", "winhttp=n")]),
                &GameOverrides::Named(vec!["winhttp".to_owned()])
            )
            .is_err()
        );
    }

    /// A value wine would read differently from this check is refused rather than guessed at.
    #[test]
    fn an_override_list_that_is_not_one_wine_reads_is_refused() {
        for value in [
            "winhttp",
            "winhttp=x",
            "winhttp=nnnn",
            "winhttp=nonsense",
            "winhttp=n,",
            "winhttp=,",
            "winhttp=n,b,n",
            "winhttp= native",
            "=n",
            "win http=n",
            "winhttp=n\nd3d11=n",
        ] {
            assert!(
                check(&env(&[("WINEDLLOVERRIDES", value)]), &GameOverrides::none()).is_err(),
                "{value:?} must be refused"
            );
        }
    }

    /// The allowed shapes pass.
    #[test]
    fn an_allowed_addition_passes() {
        let ok = env(&[
            ("MONO_PATH", "C:\\Apogee\\act\\libs"),
            (
                "WINEDLLOVERRIDES",
                "mscoree=b;winhttp=n,b;version=Native,Builtin;xaudio2_7=",
            ),
        ]);
        assert_eq!(check(&ok, &GameOverrides::none()), Ok(()));
        assert_eq!(
            merge_overrides(Some("d3d11,dxgi=native"), "winhttp=n"),
            "d3d11,dxgi=native;winhttp=n"
        );
        assert_eq!(merge_overrides(None, "winhttp=n"), "winhttp=n");
        assert!(check(&env(&[("MONO_PATH", "")]), &GameOverrides::none()).is_err());
        assert!(
            check(
                &env(&[("MONO_PATH", &"a".repeat(5000))]),
                &GameOverrides::none()
            )
            .is_err()
        );
    }

    /// The spelling the game's launch really carries is read: its native group and the group it
    /// disables both count as decided, so a companion cannot turn back on what the launch turned off.
    #[test]
    fn the_games_own_spelling_is_read_and_its_disabled_libraries_stay_decided() {
        let game = GameOverrides::of(Some(
            "d3d10core,d3d11,d3d9,dxgi=native;nvapi,nvapi64,nvofapi64,winhttp=",
        ));
        let GameOverrides::Named(names) = &game else {
            panic!("the launch's own value must parse");
        };
        assert!(names.iter().any(|name| name == "winhttp"));
        assert!(check(&env(&[("WINEDLLOVERRIDES", "winhttp=n")]), &game).is_err());
        assert!(check(&env(&[("WINEDLLOVERRIDES", "nvofapi64=n")]), &game).is_err());
        assert_eq!(
            check(&env(&[("WINEDLLOVERRIDES", "mscoree=b")]), &game),
            Ok(())
        );
    }

    /// A game value this cannot read refuses every companion override, the harmless ones included,
    /// and still leaves a companion that asks for none alone.
    #[test]
    fn an_unreadable_game_value_refuses_every_companion_override() {
        let game = GameOverrides::of(Some("d3d11=native;dxgi"));
        assert_eq!(game, GameOverrides::Unreadable);
        assert!(check(&env(&[("WINEDLLOVERRIDES", "mscoree=b")]), &game).is_err());
        assert!(check(&env(&[("WINEDLLOVERRIDES", "")]), &game).is_err());
        assert_eq!(check(&env(&[("MONO_PATH", "C:\\libs")]), &game), Ok(()));
        assert_eq!(GameOverrides::of(None), GameOverrides::none());
    }

    /// Keys worth trying: anything at all, and near misses of the allowed ones (another case, a
    /// neighbouring character on either side), which arbitrary strings would almost never reach.
    fn any_key() -> impl Strategy<Value = String> {
        let allowed = proptest::sample::select(ALLOWED_KEYS.to_vec());
        prop_oneof![
            any::<String>(),
            allowed.clone().prop_map(str::to_owned),
            (
                allowed,
                proptest::collection::vec(any::<bool>(), 16),
                "\\PC{0,2}",
                "\\PC{0,2}"
            )
                .prop_map(|(key, lower, before, after)| {
                    let recased: String = key
                        .chars()
                        .zip(lower.iter().cycle())
                        .map(|(c, lower)| if *lower { c.to_ascii_lowercase() } else { c })
                        .collect();
                    format!("{before}{recased}{after}")
                }),
        ]
    }

    /// Values worth trying for an allowed key: anything at all, a well-formed value with one
    /// arbitrary character dropped into it, and lengths on both sides of the cap.
    fn any_value() -> impl Strategy<Value = String> {
        prop_oneof![
            any::<String>(),
            (any::<char>(), 0_usize..=9).prop_map(|(c, at)| {
                let mut value = "winhttp=n".to_owned();
                value.insert(at, c);
                value
            }),
            (MAX_VALUE_BYTES - 2..MAX_VALUE_BYTES + 3).prop_map(|len| "a".repeat(len)),
        ]
    }

    proptest! {
        /// A key is accepted exactly when it is one of the allowed keys, byte for byte. The value is
        /// one both keys take, so the key alone decides.
        #[test]
        fn a_key_is_accepted_only_when_it_is_exactly_an_allowed_one(key in any_key()) {
            let accepted = check(&env(&[(&key, "winhttp=n")]), &GameOverrides::none()).is_ok();
            prop_assert_eq!(accepted, ALLOWED_KEYS.contains(&key.as_str()));
        }

        /// Whatever value an allowed key is given, one that is accepted is short enough for an
        /// environment and carries no control character, a null byte included.
        #[test]
        fn an_accepted_value_is_bounded_and_carries_no_control_character(
            key in proptest::sample::select(ALLOWED_KEYS.to_vec()),
            value in any_value(),
        ) {
            if check(&env(&[(key, &value)]), &GameOverrides::none()).is_ok() {
                prop_assert!(value.len() <= MAX_VALUE_BYTES);
                prop_assert!(!value.chars().any(char::is_control));
            }
        }
    }
}
