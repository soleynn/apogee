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
const RESERVED_LIBRARIES: [&str; 13] = [
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

/// Check every variable in `env`, refusing the first that breaks a rule.
///
/// `game_overrides` are the libraries the game's own launch environment overrides, beyond the fixed
/// set, so an addition naming one is refused as well.
pub(crate) fn check(
    env: &BTreeMap<String, String>,
    game_overrides: &[String],
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
            for library in override_names(value).map_err(refuse)? {
                if RESERVED_LIBRARIES.contains(&library.as_str())
                    || game_overrides.contains(&library)
                {
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
/// `,`-separated, the mode made only of `n`, `b` and `,` (or empty, which disables the library).
pub(crate) fn override_names(value: &str) -> Result<Vec<String>, &'static str> {
    let mut names = Vec::new();
    for entry in value.split(';') {
        if entry.is_empty() {
            continue;
        }
        let Some((libraries, mode)) = entry.split_once('=') else {
            return Err("an override entry names no load order");
        };
        if !mode.chars().all(|c| matches!(c, 'n' | 'b' | ',')) || mode.len() > 3 {
            return Err("an override entry's load order is not one wine reads");
        }
        for library in libraries.split(',') {
            names.push(normalize(library)?);
        }
    }
    Ok(names)
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

#[cfg(test)]
mod tests {
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
            let refused = check(&env(&[(key, "x")]), &[]).expect_err(key);
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
                check(&env(&[("WINEDLLOVERRIDES", value)]), &[]).is_err(),
                "{value} must be refused"
            );
        }
        // The launch's own extra overrides join the fixed set.
        assert!(
            check(
                &env(&[("WINEDLLOVERRIDES", "winhttp=n")]),
                &["winhttp".to_owned()]
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
            "=n",
            "win http=n",
            "winhttp=n\nd3d11=n",
        ] {
            assert!(
                check(&env(&[("WINEDLLOVERRIDES", value)]), &[]).is_err(),
                "{value:?} must be refused"
            );
        }
    }

    /// The allowed shapes pass.
    #[test]
    fn an_allowed_addition_passes() {
        let ok = env(&[
            ("MONO_PATH", "C:\\Apogee\\act\\libs"),
            ("WINEDLLOVERRIDES", "mscoree=b;winhttp=n,b"),
        ]);
        assert_eq!(check(&ok, &[]), Ok(()));
        assert!(check(&env(&[("MONO_PATH", "")]), &[]).is_err());
        assert!(check(&env(&[("MONO_PATH", &"a".repeat(5000))]), &[]).is_err());
    }
}
