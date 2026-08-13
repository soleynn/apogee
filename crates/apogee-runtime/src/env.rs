//! The environment matrix: the variables and wrappers a launch runs with.
//!
//! A profile's graphics and synchronization knobs are resolved against the host by
//! [`compute_environment`], which is pure and takes those capabilities as an argument
//! ([`HostCaps`]), so one fixed profile always yields the same [`Environment`] and a golden test
//! can pin it. It produces the graphics, sync and user half only: the structural prefix variables
//! (`WINEPREFIX`, `GAMEID`, `PROTONPATH`) are set by the spawner from the prepared prefix.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The Direct3D DLL stems DXVK provides.
///
/// Shared with the DXVK install and its health check, so the set overridden to native at launch and
/// the set verified on disk cannot drift apart.
pub(crate) const DXVK_DLL_STEMS: [&str; 4] = ["d3d9", "d3d10core", "d3d11", "dxgi"];

/// The DLL stems `dxvk-nvapi` provides.
///
/// Every `.dll` its archive carries across both architectures, measured on the pinned v0.9.2 build:
/// `x64/nvapi64.dll`, `x64/nvofapi64.dll` and `x32/nvapi.dll`.
// Wider than the set the health check requires on disk, and deliberately so: an override only
// decides what happens when something loads that name, so naming a stem a given build does not ship
// costs nothing, while *requiring* one would report a prefix as broken for a file its companion
// never had.
pub(crate) const NVAPI_DLL_STEMS: [&str; 3] = ["nvapi", "nvapi64", "nvofapi64"];

/// Which wine synchronization primitive the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncChoice {
    /// Take the best the host supports: ntsync, else fsync, else esync.
    #[default]
    Auto,
    /// Force ntsync, whatever the host reports.
    Ntsync,
    /// Force fsync, whatever the host reports.
    Fsync,
    /// Force esync, whatever the host reports.
    Esync,
    /// No accelerated synchronization, leaving wine's server-side path; for debugging.
    None,
}

/// The synchronization primitive a launch resolved to.
///
/// Status rather than a second toggle: it is the resolved [`SyncChoice`], and what a front end
/// tells the user their setup came out as. Not a guarantee about the process: a forced choice the
/// host cannot honour, and a raw `env` entry that overrides the variable directly, both leave the
/// launch running on something else while this still reports what was resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    /// ntsync, which a runner that supports it uses with no variable set.
    Ntsync,
    /// fsync, via `WINEFSYNC=1`.
    Fsync,
    /// esync, via `WINEESYNC=1` with `WINEFSYNC=0`.
    Esync,
    /// Neither, leaving wine's server-side synchronization.
    None,
}

/// The in-game overlay.
///
/// Mutually exclusive by construction: DXVK's HUD and MangoHud are never both enabled.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hud {
    /// No overlay.
    #[default]
    None,
    /// DXVK's built-in HUD; the string is the `DXVK_HUD` spec, such as `"fps,frametimes"`.
    Dxvk(String),
    /// MangoHud, enabled with `MANGOHUD=1`.
    Mango,
}

/// Which GPU a hybrid-graphics host renders on.
///
/// The per-vendor variable sets are the ones observed on real hybrid laptops, so keeping up with a
/// driver is a change to one arm rather than to the launch path.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GpuSelect {
    /// The system default GPU; set nothing.
    #[default]
    Default,
    /// PRIME render offload on the proprietary NVIDIA driver.
    NvidiaPrime,
    /// Mesa PRIME offload to a discrete AMD or Intel GPU (`DRI_PRIME=1`).
    MesaPrime,
    /// A specific Vulkan device for `MESA_VK_DEVICE_SELECT`, such as `"10de:2482"`.
    VulkanDevice(String),
}

/// gamescope options, composed as the outermost wrapper around the launch.
///
/// Every field defaults, so a hand-written partial object still loads rather than making the whole
/// profile unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Gamescope {
    /// Output width, gamescope's `-W`; `None` leaves its own default.
    pub width: Option<u32>,
    /// Output height, gamescope's `-H`; `None` leaves its own default.
    pub height: Option<u32>,
    /// Refresh rate in Hz, gamescope's `-r`; `None` leaves its own default.
    pub refresh: Option<u32>,
    /// Run fullscreen (`-f`).
    pub fullscreen: bool,
    /// Enable HDR output (`--hdr-enabled`).
    pub hdr: bool,
    /// Extra raw gamescope arguments, appended before the `--` separator.
    pub extra: Vec<String>,
}

/// What a launch says about `dxvk-nvapi`'s DLLs.
///
/// Three states rather than a flag, because saying nothing is not the same as saying no. The
/// companion's DLLs have no wine builtin behind them, so when nothing names them wine loads
/// whichever copy is in `system32` (measured on wine 10.0), which means an install that ran once
/// keeps loading forever unless a launch says otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NvapiOverride {
    /// Name the DLLs to nobody: whatever the prefix and the runner resolve on their own stands.
    ///
    /// The answer wherever this launcher did not install the companion, in either direction:
    /// overriding to native would name a file that may not exist, and disabling would take away a
    /// runner's own build nobody here provided.
    #[default]
    Unset,
    /// Override them to the native `dxvk-nvapi` build the prefix has.
    Native,
    /// Refuse to load them, which is the whole of turning an installed companion off.
    ///
    /// The DLLs are never deleted, so there is no uninstall path: they may be the runner's own, and
    /// an uninstall that guessed would remove files this launcher did not write.
    Disabled,
}

/// The DXVK runtime environment, for a prefix that has DXVK installed.
///
/// Distinct from the DXVK install (the DLLs on disk): this is only the environment that activates
/// and tunes them.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DxvkEnv {
    /// Where DXVK persists its shader state cache; `None` leaves the build's own default.
    pub state_cache: Option<PathBuf>,
    /// What this launch says about the `dxvk-nvapi` DLLs.
    pub nvapi: NvapiOverride,
}

/// The environment knobs a profile chooses, before a host resolves them.
///
/// [`compute_environment`] turns one of these into an [`Environment`]. The `env` map is merged
/// last and wins over every value the other fields compute, so a variable the user set by hand is
/// never overwritten by one of these knobs; `wrappers` composes innermost for the same reason.
///
/// # Examples
///
/// ```
/// use apogee_runtime::{EnvConfig, HostCaps, SyncChoice, compute_environment};
///
/// let mut config = EnvConfig {
///     sync: SyncChoice::Fsync,
///     ..Default::default()
/// };
/// config.env.insert("WINEFSYNC".to_owned(), "0".to_owned());
///
/// let env = compute_environment(&config, &HostCaps { ntsync: false, fsync: true });
/// assert_eq!(env.vars["WINEFSYNC"], "0");
/// ```
#[derive(Debug, Clone, Default)]
pub struct EnvConfig {
    /// Which synchronization primitive to use; [`SyncChoice::Auto`] by default.
    pub sync: SyncChoice,
    /// The in-game overlay; [`Hud::None`] by default.
    pub hud: Hud,
    /// Which GPU to render on; [`GpuSelect::Default`] by default.
    pub gpu: GpuSelect,
    /// The DXVK environment, `Some` when the prefix has DXVK installed.
    pub dxvk: Option<DxvkEnv>,
    /// gamescope options, `Some` to run the launch inside it.
    pub gamescope: Option<Gamescope>,
    /// Wrap the launch in `gamemoderun`.
    pub gamemode: bool,
    /// Free-form wrapper commands, composed innermost (closest to the runner).
    pub wrappers: Vec<String>,
    /// Free-form variables, merged last so they win over every computed value.
    pub env: BTreeMap<String, String>,
}

/// What the host supports, passed in so the matrix stays pure and testable.
///
/// `ntsync` has to account for the selected runner as well as the kernel, which is what
/// [`for_runner`](Self::for_runner) applies.
// Deliberately exhaustive, unlike the enums around it: the whole point of the type is that a caller
// can build one, so a test can compute an environment for a host it is not running on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCaps {
    /// ntsync is usable on this host: `/dev/ntsync` present and kernel 6.14 or newer. Whether the
    /// selected build uses it is folded in by [`HostCaps::for_runner`].
    pub ntsync: bool,
    /// fsync is usable: kernel 5.16 or newer, so `futex_waitv` exists.
    pub fsync: bool,
}

impl HostCaps {
    /// Detect the host's capabilities from `/dev` and the kernel version.
    ///
    /// The ntsync half is a hint taken from the device node, never a load of the module: a host
    /// that could support ntsync but has not loaded it reads as not supporting it. `ntsync` here
    /// reflects the host alone, so pass the selected runner through
    /// [`for_runner`](Self::for_runner) before computing an environment.
    #[must_use]
    pub fn detect() -> Self {
        let kernel = read_kernel_version();
        Self {
            ntsync: std::path::Path::new("/dev/ntsync").exists()
                && kernel.is_some_and(|k| k >= (6, 14)),
            fsync: kernel.is_some_and(|k| k >= (5, 16)),
        }
    }

    /// The same host seen through a [`Runner`](crate::Runner): ntsync survives only if that build
    /// uses it.
    ///
    /// Without this the two halves of the requirement drift apart, and the failure is silent in the
    /// worst direction: ntsync is selected by setting no variable, so a build that ignores it gets
    /// no esync or fsync toggle either and runs on server-side synchronization while every report
    /// says ntsync.
    #[must_use]
    pub fn for_runner(self, runner: &crate::catalog::Runner) -> Self {
        Self {
            ntsync: self.ntsync && runner.uses_ntsync(),
            ..self
        }
    }
}

/// A resolved launch environment: what to set, what to wrap it in, and what sync it came out as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// The computed variables, with the user's own overrides already merged in.
    pub vars: BTreeMap<String, String>,
    /// Wrapper commands, outermost first: gamescope, then gamemode, then the free-form ones.
    pub wrappers: Vec<String>,
    /// The synchronization primitive this launch resolves to.
    pub sync: SyncStatus,
}

/// Resolve `config` against `host` into a launch [`Environment`].
///
/// Pure: the same inputs always produce the same output. The `config.env` overrides are applied
/// last and win over every computed value.
///
/// # Examples
///
/// ```
/// use apogee_runtime::{EnvConfig, HostCaps, SyncChoice, SyncStatus, compute_environment};
///
/// let config = EnvConfig {
///     sync: SyncChoice::Esync,
///     ..Default::default()
/// };
/// let env = compute_environment(&config, &HostCaps { ntsync: true, fsync: true });
///
/// assert_eq!(env.sync, SyncStatus::Esync);
/// assert_eq!(env.vars["WINEESYNC"], "1");
/// assert_eq!(env.vars["WINEFSYNC"], "0");
/// ```
#[must_use]
pub fn compute_environment(config: &EnvConfig, host: &HostCaps) -> Environment {
    let mut vars = BTreeMap::new();

    let sync = resolve_sync(config.sync, host);
    apply_sync(&mut vars, sync);
    apply_gpu(&mut vars, &config.gpu);
    apply_hud(&mut vars, &config.hud);
    if let Some(dxvk) = &config.dxvk {
        apply_dxvk(&mut vars, dxvk);
    }

    // User overrides win: merged last, overwriting any computed value with the same key.
    for (key, value) in &config.env {
        vars.insert(key.clone(), value.clone());
    }

    Environment {
        vars,
        wrappers: build_wrappers(config),
        sync,
    }
}

/// Resolve the choice against host support. An explicit choice is honored even where the host
/// cannot back it, which is what makes it usable as a debugging override.
fn resolve_sync(choice: SyncChoice, host: &HostCaps) -> SyncStatus {
    match choice {
        SyncChoice::Auto => {
            if host.ntsync {
                SyncStatus::Ntsync
            } else if host.fsync {
                SyncStatus::Fsync
            } else {
                SyncStatus::Esync
            }
        }
        SyncChoice::Ntsync => SyncStatus::Ntsync,
        SyncChoice::Fsync => SyncStatus::Fsync,
        SyncChoice::Esync => SyncStatus::Esync,
        SyncChoice::None => SyncStatus::None,
    }
}

/// Set the synchronization variables. ntsync needs none (a runner that supports it uses it on its
/// own); esync forces fsync off so it cannot shadow it.
fn apply_sync(vars: &mut BTreeMap<String, String>, sync: SyncStatus) {
    match sync {
        SyncStatus::Ntsync => {}
        SyncStatus::Fsync => {
            vars.insert("WINEFSYNC".into(), "1".into());
        }
        SyncStatus::Esync => {
            vars.insert("WINEFSYNC".into(), "0".into());
            vars.insert("WINEESYNC".into(), "1".into());
        }
        SyncStatus::None => {
            vars.insert("WINEFSYNC".into(), "0".into());
            vars.insert("WINEESYNC".into(), "0".into());
        }
    }
}

fn apply_gpu(vars: &mut BTreeMap<String, String>, gpu: &GpuSelect) {
    match gpu {
        GpuSelect::Default => {}
        GpuSelect::NvidiaPrime => {
            vars.insert("__NV_PRIME_RENDER_OFFLOAD".into(), "1".into());
            vars.insert("__GLX_VENDOR_LIBRARY_NAME".into(), "nvidia".into());
            vars.insert("__VK_LAYER_NV_optimus".into(), "NVIDIA_only".into());
        }
        GpuSelect::MesaPrime => {
            vars.insert("DRI_PRIME".into(), "1".into());
        }
        GpuSelect::VulkanDevice(selector) => {
            vars.insert("MESA_VK_DEVICE_SELECT".into(), selector.clone());
        }
    }
}

fn apply_hud(vars: &mut BTreeMap<String, String>, hud: &Hud) {
    match hud {
        Hud::None => {}
        Hud::Dxvk(spec) => {
            vars.insert("DXVK_HUD".into(), spec.clone());
        }
        Hud::Mango => {
            vars.insert("MANGOHUD".into(), "1".into());
        }
    }
}

/// Set the DLL overrides DXVK needs, and the shader-cache path when one was chosen.
fn apply_dxvk(vars: &mut BTreeMap<String, String>, dxvk: &DxvkEnv) {
    // Override the Direct3D DLLs (and nvapi, when this launch activates it) to the native DXVK
    // builds. Turning the companion off adds a second group instead: an empty right-hand side is
    // wine's "load nothing for this name", which is what stops DLLs an earlier install placed from
    // being loaded by a launch that no longer wants them.
    let mut native = DXVK_DLL_STEMS.to_vec();
    let mut disabled = Vec::new();
    match dxvk.nvapi {
        NvapiOverride::Unset => {}
        NvapiOverride::Native => native.extend(NVAPI_DLL_STEMS),
        NvapiOverride::Disabled => disabled.extend(NVAPI_DLL_STEMS),
    }
    native.sort_unstable();
    disabled.sort_unstable();
    let mut overrides = format!("{}=native", native.join(","));
    if !disabled.is_empty() {
        overrides.push_str(&format!(";{}=", disabled.join(",")));
    }
    vars.insert("WINEDLLOVERRIDES".into(), overrides);
    if let Some(cache) = &dxvk.state_cache {
        // Both spellings. The 2.x builds read the first and the 3.x builds renamed it to the second,
        // and which one a prefix has is a catalog row rather than something decided here. A build
        // that does not know a name simply does not read it, so naming both costs nothing and
        // getting it wrong costs the cache silently landing outside the prefix it belongs to.
        let path = cache.to_string_lossy().into_owned();
        vars.insert("DXVK_STATE_CACHE_PATH".into(), path.clone());
        vars.insert("DXVK_SHADER_CACHE_PATH".into(), path);
    }
}

/// Compose the wrapper token list, outermost first. gamescope owns the window so it wraps
/// everything, its arguments ending at a `--` separator; gamemode is next; the free-form wrappers
/// sit innermost, directly around the runner.
fn build_wrappers(config: &EnvConfig) -> Vec<String> {
    let mut wrappers = Vec::new();
    if let Some(gs) = &config.gamescope {
        wrappers.push("gamescope".into());
        if let Some(width) = gs.width {
            wrappers.push("-W".into());
            wrappers.push(width.to_string());
        }
        if let Some(height) = gs.height {
            wrappers.push("-H".into());
            wrappers.push(height.to_string());
        }
        if let Some(refresh) = gs.refresh {
            wrappers.push("-r".into());
            wrappers.push(refresh.to_string());
        }
        if gs.fullscreen {
            wrappers.push("-f".into());
        }
        if gs.hdr {
            wrappers.push("--hdr-enabled".into());
        }
        wrappers.extend(gs.extra.iter().cloned());
        wrappers.push("--".into());
    }
    if config.gamemode {
        wrappers.push("gamemoderun".into());
    }
    wrappers.extend(config.wrappers.iter().cloned());
    wrappers
}

/// Parse the leading `major.minor` of a kernel release string such as `"6.14.0-27-generic"`.
fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(['.', '-', '+']);
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    Some((major, minor))
}

fn read_kernel_version() -> Option<(u32, u32)> {
    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease").ok()?;
    parse_kernel_version(release.trim())
}

#[cfg(test)]
mod tests {
    use apogee_fetch::DigestPin;

    use super::*;

    fn caps(ntsync: bool, fsync: bool) -> HostCaps {
        HostCaps { ntsync, fsync }
    }

    /// A catalog row with only the field the sync fold reads set.
    fn runner_with_ntsync(ntsync: Option<bool>) -> crate::catalog::Runner {
        crate::catalog::Runner {
            name: "test".to_owned(),
            version: "1".to_owned(),
            kind: crate::catalog::RunnerKind::Wine,
            url: url::Url::parse("https://example.invalid/r.tar.xz").unwrap(),
            pin: DigestPin::Blake3([0u8; 32]),
            archive: crate::catalog::ArchiveLayout {
                format: crate::catalog::ArchiveFormat::TarXz,
                strip_prefix: None,
            },
            ntsync,
        }
    }

    /// ntsync needs the kernel *and* the build. Selecting it emits no variable, so a build that does
    /// not use it would otherwise launch with no accelerated synchronization at all while reporting
    /// ntsync: the one failure here that looks like success.
    #[test]
    fn a_runner_that_does_not_use_ntsync_falls_back_rather_than_losing_sync() {
        let host = caps(true, true);
        let without = host.for_runner(&runner_with_ntsync(Some(false)));
        assert!(!without.ntsync, "the build decides, not the kernel alone");
        assert!(without.fsync, "the fold touches nothing else");

        let out = compute_environment(&EnvConfig::default(), &without);
        assert_eq!(out.sync, SyncStatus::Fsync);
        assert_eq!(out.vars.get("WINEFSYNC").map(String::as_str), Some("1"));
    }

    /// A row that says nothing is read as no. The cost of being wrong that way is fsync instead of
    /// ntsync; the cost of the other reading is a prefix with neither.
    #[test]
    fn an_unstated_ntsync_capability_is_read_as_no() {
        let host = caps(true, true);
        assert!(!host.for_runner(&runner_with_ntsync(None)).ntsync);
        assert!(host.for_runner(&runner_with_ntsync(Some(true))).ntsync);
    }

    /// The fold cannot manufacture support the kernel does not have.
    #[test]
    fn a_declaring_runner_still_needs_the_kernel() {
        let host = caps(false, true);
        assert!(!host.for_runner(&runner_with_ntsync(Some(true))).ntsync);
    }

    /// Real release strings yield their major and minor. Anything else yields nothing rather than a
    /// wrong version.
    #[test]
    fn kernel_version_parses_common_release_strings() {
        assert_eq!(parse_kernel_version("6.14.0-27-generic"), Some((6, 14)));
        assert_eq!(parse_kernel_version("5.15.0"), Some((5, 15)));
        assert_eq!(parse_kernel_version("6.1"), Some((6, 1)));
        assert_eq!(parse_kernel_version("6.12.9-arch1-1"), Some((6, 12)));
        assert_eq!(parse_kernel_version(""), None);
        assert_eq!(parse_kernel_version("garbage"), None);
    }

    /// The preference order `Auto` resolves through, at each level of host support.
    #[test]
    fn auto_sync_prefers_ntsync_then_fsync_then_esync() {
        assert_eq!(
            resolve_sync(SyncChoice::Auto, &caps(true, true)),
            SyncStatus::Ntsync
        );
        assert_eq!(
            resolve_sync(SyncChoice::Auto, &caps(false, true)),
            SyncStatus::Fsync
        );
        assert_eq!(
            resolve_sync(SyncChoice::Auto, &caps(false, false)),
            SyncStatus::Esync
        );
    }

    /// Only `Auto` consults the host. A named primitive passes through either way, which is what
    /// lets a user reproduce a bug on a host that would not have chosen it.
    #[test]
    fn an_explicit_sync_choice_is_honored_regardless_of_host() {
        assert_eq!(
            resolve_sync(SyncChoice::Ntsync, &caps(false, false)),
            SyncStatus::Ntsync
        );
        assert_eq!(
            resolve_sync(SyncChoice::None, &caps(true, true)),
            SyncStatus::None
        );
    }

    /// The precedence rule: a variable the user set by hand survives the knob that computes it.
    #[test]
    fn a_user_override_wins_over_a_computed_value() {
        let mut env = BTreeMap::new();
        env.insert("WINEFSYNC".to_owned(), "0".to_owned()); // user forces fsync off
        env.insert("EXTRA".to_owned(), "yes".to_owned());
        let config = EnvConfig {
            sync: SyncChoice::Fsync, // would compute WINEFSYNC=1
            env,
            ..Default::default()
        };
        let out = compute_environment(&config, &caps(true, true));
        assert_eq!(out.vars.get("WINEFSYNC").map(String::as_str), Some("0"));
        assert_eq!(out.vars.get("EXTRA").map(String::as_str), Some("yes"));
        // The status still reflects the requested primitive; the override only changes the env.
        assert_eq!(out.sync, SyncStatus::Fsync);
    }

    /// One overlay at a time: neither arm leaves the other's variable behind.
    #[test]
    fn hud_is_mutually_exclusive_by_construction() {
        let dxvk = compute_environment(
            &EnvConfig {
                hud: Hud::Dxvk("fps".into()),
                ..Default::default()
            },
            &caps(false, true),
        );
        assert_eq!(dxvk.vars.get("DXVK_HUD").map(String::as_str), Some("fps"));
        assert!(!dxvk.vars.contains_key("MANGOHUD"));

        let mango = compute_environment(
            &EnvConfig {
                hud: Hud::Mango,
                ..Default::default()
            },
            &caps(false, true),
        );
        assert_eq!(mango.vars.get("MANGOHUD").map(String::as_str), Some("1"));
        assert!(!mango.vars.contains_key("DXVK_HUD"));
    }

    /// The override string each of the three nvapi states produces.
    ///
    /// The disabled arm is the one that carries weight. Measured on wine 10.0 with a companion's DLL
    /// in `system32`: with no override naming it, `LoadLibraryA("nvapi64.dll")` loads it from
    /// `C:\windows\system32`; with the empty override it fails with 126. Nothing else stops it,
    /// since wine ships no builtin `nvapi64` for the loader to prefer, so this string is the whole
    /// of what turning the companion off does at launch.
    #[test]
    fn the_nvapi_dlls_are_named_by_what_the_launch_decided() {
        let cases = [
            (NvapiOverride::Unset, "d3d10core,d3d11,d3d9,dxgi=native"),
            (
                NvapiOverride::Native,
                "d3d10core,d3d11,d3d9,dxgi,nvapi,nvapi64,nvofapi64=native",
            ),
            (
                NvapiOverride::Disabled,
                "d3d10core,d3d11,d3d9,dxgi=native;nvapi,nvapi64,nvofapi64=",
            ),
        ];
        for (nvapi, expected) in cases {
            let out = compute_environment(
                &EnvConfig {
                    dxvk: Some(DxvkEnv {
                        nvapi,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                &caps(false, true),
            );
            assert_eq!(
                out.vars.get("WINEDLLOVERRIDES").map(String::as_str),
                Some(expected),
                "{nvapi:?}"
            );
        }
    }

    /// The wrapper order, including where the `--` separator ends gamescope's own arguments.
    #[test]
    fn gamescope_and_gamemode_compose_outermost_first() {
        let config = EnvConfig {
            gamescope: Some(Gamescope {
                width: Some(2560),
                height: Some(1440),
                refresh: Some(120),
                fullscreen: true,
                hdr: true,
                extra: vec!["--expose-wayland".into()],
            }),
            gamemode: true,
            wrappers: vec!["strace".into()],
            ..Default::default()
        };
        let out = compute_environment(&config, &caps(false, true));
        assert_eq!(
            out.wrappers,
            vec![
                "gamescope",
                "-W",
                "2560",
                "-H",
                "1440",
                "-r",
                "120",
                "-f",
                "--hdr-enabled",
                "--expose-wayland",
                "--",
                "gamemoderun",
                "strace",
            ]
        );
    }

    /// The shader-cache variable was renamed between DXVK's major versions. A catalog can pin
    /// either, so naming only one is a cache that silently goes somewhere else.
    #[test]
    fn the_shader_cache_is_named_the_way_both_generations_read_it() {
        let out = compute_environment(
            &EnvConfig {
                dxvk: Some(DxvkEnv {
                    state_cache: Some(PathBuf::from("/prefix/dxvk_cache")),
                    nvapi: NvapiOverride::Unset,
                }),
                ..Default::default()
            },
            &caps(false, true),
        );
        assert_eq!(
            out.vars.get("DXVK_STATE_CACHE_PATH").map(String::as_str),
            Some("/prefix/dxvk_cache")
        );
        assert_eq!(
            out.vars.get("DXVK_SHADER_CACHE_PATH").map(String::as_str),
            Some("/prefix/dxvk_cache")
        );
    }

    /// The wrapper options are the one knob with no command to set them. A hand-written partial
    /// object is the realistic way one arrives, and every field defaulting is what keeps a single
    /// bad profile from failing the listing of every profile.
    #[test]
    fn a_partly_written_wrapper_configuration_still_loads() {
        let partial: Gamescope =
            serde_json::from_str(r#"{"width": 1280, "height": 800}"#).expect("partial loads");
        assert_eq!(partial.width, Some(1280));
        assert!(!partial.fullscreen);
        assert!(partial.extra.is_empty());

        let empty: Gamescope = serde_json::from_str("{}").expect("an empty object loads");
        assert_eq!(empty, Gamescope::default());
    }

    /// A rich, fixed profile pinned as a golden so the full matrix cannot change silently.
    #[test]
    fn full_matrix_is_byte_exact_for_a_fixed_profile() {
        let mut env = BTreeMap::new();
        env.insert("MANGOHUD_CONFIG".to_owned(), "cpu_temp".to_owned());
        let config = EnvConfig {
            sync: SyncChoice::Auto,
            hud: Hud::Mango,
            gpu: GpuSelect::NvidiaPrime,
            dxvk: Some(DxvkEnv {
                state_cache: Some(PathBuf::from("/prefix/dxvk_cache")),
                nvapi: NvapiOverride::Native,
            }),
            gamescope: Some(Gamescope {
                width: Some(1920),
                height: Some(1080),
                fullscreen: true,
                ..Default::default()
            }),
            gamemode: true,
            wrappers: vec![],
            env,
        };
        let out = compute_environment(&config, &caps(true, true));
        insta::assert_debug_snapshot!(out);
    }
}
