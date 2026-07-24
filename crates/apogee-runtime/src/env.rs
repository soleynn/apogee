//! The environment matrix: resolving a profile's graphics and sync knobs into the concrete
//! environment variables and wrapper commands a launch runs with.
//!
//! The computation is pure and host-injected ([`HostCaps`]), so a fixed profile yields a byte-exact
//! result a golden test can pin. The one rule that overrides everything else: the user's free-form
//! overrides are merged **last**, so they always win over Apogee's computed values (Apogee.md §5.5).
//!
//! The matrix produces the *graphics/sync/user* environment. The structural prefix variables
//! (`WINEPREFIX`, `GAMEID`, `PROTONPATH`) are set by the spawner from the prepared prefix, not here.

use std::collections::BTreeMap;
use std::path::PathBuf;

/// The Direct3D DLL stems DXVK provides. The single source of truth shared with the DXVK install and
/// health check ([`crate::dxvk`]), so the set overridden to native and the set verified on disk cannot
/// drift apart.
pub(crate) const DXVK_DLL_STEMS: [&str; 4] = ["d3d9", "d3d10core", "d3d11", "dxgi"];

/// Which wine synchronization primitive the user wants. `Auto` resolves to the best the host supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SyncChoice {
    /// Pick the best available: ntsync, else fsync, else esync.
    #[default]
    Auto,
    Ntsync,
    Fsync,
    Esync,
    /// No accelerated sync (server-side synchronization); for debugging.
    None,
}

/// The synchronization primitive a launch will actually use, surfaced to the user as status (not a
/// folklore toggle): "your setup will use ntsync".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStatus {
    Ntsync,
    Fsync,
    Esync,
    None,
}

/// The in-game overlay. Mutually exclusive by construction: never DXVK's HUD and MangoHud at once.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Hud {
    #[default]
    None,
    /// DXVK's built-in HUD; the string is the `DXVK_HUD` spec (e.g. `"fps,frametimes"`).
    Dxvk(String),
    /// MangoHud, enabled with `MANGOHUD=1`.
    Mango,
}

/// Hybrid-GPU selection. The per-vendor variable sets are the ones observed on real hybrid laptops
/// (runtime §7); a bump is a change to one arm, not the launch path.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum GpuSelect {
    /// The system default GPU; set nothing.
    #[default]
    Default,
    /// NVIDIA PRIME render offload (the proprietary driver).
    NvidiaPrime,
    /// Mesa PRIME offload to a discrete AMD/Intel GPU (`DRI_PRIME=1`).
    MesaPrime,
    /// A specific Vulkan device via `MESA_VK_DEVICE_SELECT` (e.g. `"10de:2482"`).
    VulkanDevice(String),
}

/// gamescope embedding options, composed as the outermost wrapper around the launch.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Gamescope {
    pub width: Option<u32>,
    pub height: Option<u32>,
    pub refresh: Option<u32>,
    pub fullscreen: bool,
    pub hdr: bool,
    /// Extra raw gamescope arguments, appended before the `--` separator.
    pub extra: Vec<String>,
}

/// The DXVK runtime environment, present when a prefix has DXVK installed. Distinct from the DXVK
/// *install* (the DLLs on disk): this is only the env that activates and tunes it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DxvkEnv {
    /// Where DXVK persists its shader state cache (`DXVK_STATE_CACHE_PATH`); `None` leaves the default.
    pub state_cache: Option<PathBuf>,
    /// Whether `dxvk-nvapi`'s DLLs are installed and should be overridden to native too.
    pub nvapi: bool,
}

/// The user/profile-chosen environment knobs Apogee resolves into an [`Environment`].
#[derive(Debug, Clone, Default)]
pub struct EnvConfig {
    pub sync: SyncChoice,
    pub hud: Hud,
    pub gpu: GpuSelect,
    /// DXVK env, `Some` when the prefix has DXVK installed.
    pub dxvk: Option<DxvkEnv>,
    pub gamescope: Option<Gamescope>,
    pub gamemode: bool,
    /// Free-form wrapper commands, composed innermost (closest to the runner).
    pub wrappers: Vec<String>,
    /// Free-form per-profile environment overrides, merged last so they always win.
    pub env: BTreeMap<String, String>,
}

/// What the host supports, injected so the matrix stays pure and testable. `ntsync` must already
/// reflect the selected runner's support (the caller ANDs the runner in), since ntsync needs both a
/// new-enough kernel and a runner build that uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCaps {
    /// ntsync is usable: `/dev/ntsync` present, kernel new enough, and the runner supports it.
    pub ntsync: bool,
    /// fsync is usable (kernel has `futex_waitv`, 5.16+).
    pub fsync: bool,
}

impl HostCaps {
    /// Detect the host's capabilities from `/dev` and the kernel version. `ntsync` here reflects only
    /// the host; a caller launching an ntsync-incapable runner should clear it.
    #[must_use]
    pub fn detect() -> Self {
        let kernel = read_kernel_version();
        Self {
            ntsync: std::path::Path::new("/dev/ntsync").exists()
                && kernel.is_some_and(|k| k >= (6, 14)),
            fsync: kernel.is_some_and(|k| k >= (5, 16)),
        }
    }
}

/// The resolved launch environment: the variables to set, the wrappers to compose, and the sync
/// primitive that will be used (for display).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Environment {
    /// The computed variables, user overrides already merged in (and winning).
    pub vars: BTreeMap<String, String>,
    /// Wrapper commands, outermost first: gamescope, then gamemode, then the user's free-form ones.
    pub wrappers: Vec<String>,
    /// The synchronization primitive this launch resolves to.
    pub sync: SyncStatus,
}

/// Resolve `config` against `host` into the concrete launch [`Environment`]. Pure: the same inputs
/// always produce the same output. User overrides in `config.env` are applied last and win over every
/// computed value.
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

/// Resolve the sync choice against host support. `Auto` prefers ntsync, then fsync, then esync; an
/// explicit choice is honored as status even where the host cannot back it (a debugging override).
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

/// Set the sync environment. ntsync needs no variable (a supporting runner uses it automatically);
/// fsync and esync are explicit toggles, and esync forces fsync off so it does not shadow it.
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

fn apply_dxvk(vars: &mut BTreeMap<String, String>, dxvk: &DxvkEnv) {
    // Override the Direct3D DLLs (and nvapi, when installed) to the native DXVK builds.
    let mut dlls = DXVK_DLL_STEMS.to_vec();
    if dxvk.nvapi {
        dlls.push("nvapi");
        dlls.push("nvapi64");
    }
    dlls.sort_unstable();
    vars.insert(
        "WINEDLLOVERRIDES".into(),
        format!("{}=native", dlls.join(",")),
    );
    if let Some(cache) = &dxvk.state_cache {
        vars.insert(
            "DXVK_STATE_CACHE_PATH".into(),
            cache.to_string_lossy().into_owned(),
        );
    }
}

/// Compose the wrapper token list, outermost first. gamescope owns the window so it wraps everything
/// (its arguments end at a `--` separator); gamemode is next; the user's free-form wrappers sit
/// innermost, directly around the runner.
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

/// Parse a `major.minor` pair from a kernel version string (`/proc/sys/kernel/osrelease`, e.g.
/// `"6.14.0-27-generic"`).
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
    use super::*;

    fn caps(ntsync: bool, fsync: bool) -> HostCaps {
        HostCaps { ntsync, fsync }
    }

    #[test]
    fn kernel_version_parses_common_release_strings() {
        assert_eq!(parse_kernel_version("6.14.0-27-generic"), Some((6, 14)));
        assert_eq!(parse_kernel_version("5.15.0"), Some((5, 15)));
        assert_eq!(parse_kernel_version("6.1"), Some((6, 1)));
        assert_eq!(parse_kernel_version("6.12.9-arch1-1"), Some((6, 12)));
        assert_eq!(parse_kernel_version(""), None);
        assert_eq!(parse_kernel_version("garbage"), None);
    }

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

    #[test]
    fn dxvk_overrides_include_nvapi_only_when_enabled() {
        let plain = compute_environment(
            &EnvConfig {
                dxvk: Some(DxvkEnv::default()),
                ..Default::default()
            },
            &caps(false, true),
        );
        assert_eq!(
            plain.vars.get("WINEDLLOVERRIDES").map(String::as_str),
            Some("d3d10core,d3d11,d3d9,dxgi=native")
        );
        let with_nvapi = compute_environment(
            &EnvConfig {
                dxvk: Some(DxvkEnv {
                    nvapi: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
            &caps(false, true),
        );
        assert_eq!(
            with_nvapi.vars.get("WINEDLLOVERRIDES").map(String::as_str),
            Some("d3d10core,d3d11,d3d9,dxgi,nvapi,nvapi64=native")
        );
    }

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
                nvapi: true,
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
