//! Building the launch command for a runner (umu-run for Proton, or plain wine).

use std::path::{Path, PathBuf};

use tokio::process::Command;

use crate::catalog::RunnerKind;
use crate::error::{HostTool, RuntimeError};
use crate::plan::{LaunchPlan, Prefix};

/// A generic umu `GAMEID`: the Steam Linux Runtime environment with no per-title protonfix.
pub(crate) const DEFAULT_GAMEID: &str = "0";

/// Candidate relative paths to a runner's `wine` binary, most-specific first.
const WINE_CANDIDATES: &[&str] = &[
    "bin/wine64",
    "bin/wine",
    "files/bin/wine64",
    "files/bin/wine",
];
/// Candidate relative paths to a runner's `wineserver`.
const WINESERVER_CANDIDATES: &[&str] = &["bin/wineserver", "files/bin/wineserver"];

/// The runner's `wine` binary, or `None` if the layout has none where expected.
pub(crate) fn find_wine(runner_dir: &Path) -> Option<PathBuf> {
    find_binary(runner_dir, WINE_CANDIDATES)
}

/// Build the process command for `plan` (which must carry a prefix). `umu_run` is the resolved
/// umu-run path (managed or on `PATH`) for Proton runners.
pub(crate) fn build_command(
    plan: &LaunchPlan,
    umu_run: Option<&Path>,
) -> Result<Command, RuntimeError> {
    let prefix = plan.prefix_ref().ok_or(RuntimeError::InvalidLaunchPlan {
        reason: "launch plan has no prefix",
    })?;
    let runner = prefix.runner();

    // The runner invocation: the launcher binary, then the program, then the opaque args.
    let mut invocation: Vec<String> = Vec::new();
    match runner.kind() {
        RunnerKind::ProtonUmu => {
            let umu = umu_run.ok_or(RuntimeError::MissingHostTool {
                tool: HostTool::Umu,
            })?;
            invocation.push(umu.to_string_lossy().into_owned());
        }
        RunnerKind::Wine | RunnerKind::Custom => {
            let wine = find_binary(runner.dir(), WINE_CANDIDATES).ok_or(
                RuntimeError::MissingHostTool {
                    tool: HostTool::Wine,
                },
            )?;
            invocation.push(wine.to_string_lossy().into_owned());
        }
    }
    invocation.push(plan.program().to_owned());
    if !plan.args().is_empty() {
        invocation.push(plan.args().to_owned());
    }

    // Wrappers (gamescope/gamemode/...) wrap the whole invocation.
    let mut argv: Vec<String> = Vec::with_capacity(plan.wrapper_list().len() + invocation.len());
    argv.extend(plan.wrapper_list().iter().cloned());
    argv.extend(invocation);

    let (exe, rest) = argv.split_first().ok_or(RuntimeError::InvalidLaunchPlan {
        reason: "empty launch command",
    })?;
    let mut cmd = Command::new(exe);
    cmd.args(rest);
    apply_env(&mut cmd, plan, prefix, runner.kind());
    if let Some(working_dir) = plan.working_dir_ref() {
        cmd.current_dir(working_dir);
    }
    cmd.kill_on_drop(false);
    Ok(cmd)
}

/// Kill everything in a prefix (`wineserver -k`) — the separate, explicit broad stop.
pub(crate) async fn kill_prefix(
    prefix: &Prefix,
    umu_run: Option<PathBuf>,
) -> Result<(), RuntimeError> {
    let runner = prefix.runner();
    let mut cmd = match runner.kind() {
        RunnerKind::ProtonUmu => {
            let umu = umu_run.ok_or(RuntimeError::MissingHostTool {
                tool: HostTool::Umu,
            })?;
            let mut cmd = Command::new(umu);
            cmd.arg("wineserver").arg("-k");
            // Proton relocates the live prefix under /pfx.
            cmd.env("WINEPREFIX", prefix.path().join("pfx"));
            cmd.env("GAMEID", DEFAULT_GAMEID);
            cmd.env("PROTONPATH", runner.dir());
            cmd
        }
        RunnerKind::Wine | RunnerKind::Custom => {
            let wineserver = find_binary(runner.dir(), WINESERVER_CANDIDATES).ok_or(
                RuntimeError::MissingHostTool {
                    tool: HostTool::Wine,
                },
            )?;
            let mut cmd = Command::new(wineserver);
            cmd.arg("-k");
            cmd.env("WINEPREFIX", prefix.path());
            cmd
        }
    };
    // A non-zero status (nothing to kill) is not an error.
    cmd.status().await.map_err(|source| RuntimeError::Spawn {
        runner: runner.name().to_owned(),
        source,
    })?;
    Ok(())
}

/// Set the launch environment: prefix/runner variables first, user overrides merged last so they
/// always win. Sync (fsync/esync/ntsync) is left to wine/Proton defaults at this phase.
fn apply_env(cmd: &mut Command, plan: &LaunchPlan, prefix: &Prefix, kind: RunnerKind) {
    cmd.env("WINEPREFIX", prefix.path());
    if kind == RunnerKind::ProtonUmu {
        cmd.env("GAMEID", DEFAULT_GAMEID);
        cmd.env("PROTONPATH", prefix.runner().dir());
    }
    for (key, value) in plan.env() {
        cmd.env(key, value);
    }
}

/// The first existing file among `root/<candidate>`.
fn find_binary(root: &Path, candidates: &[&str]) -> Option<PathBuf> {
    candidates
        .iter()
        .map(|c| root.join(c))
        .find(|p| p.is_file())
}

/// Resolve `umu-run`: a managed install under `tools_dir` first, else on `PATH`.
pub(crate) fn resolve_umu(tools_dir: &Path) -> Option<PathBuf> {
    if let Ok(entries) = std::fs::read_dir(tools_dir) {
        for entry in entries.flatten() {
            if entry
                .file_name()
                .to_string_lossy()
                .starts_with("umu-launcher")
            {
                for candidate in ["umu-run", "bin/umu-run"] {
                    let path = entry.path().join(candidate);
                    if path.is_file() {
                        return Some(path);
                    }
                }
            }
        }
    }
    which("umu-run")
}

/// The first `name` found on `PATH`.
fn which(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use super::*;
    use crate::plan::{Prefix, RunnerHandle};

    #[test]
    fn build_command_sets_the_working_directory() {
        let tmp = tempfile::tempdir().unwrap();

        // A custom runner needs a resolvable `wine` binary for the command to build.
        let runner_dir = tmp.path().join("runner");
        std::fs::create_dir_all(runner_dir.join("bin")).unwrap();
        let wine = runner_dir.join("bin/wine");
        std::fs::write(&wine, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755)).unwrap();

        let working = tmp.path().join("game");
        std::fs::create_dir_all(&working).unwrap();

        let runner = RunnerHandle::new(runner_dir, RunnerKind::Custom, "test", "custom");
        let prefix = Prefix::new(tmp.path().join("prefix"), runner);
        let plan = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new())
            .prefix(&prefix)
            .working_dir(&working);

        let cmd = build_command(&plan, None).unwrap();
        assert_eq!(cmd.as_std().get_current_dir(), Some(working.as_path()));
    }

    #[test]
    fn build_command_leaves_the_working_directory_unset_by_default() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_dir = tmp.path().join("runner");
        std::fs::create_dir_all(runner_dir.join("bin")).unwrap();
        let wine = runner_dir.join("bin/wine");
        std::fs::write(&wine, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755)).unwrap();

        let runner = RunnerHandle::new(runner_dir, RunnerKind::Custom, "test", "custom");
        let prefix = Prefix::new(tmp.path().join("prefix"), runner);
        let plan = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new()).prefix(&prefix);

        let cmd = build_command(&plan, None).unwrap();
        assert_eq!(cmd.as_std().get_current_dir(), None);
    }
}
