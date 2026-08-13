//! Building the launch command for a runner (umu-run for Proton, or plain wine).

use std::path::{Path, PathBuf};

use tokio::process::Command;

use crate::catalog::RunnerKind;
use crate::error::{HostTool, RuntimeError};
use crate::flatpak::{Confinement, check_sandbox_tool, on_path};
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

/// The binary that runs a program inside `prefix`: `umu-run` for a Proton runner, the runner's own
/// `wine` otherwise. `umu_run` is the resolved umu-run path (managed or on `PATH`).
pub(crate) fn prefix_launcher(
    prefix: &Prefix,
    umu_run: Option<&Path>,
) -> Result<PathBuf, RuntimeError> {
    let runner = prefix.runner();
    match runner.kind() {
        RunnerKind::ProtonUmu => {
            umu_run
                .map(Path::to_path_buf)
                .ok_or(RuntimeError::MissingHostTool {
                    tool: HostTool::Umu,
                })
        }
        RunnerKind::Wine | RunnerKind::Custom => {
            find_binary(runner.dir(), WINE_CANDIDATES).ok_or(RuntimeError::MissingHostTool {
                tool: HostTool::Wine,
            })
        }
    }
}

/// Set the variables that place a program in `prefix`.
pub(crate) fn prefix_env(cmd: &mut Command, prefix: &Prefix) {
    cmd.env("WINEPREFIX", prefix.path());
    if prefix.runner().kind() == RunnerKind::ProtonUmu {
        cmd.env("GAMEID", DEFAULT_GAMEID);
        cmd.env("PROTONPATH", prefix.runner().dir());
    }
}

/// Build the process command for `plan` (which must carry a prefix). `umu_run` is the resolved
/// umu-run path (managed or on `PATH`) for Proton runners.
///
/// The whole invocation runs on one side of a sandbox boundary and that side is the sandbox
/// ([`crate::flatpak`]), so `confinement` decides nothing about composition here. What it does
/// decide is whether the outermost wrapper is pre-flighted: inside a sandbox, a wrapper the build
/// does not ship fails as itself rather than as an `ENOENT` naming a path the user has never seen.
pub(crate) fn build_command(
    plan: &LaunchPlan,
    umu_run: Option<&Path>,
    confinement: &Confinement,
) -> Result<Command, RuntimeError> {
    let prefix = plan.prefix().ok_or(RuntimeError::InvalidLaunchPlan {
        reason: "launch plan has no prefix",
    })?;
    // The runner invocation: the launcher binary, the program, whatever an injectable inserted, then
    // the opaque args. The inserted tokens go before the argument string rather than after it, because
    // that string is the game's own single argument: anything appended would be read by the game
    // rather than by the loader that asked for it.
    let mut invocation: Vec<String> = Vec::new();
    invocation.push(
        prefix_launcher(prefix, umu_run)?
            .to_string_lossy()
            .into_owned(),
    );
    invocation.push(plan.program().to_owned());
    invocation.extend(plan.inserted_args().iter().cloned());
    if !plan.args().is_empty() {
        invocation.push(plan.args().to_owned());
    }

    // Wrappers (gamescope/gamemode/...) wrap the whole invocation.
    let mut argv: Vec<String> = Vec::with_capacity(plan.wrappers().len() + invocation.len());
    argv.extend(plan.wrappers().iter().cloned());
    argv.extend(invocation);

    let (exe, rest) = argv.split_first().ok_or(RuntimeError::InvalidLaunchPlan {
        reason: "empty launch command",
    })?;
    check_sandbox_tool(confinement, exe)?;
    let mut cmd = Command::new(exe);
    cmd.args(rest);
    apply_env(&mut cmd, plan, prefix);
    if let Some(working_dir) = plan.working_dir() {
        cmd.current_dir(working_dir);
    }
    cmd.kill_on_drop(false);
    Ok(cmd)
}

/// Kill everything in a prefix: the separate, explicit broad stop.
pub(crate) async fn kill_prefix(
    prefix: &Prefix,
    umu_run: Option<PathBuf>,
) -> Result<(), RuntimeError> {
    let mut cmd = kill_command(prefix, umu_run)?;
    // A non-zero status (nothing to kill) is not an error.
    cmd.status().await.map_err(|source| RuntimeError::Spawn {
        runner: prefix.runner().name().to_owned(),
        source,
    })?;
    Ok(())
}

/// Compose the broad-stop command for `prefix`: `wineserver -k` for a wine runner, `wineboot -k`
/// through umu for a Proton one.
fn kill_command(prefix: &Prefix, umu_run: Option<PathBuf>) -> Result<Command, RuntimeError> {
    let runner = prefix.runner();
    match runner.kind() {
        RunnerKind::ProtonUmu => {
            let umu = umu_run.ok_or(RuntimeError::MissingHostTool {
                tool: HostTool::Umu,
            })?;
            let mut cmd = Command::new(umu);
            // `wineboot -k`, not `wineserver -k`: umu runs a program inside the prefix, and bare
            // `wineserver` does not resolve there (it exits nonzero having killed nothing).
            cmd.arg("wineboot").arg("-k");
            // The prefix root, never `<prefix>/pfx`: umu owns that relocation, and handing it the
            // relocated path makes it nest another one (leaving a `pfx -> .` loop behind).
            cmd.env("WINEPREFIX", prefix.path());
            cmd.env("GAMEID", DEFAULT_GAMEID);
            cmd.env("PROTONPATH", runner.dir());
            Ok(cmd)
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
            Ok(cmd)
        }
    }
}

/// Set the launch environment: prefix/runner variables first, then the plan's own, merged last so
/// they win. The plan's variables are already resolved (synchronization, graphics, the user's
/// overrides), so nothing is decided here.
fn apply_env(cmd: &mut Command, plan: &LaunchPlan, prefix: &Prefix) {
    prefix_env(cmd, prefix);
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
    // Inside a sandbox this is the sandbox's `PATH`, which is the right answer: a host umu-run
    // would start the game on the far side of the boundary supervision cannot read across.
    on_path("umu-run")
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
            .in_prefix(&prefix)
            .in_directory(&working);

        let cmd = build_command(&plan, None, &Confinement::default()).unwrap();
        assert_eq!(cmd.as_std().get_current_dir(), Some(working.as_path()));
    }

    /// Through umu the broad stop must be `wineboot -k` against the prefix *root*. `wineserver -k`
    /// does not resolve as a program inside the prefix, and `<prefix>/pfx` makes umu nest a second
    /// relocation; either way the stop exits nonzero having killed nothing.
    #[test]
    fn kill_command_runs_wineboot_against_the_umu_prefix_root() {
        let tmp = tempfile::tempdir().unwrap();
        let prefix_dir = tmp.path().join("prefix");
        let runner = RunnerHandle::new(
            tmp.path().join("runner"),
            RunnerKind::ProtonUmu,
            "GE-Proton",
            "11-1",
        );
        let prefix = Prefix::new(prefix_dir.clone(), runner);

        let cmd = kill_command(&prefix, Some(PathBuf::from("/usr/bin/umu-run"))).unwrap();
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert_eq!(args, ["wineboot", "-k"]);
        let wineprefix = cmd
            .as_std()
            .get_envs()
            .find(|(k, _)| *k == "WINEPREFIX")
            .and_then(|(_, v)| v)
            .unwrap();
        assert_eq!(Path::new(wineprefix), prefix_dir);
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
        let plan = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new()).in_prefix(&prefix);

        let cmd = build_command(&plan, None, &Confinement::default()).unwrap();
        assert_eq!(cmd.as_std().get_current_dir(), None);
    }

    /// A loader's own flags go between the program and the argument string. Appending them instead
    /// would hand them to the game, which parses that string itself and would see the loader's flags
    /// as its own; the loader would see none of them.
    #[test]
    fn inserted_args_land_between_the_program_and_the_argument_string() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_dir = tmp.path().join("runner");
        std::fs::create_dir_all(runner_dir.join("bin")).unwrap();
        let wine = runner_dir.join("bin/wine");
        std::fs::write(&wine, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755)).unwrap();

        let runner = RunnerHandle::new(runner_dir, RunnerKind::Custom, "test", "custom");
        let prefix = Prefix::new(tmp.path().join("prefix"), runner);
        let mut plan = LaunchPlan::new("/loader/Injector.exe", "//**sqex0003**//", BTreeMap::new())
            .in_prefix(&prefix);
        plan.set_inserted_args(vec!["launch".to_owned(), "--mode=inject".to_owned()]);

        let cmd = build_command(&plan, None, &Confinement::default()).unwrap();
        let args: Vec<_> = cmd.as_std().get_args().collect();
        assert_eq!(
            args,
            [
                "/loader/Injector.exe",
                "launch",
                "--mode=inject",
                "//**sqex0003**//"
            ],
            "the loader's flags belong ahead of the game's own argument"
        );
    }

    /// Inside a sandbox a wrapper the build does not ship is named, and the launch it would have
    /// wrapped is refused before anything starts. The runner underneath it is an absolute path the
    /// caller already resolved, so the same pre-flight leaves an unwrapped launch alone.
    #[test]
    fn a_confined_launch_names_the_wrapper_its_sandbox_does_not_carry() {
        let tmp = tempfile::tempdir().unwrap();
        let runner_dir = tmp.path().join("runner");
        std::fs::create_dir_all(runner_dir.join("bin")).unwrap();
        let wine = runner_dir.join("bin/wine");
        std::fs::write(&wine, "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(&wine, std::fs::Permissions::from_mode(0o755)).unwrap();

        let runner = RunnerHandle::new(runner_dir, RunnerKind::Custom, "test", "custom");
        let prefix = Prefix::new(tmp.path().join("prefix"), runner);
        let confined = Confinement {
            flatpak: true,
            host_spawn: Some(PathBuf::from("/usr/bin/flatpak-spawn")),
        };

        // `gamescope` is not in any Flatpak runtime, so a sandbox that did not bundle it resolves
        // nothing. The name is pinned in the matrix precisely so this failure can be told apart from
        // the program itself refusing to start.
        let wrapped = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new())
            .in_prefix(&prefix)
            .with_wrappers(vec!["gamescope".to_owned(), "--".to_owned()]);
        let err = build_command(&wrapped, None, &confined)
            .expect_err("a wrapper the sandbox does not carry is not a launch");
        assert!(
            matches!(
                err,
                RuntimeError::MissingHostTool {
                    tool: HostTool::Gamescope
                }
            ),
            "{err:?}"
        );

        let plain = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new()).in_prefix(&prefix);
        build_command(&plain, None, &confined)
            .expect("the runner is a resolved path, not a name to vet");
    }

    /// Nothing is inserted unless an injectable asked for it, and the supervised process defaults to
    /// the program itself.
    #[test]
    fn a_plan_nobody_touched_inserts_nothing_and_names_no_other_process() {
        let plan = LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new());
        assert!(plan.inserted_args().is_empty());
        assert_eq!(plan.supervised(), None);
    }
}
