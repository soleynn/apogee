//! Starting a program outside a Flatpak sandbox, and deciding which programs those are.
//!
//! Inside a sandbox the launcher's filesystem, process table and environment are not the host's. A
//! program that has to run on the other side of that boundary is started through
//! `flatpak-spawn --host`, which hands the invocation to the Flatpak portal and proxies the exit
//! status back. Which programs those are is the whole of the decision, and it is pinned here rather
//! than restated at each spawn site.
//!
//! # What the boundary costs
//!
//! Measured against flatpak 1.16.6 and `org.freedesktop.Platform` 25.08, from a sandbox holding
//! `--talk-name=org.freedesktop.Flatpak`:
//!
//! - **The process table is not shared.** A sandbox has its own PID namespace: the launcher sees
//!   itself as pid 2 with five entries in `/proc`, and a host pid it was handed is not among them.
//!   Everything this crate does after a spawn reads `/proc` (resolving the game the runner renamed
//!   itself into, narrowing on each process's own `WINEPREFIX`, the targeted kill, the guard that
//!   answers whether the game is running), so a host-spawned game is one this crate can neither
//!   find, stop, nor report on.
//! - **The environment does not travel.** A variable exported in the sandbox arrives unset; the
//!   host command gets the host session's environment instead, host `PATH` included. Every variable
//!   the matrix computes ([`crate::compute_environment`]) and every structural one the spawner sets
//!   (`WINEPREFIX`, `GAMEID`, `PROTONPATH`) would be dropped in silence, and a wine with no
//!   `WINEPREFIX` does not fail: it uses `~/.wine`. Whatever must survive is named as an explicit
//!   `--env=` argument, which is what [`host_arguments`] is for.
//! - **Only a graceful stop crosses.** `SIGTERM` is forwarded to the host command. `SIGKILL` cannot
//!   be: killing the proxy leaves the host command running, and `--watch-bus` does not change that
//!   (measured on both a killed proxy and a torn-down sandbox), which is why it is not passed.
//! - **The working directory and the exit status do travel**, the first as `--directory=` and the
//!   second verbatim.
//! - **A missing host program is not a missing program.** The proxy starts, so the spawn succeeds
//!   and the failure arrives as the proxy's own exit status 1 with the portal's message on stderr.
//!   Nothing downstream can tell that from the program itself exiting 1.
//!
//! # The matrix
//!
//! | invocation | side | why |
//! | --- | --- | --- |
//! | the runner (`wine`, `umu-run`) and the game | sandbox | this crate downloaded and extracted the runner into the application's own data directory, for the runtime the application was built against; and see the process table above, which is what supervision reads |
//! | `gamescope` | sandbox | it is the first token of the *same* argv as the runner, so host-spawning it host-spawns the game inside it. The application's Flatpak has to carry it |
//! | `gamemoderun` | sandbox | it is an `LD_PRELOAD` shim for the process it wraps, so it belongs on the game's side of the boundary; the daemon it drives is reached over D-Bus. `org.freedesktop.Platform` 25.08 already carries the script and `libgamemodeauto.so.0` |
//! | a free-form wrapper | sandbox | same argv again, and it is usually a tracer or a preload of the game. Rewriting a command the user typed is not this crate's call |
//! | a program run inside a prefix | sandbox | same runner, same prefix |
//! | the prefix-wide stop | sandbox | `wineserver -k` and `umu-run wineboot -k` have to reach the wine processes they are stopping, which are the sandbox's |
//! | a host companion ([`CompanionSpec::host`](crate::CompanionSpec::host)) | **host** | the one invocation whose definition is a native tool from outside this application: the user points at a program on their own machine, which the sandbox neither installed nor can see |
//!
//! So the launch chain runs whole on one side, and that side is the sandbox. Nothing about that is a
//! smaller build of the feature: the alternative is a game the launcher loses track of the moment it
//! starts, running with none of the environment it was configured with.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{HostTool, RuntimeError};

/// The file every Flatpak sandbox carries and nothing outside one does.
const FLATPAK_INFO: &str = "/.flatpak-info";

/// The tool that starts a host program from inside a sandbox. It belongs to the runtime rather than
/// to the application, so an application does not install it and cannot assume it either.
const HOST_SPAWN: &str = "flatpak-spawn";

/// The launch-chain tools this crate names rather than resolves, paired with what to call each one
/// when it is not there.
///
/// Only these two are ever the first token of a launch argv as a bare name; the runner, `wineserver`
/// and a managed `umu-run` all arrive as absolute paths, and a free-form wrapper is the user's own
/// word with no variant to report it under.
const SANDBOX_TOOLS: &[(&str, HostTool)] = &[
    ("gamescope", HostTool::Gamescope),
    ("gamemoderun", HostTool::Gamemode),
];

/// What is being started, for [`Confinement::runs_on_host`]. One arm per row of the matrix in the
/// module documentation, so the classification is a value a test can pin rather than a rule each
/// call site repeats.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Invocation {
    /// The runner, the game, and every wrapper composed around them: one argv, one side.
    Launch,
    /// A setup program run inside a prefix through its runner.
    InPrefix,
    /// Stopping every process in a prefix.
    PrefixStop,
    /// A native tool that is not part of the launch and did not arrive with this application.
    HostTool,
}

/// Whether this process runs inside a Flatpak sandbox, and what it can leave one with.
///
/// A sandbox does not share the host's process table, environment, or filesystem, so what crosses
/// the boundary is decided once and for the whole crate: **the launch chain runs inside the
/// sandbox**, every part of it, and the only invocation relayed out through `flatpak-spawn --host`
/// is a host companion, which is a program the user pointed at on their own machine. The runner and
/// the game go nowhere near the host because a host-spawned game is one this crate cannot find in
/// `/proc`, cannot hand its computed environment to, and cannot stop; `gamescope`, `gamemoderun` and
/// a free-form wrapper are tokens of that same argv and follow it. [`Self::runs_on_host`] is that
/// table as a value, and the module documentation records the measurements behind it.
///
/// Deliberately exhaustive, unlike most of the types around it: the whole point is that a caller can
/// build one, so a test can compose a launch for a confinement it is not running under and a
/// composition root that already knows can say so instead of probing again.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Confinement {
    /// This process runs inside a Flatpak sandbox.
    pub flatpak: bool,
    /// The `flatpak-spawn` this process can reach the host with. Meaningful only alongside
    /// `flatpak`: a sandbox without one has no way out, which is a typed failure rather than a
    /// silent run on the wrong side.
    pub host_spawn: Option<PathBuf>,
}

impl Confinement {
    /// Detect this process's confinement. `/.flatpak-info` says whether there is a sandbox, and
    /// `PATH` says whether it carries the tool to leave it with.
    ///
    /// Off Linux both probes answer no, which is the correct answer there.
    #[must_use]
    pub fn detect() -> Self {
        Self::from_reads(Path::new(FLATPAK_INFO).exists(), on_path(HOST_SPAWN))
    }

    /// The same decision over values, so what a given pair means is settled by a test rather than by
    /// whichever machine runs the suite. Split from the reads the way the kernel version and the
    /// machine identity are ([`crate::HostCaps`], [`crate::HostIdentity`]).
    fn from_reads(flatpak_info: bool, host_spawn: Option<PathBuf>) -> Self {
        Self {
            flatpak: flatpak_info,
            // Dropped rather than carried when there is no sandbox, so the type cannot hold the one
            // combination that means nothing: a way out of somewhere this process is not.
            host_spawn: flatpak_info.then_some(host_spawn).flatten(),
        }
    }

    /// Whether this process runs inside a sandbox at all.
    #[must_use]
    pub fn is_confined(&self) -> bool {
        self.flatpak
    }

    /// Whether `invocation` runs outside the sandbox. The matrix in the module documentation, as a
    /// value; unconfined, the answer is always no, because there is nothing to be outside of.
    #[must_use]
    pub fn runs_on_host(&self, invocation: Invocation) -> bool {
        match invocation {
            Invocation::Launch | Invocation::InPrefix | Invocation::PrefixStop => false,
            Invocation::HostTool => self.flatpak,
        }
    }

    /// The `flatpak-spawn` a host invocation goes through.
    ///
    /// # Errors
    /// [`RuntimeError::MissingHostTool`] if the sandbox carries none. Reported rather than fallen
    /// back on: running the tool inside the sandbox instead would look like it worked, and the
    /// program a user pointed at is on their machine and not in this one's runtime.
    pub(crate) fn require_host_spawn(&self) -> Result<&Path, RuntimeError> {
        self.host_spawn
            .as_deref()
            .ok_or(RuntimeError::MissingHostTool {
                tool: HostTool::FlatpakSpawn,
            })
    }
}

/// The arguments that make `flatpak-spawn` run `program` on the host with `args`, `env` and
/// `working_dir`.
///
/// Every variable is named individually because none are inherited across the boundary, and the
/// option list is closed with `--` so a program whose path begins with a dash stays a program.
pub(crate) fn host_arguments(
    program: &Path,
    args: &[String],
    env: &BTreeMap<String, String>,
    working_dir: Option<&Path>,
) -> Vec<OsString> {
    let mut argv = vec![OsString::from("--host")];
    if let Some(dir) = working_dir {
        let mut flag = OsString::from("--directory=");
        flag.push(dir);
        argv.push(flag);
    }
    for (key, value) in env {
        argv.push(OsString::from(format!("--env={key}={value}")));
    }
    argv.push(OsString::from("--"));
    argv.push(program.into());
    argv.extend(args.iter().map(OsString::from));
    argv
}

/// Which launch-chain tool `argv0` names, when it names one the sandbox does not carry.
///
/// `resolve` is how a name becomes a program, injected so the classification is decided by a test
/// over literals instead of by whatever is installed on the machine running it. A token holding a
/// separator is a path the caller already resolved, and whether it exists is the spawn's answer to
/// give rather than this one's.
fn missing_sandbox_tool(
    argv0: &str,
    resolve: impl Fn(&str) -> Option<PathBuf>,
) -> Option<HostTool> {
    if argv0.contains('/') {
        return None;
    }
    SANDBOX_TOOLS
        .iter()
        .find(|(name, _)| *name == argv0)
        .filter(|_| resolve(argv0).is_none())
        .map(|(_, tool)| *tool)
}

/// Refuse a launch whose outermost wrapper is a tool this sandbox does not carry.
///
/// Only under confinement, and the difference is what the failure means rather than how it reads.
/// On a host, a missing `gamescope` is a package the user has not installed on a machine they know;
/// inside a sandbox it is a build that does not ship one, and the bare `ENOENT` names a path the
/// user has never seen and cannot act on.
///
/// # Errors
/// [`RuntimeError::MissingHostTool`] naming the tool.
pub(crate) fn check_sandbox_tool(
    confinement: &Confinement,
    argv0: &str,
) -> Result<(), RuntimeError> {
    if !confinement.flatpak {
        return Ok(());
    }
    match missing_sandbox_tool(argv0, on_path) {
        Some(tool) => Err(RuntimeError::MissingHostTool { tool }),
        None => Ok(()),
    }
}

/// The first `name` on `PATH`.
///
/// Lives here because deciding where a program comes from is what this module is for; the runner
/// side ([`crate::spawn`]) resolves `umu-run` through the same lookup.
pub(crate) fn on_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(name))
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confined() -> Confinement {
        Confinement {
            flatpak: true,
            host_spawn: Some(PathBuf::from("/usr/bin/flatpak-spawn")),
        }
    }

    /// The marker and the tool are separate reads, and the pairing that matters is a sandbox that
    /// carries no way out of itself: present as a sandbox, absent as a spawn.
    #[test]
    fn the_sandbox_marker_and_the_tool_are_read_separately() {
        let found = Path::new("/usr/bin/flatpak-spawn");
        let tool = || Some(found.to_path_buf());

        let full = Confinement::from_reads(true, tool());
        assert!(full.is_confined());
        assert_eq!(full.host_spawn.as_deref(), Some(found));

        let stranded = Confinement::from_reads(true, None);
        assert!(stranded.is_confined());
        assert!(stranded.host_spawn.is_none());

        // A tool on the path of a process that is not sandboxed says nothing, so it is not carried:
        // the host arm must not be reachable by a machine that merely has flatpak installed.
        let host = Confinement::from_reads(false, tool());
        assert!(!host.is_confined());
        assert!(host.host_spawn.is_none());
        assert_eq!(host, Confinement::default());
    }

    /// The matrix, pinned. A change here is a change to which side the game runs on, which is the one
    /// decision this module exists to make.
    #[test]
    fn only_a_host_tool_runs_outside_the_sandbox() {
        let every = [
            Invocation::Launch,
            Invocation::InPrefix,
            Invocation::PrefixStop,
            Invocation::HostTool,
        ];
        let confined = confined();
        let outside: Vec<_> = every
            .iter()
            .filter(|i| confined.runs_on_host(**i))
            .collect();
        assert_eq!(outside, [&Invocation::HostTool]);

        // Unconfined there is nothing to be outside of, so every invocation is an ordinary child.
        let host = Confinement::default();
        for invocation in every {
            assert!(!host.runs_on_host(invocation), "{invocation:?}");
        }
    }

    /// A sandbox with no `flatpak-spawn` cannot start a host tool, and saying so is the point: the
    /// alternative silently runs the user's own program inside a runtime that does not have it.
    #[test]
    fn a_sandbox_with_no_way_out_is_a_typed_failure() {
        let stranded = Confinement {
            flatpak: true,
            host_spawn: None,
        };
        assert!(matches!(
            stranded.require_host_spawn(),
            Err(RuntimeError::MissingHostTool {
                tool: HostTool::FlatpakSpawn
            })
        ));
        assert_eq!(
            confined().require_host_spawn().expect("resolved"),
            Path::new("/usr/bin/flatpak-spawn")
        );
    }

    /// Every variable is named, because none of them are inherited: measured on flatpak 1.16.6, a
    /// variable exported in the sandbox arrives unset on the host. Dropping one silently is how a
    /// tool told where the prefix is ends up looking somewhere else.
    #[test]
    fn every_variable_is_named_because_none_are_inherited() {
        let mut env = BTreeMap::new();
        env.insert("APOGEE_GAME_PID".to_owned(), "1234".to_owned());
        env.insert("APOGEE_GAME_PREFIX".to_owned(), "/prefixes/one".to_owned());

        let argv = host_arguments(
            Path::new("/opt/tool/overlay"),
            &["--attach".to_owned(), "one two".to_owned()],
            &env,
            Some(Path::new("/opt/tool")),
        );

        assert_eq!(
            argv,
            [
                "--host",
                "--directory=/opt/tool",
                "--env=APOGEE_GAME_PID=1234",
                "--env=APOGEE_GAME_PREFIX=/prefixes/one",
                "--",
                "/opt/tool/overlay",
                "--attach",
                // No shell anywhere on this path, so a value with a space stays one argument.
                "one two",
            ]
        );
    }

    /// With nothing to carry, the invocation is the program and its arguments behind the separator.
    #[test]
    fn a_bare_host_invocation_carries_only_the_separator() {
        let argv = host_arguments(Path::new("/usr/bin/tool"), &[], &BTreeMap::new(), None);
        assert_eq!(argv, ["--host", "--", "/usr/bin/tool"]);
    }

    /// Which names are pre-flighted, and which are left to the spawn. A path is the caller's own
    /// resolution and a wrapper the user typed is theirs, so neither is second-guessed here.
    #[test]
    fn only_an_unresolvable_matrix_tool_is_refused() {
        let absent = |_: &str| None;
        let present = |_: &str| Some(PathBuf::from("/usr/bin/gamescope"));

        assert!(matches!(
            missing_sandbox_tool("gamescope", absent),
            Some(HostTool::Gamescope)
        ));
        assert!(matches!(
            missing_sandbox_tool("gamemoderun", absent),
            Some(HostTool::Gamemode)
        ));
        assert!(missing_sandbox_tool("gamescope", present).is_none());
        // A path resolves or fails on its own; the user's own wrapper has no variant to report it
        // under and is not this crate's to vet.
        assert!(missing_sandbox_tool("/usr/bin/gamescope", absent).is_none());
        assert!(missing_sandbox_tool("strace", absent).is_none());
        assert!(missing_sandbox_tool("", absent).is_none());
    }

    /// The pre-flight is a sandbox rule. On a host the same missing tool is a package the user did
    /// not install, and turning that into a different error class would change a working path for
    /// everyone who is not sandboxed.
    #[test]
    fn an_unconfined_launch_is_never_pre_flighted() {
        assert!(check_sandbox_tool(&Confinement::default(), "gamescope").is_ok());
    }
}
