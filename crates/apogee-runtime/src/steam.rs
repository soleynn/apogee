//! Registering this launcher with Steam as a compatibility tool, so a game can be started from the
//! Steam interface without a desktop.
//!
//! Steam lets a user force any installed game through a "compatibility tool", which is a directory
//! holding two declaration files and a program to run. Steam then invokes that program with a verb
//! and the game it was going to start. That is the only mechanism by which anything can be launched
//! from the Steam interface on a handheld, where there is no desktop to click a launcher in, so it is
//! the mechanism used here even though nothing about this launcher is a compatibility layer.
//!
//! Two consequences follow from bending it that way, and both are deliberate:
//!
//! - **The named game is ignored.** Steam passes the executable of whichever title the tool was
//!   forced onto; this launcher already knows which installation and profile it launches, and the
//!   two need not be the same game or even the same account. That is also why the registration works
//!   against any title the user owns rather than requiring a particular one.
//! - **Only one verb acts.** Steam calls the tool more than once per launch, with a verb saying what
//!   the call is for. Acting on more than the one that means "start it and wait" would start the
//!   game twice, so every other verb succeeds without doing anything.
//!
//! The declaration files are Valve's key-value format, written here rather than parsed: this crate
//! emits its own registration and never reads anyone else's.

use std::io;
use std::path::{Path, PathBuf};

use crate::error::{HostTool, RuntimeError};

/// The directory this launcher registers itself under, inside a Steam installation's tool directory.
/// Also the internal name Steam keys the registration on, so changing it orphans an existing
/// registration rather than replacing it.
const TOOL_DIR: &str = "apogee";

/// Where a Steam installation keeps the tools a user added.
const TOOLS_SUBDIR: &str = "compatibilitytools.d";

/// The program Steam runs, relative to the tool directory.
const LAUNCH_SCRIPT: &str = "apogee-run";

/// The verb that means "start it and wait for it to finish". Every other verb is a call this
/// registration has nothing to do, and starting the game on more than one of them starts it twice.
const RUN_VERB: &str = "waitforexitandrun";

/// A registration: the command Steam should end up running, and the name it is offered under.
#[derive(Debug, Clone)]
pub struct CompatTool {
    launcher: PathBuf,
    args: Vec<String>,
    display_name: String,
}

/// Where a registration was written, and what it runs.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CompatToolInstall {
    /// The tool directory Steam will find the registration in.
    pub dir: PathBuf,
    /// The command the registration runs, as it was written into the launch script.
    pub command: String,
}

impl CompatTool {
    /// A registration running `launcher` with `args`.
    ///
    /// `launcher` must be an absolute path to a program that can start a game on its own, since
    /// nothing about Steam's invocation is passed on to it. A relative path would resolve against
    /// whatever directory Steam happens to run the tool from.
    #[must_use]
    pub fn new(launcher: impl Into<PathBuf>, args: Vec<String>) -> Self {
        Self {
            launcher: launcher.into(),
            args,
            display_name: "Apogee".to_owned(),
        }
    }

    /// The name Steam offers the registration under. Worth setting when it names the profile it
    /// launches, because that name is all the user has to choose between two registrations by.
    #[must_use]
    pub fn display_name(mut self, name: impl Into<String>) -> Self {
        self.display_name = name.into();
        self
    }

    /// Write the registration into the Steam installation at `steam_root`, replacing any previous
    /// one. Steam reads its tool list at startup, so an installation made while it is running is not
    /// visible until it restarts.
    ///
    /// # Errors
    /// [`RuntimeError::MissingHostTool`] if `steam_root` is not a directory, which is what a path
    /// that Steam has never created looks like, and [`RuntimeError::Io`] on a failed write.
    pub fn install(&self, steam_root: &Path) -> Result<CompatToolInstall, RuntimeError> {
        if !steam_root.is_dir() {
            return Err(RuntimeError::MissingHostTool {
                tool: HostTool::Steam,
            });
        }
        let dir = tool_dir(steam_root);
        std::fs::create_dir_all(&dir).map_err(io_at(&dir))?;

        let command = self.command_line();
        write_file(
            &dir.join("compatibilitytool.vdf"),
            &registration_vdf(&self.display_name),
            0o644,
        )?;
        write_file(&dir.join("toolmanifest.vdf"), &tool_manifest_vdf(), 0o644)?;
        write_file(&dir.join(LAUNCH_SCRIPT), &launch_script(&command), 0o755)?;

        Ok(CompatToolInstall { dir, command })
    }

    /// The shell command the launch script runs, with each token quoted so a path holding a space
    /// stays one argument.
    fn command_line(&self) -> String {
        std::iter::once(self.launcher.to_string_lossy().into_owned())
            .chain(self.args.iter().cloned())
            .map(|token| shell_quote(&token))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// The tool directory inside a Steam installation.
fn tool_dir(steam_root: &Path) -> PathBuf {
    steam_root.join(TOOLS_SUBDIR).join(TOOL_DIR)
}

/// The registration in the Steam installation at `steam_root`, if there is one.
#[must_use]
pub fn installed_compat_tool(steam_root: &Path) -> Option<PathBuf> {
    let dir = tool_dir(steam_root);
    dir.join(LAUNCH_SCRIPT).is_file().then_some(dir)
}

/// Remove the registration from `steam_root`, reporting whether there was one. Only the directory
/// this launcher writes is removed, never the tool directory it sits in, which holds everyone else's.
///
/// # Errors
/// [`RuntimeError::Io`] if the directory exists and cannot be removed.
pub fn remove_compat_tool(steam_root: &Path) -> Result<bool, RuntimeError> {
    let dir = tool_dir(steam_root);
    if !dir.exists() {
        return Ok(false);
    }
    std::fs::remove_dir_all(&dir).map_err(io_at(&dir))?;
    Ok(true)
}

/// Every Steam installation belonging to this user, most conventional first.
///
/// Only directories that exist are returned, and a path is included once however many ways it can be
/// reached: the usual layout reaches one installation through a symlink and a real path both, and
/// offering the same installation twice would let a user register into one name and look for it under
/// the other. System-wide tool directories are deliberately absent: they are not this user's to write
/// to, and a registration there would apply to every account on the machine.
#[must_use]
pub fn steam_installs() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        return Vec::new();
    };
    let candidates = [
        ".steam/root",
        ".steam/steam",
        ".local/share/Steam",
        // Steam packaged as a sandboxed application keeps its own home, and the tool directory has
        // to be inside it to be visible to the sandboxed client.
        ".var/app/com.valvesoftware.Steam/.steam/root",
        "snap/steam/common/.steam/root",
    ];
    let mut found: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        let path = home.join(candidate);
        if !path.is_dir() {
            continue;
        }
        // Resolve before comparing: `.steam/root` is normally a symlink to one of the others.
        let key = path.canonicalize().unwrap_or_else(|_| path.clone());
        if found
            .iter()
            .any(|seen| seen.canonicalize().unwrap_or_else(|_| seen.clone()) == key)
        {
            continue;
        }
        found.push(path);
    }
    found
}

/// The registration Steam reads to offer the tool in its list.
fn registration_vdf(display_name: &str) -> String {
    format!(
        "\"compatibilitytools\"\n\
         {{\n\
         \t\"compat_tools\"\n\
         \t{{\n\
         \t\t\"{tool}\"\n\
         \t\t{{\n\
         \t\t\t\"install_path\" \".\"\n\
         \t\t\t\"display_name\" \"{name}\"\n\
         \t\t\t\"from_oslist\" \"windows\"\n\
         \t\t\t\"to_oslist\" \"linux\"\n\
         \t\t}}\n\
         \t}}\n\
         }}\n",
        tool = TOOL_DIR,
        name = vdf_escape(display_name),
    )
}

/// What Steam runs, and how. The verb is substituted by Steam into the placeholder.
///
/// No supporting runtime is requested. One would place the tool inside Steam's own container, which
/// changes what is on the path and what is visible on disk; this launcher brings its own runtime for
/// the runners that want one and needs the host's view for everything else.
fn tool_manifest_vdf() -> String {
    format!(
        "\"manifest\"\n\
         {{\n\
         \t\"version\" \"2\"\n\
         \t\"commandline\" \"/{script} %verb%\"\n\
         }}\n",
        script = LAUNCH_SCRIPT,
    )
}

/// The program Steam invokes: a verb, then the game it meant to start, which is discarded.
fn launch_script(command: &str) -> String {
    format!(
        "#!/bin/sh\n\
         # Written by the launcher's Steam registration; edits are lost on the next one.\n\
         # Steam calls this more than once per launch, with a verb saying why. Only one of them means\n\
         # \"start it and wait\", and starting on any other would start the game a second time.\n\
         [ \"$1\" = \"{RUN_VERB}\" ] || exit 0\n\
         # Everything after the verb names the title Steam was going to run. This launcher already\n\
         # knows what it launches, so the rest of the arguments are deliberately unused.\n\
         exec {command}\n"
    )
}

/// Quote a token for the launch script, so a path holding a space or a quote survives as one word.
fn shell_quote(token: &str) -> String {
    format!("'{}'", token.replace('\'', r"'\''"))
}

/// Escape a value for Valve's key-value format, which delimits with quotes and escapes with
/// backslashes.
fn vdf_escape(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', "\\\"")
}

fn write_file(path: &Path, contents: &str, mode: u32) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, contents).map_err(io_at(path))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(io_at(path))
}

fn io_at(path: &Path) -> impl Fn(io::Error) -> RuntimeError + '_ {
    move |source| RuntimeError::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool() -> CompatTool {
        CompatTool::new(
            "/usr/bin/apogee-cli",
            vec![
                "launch".to_owned(),
                "--profile".to_owned(),
                "main".to_owned(),
            ],
        )
    }

    #[test]
    fn installing_writes_a_registration_a_manifest_and_a_runnable_script() {
        use std::os::unix::fs::PermissionsExt;

        let steam = tempfile::tempdir().expect("tempdir");
        let install = tool().install(steam.path()).expect("install");

        assert_eq!(
            install.dir,
            steam.path().join("compatibilitytools.d/apogee")
        );
        for name in ["compatibilitytool.vdf", "toolmanifest.vdf", LAUNCH_SCRIPT] {
            assert!(install.dir.join(name).is_file(), "{name} written");
        }
        let mode = std::fs::metadata(install.dir.join(LAUNCH_SCRIPT))
            .expect("script metadata")
            .permissions()
            .mode();
        assert_ne!(mode & 0o111, 0, "Steam has to be able to run it");

        // The manifest points at the script by the same name the script was written under.
        let manifest =
            std::fs::read_to_string(install.dir.join("toolmanifest.vdf")).expect("manifest");
        assert!(manifest.contains(&format!("\"/{LAUNCH_SCRIPT} %verb%\"")));
    }

    /// Steam calls the tool more than once for one launch. Starting the game on any verb but the one
    /// that means "start it and wait" starts it twice, which is the failure this shape exists to
    /// avoid, so the guard is asserted rather than left to review.
    #[test]
    fn the_script_starts_the_game_on_one_verb_and_no_other() {
        let script = launch_script("'/usr/bin/apogee-cli' 'launch'");
        assert!(
            script.contains(&format!("[ \"$1\" = \"{RUN_VERB}\" ] || exit 0")),
            "every other verb exits without starting anything"
        );
        assert_eq!(RUN_VERB, "waitforexitandrun");
        // The command is reached only after that guard.
        let guard = script.find("|| exit 0").expect("guard present");
        let exec = script.find("exec ").expect("exec present");
        assert!(guard < exec);
    }

    /// A second registration replaces the first rather than accumulating beside it, so re-running an
    /// install after moving the binary is the fix rather than a second entry in Steam's list.
    #[test]
    fn installing_twice_leaves_one_registration_pointing_at_the_newer_command() {
        let steam = tempfile::tempdir().expect("tempdir");
        tool().install(steam.path()).expect("first install");
        let second = CompatTool::new("/opt/apogee/apogee-cli", vec!["launch".to_owned()])
            .install(steam.path())
            .expect("second install");

        let script = std::fs::read_to_string(second.dir.join(LAUNCH_SCRIPT)).expect("script");
        assert!(script.contains("/opt/apogee/apogee-cli"));
        assert!(!script.contains("/usr/bin/apogee-cli"));
        assert_eq!(
            std::fs::read_dir(steam.path().join("compatibilitytools.d"))
                .expect("tool dir")
                .count(),
            1
        );
    }

    #[test]
    fn a_path_steam_has_never_created_is_reported_as_no_steam() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let err = tool()
            .install(&tmp.path().join("absent"))
            .expect_err("no steam there");
        assert!(matches!(
            err,
            RuntimeError::MissingHostTool {
                tool: HostTool::Steam
            }
        ));
    }

    #[test]
    fn removing_reports_whether_there_was_anything_to_remove() {
        let steam = tempfile::tempdir().expect("tempdir");
        assert!(!remove_compat_tool(steam.path()).expect("nothing to remove"));
        assert!(installed_compat_tool(steam.path()).is_none());

        tool().install(steam.path()).expect("install");
        assert!(installed_compat_tool(steam.path()).is_some());
        assert!(remove_compat_tool(steam.path()).expect("removed"));
        assert!(installed_compat_tool(steam.path()).is_none());
        // The directory holding everyone else's tools survives.
        assert!(steam.path().join("compatibilitytools.d").is_dir());
    }

    /// The command is rebuilt as shell text, so a path a user can really have has to survive it.
    #[test]
    fn a_launcher_path_with_a_space_stays_one_argument() {
        let script =
            CompatTool::new("/home/u/my apps/apogee-cli", vec!["launch".to_owned()]).command_line();
        assert_eq!(script, "'/home/u/my apps/apogee-cli' 'launch'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn a_display_name_cannot_break_out_of_its_quoted_value() {
        let vdf = registration_vdf(r#"Apogee "main" \ profile"#);
        assert!(vdf.contains(r#"\"main\""#));
        assert!(vdf.contains(r"\\"));
        // The keys around it are still the ones Steam looks for.
        assert!(vdf.contains("\"compat_tools\""));
        assert!(vdf.contains("\"from_oslist\" \"windows\""));
        assert!(vdf.contains("\"to_oslist\" \"linux\""));
    }
}
