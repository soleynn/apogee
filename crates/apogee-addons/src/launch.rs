//! What a companion adds to a launch, as a value rather than as a mutation.
//!
//! An [`Injectable`](crate::Injectable) composes a [`LaunchEdit`] and hands it back; the loop that runs
//! the companions is what puts it into the plan. Two things fall out of that. A companion whose own work
//! fails partway through composing an invocation contributes nothing rather than half of one, because
//! the half it built goes with the error. And refusing a contribution costs nothing: the loop declines
//! to apply a value it is holding, instead of restoring a plan it has already let somebody write to.

use std::collections::BTreeMap;

use apogee_runtime::LaunchPlan;

/// What an injectable does with the launch it is offered.
#[derive(Debug, Clone)]
pub enum Contribution {
    /// It is not taking part in this launch, and has said why on the setup stream.
    ///
    /// Distinct from an empty [`LaunchEdit`] at the call site rather than in effect: a companion that
    /// stood down and one that had nothing to add read the same to a plan, and only one of them owes
    /// the user a sentence.
    Declined,
    /// What to add to the launch.
    Edit(LaunchEdit),
}

impl From<LaunchEdit> for Contribution {
    fn from(edit: LaunchEdit) -> Self {
        Self::Edit(edit)
    }
}

/// A companion's additions to a launch: a redirect, environment variables, wrapper commands.
///
/// Only what a companion has business changing. The program, the game's own argument string, the
/// working directory and the prefix are the launch the launcher composed, and the fields here are the
/// three ways an addition to it can be expressed.
#[derive(Debug, Clone, Default)]
pub struct LaunchEdit {
    redirect: Option<Redirect>,
    env: BTreeMap<String, String>,
    wrappers: Vec<String>,
}

impl LaunchEdit {
    /// An edit that changes nothing, to add to.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Become the program the launch spawns.
    ///
    /// A launch has room for one of these across every companion in the pass, and the loop is what
    /// enforces that (see [`Addons::prepare_launch`](crate::Addons::prepare_launch)). A second call
    /// here replaces the first, since both are the same companion's and it is composing one invocation.
    #[must_use]
    pub fn redirect(mut self, redirect: Redirect) -> Self {
        self.redirect = Some(redirect);
        self
    }

    /// Set an environment variable for the launch, over anything already there under that name.
    #[must_use]
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.insert(key.into(), value.into());
        self
    }

    /// Add a wrapper command around the launch, inside whatever already wraps it.
    #[must_use]
    pub fn wrapper(mut self, wrapper: impl Into<String>) -> Self {
        self.wrappers.push(wrapper.into());
        self
    }

    /// Whether this edit takes over the program the launch spawns.
    #[must_use]
    pub fn redirects(&self) -> bool {
        self.redirect.is_some()
    }

    /// Write it into `plan`. The loop's, not an implementor's.
    ///
    /// Wrappers append and environment variables overwrite, which is the difference between what they
    /// are: a wrapper is a command composed around the ones already there, so dropping the existing
    /// ones would drop the launcher's own (gamemode, gamescope), while a variable is one value under a
    /// name and the last companion to name it is the one that meant it.
    pub(crate) fn apply(self, plan: &mut LaunchPlan) {
        if let Some(redirect) = self.redirect {
            plan.set_inserted_args(redirect.inserted_args);
            plan.set_program(redirect.program);
            if let Some(basename) = redirect.supervised {
                plan.set_supervised(basename);
            }
        }
        plan.env_mut().extend(self.env);
        for wrapper in self.wrappers {
            plan.push_wrapper(wrapper);
        }
    }
}

/// Becoming the program a launch spawns, with the flags and the process to wait on that go with it.
///
/// One value rather than three fields on [`LaunchEdit`], because they are one decision: tokens that are
/// not the game's only make sense ahead of a program that is not the game, and the only reason to wait
/// on something other than what was spawned is a loader that starts the game beside itself.
#[derive(Debug, Clone)]
pub struct Redirect {
    program: String,
    inserted_args: Vec<String>,
    supervised: Option<String>,
}

impl Redirect {
    /// Spawn `program` instead of what the plan names, in the form the runner reads it: a PE basename
    /// or a Windows path, since a host path is accepted by plain wine and routed through a launch
    /// helper by Proton.
    #[must_use]
    pub fn to(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            inserted_args: Vec::new(),
            supervised: None,
        }
    }

    /// The argv tokens that go between the program and the game's own argument string.
    ///
    /// That string is one token the game parses itself, so a loader's flags belong here: appending
    /// them would hand the game flags meant for the loader, and prepending would hand the loader the
    /// game's arguments as its own.
    #[must_use]
    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.inserted_args = args;
        self
    }

    /// Wait on `basename` rather than on the program this spawns.
    ///
    /// For a loader that starts the game as a separate process and exits: without this the launcher
    /// tracks the loader, sees it go, and reports the session as over while the game is still starting.
    /// A redirect that becomes the game itself leaves this alone.
    #[must_use]
    pub fn supervising(mut self, basename: impl Into<String>) -> Self {
        self.supervised = Some(basename.into());
        self
    }
}
