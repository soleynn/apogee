//! Deciding what a prefix still needs, before anything touches it.
//!
//! Kept as a pure function over the manifest and the prefix's own record, because the property that
//! matters here is about the decision rather than the doing: a verb the prefix already records is
//! not applied again, and one whose effect has gone is. Both are checkable without a prefix, a
//! download, or a wine.

use apogee_runtime::InstalledComponent;

use crate::manifest::{ComponentManifest, ProgramEntry, ProgramStep, Verb};

/// What the setup pass will do about one verb.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub(crate) enum StepAction {
    /// Apply it.
    Apply,
    /// The prefix already records it.
    AlreadyPresent,
}

/// One thing a setup pass will consider, in the order it will be considered.
///
/// It borrows the row rather than copying its name out, so the pass that carries the plan out cannot
/// look a name back up and find nothing: the manifest a step came from is the manifest it is applied
/// against, and holding the row is what says so in the types.
#[derive(Debug, Clone)]
pub(crate) struct PlanStep<'m> {
    pub verb: &'m Verb,
    pub action: StepAction,
    /// The program this step installs, or `None` for a base verb.
    pub program: Option<&'m ProgramEntry>,
    /// Whether it seeds configuration the program then owns.
    pub seeded: bool,
}

/// The ordered decision a setup pass is about to carry out.
#[derive(Debug, Clone)]
pub(crate) struct SetupPlan<'m> {
    steps: Vec<PlanStep<'m>>,
}

impl<'m> SetupPlan<'m> {
    /// Plan every verb `manifest` defines, marking what `installed` already covers.
    ///
    /// Every verb, not a chosen subset: a verb is prefix hygiene the launcher performs, so the list
    /// a signed manifest publishes *is* the setup, and adding one is an edit rather than something a
    /// user has to find and switch on.
    ///
    /// `stale` names verbs the record claims but whose effect has been checked and is gone, which
    /// overrides the record. That is what makes a verb whose effect a runner upgrade removed from
    /// under us come back, instead of being skipped forever on the strength of an entry that is no
    /// longer true.
    #[cfg(test)]
    #[must_use]
    pub fn build(
        manifest: &'m ComponentManifest,
        installed: &[InstalledComponent],
        stale: &[String],
    ) -> Self {
        Self::build_for(manifest, installed, stale, &[])
    }

    /// Plan every base verb, then the steps of each program in `programs`, in the order given.
    ///
    /// A program's steps follow the base verbs, because a step runs a program's installer inside a
    /// prefix the verbs have already made fit for it, and each program's steps stay together so they
    /// run just before the next program's and never twice.
    ///
    /// A program step is already present when the prefix records it at the row's version: a version
    /// moved in the catalog is what makes the step run again. A seeded step only needs recording, at
    /// any version, because it seeds settings the program then owns.
    #[must_use]
    pub fn build_for(
        manifest: &'m ComponentManifest,
        installed: &[InstalledComponent],
        stale: &[String],
        programs: &[&'m ProgramEntry],
    ) -> Self {
        let mut steps: Vec<PlanStep<'m>> = manifest
            .verbs
            .iter()
            .map(|verb| PlanStep {
                action: action_for(&verb.name, installed, stale),
                verb,
                program: None,
                seeded: false,
            })
            .collect();
        for program in programs {
            for step in &program.steps {
                steps.push(PlanStep {
                    action: program_action(program, step, installed, stale),
                    verb: &step.verb,
                    program: Some(program),
                    seeded: step.seeded,
                });
            }
        }
        Self { steps }
    }

    /// Every step, in order.
    #[must_use]
    pub fn steps(&self) -> &[PlanStep<'m>] {
        &self.steps
    }
}

fn program_action(
    program: &ProgramEntry,
    step: &ProgramStep,
    installed: &[InstalledComponent],
    stale: &[String],
) -> StepAction {
    if stale.contains(&step.verb.name) {
        return StepAction::Apply;
    }
    match installed.iter().find(|c| c.name() == step.verb.name) {
        Some(_) if step.seeded => StepAction::AlreadyPresent,
        Some(record) if record.version() == Some(program.version.as_str()) => {
            StepAction::AlreadyPresent
        }
        _ => StepAction::Apply,
    }
}

fn action_for(name: &str, installed: &[InstalledComponent], stale: &[String]) -> StepAction {
    if stale.iter().any(|s| s == name) {
        return StepAction::Apply;
    }
    if installed.iter().any(|c| c.name() == name) {
        StepAction::AlreadyPresent
    } else {
        StepAction::Apply
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two verbs, neither of which needs a wine to plan.
    fn manifest() -> ComponentManifest {
        let json = r#"{
          "version": 1,
          "verbs": [
            { "name": "first", "reason": "r", "ops": [] },
            { "name": "second", "reason": "r", "ops": [] }
          ]
        }"#;
        ComponentManifest::from_json_bytes(json.as_bytes()).expect("fixture parses")
    }

    fn recorded(name: &str) -> InstalledComponent {
        InstalledComponent::Name(name.to_owned())
    }

    fn actions<'p>(plan: &'p SetupPlan<'_>) -> Vec<&'p StepAction> {
        plan.steps().iter().map(|s| &s.action).collect()
    }

    /// The manifest's list is the setup, in its own order: nothing chooses a subset, because a verb
    /// is hygiene rather than a feature somebody opts into.
    #[test]
    fn every_verb_the_manifest_defines_is_planned_in_manifest_order() {
        let manifest = manifest();
        let plan = SetupPlan::build(&manifest, &[], &[]);
        assert_eq!(
            plan.steps()
                .iter()
                .map(|s| s.verb.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(actions(&plan).iter().all(|a| **a == StepAction::Apply));
    }

    /// The prefix's own record is what makes a second pass a no-op. There is no second list of what
    /// a prefix has, because a second list is a second thing that can be wrong about a prefix other
    /// code also writes into.
    #[test]
    fn what_the_prefix_already_records_is_not_applied_again() {
        let manifest = manifest();
        let plan = SetupPlan::build(&manifest, &[recorded("first")], &[]);
        assert_eq!(
            actions(&plan),
            [&StepAction::AlreadyPresent, &StepAction::Apply]
        );

        let all = SetupPlan::build(&manifest, &[recorded("first"), recorded("second")], &[]);
        assert!(
            actions(&all)
                .iter()
                .all(|a| **a == StepAction::AlreadyPresent),
            "a fully-applied prefix has nothing to do"
        );
    }

    /// A verb whose effect has gone has to be applied again, whatever the record says. Without this,
    /// one runner upgrade that removes what a verb wrote leaves it skipped forever on the strength
    /// of an entry that is no longer true.
    #[test]
    fn a_recorded_verb_whose_effect_is_gone_is_applied_again() {
        let manifest = manifest();
        let installed = vec![recorded("first"), recorded("second")];
        let plan = SetupPlan::build(&manifest, &installed, &["first".to_owned()]);
        assert_eq!(
            actions(&plan),
            [&StepAction::Apply, &StepAction::AlreadyPresent],
            "the stale verb comes back and the intact one is left alone"
        );
    }

    /// A program's steps come after every base verb and stay together, in the order the programs are
    /// given. A step recorded at another version of its row is installed again, while a seeded step
    /// recorded at any version is left alone, so a version bump reinstalls the program without
    /// overwriting the settings its user has since changed.
    #[test]
    fn program_steps_follow_the_verbs_and_reinstall_on_a_version_move() {
        let row = |name: &str, steps: &str| {
            format!(
                r#"{{ "name": "{name}", "version": "2", "tier": "first_class",
                     "game_versions": ["1"], "runners": [{{ "name": "r", "version": "1" }}],
                     "steps": {steps},
                     "start": {{ "program": "Apogee/{name}/x.exe", "trigger": "with_game" }} }}"#
            )
        };
        let json = format!(
            r#"{{ "version": 1,
                 "verbs": [ {{ "name": "base", "reason": "r", "ops": [] }} ],
                 "programs": [ {}, {} ] }}"#,
            row(
                "first",
                r#"[{ "name": "first-files", "reason": "r", "ops": [] },
                    { "name": "first-config", "reason": "r", "seeded": true, "ops": [] }]"#
            ),
            row(
                "second",
                r#"[{ "name": "second-files", "reason": "r", "ops": [] }]"#
            ),
        );
        let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("parses");
        assert!(
            manifest.refused_programs.is_empty(),
            "{:?}",
            manifest.refused_programs
        );
        let programs: Vec<&ProgramEntry> = manifest.programs.iter().rev().collect();
        let versioned = |name: &str, version: &str| InstalledComponent::Versioned {
            name: name.to_owned(),
            version: version.to_owned(),
        };
        let installed = vec![
            recorded("base"),
            versioned("first-files", "1"),
            versioned("first-config", "1"),
            versioned("second-files", "2"),
        ];
        let plan = SetupPlan::build_for(&manifest, &installed, &[], &programs);
        let shape: Vec<(&str, &StepAction)> = plan
            .steps()
            .iter()
            .map(|s| (s.verb.name.as_str(), &s.action))
            .collect();
        assert_eq!(
            shape,
            [
                ("base", &StepAction::AlreadyPresent),
                ("second-files", &StepAction::AlreadyPresent),
                ("first-files", &StepAction::Apply),
                ("first-config", &StepAction::AlreadyPresent),
            ]
        );
    }

    /// A manifest with no verbs is a prefix with nothing to do, not an error: the catalog is allowed
    /// to publish none.
    #[test]
    fn a_manifest_with_no_verbs_plans_nothing() {
        let manifest = ComponentManifest::from_json_bytes(br#"{ "version": 1 }"#)
            .expect("an empty manifest parses");
        assert!(SetupPlan::build(&manifest, &[], &[]).steps().is_empty());
    }
}
