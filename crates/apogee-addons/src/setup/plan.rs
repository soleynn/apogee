//! Deciding what a prefix still needs, before anything touches it.
//!
//! Kept as a pure function over the manifest and the prefix's own record, because the property that
//! matters here is about the decision rather than the doing: a verb the prefix already records is not
//! applied again, and one whose effect has gone is. Both are checkable without a prefix, a download,
//! or a wine.

use apogee_runtime::InstalledComponent;

use crate::manifest::ComponentManifest;

/// What the setup pass will do about one verb.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StepAction {
    /// Apply it.
    Apply,
    /// The prefix already records it.
    AlreadyPresent,
}

/// One thing a setup pass will consider, in the order it will be considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub name: String,
    pub action: StepAction,
}

/// The ordered decision a setup pass is about to carry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupPlan {
    steps: Vec<PlanStep>,
}

impl SetupPlan {
    /// Plan every verb `manifest` defines, marking what `installed` already covers.
    ///
    /// Every verb, not a chosen subset: a verb is prefix hygiene the launcher performs, so the list a
    /// signed manifest publishes *is* the setup, and adding one is an edit rather than something a user
    /// has to find and switch on.
    ///
    /// `stale` names verbs the record claims but whose effect has been checked and is gone, which
    /// overrides the record. That is what makes a verb whose effect a runner upgrade removed from under
    /// us come back, instead of being skipped forever on the strength of an entry that is no longer
    /// true.
    #[must_use]
    pub fn build(
        manifest: &ComponentManifest,
        installed: &[InstalledComponent],
        stale: &[String],
    ) -> Self {
        let steps = manifest
            .verbs
            .iter()
            .map(|verb| PlanStep {
                action: action_for(&verb.name, installed, stale),
                name: verb.name.clone(),
            })
            .collect();
        Self { steps }
    }

    /// Every step, in order.
    #[must_use]
    pub fn steps(&self) -> &[PlanStep] {
        &self.steps
    }

    /// Whether anything would actually be done.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        !self
            .steps
            .iter()
            .any(|step| step.action == StepAction::Apply)
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

    fn actions(plan: &SetupPlan) -> Vec<&StepAction> {
        plan.steps().iter().map(|s| &s.action).collect()
    }

    /// The manifest's list is the setup, in its own order: nothing chooses a subset, because a verb is
    /// hygiene rather than a feature somebody opts into.
    #[test]
    fn every_verb_the_manifest_defines_is_planned_in_manifest_order() {
        let plan = SetupPlan::build(&manifest(), &[], &[]);
        assert_eq!(
            plan.steps()
                .iter()
                .map(|s| s.name.as_str())
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
        assert!(!plan.is_empty());
    }

    /// The prefix's own record is what makes a second pass a no-op. There is no second list of what a
    /// prefix has, because a second list is a second thing that can be wrong about a prefix other code
    /// also writes into.
    #[test]
    fn what_the_prefix_already_records_is_not_applied_again() {
        let plan = SetupPlan::build(&manifest(), &[recorded("first")], &[]);
        assert_eq!(
            actions(&plan),
            [&StepAction::AlreadyPresent, &StepAction::Apply]
        );

        let all = SetupPlan::build(&manifest(), &[recorded("first"), recorded("second")], &[]);
        assert!(all.is_empty(), "a fully-applied prefix has nothing to do");
    }

    /// A verb whose effect has gone has to be applied again, whatever the record says. Without this, one
    /// runner upgrade that removes what a verb wrote leaves it skipped forever on the strength of an
    /// entry that is no longer true.
    #[test]
    fn a_recorded_verb_whose_effect_is_gone_is_applied_again() {
        let installed = vec![recorded("first"), recorded("second")];
        let plan = SetupPlan::build(&manifest(), &installed, &["first".to_owned()]);
        assert_eq!(
            actions(&plan),
            [&StepAction::Apply, &StepAction::AlreadyPresent],
            "the stale verb comes back and the intact one is left alone"
        );
    }

    /// A manifest with no verbs is a prefix with nothing to do, not an error: the catalog is allowed to
    /// publish none.
    #[test]
    fn a_manifest_with_no_verbs_plans_nothing() {
        let manifest = ComponentManifest::from_json_bytes(br#"{ "version": 1 }"#)
            .expect("an empty manifest parses");
        assert!(SetupPlan::build(&manifest, &[], &[]).is_empty());
    }
}
