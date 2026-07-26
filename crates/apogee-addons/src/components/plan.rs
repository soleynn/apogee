//! Deciding what an install has to do, before it does any of it.
//!
//! Kept as a pure function over the manifest and the prefix's own record, because the two properties
//! that matter here are both about the decision rather than the doing: a verb a tool needs runs before
//! that tool, and a component the prefix already records is not touched. Both are checkable without a
//! prefix, a download, or a wine.

use apogee_runtime::InstalledComponent;

use crate::manifest::{ComponentManifest, ToolKind};
use crate::{AddonError, Result};

/// Which list a step's row came from, which is also what installing it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StepKind {
    /// A curated prefix-setup step.
    Verb,
    /// A companion tool.
    Tool(ToolKind),
}

/// What the install will do about one step.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StepAction {
    /// Do it.
    Install,
    /// The prefix already records it.
    AlreadyPresent,
    /// The manifest offers it but this build cannot drive it.
    Unsupported { what: &'static str },
}

/// One thing an install will consider, in the order it will be considered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanStep {
    pub name: String,
    pub kind: StepKind,
    pub action: StepAction,
}

/// The ordered decision an install is about to carry out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnsurePlan {
    steps: Vec<PlanStep>,
}

impl EnsurePlan {
    /// Resolve `wanted` against `manifest`, expanding the verbs each tool asks for and marking what
    /// `installed` already covers.
    ///
    /// A verb a tool needs is planned immediately before it, not collected into a leading batch. That
    /// matters when a later tool needs a verb an earlier one did not: batching would apply it before a
    /// tool that has no use for it, which is a prefix mutation the user did not ask for yet.
    ///
    /// A tool is already present only if the version the record carries is the version the row now
    /// offers, so a bumped row is an install rather than a no-op. That is the whole point of a
    /// version living in a manifest. A record with no version at all — a verb, or something an older
    /// build wrote — counts as present, because there is nothing to compare and re-installing on every
    /// run would be worse than a stale entry.
    ///
    /// # Errors
    /// [`AddonError::UnknownComponent`] if a name is in no list. Refused for the whole call rather than
    /// recorded per-name: a name that resolves to nothing is a configuration mistake, and installing
    /// the rest of the set while silently dropping one is how a launcher ends up "working" with half a
    /// companion set.
    pub fn build(
        manifest: &ComponentManifest,
        wanted: &[String],
        installed: &[InstalledComponent],
    ) -> Result<Self> {
        let mut steps: Vec<PlanStep> = Vec::new();
        for name in wanted {
            if let Some(tool) = manifest.tool(name) {
                for verb in &tool.verbs {
                    // Present by construction: the manifest refuses a tool naming a verb it does not
                    // define.
                    push(&mut steps, verb, None, StepKind::Verb, installed);
                }
                push(
                    &mut steps,
                    name,
                    Some(tool.version.as_str()),
                    StepKind::Tool(tool.kind),
                    installed,
                );
            } else if manifest.verb(name).is_some() {
                push(&mut steps, name, None, StepKind::Verb, installed);
            } else if manifest.injectable(name).is_some() {
                // Offered by the schema so a manifest does not need a new version when the code that
                // drives these lands. Until then, saying so beats installing nothing quietly.
                push_step(
                    &mut steps,
                    PlanStep {
                        name: name.clone(),
                        kind: StepKind::Verb,
                        action: StepAction::Unsupported {
                            what: "this build does not install injectable companions",
                        },
                    },
                );
            } else {
                return Err(AddonError::UnknownComponent { name: name.clone() });
            }
        }
        Ok(Self { steps })
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
            .any(|step| step.action == StepAction::Install)
    }
}

fn push(
    steps: &mut Vec<PlanStep>,
    name: &str,
    wanted_version: Option<&str>,
    kind: StepKind,
    installed: &[InstalledComponent],
) {
    let action = match installed.iter().find(|c| c.name() == name) {
        // Nothing to compare: a verb, or a record from a build that did not keep versions.
        Some(record) if record.version().is_none() => StepAction::AlreadyPresent,
        Some(record) if record.version() == wanted_version => StepAction::AlreadyPresent,
        _ => StepAction::Install,
    };
    push_step(
        steps,
        PlanStep {
            name: name.to_owned(),
            kind,
            action,
        },
    );
}

/// Append unless the same name is already planned. A verb two tools both need is applied once.
fn push_step(steps: &mut Vec<PlanStep>, step: PlanStep) {
    if !steps.iter().any(|planned| planned.name == step.name) {
        steps.push(step);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two tools, the second sharing the first's verb and adding one of its own.
    fn manifest() -> ComponentManifest {
        let json = r#"{
          "version": 1,
          "tools": [
            { "name": "ACT", "version": "1", "kind": "prefix_tool",
              "url": "https://example.invalid/a.zip",
              "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
              "archive": { "format": "zip" }, "into": "apogee/ACT",
              "verbs": ["shared"] },
            { "name": "Other", "version": "1", "kind": "prefix_tool",
              "url": "https://example.invalid/b.zip",
              "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
              "archive": { "format": "zip" }, "into": "apogee/Other",
              "verbs": ["shared", "extra"] },
            { "name": "Native", "version": "1", "kind": "external_native",
              "url": "https://example.invalid/c.zip",
              "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
              "archive": { "format": "zip" }, "into": "Native" }
          ],
          "verbs": [
            { "name": "shared", "reason": "r", "ops": [] },
            { "name": "extra", "reason": "r", "ops": [] }
          ]
        }"#;
        ComponentManifest::from_json_bytes(json.as_bytes()).expect("fixture parses")
    }

    fn names(plan: &EnsurePlan) -> Vec<&str> {
        plan.steps().iter().map(|s| s.name.as_str()).collect()
    }

    /// A tool's verbs come before it, and a verb two tools share is applied once, next to the first one
    /// that needs it.
    #[test]
    fn a_tools_verbs_are_planned_immediately_before_it_and_never_twice() {
        let plan = EnsurePlan::build(&manifest(), &["ACT".to_owned(), "Other".to_owned()], &[])
            .expect("plan");
        assert_eq!(names(&plan), ["shared", "ACT", "extra", "Other"]);
    }

    /// A verb the user asked for directly is one step, not a duplicate of the one a tool pulls in.
    #[test]
    fn naming_a_verb_directly_and_through_a_tool_plans_it_once() {
        let plan = EnsurePlan::build(&manifest(), &["shared".to_owned(), "ACT".to_owned()], &[])
            .expect("plan");
        assert_eq!(names(&plan), ["shared", "ACT"]);
    }

    /// A record for a verb, or for a tool at the version the manifest offers.
    fn present(name: &str, version: Option<&str>) -> InstalledComponent {
        match version {
            Some(version) => InstalledComponent::Versioned {
                name: name.to_owned(),
                version: version.to_owned(),
            },
            None => InstalledComponent::Name(name.to_owned()),
        }
    }

    /// The prefix's own record is what makes a second run a no-op, and it covers the pulled-in verbs
    /// too, not only the names the user typed.
    #[test]
    fn what_the_prefix_already_records_is_not_installed_again() {
        let installed = vec![present("shared", None), present("ACT", Some("1"))];
        let plan = EnsurePlan::build(
            &manifest(),
            &["ACT".to_owned(), "Other".to_owned()],
            &installed,
        )
        .expect("plan");
        let actions: Vec<&StepAction> = plan.steps().iter().map(|s| &s.action).collect();
        assert_eq!(
            actions,
            [
                &StepAction::AlreadyPresent,
                &StepAction::AlreadyPresent,
                &StepAction::Install,
                &StepAction::Install
            ]
        );
        assert!(!plan.is_empty(), "two steps still have work");

        let all = EnsurePlan::build(&manifest(), &["ACT".to_owned()], &installed).expect("plan");
        assert!(all.is_empty(), "a fully-installed set has nothing to do");
    }

    /// The point of a version living in a manifest: bumping a row has to install, not report the prefix
    /// as up to date against a row it has never seen.
    #[test]
    fn a_row_at_a_different_version_than_the_record_is_installed_again() {
        // The fixture's ACT row is version "1".
        let stale = vec![present("shared", None), present("ACT", Some("0"))];
        let plan = EnsurePlan::build(&manifest(), &["ACT".to_owned()], &stale).expect("plan");
        assert_eq!(
            plan.steps().iter().map(|s| &s.action).collect::<Vec<_>>(),
            [&StepAction::AlreadyPresent, &StepAction::Install]
        );
        assert!(!plan.is_empty());
    }

    /// A record with no version is all an older build wrote, and there is nothing to compare it against.
    /// Treating that as needing an install would re-download every component on the first run of this
    /// build, which is worse than a stale entry.
    #[test]
    fn a_record_with_no_version_counts_as_present() {
        let unversioned = vec![present("shared", None), present("ACT", None)];
        let plan = EnsurePlan::build(&manifest(), &["ACT".to_owned()], &unversioned).expect("plan");
        assert!(plan.is_empty(), "{:?}", plan.steps());
    }

    #[test]
    fn the_step_kind_says_where_a_tool_installs() {
        let plan = EnsurePlan::build(&manifest(), &["ACT".to_owned(), "Native".to_owned()], &[])
            .expect("plan");
        let kinds: Vec<StepKind> = plan.steps().iter().map(|s| s.kind).collect();
        assert_eq!(
            kinds,
            [
                StepKind::Verb,
                StepKind::Tool(ToolKind::PrefixTool),
                StepKind::Tool(ToolKind::ExternalNative)
            ]
        );
    }

    /// A name that resolves to nothing is a configuration mistake, and installing the rest of the set
    /// around it is how a launcher reports success with half a companion set.
    #[test]
    fn a_name_no_row_offers_fails_the_whole_plan() {
        match EnsurePlan::build(&manifest(), &["ACT".to_owned(), "Ghost".to_owned()], &[]) {
            Err(AddonError::UnknownComponent { name }) => assert_eq!(name, "Ghost"),
            other => panic!("expected UnknownComponent, got {other:?}"),
        }
    }

    /// The schema carries injectable rows so it does not need a new version when the code that drives
    /// them lands. Until then, one has to say it is not handled rather than install nothing quietly.
    #[test]
    fn an_injectable_is_planned_as_unsupported_rather_than_ignored() {
        let json = r#"{ "version": 1, "injectables": [
            { "name": "Dalamud", "kind": "dalamud", "distribution": "https://example.invalid/v",
              "tier": "best_effort", "note": "n" } ] }"#;
        let manifest = ComponentManifest::from_json_bytes(json.as_bytes()).expect("parse");
        let plan = EnsurePlan::build(&manifest, &["Dalamud".to_owned()], &[]).expect("plan");
        assert!(matches!(
            plan.steps(),
            [PlanStep {
                action: StepAction::Unsupported { .. },
                ..
            }]
        ));
        assert!(plan.is_empty(), "nothing to install");
    }
}
