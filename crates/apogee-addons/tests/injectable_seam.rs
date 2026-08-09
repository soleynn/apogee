#![cfg(target_os = "linux")]
//! One code path for every injectable.
//!
//! The seam only earns its keep if the launcher cannot tell what it is composing, so this drives a fake
//! first-class companion and Dalamud through the same two calls and asserts the launcher treats them
//! identically: both are asked to install, both contribute to the plan, and a failure from either is
//! reported with its tier rather than failing the launch.
//!
//! The fake is what the framework will arrive as. Its whole purpose here is that adding it needed no
//! change to the loop that runs it.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use apogee_addons::{
    AddonError, AddonPaths, Addons, ComponentManifest, DalamudConfig, Injectable, SetupEvent,
    SetupEvents, SupportTier,
};
use apogee_fetch::Fetcher;
use apogee_runtime::{LaunchPlan, Prefix, RunnerKind, Runtime, RuntimePaths};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

/// A first-class companion that records what it was asked to do and wraps the launch its own way.
struct Framework {
    ensured: AtomicUsize,
    fail_prepare: bool,
}

impl Framework {
    fn new(fail_prepare: bool) -> Self {
        Self {
            ensured: AtomicUsize::new(0),
            fail_prepare,
        }
    }
}

#[async_trait]
impl Injectable for Framework {
    fn name(&self) -> &str {
        "Framework"
    }

    fn support_tier(&self) -> SupportTier {
        SupportTier::FirstClass
    }

    async fn ensure(
        &self,
        _prefix: &Prefix,
        _cancel: &CancellationToken,
        events: &SetupEvents,
    ) -> Result<(), AddonError> {
        self.ensured.fetch_add(1, Ordering::SeqCst);
        events.emit(SetupEvent::Installed {
            what: "Framework".to_owned(),
        });
        Ok(())
    }

    fn prepare_launch(
        &self,
        plan: &mut LaunchPlan,
        _events: &SetupEvents,
    ) -> Result<(), AddonError> {
        if self.fail_prepare {
            return Err(AddonError::Inject {
                injectable: "Framework".to_owned(),
                tier: SupportTier::FirstClass,
                source: Box::new(std::io::Error::other(
                    "the loader is not built for this game",
                )),
            });
        }
        plan.env_mut()
            .insert("APOGEE_FRAMEWORK".to_owned(), "1".to_owned());
        Ok(())
    }
}

/// A companion that reaches the game the way the shipped one does: by becoming the program the launch
/// spawns, with its own flags ahead of the game's argument string and the game named as the process to
/// wait on.
struct Loader {
    name: &'static str,
}

#[async_trait]
impl Injectable for Loader {
    fn name(&self) -> &str {
        self.name
    }

    fn support_tier(&self) -> SupportTier {
        SupportTier::FirstClass
    }

    async fn ensure(
        &self,
        _prefix: &Prefix,
        _cancel: &CancellationToken,
        _events: &SetupEvents,
    ) -> Result<(), AddonError> {
        Ok(())
    }

    fn prepare_launch(
        &self,
        plan: &mut LaunchPlan,
        _events: &SetupEvents,
    ) -> Result<(), AddonError> {
        let supervised = Path::new(plan.program())
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());
        plan.set_inserted_args(vec![format!("--loader={}", self.name)]);
        plan.set_program(format!("C:\\{}\\loader.exe", self.name));
        if let Some(basename) = supervised {
            plan.set_supervised(basename);
        }
        plan.env_mut().insert(
            format!("APOGEE_{}", self.name.to_uppercase()),
            "1".to_owned(),
        );
        Ok(())
    }
}

/// The row the launch setting reads, pointed at a name that cannot resolve.
///
/// Deliberately not the real distribution. What is under test is the loop, not the download, and a test
/// that reached goatcorp would pull a real release over the network on every CI run while claiming to be
/// hermetic. `.invalid` is reserved for exactly this and never resolves.
fn manifest() -> Result<ComponentManifest, Box<dyn Error>> {
    let json = r#"{ "version": 1, "injectables": [
        { "name": "Dalamud", "kind": "dalamud",
          "distribution": "https://dalamud.invalid/Dalamud/Release/VersionInfo",
          "tier": "best_effort", "note": "Best with the wine-xiv runner." } ] }"#;
    Ok(ComponentManifest::from_json_bytes(json.as_bytes())?)
}

fn addons(root: &Path) -> Result<Addons, Box<dyn Error>> {
    let fetcher = Fetcher::builder().build()?;
    let runtime = Runtime::new(fetcher.clone(), RuntimePaths::default());
    Ok(Addons::new(
        runtime,
        fetcher,
        AddonPaths::new(root.join("addons")),
    ))
}

fn prefix(root: &Path) -> Result<Prefix, Box<dyn Error>> {
    apogee_test_support::sandbox::write_prefix_skeleton(root)?;
    Ok(Prefix::for_testing(
        root,
        root.join("runner"),
        RunnerKind::Wine,
        "wine-xiv-staging",
        "custom",
    ))
}

fn plan(prefix: &Prefix) -> LaunchPlan {
    LaunchPlan::new(
        "/games/ffxiv/game/ffxiv_dx11.exe",
        "//**sqex0003**//",
        BTreeMap::new(),
    )
    .prefix(prefix)
}

fn events() -> (
    SetupEvents,
    Mutex<tokio::sync::mpsc::UnboundedReceiver<SetupEvent>>,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    (SetupEvents::new(tx), Mutex::new(rx))
}

/// The launcher asks every injectable the same two questions in the same loop. A companion that arrives
/// later has to need no change here, which is the only thing that makes the seam worth having.
#[tokio::test]
async fn a_new_injectable_and_dalamud_go_through_the_same_calls() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let addons = addons(root.path())?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let manifest = manifest()?;
    let dalamud = addons
        .dalamud(&manifest, DalamudConfig::default(), &SetupEvents::none())
        .ok_or("the manifest offers no Dalamud row")?;
    let framework = Framework::new(false);
    let both: [&dyn Injectable; 2] = [&framework, &dalamud];
    let (sink, _rx) = events();

    // Dalamud has no endpoints it can reach here, so its install fails; the framework's succeeds. Both
    // are driven by the same loop, and one failing does not stop the other.
    let failures = addons
        .ensure_injectables(&both, &prefix, &CancellationToken::new(), &sink)
        .await;
    assert_eq!(framework.ensured.load(Ordering::SeqCst), 1);
    assert_eq!(
        failures.len(),
        1,
        "only Dalamud could not install: {failures:?}"
    );

    let mut plan = plan(&prefix);
    let failures = addons.prepare_launch(&both, &mut plan, &sink);
    assert!(failures.is_empty(), "{failures:?}");
    assert_eq!(
        plan.env().get("APOGEE_FRAMEWORK").map(String::as_str),
        Some("1"),
        "the first-class companion contributed to the launch"
    );
    // Dalamud declined because nothing is installed, and declining is not a failure.
    assert!(plan.inserted_args().is_empty());
    Ok(())
}

/// An injectable that cannot compose its launch is reported with the tier it is on, and the launch goes
/// ahead. A companion is an addition to a launch, never a precondition for one.
#[tokio::test]
async fn an_injectable_that_fails_is_reported_with_its_tier_and_does_not_stop_the_launch()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let addons = addons(root.path())?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let framework = Framework::new(true);
    let only: [&dyn Injectable; 1] = [&framework];
    let (sink, rx) = events();
    let mut plan = plan(&prefix);

    let failures = addons.prepare_launch(&only, &mut plan, &sink);

    assert!(
        matches!(
            failures.as_slice(),
            [AddonError::Inject {
                injectable,
                tier: SupportTier::FirstClass,
                ..
            }] if injectable == "Framework"
        ),
        "the failure names the companion and its tier: {failures:?}"
    );
    assert_eq!(
        plan.program(),
        "/games/ffxiv/game/ffxiv_dx11.exe",
        "the launch is untouched by a companion that could not compose one"
    );
    let mut rx = rx.into_inner()?;
    let mut reported = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(&event, SetupEvent::Failed { what, .. } if what == "Framework") {
            reported = true;
        }
    }
    assert!(reported, "the failure reached the event stream");
    Ok(())
}

/// A launch spawns one program, so two companions that each become it cannot share one. The first to
/// redirect keeps it, the second is refused by name, and the game still starts: a companion is an
/// addition to a launch, never a precondition for one. The refused one leaves nothing behind, because a
/// plan carrying one companion's argv and env around another's program is a launch neither composed.
#[tokio::test]
async fn a_second_companion_cannot_redirect_a_launch_that_is_already_redirected()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let addons = addons(root.path())?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let first = Loader { name: "Loader" };
    let second = Loader { name: "Injector" };
    let both: [&dyn Injectable; 2] = [&first, &second];
    let (sink, rx) = events();
    let mut plan = plan(&prefix);

    let failures = addons.prepare_launch(&both, &mut plan, &sink);

    assert!(
        matches!(
            failures.as_slice(),
            [AddonError::LaunchAlreadyRedirected {
                injectable,
                redirector,
            }] if injectable == "Injector" && redirector == "Loader"
        ),
        "the second is refused, and the failure names both: {failures:?}"
    );
    assert_eq!(
        plan.program(),
        "C:\\Loader\\loader.exe",
        "the launch is the first one's"
    );
    assert_eq!(
        plan.inserted_args(),
        ["--loader=Loader"],
        "with the first one's flags, not the second's"
    );
    assert_eq!(
        plan.env().get("APOGEE_LOADER").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        plan.env().get("APOGEE_INJECTOR"),
        None,
        "the refused companion left nothing in the launch"
    );
    // Still a launch: the game's own argument string is untouched and the launcher waits on the game
    // rather than on the loader that wraps it.
    assert_eq!(plan.args(), "//**sqex0003**//");
    assert_eq!(plan.supervised(), Some("ffxiv_dx11.exe"));

    drop(sink);
    let mut rx = rx.into_inner()?;
    let mut reported = Vec::new();
    while let Ok(SetupEvent::Failed { what, reason }) = rx.try_recv() {
        reported.push(format!("{what}: {reason}"));
    }
    assert_eq!(
        reported.len(),
        1,
        "the loser is reported once, and only the loser: {reported:?}"
    );
    assert!(reported[0].starts_with("Injector: "), "{reported:?}");
    assert!(reported[0].contains("Loader already did"), "{reported:?}");
    Ok(())
}

/// A build whose catalog carries no row for an injectable has nothing honest to say about where to
/// fetch it or what the tier costs, so it declines. The user asked for it at a launch, so the decline
/// is narrated, and the sentence is this layer's: a caller writing one would be describing a decision
/// it did not make.
#[tokio::test]
async fn a_catalog_with_no_row_declines_and_says_so() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let addons = addons(root.path())?;
    let empty = ComponentManifest::from_json_bytes(br#"{ "version": 1 }"#)?;
    let (sink, rx) = events();

    let declined = addons.dalamud(&empty, DalamudConfig::default(), &sink);

    assert!(declined.is_none(), "there is no row to build it from");
    drop(sink);
    let mut rx = rx.into_inner()?;
    let mut reasons = Vec::new();
    while let Ok(SetupEvent::Failed { what, reason }) = rx.try_recv() {
        reasons.push(format!("{what}: {reason}"));
    }
    assert_eq!(
        reasons.len(),
        1,
        "the decline is said once, and by the layer that decided it: {reasons:?}"
    );
    assert!(reasons[0].contains("no row"), "{reasons:?}");
    Ok(())
}
