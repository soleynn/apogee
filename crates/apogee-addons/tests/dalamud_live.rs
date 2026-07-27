#![cfg(target_os = "linux")]
//! Dalamud installed from the real goatcorp distribution.
//!
//! `#[ignore]` and env-gated, so the hermetic suite never contacts a third party and CI never pulls a
//! hundred megabytes. The hermetic suite serves a distribution it wrote itself, which checks the
//! pipeline but not the wire: field casing, the shape of the digest maps, and the redirect chain the
//! runtime archives sit behind are all upstream's, and none of them is visible from a fixture.
//!
//! Run it when the client changes or upstream does:
//! ```text
//! APOGEE_DALAMUD_LIVE=1 cargo test -p apogee-addons --test dalamud_live -- --ignored --nocapture
//! ```

use std::error::Error;
use std::path::Path;

use apogee_addons::{
    AddonPaths, ComponentManifest, Dalamud, DalamudConfig, Injectable, SetupEvent, SetupEvents,
};
use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, RunnerKind};
use tokio_util::sync::CancellationToken;

type R<T> = Result<T, Box<dyn Error>>;

/// The hosted catalog's own row, so this drives the pointer that ships rather than one written here.
fn dalamud(root: &Path) -> R<Dalamud> {
    let manifest = ComponentManifest::verify_default(
        include_bytes!("../../../site/components/manifest.json"),
        include_bytes!("../../../site/components/manifest.json.sig"),
    )?;
    let entry = manifest
        .injectables
        .iter()
        .find(|entry| entry.name == "Dalamud")
        .ok_or("the hosted catalog carries no Dalamud row")?;
    // The game version is left empty on purpose: what is under test is the install, and this asserts on
    // the caveat that mismatch produces rather than needing a real install to match against.
    Ok(Dalamud::new(
        AddonPaths::new(root).dalamud(),
        Fetcher::builder().build()?,
        entry,
        DalamudConfig::default(),
    ))
}

fn prefix(root: &Path) -> R<Prefix> {
    apogee_test_support::sandbox::write_prefix_skeleton(root)?;
    Ok(Prefix::for_testing(
        root,
        root.join("runner"),
        RunnerKind::Wine,
        "wine-xiv-staging",
        "custom",
    ))
}

/// A full install from the real distribution: the release, its bundled runtime, and its assets, each
/// checked against the digests the distribution publishes for it.
#[tokio::test]
#[ignore = "set APOGEE_DALAMUD_LIVE=1 to fetch from the real distribution"]
async fn a_real_install_verifies_against_the_digests_upstream_publishes() -> R<()> {
    if std::env::var("APOGEE_DALAMUD_LIVE").is_err() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let dalamud = dalamud(root.path())?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();

    dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::new(tx))
        .await?;

    let installed = dalamud.installed().ok_or("nothing was recorded")?;
    println!(
        "installed {} for game {} (runtime {}, assets {})",
        installed.assembly_version,
        installed.supported_game_ver,
        installed.runtime_version,
        installed.asset_version
    );
    let paths = AddonPaths::new(root.path()).dalamud();
    let version_dir = paths.addon.join("Hooks").join(&installed.assembly_version);
    for name in ["Dalamud.Injector.exe", "Dalamud.dll", "hashes.json"] {
        assert!(version_dir.join(name).is_file(), "{name} is missing");
    }
    assert!(
        paths
            .assets
            .join(installed.asset_version.to_string())
            .is_dir(),
        "the asset set did not land"
    );
    assert_eq!(
        std::fs::read_to_string(paths.runtime.join("version"))?.trim(),
        installed.runtime_version,
        "the runtime marker is only written once both archives extracted"
    );

    // The config was left with no game version, so it has to say it will not load rather than load into
    // whatever is there.
    let mut declined = false;
    while let Ok(event) = rx.try_recv() {
        if matches!(&event, SetupEvent::Caveat { note, .. } if note.contains("will not be loaded"))
        {
            declined = true;
        }
    }
    assert!(
        declined,
        "a release for a game version this install does not have has to say so"
    );

    // A second pass over a sealed runtime does not lay it down again. Asserted on the seal's own
    // modification time rather than on the clock: a re-install rewrites it, and a timing bound would be
    // a property of the machine. This is the assertion that would have caught the runtime coming down on
    // every single launch, which is what happened while the marker was written before the tree it is
    // listed in had been checked.
    let seal = paths.runtime.join("version");
    let before = std::fs::metadata(&seal)?.modified()?;
    let started = std::time::Instant::now();
    dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
        .await?;
    println!("second pass took {:?}", started.elapsed());
    assert_eq!(
        std::fs::metadata(&seal)?.modified()?,
        before,
        "the runtime was installed again over a seal that was already good"
    );
    Ok(())
}

/// Where a second pass spends its time, so the launch-path cost of leaving the setting on is a measured
/// number rather than an assumption. Printed, not asserted: it is a property of the machine.
#[tokio::test]
#[ignore = "set APOGEE_DALAMUD_LIVE=1 to fetch from the real distribution"]
async fn the_cost_of_a_no_op_pass_is_reported() -> R<()> {
    if std::env::var("APOGEE_DALAMUD_LIVE").is_err() {
        return Ok(());
    }
    let root = tempfile::tempdir()?;
    let dalamud = dalamud(root.path())?;
    let prefix = prefix(&root.path().join("prefix"))?;
    dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
        .await?;

    let paths = AddonPaths::new(root.path()).dalamud();
    for (label, dir) in [
        ("dalamud tree", paths.addon.clone()),
        ("runtime", paths.runtime.clone()),
        ("assets", paths.assets.clone()),
    ] {
        let (files, bytes) = weigh(&dir)?;
        println!("{label}: {files} files, {} MiB", bytes / (1024 * 1024));
    }
    Ok(())
}

/// The file count and total bytes under `dir`.
fn weigh(dir: &Path) -> R<(u64, u64)> {
    let mut files = 0;
    let mut bytes = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in std::fs::read_dir(&next)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                files += 1;
                bytes += meta.len();
            }
        }
    }
    Ok((files, bytes))
}
