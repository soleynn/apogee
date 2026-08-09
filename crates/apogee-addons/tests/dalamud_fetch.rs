#![cfg(target_os = "linux")]
//! Installing Dalamud from a distribution that is entirely local (feature `testing`).
//!
//! Gated behind the same feature and for the same reason the manifest fetch is: a client that trusts the
//! test servers' self-signed loopback certificates, and nothing else new. The real goatcorp endpoints are
//! never contacted here, which is the point.
//!
//! Each `ChaosServer` serves one body on every path, so every endpoint in the distribution needs its own
//! server and its own certificate. That is what makes "the runtime was not fetched" checkable at all:
//! there is a server whose request count has to stay at zero.
//!
//! The digests below are recorded facts computed outside this file. Hashing the fixtures here with the
//! same code under test would pass whatever that code did, including the wrong algorithm.

use std::error::Error;
use std::io::{Cursor, Write};
use std::path::Path;

use apogee_addons::dalamud::Endpoints;
use apogee_addons::{
    AddonPaths, Dalamud, DalamudConfig, DalamudPaths, Injectable, SetupEvents, VerifiedManifest,
};
use apogee_fetch::Fetcher;
use apogee_runtime::{Prefix, RunnerKind};
use apogee_test_support::chaos::ChaosServer;
use tokio_util::sync::CancellationToken;
use zip::write::SimpleFileOptions;

const GAME_VERSION: &str = "2026.06.18.0000.0000";
const ASSEMBLY_VERSION: &str = "15.0.2.3";

/// md5("injector"), md5("dalamud"), md5("imgui"), and sha1("asset-bytes").
const INJECTOR_MD5: &str = "A312764C3972C532880BB8BB12BE8AF2";
const DALAMUD_MD5: &str = "80E977508A49C072E578B00A3CC85AC0";
const IMGUI_MD5: &str = "B84C5C4098A44514A715FBD45CE39925";
const ASSET_SHA1: &str = "A4B45E57B3934836F20CCF8529C18BCD1E120129";

/// A release archive: the three files a version directory is unusable without, plus the digest map the
/// distribution ships inside it.
fn release_zip() -> Result<Vec<u8>, Box<dyn Error>> {
    let hashes = format!(
        r#"{{ "Dalamud.Injector.exe": "{INJECTOR_MD5}",
              "Dalamud.dll": "{DALAMUD_MD5}",
              "ImGuiScene.dll": "{IMGUI_MD5}" }}"#
    );
    zip_of(&[
        ("Dalamud.Injector.exe", b"injector".as_slice()),
        ("Dalamud.dll", b"dalamud".as_slice()),
        ("ImGuiScene.dll", b"imgui".as_slice()),
        ("hashes.json", hashes.as_bytes()),
    ])
}

/// The asset package holds every file the metadata lists, including the one the distribution declines to
/// hash: an entry with no digest is still an entry that has to be there.
fn asset_zip() -> Result<Vec<u8>, Box<dyn Error>> {
    zip_of(&[
        ("UIRes/font.otf", b"asset-bytes".as_slice()),
        ("UIRes/unchecked.json", b"{}".as_slice()),
    ])
}

fn zip_of(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let plain = SimpleFileOptions::DEFAULT.last_modified_time(zip::DateTime::default());
    for (name, bytes) in entries {
        writer.start_file(*name, plain)?;
        writer.write_all(bytes)?;
    }
    Ok(writer.finish()?.into_inner())
}

/// The five endpoints one install touches, each on its own server so each can be counted separately.
struct Distribution {
    version: ChaosServer,
    release: ChaosServer,
    asset_meta: ChaosServer,
    assets: ChaosServer,
    /// Nothing should ever reach this one when the release says no runtime is required.
    runtime: ChaosServer,
}

impl Distribution {
    async fn start(runtime_required: bool, asset_version: u32) -> Result<Self, Box<dyn Error>> {
        let release = ChaosServer::serving(release_zip()?).tls().start().await?;
        let assets = ChaosServer::serving(asset_zip()?).tls().start().await?;
        let version_info = format!(
            r#"{{ "assemblyVersion": "{ASSEMBLY_VERSION}",
                  "supportedGameVer": "{GAME_VERSION}",
                  "runtimeVersion": "10.0.0", "runtimeRequired": {runtime_required},
                  "track": "release",
                  "downloadUrl": "{release_url}" }}"#,
            release_url = release.url("dalamud.zip"),
        );
        let asset_meta = format!(
            r#"{{ "version": {asset_version},
                  "packageUrl": "{package}",
                  "assets": [
                    {{ "url": "{package}", "fileName": "UIRes/font.otf", "hash": "{ASSET_SHA1}" }},
                    {{ "url": "{package}", "fileName": "UIRes/unchecked.json", "hash": null }}
                  ] }}"#,
            package = assets.url("assets.zip"),
        );
        Ok(Self {
            version: ChaosServer::serving(version_info.into_bytes())
                .tls()
                .start()
                .await?,
            release,
            asset_meta: ChaosServer::serving(asset_meta.into_bytes())
                .tls()
                .start()
                .await?,
            assets,
            runtime: ChaosServer::serving(b"never reached".to_vec())
                .tls()
                .start()
                .await?,
        })
    }

    fn servers(&self) -> [&ChaosServer; 5] {
        [
            &self.version,
            &self.release,
            &self.asset_meta,
            &self.assets,
            &self.runtime,
        ]
    }

    fn endpoints(&self) -> Endpoints {
        Endpoints {
            version_info: self.version.url("VersionInfo"),
            release_base: self.runtime.url("Release/"),
            asset_meta: self.asset_meta.url("Asset/Meta"),
        }
    }

    /// A client trusting all five loopback certificates and nothing else new, with compression off so
    /// the bytes that arrive are exactly what was served.
    fn fetcher(&self) -> Result<Fetcher, Box<dyn Error>> {
        let mut builder = reqwest::Client::builder().gzip(false).deflate(false);
        for server in self.servers() {
            let der = server.cert_der().ok_or("server is not running over tls")?;
            builder = builder.add_root_certificate(reqwest::Certificate::from_der(der)?);
        }
        Ok(Fetcher::from_client(builder.build()?))
    }
}

/// The manifest row behind the launch setting. Its distribution pointer is overridden per test, since
/// each endpoint has to live on a different host here.
fn catalog() -> Result<VerifiedManifest, Box<dyn Error>> {
    let json = br#"{ "version": 1, "injectables": [
        { "name": "Dalamud", "kind": "dalamud",
          "distribution": "https://kamori.goats.dev/Dalamud/Release/VersionInfo",
          "tier": "best_effort", "note": "Best with the wine-xiv runner." } ] }"#;
    let signature = apogee_test_support::catalog_sign::sign_manifest(json);
    Ok(VerifiedManifest::verify(
        json,
        &signature,
        &[apogee_test_support::catalog_sign::test_verifying_key_bytes()],
    )?)
}

fn dalamud(root: &Path, dist: &Distribution) -> Result<Dalamud, Box<dyn Error>> {
    let config = DalamudConfig {
        game_version: GAME_VERSION.to_owned(),
        ..DalamudConfig::default()
    };
    Ok(Dalamud::new(
        AddonPaths::new(root).dalamud(),
        dist.fetcher()?,
        &catalog()?,
        config,
    )
    .ok_or("the fixture carries a Dalamud row")?
    .with_endpoints(dist.endpoints()))
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

fn paths(root: &Path) -> DalamudPaths {
    AddonPaths::new(root).dalamud()
}

/// The whole install, end to end: the release lands, the assets land, and what was written down is what
/// the launch path later reads.
#[tokio::test]
async fn a_full_install_lands_the_release_and_its_assets() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let dist = Distribution::start(false, 432).await?;
    let dalamud = dalamud(root.path(), &dist)?;
    let prefix = prefix(&root.path().join("prefix"))?;

    dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
        .await?;

    let paths = paths(root.path());
    assert!(
        paths
            .addon
            .join(format!("Hooks/{ASSEMBLY_VERSION}/Dalamud.Injector.exe"))
            .is_file(),
        "the injector is where the launch path will look for it"
    );
    assert!(paths.assets.join("432/UIRes/font.otf").is_file());
    assert_eq!(
        std::fs::read_to_string(paths.assets.join("asset.ver"))?.trim(),
        "432"
    );

    let installed = dalamud.installed().ok_or("nothing was recorded")?;
    assert_eq!(installed.assembly_version, ASSEMBLY_VERSION);
    assert_eq!(installed.supported_game_ver, GAME_VERSION);
    assert_eq!(installed.asset_version, 432);
    assert_eq!(installed.track, "release");
    Ok(())
}

/// A release that says it needs no runtime must not fetch one. The flag is the only thing standing
/// between a launcher and a hundred megabytes nobody asked for.
#[tokio::test]
async fn a_release_that_needs_no_runtime_does_not_fetch_one() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let dist = Distribution::start(false, 432).await?;
    let dalamud = dalamud(root.path(), &dist)?;
    let prefix = prefix(&root.path().join("prefix"))?;

    dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
        .await?;

    assert_eq!(
        dist.runtime.stats().requests(),
        0,
        "the runtime endpoints were reached for a release that declared none"
    );
    assert!(!paths(root.path()).runtime.join("version").exists());
    Ok(())
}

/// A second install with nothing changed fetches the two small descriptions and neither archive. This is
/// what makes the setting cheap to leave on: a launch costs two requests, not a hundred megabytes.
#[tokio::test]
async fn a_second_install_re_downloads_no_archive() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let dist = Distribution::start(false, 432).await?;
    let dalamud = dalamud(root.path(), &dist)?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let cancel = CancellationToken::new();

    dalamud
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;
    let release_after_first = dist.release.stats().requests();
    let assets_after_first = dist.assets.stats().requests();

    dalamud
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;

    assert_eq!(
        dist.release.stats().requests(),
        release_after_first,
        "the release archive came down twice"
    );
    assert_eq!(
        dist.assets.stats().requests(),
        assets_after_first,
        "the asset archive came down twice"
    );
    Ok(())
}

/// A version directory whose files no longer match the map that shipped with it is laid down again.
/// Without this, one corrupted file leaves an injector that loads and does nothing for good.
#[tokio::test]
async fn a_tree_that_no_longer_matches_its_digests_is_replaced() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let dist = Distribution::start(false, 432).await?;
    let dalamud = dalamud(root.path(), &dist)?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let cancel = CancellationToken::new();

    dalamud
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;
    let after_first = dist.release.stats().requests();

    let corrupted = paths(root.path())
        .addon
        .join(format!("Hooks/{ASSEMBLY_VERSION}/Dalamud.dll"));
    std::fs::write(&corrupted, b"not dalamud")?;

    dalamud
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;

    assert!(
        dist.release.stats().requests() > after_first,
        "a tree that failed its own digests was accepted"
    );
    assert_eq!(std::fs::read(&corrupted)?, b"dalamud");
    Ok(())
}

/// The published version has to be *higher* to force a refresh, and a set already on disk is not fetched
/// again just because the published number moved. Comparing for inequality instead would re-download the
/// whole set the moment the distribution rolled one back.
#[tokio::test]
async fn a_set_already_on_disk_is_not_fetched_again_when_the_published_number_moves()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let cancel = CancellationToken::new();
    let prefix = prefix(&root.path().join("prefix"))?;

    let older = Distribution::start(false, 400).await?;
    dalamud(root.path(), &older)?
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;
    let newer = Distribution::start(false, 500).await?;
    dalamud(root.path(), &newer)?
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;
    assert!(
        paths(root.path())
            .assets
            .join("500/UIRes/font.otf")
            .is_file(),
        "a newer set is what a refresh is for"
    );

    // Rolled back to the set that is still on disk from the first install.
    let rolled_back = Distribution::start(false, 400).await?;
    dalamud(root.path(), &rolled_back)?
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;

    assert_eq!(
        rolled_back.assets.stats().requests(),
        0,
        "a set already on disk was fetched again over a version number"
    );
    Ok(())
}

/// An asset set at the same version whose files are gone comes back. A version number alone would call a
/// half-written set current forever.
#[tokio::test]
async fn an_asset_set_whose_files_are_missing_is_refetched_at_the_same_version()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let dist = Distribution::start(false, 432).await?;
    let dalamud = dalamud(root.path(), &dist)?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let cancel = CancellationToken::new();

    dalamud
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;
    let after_first = dist.assets.stats().requests();
    std::fs::remove_file(paths(root.path()).assets.join("432/UIRes/font.otf"))?;

    dalamud
        .ensure(&prefix, &cancel, &SetupEvents::none())
        .await?;

    assert!(
        dist.assets.stats().requests() > after_first,
        "a set missing its own files was reported as current"
    );
    assert!(
        paths(root.path())
            .assets
            .join("432/UIRes/font.otf")
            .is_file()
    );
    Ok(())
}

/// The setting is what reaches the distribution. A launch that never calls this makes no request at all,
/// which is the promise the opt-in rests on.
#[tokio::test]
async fn preparing_a_launch_on_its_own_contacts_nothing() -> Result<(), Box<dyn Error>> {
    use std::collections::BTreeMap;

    let root = tempfile::tempdir()?;
    let dist = Distribution::start(false, 432).await?;
    let dalamud = dalamud(root.path(), &dist)?;
    let prefix = prefix(&root.path().join("prefix"))?;
    let plan =
        apogee_runtime::LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new()).prefix(&prefix);

    dalamud.prepare_launch(&plan, &SetupEvents::none())?;

    for server in dist.servers() {
        assert_eq!(
            server.stats().requests(),
            0,
            "a launch that never asked for an install still reached the distribution"
        );
    }
    Ok(())
}
