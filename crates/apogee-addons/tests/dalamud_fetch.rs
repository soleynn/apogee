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
    AddonPaths, Dalamud, DalamudConfig, DalamudPaths, Injectable, SetupEvent, SetupEvents,
    VerifiedManifest,
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
/// distribution ships inside it, with `extra` keys appended to that map as written.
fn release_zip(extra: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let hashes = format!(
        r#"{{ "Dalamud.Injector.exe": "{INJECTOR_MD5}",
              "Dalamud.dll": "{DALAMUD_MD5}",
              "ImGuiScene.dll": "{IMGUI_MD5}"{extra} }}"#
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

/// How one distribution differs from the ordinary one.
#[derive(Default)]
struct Shape {
    runtime_required: bool,
    asset_version: u32,
    /// Cut the release archive's first body off after this many bytes.
    drop_release_after: Option<u64>,
    /// Appended to the release's digest map as written, a leading comma included.
    extra_release_hashes: &'static str,
    /// The path the release names its archive at, in place of `dalamud.zip`.
    release_path: Option<String>,
    /// Answer every release request with a `302` to this, instead of serving the archive.
    release_redirect: Option<String>,
    /// The name the asset metadata gives its digested asset, in place of `UIRes/font.otf`.
    asset_file_name: Option<&'static str>,
}

impl Distribution {
    // `Box<dyn Error>` is not `Send`, which is only a problem for a future handed to a multi-threaded
    // executor. `#[tokio::test]` runs this one single-threaded, and `Box<dyn Error>` is the ordinary
    // idiom for a test's own error type.
    #[allow(clippy::future_not_send)]
    async fn start(runtime_required: bool, asset_version: u32) -> Result<Self, Box<dyn Error>> {
        Self::start_shaped(Shape {
            runtime_required,
            asset_version,
            ..Shape::default()
        })
        .await
    }

    /// The same distribution with the release archive's first download cut off after `after` bytes,
    /// so the transfer has to recover and has a tally to report for it.
    #[allow(clippy::future_not_send)]
    async fn start_flaky(asset_version: u32, after: u64) -> Result<Self, Box<dyn Error>> {
        Self::start_shaped(Shape {
            asset_version,
            drop_release_after: Some(after),
            ..Shape::default()
        })
        .await
    }

    #[allow(clippy::future_not_send)]
    async fn start_shaped(shape: Shape) -> Result<Self, Box<dyn Error>> {
        let Shape {
            runtime_required,
            asset_version,
            drop_release_after,
            extra_release_hashes,
            release_path,
            release_redirect,
            asset_file_name,
        } = shape;
        let mut release_builder = ChaosServer::serving(release_zip(extra_release_hashes)?).tls();
        if let Some(after) = drop_release_after {
            // Chunked, or there is nothing to cut: the archive is a few hundred bytes and goes out in
            // one write, which the drop threshold never gets between.
            release_builder = release_builder.drop_after(after).chunk(16);
        }
        if let Some(location) = release_redirect {
            release_builder = release_builder.redirect_to(302, location);
        }
        let release = release_builder.start().await?;
        let release_path = release_path.unwrap_or_else(|| "dalamud.zip".to_owned());
        let asset_file_name = asset_file_name.unwrap_or("UIRes/font.otf");
        let assets = ChaosServer::serving(asset_zip()?).tls().start().await?;
        let version_info = format!(
            r#"{{ "assemblyVersion": "{ASSEMBLY_VERSION}",
                  "supportedGameVer": "{GAME_VERSION}",
                  "runtimeVersion": "10.0.0", "runtimeRequired": {runtime_required},
                  "track": "release",
                  "downloadUrl": "{release_url}" }}"#,
            release_url = release.url(&release_path),
        );
        let asset_meta = format!(
            r#"{{ "version": {asset_version},
                  "packageUrl": "{package}",
                  "assets": [
                    {{ "url": "{package}", "fileName": "{asset_file_name}", "hash": "{ASSET_SHA1}" }},
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

    const fn servers(&self) -> [&ChaosServer; 5] {
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

    /// The shipped fetcher, trusting all five loopback certificates and nothing else new.
    fn fetcher(&self) -> Result<Fetcher, Box<dyn Error>> {
        let mut builder = Fetcher::builder();
        for server in self.servers() {
            let der = server.cert_der().ok_or("server is not running over tls")?;
            builder = builder.extra_root_certificate(der);
        }
        Ok(builder.build()?)
    }
}

/// The manifest row behind the launch setting. Its distribution pointer is overridden per test, since
/// each endpoint has to live on a different host here.
fn catalog() -> Result<VerifiedManifest, Box<dyn Error>> {
    catalog_allowing("[]")
}

/// The same row, naming `hosts` (a JSON list) as the only ones its downloads may go to.
fn catalog_allowing(hosts: &str) -> Result<VerifiedManifest, Box<dyn Error>> {
    let json = format!(
        r#"{{ "version": 1, "injectables": [
        {{ "name": "Dalamud", "kind": "dalamud",
          "distribution": "https://kamori.goats.dev/Dalamud/Release/VersionInfo",
          "tier": "best_effort", "note": "Best with the wine-xiv runner.",
          "allowed_hosts": {hosts} }} ] }}"#
    );
    let signature = apogee_test_support::catalog_sign::sign_manifest(json.as_bytes());
    Ok(VerifiedManifest::verify(
        json.as_bytes(),
        &signature,
        &[apogee_test_support::catalog_sign::test_verifying_key_bytes()],
    )?)
}

fn dalamud(root: &Path, dist: &Distribution) -> Result<Dalamud, Box<dyn Error>> {
    dalamud_under(root, dist, &catalog()?)
}

fn dalamud_under(
    root: &Path,
    dist: &Distribution,
    catalog: &VerifiedManifest,
) -> Result<Dalamud, Box<dyn Error>> {
    let config = DalamudConfig {
        game_version: GAME_VERSION.to_owned(),
        ..DalamudConfig::default()
    };
    Ok(Dalamud::new(
        AddonPaths::new(root).dalamud(),
        dist.fetcher()?,
        catalog,
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

/// A download that had to recover says so on the setup stream.
///
/// The whole reason the tally exists is that a recovery ends in success, so this install looks
/// identical to a clean one from every other angle: the same files land and `ensure` returns `Ok`.
/// Before the tally was relayed, "the release archive took two attempts" was reachable from nowhere
/// outside the fetch crate's own process.
#[tokio::test]
async fn a_recovered_download_reports_its_tally_on_the_setup_stream() -> Result<(), Box<dyn Error>>
{
    let root = tempfile::tempdir()?;
    // The release archive's first body is cut off part way, so the transfer retries and completes.
    let dist = Distribution::start_flaky(432, 64).await?;
    let dalamud = dalamud(root.path(), &dist)?;
    let prefix = prefix(&root.path().join("prefix"))?;

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::new(tx))
        .await?;

    let mut seen = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let SetupEvent::Downloading { recoveries, .. } = event {
            seen.push(recoveries);
        }
    }
    assert!(
        !seen.is_empty(),
        "a download must report progress on the setup stream",
    );
    let worst = seen.iter().map(|r| r.retries).max().unwrap_or(0);
    assert_eq!(
        worst, 1,
        "the cut-off release archive retried once and the tally should say so: {seen:?}",
    );
    // The install still succeeded, which is exactly why nothing else would have said this.
    let paths = paths(root.path());
    assert!(
        paths
            .addon
            .join(format!("Hooks/{ASSEMBLY_VERSION}/Dalamud.Injector.exe"))
            .is_file(),
    );
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
        apogee_runtime::LaunchPlan::new("ffxiv_dx11.exe", "", BTreeMap::new()).in_prefix(&prefix);

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

/// The hosts every test distribution lives on, as a row would name them: the pointer's own, which the
/// row must admit, and the loopback address every chaos server answers on.
const LOOPBACK_ROW: &str = r#"["kamori.goats.dev", "127.0.0.1"]"#;

/// An allowed host that answers `302` to a host the row does not name is refused before that host is
/// asked anything, and the install fails rather than degrades. The host it would have gone to holds
/// the exact archive the release names, so nothing but the refusal stops it.
#[tokio::test]
async fn a_redirect_off_the_rows_hosts_is_refused_before_the_second_connect()
-> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let elsewhere = ChaosServer::serving(release_zip("")?).tls().start().await?;
    let mut off_list = elsewhere.url("dalamud.zip");
    off_list
        .set_host(Some("localhost"))
        .map_err(|e| e.to_string())?;
    let dist = Distribution::start_shaped(Shape {
        asset_version: 432,
        release_redirect: Some(off_list.to_string()),
        ..Shape::default()
    })
    .await?;
    let dalamud = dalamud_under(root.path(), &dist, &catalog_allowing(LOOPBACK_ROW)?)?;
    let prefix = prefix(&root.path().join("prefix"))?;

    let err = dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
        .await
        .err()
        .ok_or("an off-list redirect was followed")?;

    assert!(
        matches!(
            &err,
            apogee_addons::AddonError::Download(
                apogee_fetch::FetchError::RedirectHostNotAllowed { host, .. }
            ) if host == "localhost"
        ),
        "got {err:?}"
    );
    assert_eq!(
        elsewhere.stats().requests(),
        0,
        "the off-list host was contacted"
    );
    assert_eq!(
        dist.release.stats().requests(),
        1,
        "a refused hop was asked again"
    );
    assert!(
        dalamud.installed().is_none(),
        "a refused install was recorded"
    );
    Ok(())
}

/// The control for the case above: the same redirect onto a host the row does name is followed and
/// installs, so the refusal is the list's doing and not a refusal of every redirect.
#[tokio::test]
async fn a_redirect_onto_the_rows_hosts_is_followed() -> Result<(), Box<dyn Error>> {
    let root = tempfile::tempdir()?;
    let store = ChaosServer::serving(release_zip("")?).tls().start().await?;
    let dist = Distribution::start_shaped(Shape {
        asset_version: 432,
        release_redirect: Some(store.url("dalamud.zip").to_string()),
        ..Shape::default()
    })
    .await?;
    let mut builder = Fetcher::builder();
    for server in dist.servers().into_iter().chain([&store]) {
        builder = builder.extra_root_certificate(server.cert_der().ok_or("not tls")?);
    }
    let dalamud = Dalamud::new(
        AddonPaths::new(root.path()).dalamud(),
        builder.build()?,
        &catalog_allowing(LOOPBACK_ROW)?,
        DalamudConfig {
            game_version: GAME_VERSION.to_owned(),
            ..DalamudConfig::default()
        },
    )
    .ok_or("the fixture carries a Dalamud row")?
    .with_endpoints(dist.endpoints());
    let prefix = prefix(&root.path().join("prefix"))?;

    dalamud
        .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
        .await?;

    assert!(store.stats().requests() > 0, "the store served the archive");
    assert!(dalamud.installed().is_some());
    Ok(())
}

/// A release named by its content's sha256, as the real file host names every download, is held to
/// that digest. The archive served here is intact and its own digest map agrees with every file in
/// it, so the address is the only thing that can refuse it.
#[tokio::test]
async fn a_content_addressed_archive_must_hash_to_its_address() -> Result<(), Box<dyn Error>> {
    use sha2::{Digest as _, Sha256};

    let digest = Sha256::digest(release_zip("")?);
    let address: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    let wrong = "0".repeat(64);
    for (path, admitted) in [(&address, true), (&wrong, false)] {
        let root = tempfile::tempdir()?;
        let dist = Distribution::start_shaped(Shape {
            asset_version: 432,
            release_path: Some(format!("File/Get/{path}")),
            ..Shape::default()
        })
        .await?;
        let dalamud = dalamud(root.path(), &dist)?;
        let prefix = prefix(&root.path().join("prefix"))?;

        let outcome = dalamud
            .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
            .await;

        if admitted {
            outcome?;
        } else {
            let err = outcome
                .err()
                .ok_or("bytes that are not their address were accepted")?;
            assert!(
                matches!(
                    &err,
                    apogee_addons::AddonError::IntegrityMismatch { expected, got, .. }
                        if *expected == wrong && *got == address
                ),
                "got {err:?}"
            );
            assert!(
                !paths(root.path())
                    .addon
                    .join(format!("Hooks/{ASSEMBLY_VERSION}/Dalamud.Injector.exe"))
                    .exists(),
                "an archive that failed its address was extracted"
            );
        }
    }
    Ok(())
}

/// A digest map whose key climbs out of the tree fails the install as an unsafe path, whichever map
/// it is in. The file the release's key points at exists, holding exactly the bytes the map claims,
/// so a resolver that followed the key would call the tree intact.
#[tokio::test]
async fn a_digest_key_that_leaves_its_tree_fails_the_install() -> Result<(), Box<dyn Error>> {
    for (extra, asset, named) in [
        (
            r#", "..\\..\\escape.dll": "A312764C3972C532880BB8BB12BE8AF2""#,
            None,
            r"..\..\escape.dll",
        ),
        ("", Some("../../../escape.otf"), "../../../escape.otf"),
    ] {
        let root = tempfile::tempdir()?;
        let dist = Distribution::start_shaped(Shape {
            asset_version: 432,
            extra_release_hashes: extra,
            asset_file_name: asset,
            ..Shape::default()
        })
        .await?;
        let dalamud = dalamud(root.path(), &dist)?;
        let prefix = prefix(&root.path().join("prefix"))?;
        // Two levels above the version directory is the addon directory itself.
        let addon = paths(root.path()).addon;
        std::fs::create_dir_all(&addon)?;
        std::fs::write(addon.join("escape.dll"), b"injector")?;

        let err = dalamud
            .ensure(&prefix, &CancellationToken::new(), &SetupEvents::none())
            .await
            .err()
            .ok_or("a map naming a file outside its tree was accepted")?;

        assert!(
            matches!(
                &err,
                apogee_addons::AddonError::UnsafePath { path, .. } if path == Path::new(named)
            ),
            "{named}: got {err:?}"
        );
        assert!(dalamud.installed().is_none(), "{named}: it was recorded");
    }
    Ok(())
}
