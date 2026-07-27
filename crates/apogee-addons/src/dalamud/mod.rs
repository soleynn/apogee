//! Dalamud: installed from its own distribution, and reaching the game by wrapping its launch.
//!
//! Opt-in and nothing else. Every endpoint below is contacted only once a launch has asked for it, so a
//! user who leaves the setting off never contacts goatcorp; that is asserted rather than asserted-to.
//!
//! The bytes are not pinned by Apogee's signed manifest, because their version is upstream's to choose
//! and a pin has to describe bytes somebody keeps serving. The manifest carries a *pointer* instead: the
//! distribution endpoint and the support tier, both correctable by an edit and a re-sign. What stands in
//! for a pin is the digest map the distribution ships beside the bytes ([`integrity`]).
//!
//! Failure degrades rather than propagates. A version built for another game version, a tree that will
//! not verify, an endpoint that will not answer: each of them leaves the launch alone and says so. The
//! alternative is a launcher that refuses to start the game because a companion is between releases,
//! which is the wrong trade every time.

mod injector;
mod integrity;
mod wire;

use std::path::{Path, PathBuf};
use std::time::Duration;

use apogee_fetch::{DownloadSpec, Fetcher, Validator};
use apogee_runtime::{LaunchPlan, Prefix};
use async_trait::async_trait;
use tokio_util::sync::CancellationToken;
use url::Url;

pub use injector::{ClientLanguage, InjectorInvocation, LoadMode, PluginPolicy, injector_argv};
pub use wire::Installed;

use crate::manifest::InjectableEntry;
use crate::setup::{SetupEvent, SetupEvents};
use crate::{AddonError, Injectable, Result, SupportTier};
use integrity::Digest;
use wire::{AssetMeta, HashManifest, VersionInfo};

/// The name this companion is recorded and reported under.
pub const DALAMUD: &str = "Dalamud";

/// The runner Dalamud's injector is known to work behind. Its name is matched loosely because the
/// catalog publishes variants (staging, and a version suffix), and the point is to say what the runner
/// costs rather than to gate on it.
const STEERED_RUNNER: &str = "wine-xiv";

/// An empty JSON object, base64-encoded: the troubleshooting pack Dalamud's crash reporting expects to
/// exist. There is nothing this launcher wants to put in it, and the flag is not optional upstream, so
/// it carries the smallest well-formed value there is.
const EMPTY_TROUBLESHOOTING_PACK: &str = "e30=";

/// The trees Dalamud installs into. Siblings under one root, so pointing it elsewhere or deleting it is
/// one directory either way.
#[derive(Debug, Clone, Default)]
pub struct DalamudPaths {
    /// Holds `Hooks/<assembly version>/`, one directory per release.
    pub addon: PathBuf,
    /// The bundled .NET runtime, shared across releases and versioned by a marker inside it.
    pub runtime: PathBuf,
    /// Holds `<asset version>/`, one directory per asset set.
    pub assets: PathBuf,
    /// Dalamud's own configuration and the user's installed plugins.
    pub config: PathBuf,
    /// Where Dalamud writes its logs.
    pub logs: PathBuf,
}

impl DalamudPaths {
    /// The standard layout beneath one root.
    #[must_use]
    pub fn under(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            addon: root.join("addon"),
            runtime: root.join("runtime"),
            assets: root.join("assets"),
            config: root.join("config"),
            logs: root.join("logs"),
        }
    }

    fn hooks(&self) -> PathBuf {
        self.addon.join("Hooks")
    }

    fn version_dir(&self, assembly_version: &str) -> PathBuf {
        self.hooks().join(assembly_version)
    }

    fn asset_dir(&self, version: u32) -> PathBuf {
        self.assets.join(version.to_string())
    }

    fn plugins(&self) -> PathBuf {
        self.config.join("installedPlugins")
    }

    fn config_file(&self) -> PathBuf {
        self.config.join("dalamudConfig.json")
    }

    /// What a completed install wrote down about itself.
    fn record(&self) -> PathBuf {
        self.addon.join("installed.json")
    }

    /// Where a download in progress writes, cleared before every attempt.
    fn staging(&self) -> PathBuf {
        self.addon.join(".fetching")
    }
}

/// How this launch wants Dalamud loaded.
#[derive(Debug, Clone)]
pub struct DalamudConfig {
    pub mode: LoadMode,
    pub language: ClientLanguage,
    /// How long Dalamud waits before initializing. Zero unless something needs it.
    pub delay_initialize: Duration,
    pub plugins: PluginPolicy,
    /// The install's own `ffxivgame.ver`. A release built for a different one is not loaded.
    pub game_version: String,
}

impl Default for DalamudConfig {
    fn default() -> Self {
        Self {
            mode: LoadMode::default(),
            language: ClientLanguage::default(),
            delay_initialize: Duration::ZERO,
            plugins: PluginPolicy::default(),
            game_version: String::new(),
        }
    }
}

/// The endpoints one distribution serves, derived from the pointer the manifest row carries.
///
/// Derived rather than listed row by row, because they are one service's layout and a row that could
/// name them separately could also name five different hosts. Constructible directly so a test can
/// stand each one up on its own server.
#[derive(Debug, Clone)]
pub struct Endpoints {
    /// Where a release is described.
    pub version_info: Url,
    /// The directory the runtime endpoints hang off.
    pub release_base: Url,
    /// Where the asset set is described.
    pub asset_meta: Url,
}

impl Endpoints {
    /// The layout around a `.../Release/VersionInfo` pointer.
    ///
    /// `None` when the pointer is not shaped like one, which is a manifest mistake rather than a
    /// runtime condition: every other endpoint is a sibling of it.
    #[must_use]
    pub fn derive(version_info: &Url) -> Option<Self> {
        let release_base = version_info.join("./").ok()?;
        let asset_meta = release_base.join("../Asset/Meta").ok()?;
        Some(Self {
            version_info: version_info.clone(),
            release_base,
            asset_meta,
        })
    }

    fn runtime_hashes(&self, version: &str) -> Option<Url> {
        self.release_base
            .join(&format!("Runtime/Hashes/{version}"))
            .ok()
    }

    fn runtime_archives(&self, version: &str) -> Option<(Url, Url)> {
        Some((
            self.release_base
                .join(&format!("Runtime/DotNet/{version}"))
                .ok()?,
            self.release_base
                .join(&format!("Runtime/WindowsDesktop/{version}"))
                .ok()?,
        ))
    }

    /// The version-info request for the release track.
    ///
    /// The rollout bucket is sent as the stable one rather than sampled. Upstream picks a bucket at
    /// random once and remembers it, which spreads a bad release across a fraction of installs; a
    /// launcher that says which half it is in every time is one fewer thing that differs between two
    /// machines reporting different behaviour.
    fn release_query(&self) -> Url {
        let mut url = self.version_info.clone();
        url.query_pairs_mut()
            .append_pair("track", "release")
            .append_pair("bucket", "Control");
        url
    }
}

/// Dalamud, behind the launch setting.
#[derive(Debug, Clone)]
pub struct Dalamud {
    paths: DalamudPaths,
    fetcher: Fetcher,
    endpoints: Option<Endpoints>,
    tier: SupportTier,
    caveats: Vec<String>,
    config: DalamudConfig,
}

impl Dalamud {
    /// Build it from the manifest row that points at its distribution.
    #[must_use]
    pub fn new(
        paths: DalamudPaths,
        fetcher: Fetcher,
        entry: &InjectableEntry,
        config: DalamudConfig,
    ) -> Self {
        Self {
            paths,
            fetcher,
            endpoints: Endpoints::derive(&entry.distribution),
            tier: entry.tier.clone(),
            caveats: entry.caveats.clone(),
            config,
        }
    }

    /// Point it at endpoints assembled by hand, so a test can serve each one separately.
    #[must_use]
    pub fn with_endpoints(mut self, endpoints: Endpoints) -> Self {
        self.endpoints = Some(endpoints);
        self
    }

    /// What a completed install left behind, or `None` when nothing is installed.
    ///
    /// Read from disk rather than remembered, because the launch path runs in a different call from the
    /// install and must be able to answer without one.
    #[must_use]
    pub fn installed(&self) -> Option<Installed> {
        let bytes = std::fs::read(self.paths.record()).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn endpoints(&self) -> Result<&Endpoints> {
        self.endpoints.as_ref().ok_or_else(|| AddonError::Inject {
            injectable: DALAMUD.to_owned(),
            tier: self.tier.clone(),
            source: Box::new(std::io::Error::other(
                "the manifest's distribution pointer is not a shape the other endpoints hang off",
            )),
        })
    }

    /// Say what this row's own caveats are, and what the runner in front of it costs, before anything is
    /// fetched.
    ///
    /// The tier note is not said here. It is said for every injectable by the loop that installs them,
    /// so a second one gets the warning by existing rather than by remembering to announce itself.
    fn announce(&self, prefix: &Prefix, events: &SetupEvents) {
        for caveat in &self.caveats {
            events.emit(SetupEvent::Caveat {
                what: DALAMUD.to_owned(),
                note: caveat.clone(),
            });
        }
        // Steering rather than gating. The injector's process handoff was written against a patched
        // wine, so another runner is a worse bet and the user should hear which one they are on; it is
        // still their prefix, and refusing to install would take the choice away over a maybe.
        let runner = prefix.runner().name();
        if !runner.contains(STEERED_RUNNER) {
            events.emit(SetupEvent::Caveat {
                what: DALAMUD.to_owned(),
                note: format!(
                    "this prefix runs under {runner}; Dalamud is best supported on a {STEERED_RUNNER} runner"
                ),
            });
        }
    }

    /// The whole install, in the order the distribution's own client does it.
    async fn install(&self, events: &SetupEvents, cancel: &CancellationToken) -> Result<()> {
        let endpoints = self.endpoints()?;
        let info: VersionInfo = self
            .fetch_json(&endpoints.release_query(), "release", cancel)
            .await?;

        let version_dir = self.paths.version_dir(&info.assembly_version);
        if !self.tree_is_intact(&version_dir) {
            events.emit(SetupEvent::Installing {
                what: DALAMUD.to_owned(),
                version: info.assembly_version.clone(),
            });
            let url = self.absolute(&info.download_url)?;
            self.lay_down(&url, &version_dir, DALAMUD, events, cancel)
                .await?;
            if !self.tree_is_intact(&version_dir) {
                return Err(
                    self.failed("the version that was downloaded does not match its own hashes")
                );
            }
        }

        if info.runtime_required {
            self.ensure_runtime(&info.runtime_version, events, cancel)
                .await?;
        }

        let asset_version = self.ensure_assets(events, cancel).await?;

        self.write_record(&Installed {
            assembly_version: info.assembly_version.clone(),
            supported_game_ver: info.supported_game_ver.clone(),
            runtime_version: info.runtime_version.clone(),
            track: info.track.clone(),
            asset_version,
        })?;
        events.emit(SetupEvent::Installed {
            what: DALAMUD.to_owned(),
        });
        // Said after the install rather than instead of it, because an out-of-date Dalamud is still
        // worth having on disk: the next game patch is as likely to move the game onto it as off it.
        if info.supported_game_ver != self.config.game_version {
            events.emit(SetupEvent::Caveat {
                what: DALAMUD.to_owned(),
                note: format!(
                    "this release targets game version {}, and the install is {}; it will not be loaded",
                    info.supported_game_ver, self.config.game_version
                ),
            });
        }
        Ok(())
    }

    /// Whether a version directory is complete and matches the digest map it ships with.
    fn tree_is_intact(&self, version_dir: &Path) -> bool {
        if !integrity::required_files_present(version_dir) {
            return false;
        }
        let Ok(bytes) = std::fs::read(version_dir.join("hashes.json")) else {
            // The map ships inside the archive, so its absence is an incomplete tree rather than a
            // distribution that declined to publish one.
            return false;
        };
        serde_json::from_slice::<HashManifest>(&bytes)
            .is_ok_and(|manifest| integrity::verify_tree(version_dir, &manifest, Digest::Md5))
    }

    /// Bring the bundled runtime to `version`, which is two archives overlaid into one tree.
    ///
    /// The marker beside the tree is a **seal**, not a note: it is written only once both archives have
    /// extracted *and* the result has matched the digest map published for that version. So a marker
    /// naming the version being asked for is a tree this launcher verified, and a later pass trusts it
    /// rather than hashing it again.
    ///
    /// That trade is deliberate and it is where most of a no-op pass's cost went: the runtime is 481
    /// files and about 170 MiB of stock Microsoft redistributable, and hashing it on every launch buys
    /// nothing the seal does not already say. What it would have caught is damage done after a verified
    /// install by something other than this launcher, and the answer to that is to install it again. The
    /// version directory Dalamud itself lives in is still swept every pass, because that is the code
    /// being loaded into the game and it is the tree the digest map is really for.
    async fn ensure_runtime(
        &self,
        version: &str,
        events: &SetupEvents,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let marker = self.paths.runtime.join("version");
        if std::fs::read_to_string(&marker).unwrap_or_default().trim() == version {
            return Ok(());
        }
        let endpoints = self.endpoints()?;
        let (dotnet, desktop) = endpoints
            .runtime_archives(version)
            .ok_or_else(|| self.failed("the runtime endpoints cannot be derived"))?;
        events.emit(SetupEvent::Installing {
            what: "Dalamud runtime".to_owned(),
            version: version.to_owned(),
        });
        // The marker goes first, so a pass interrupted anywhere below leaves a tree that reads as
        // unsealed rather than as one that verified.
        let _ = std::fs::remove_file(&marker);
        for url in [dotnet, desktop] {
            self.lay_down(&url, &self.paths.runtime, "Dalamud runtime", events, cancel)
                .await?;
        }
        // The marker is written *before* the check, because the published map describes it: the
        // distribution lists `version` as an entry whose digest is the version string's, so a tree
        // without it is a tree that is one file short. Written with no trailing newline for the same
        // reason, since the digest is over the bare string.
        write_atomic(&marker, version.as_bytes()).map_err(|source| AddonError::Io {
            what: DALAMUD.to_owned(),
            step: "seal the runtime",
            source: Box::new(source),
        })?;
        if !self.runtime_matches(version, cancel).await {
            // Unsealed rather than left behind: the next pass lays it down again instead of trusting a
            // marker for a tree that did not verify.
            let _ = std::fs::remove_file(&marker);
            return Err(
                self.failed("the runtime that was downloaded does not match its own hashes")
            );
        }
        Ok(())
    }

    /// Whether the runtime on disk matches the digest map published for `version`.
    ///
    /// The map is cached beside the tree so a re-install costs no second request. A map that cannot be
    /// fetched and was never cached answers "no", which refuses the seal: there is no third answer, and
    /// an unsealed tree is laid down again next pass rather than trusted.
    async fn runtime_matches(&self, version: &str, cancel: &CancellationToken) -> bool {
        let cache = self.paths.runtime.join(format!("hashes-{version}.json"));
        let cached = std::fs::read(&cache)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<HashManifest>(&bytes).ok());
        let manifest = match cached {
            Some(manifest) => manifest,
            None => {
                let Ok(endpoints) = self.endpoints() else {
                    return false;
                };
                let Some(url) = endpoints.runtime_hashes(version) else {
                    return false;
                };
                let Ok(fetched) = self
                    .fetch_json::<HashManifest>(&url, "runtime hashes", cancel)
                    .await
                else {
                    return false;
                };
                if let Ok(bytes) = serde_json::to_vec(&fetched) {
                    let _ = write_atomic(&cache, &bytes);
                }
                fetched
            }
        };
        integrity::verify_tree(&self.paths.runtime, &manifest, Digest::Md5)
    }

    /// Bring the asset set current, returning the version now on disk.
    ///
    /// Two conditions, not one. A higher published version means a refresh; so does an asset that is
    /// missing or no longer matches its digest, at the same version, because that is what a half-written
    /// set looks like and a version number alone would call it current forever.
    async fn ensure_assets(&self, events: &SetupEvents, cancel: &CancellationToken) -> Result<u32> {
        let endpoints = self.endpoints()?;
        let meta: AssetMeta = self
            .fetch_json(&endpoints.asset_meta, "assets", cancel)
            .await?;
        let dir = self.paths.asset_dir(meta.version);
        let local = std::fs::read_to_string(self.paths.assets.join("asset.ver"))
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok())
            .unwrap_or(0);

        if meta.version <= local && self.assets_are_intact(&dir, &meta) {
            return Ok(meta.version);
        }
        events.emit(SetupEvent::Installing {
            what: "Dalamud assets".to_owned(),
            version: meta.version.to_string(),
        });
        let url = self.absolute(&meta.package_url)?;
        self.lay_down(&url, &dir, "Dalamud assets", events, cancel)
            .await?;
        if !self.assets_are_intact(&dir, &meta) {
            return Err(
                self.failed("the assets that were downloaded do not match their own digests")
            );
        }
        write_atomic(
            &self.paths.assets.join("asset.ver"),
            meta.version.to_string().as_bytes(),
        )
        .map_err(|source| AddonError::Io {
            what: DALAMUD.to_owned(),
            step: "record the asset version",
            source: Box::new(source),
        })?;
        Ok(meta.version)
    }

    fn assets_are_intact(&self, dir: &Path, meta: &AssetMeta) -> bool {
        meta.assets.iter().all(|asset| {
            let path = integrity::resolve(dir, &asset.file_name);
            match asset.digest() {
                Some(expected) => {
                    integrity::hash_file(&path, Digest::Sha1).is_ok_and(|found| found == expected)
                }
                None => path.is_file(),
            }
        })
    }

    /// Fetch one JSON document from the distribution.
    ///
    /// Into a staging file that is cleared first: these carry no content pin and no declared length, and
    /// under those terms the fetcher treats an existing file at the destination as already satisfying
    /// the request. Downloading onto a stable path would serve the first release ever fetched back
    /// forever while everything appeared to work.
    async fn fetch_json<T: serde::de::DeserializeOwned>(
        &self,
        url: &Url,
        what: &'static str,
        cancel: &CancellationToken,
    ) -> Result<T> {
        let staging = self.paths.staging();
        let _ = tokio::fs::remove_dir_all(&staging).await;
        tokio::fs::create_dir_all(&staging)
            .await
            .map_err(|source| self.io_failed("stage a download", &staging, source))?;
        let dest = staging.join(format!("{}.json", what.replace(' ', "-")));
        self.download(url, &dest, what, &SetupEvents::none(), cancel)
            .await?;
        let bytes = tokio::fs::read(&dest)
            .await
            .map_err(|source| self.io_failed("read a download", &dest, source))?;
        let parsed = serde_json::from_slice(&bytes).map_err(|source| AddonError::Distribution {
            injectable: DALAMUD.to_owned(),
            source: Box::new(source),
        })?;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        Ok(parsed)
    }

    /// Download a zip and extract it over `dest`.
    ///
    /// Over rather than into a cleared directory: the runtime is two archives laid on top of each other,
    /// and a version directory is replaced wholesale by its caller when it is the one being replaced.
    async fn lay_down(
        &self,
        url: &Url,
        dest: &Path,
        what: &str,
        events: &SetupEvents,
        cancel: &CancellationToken,
    ) -> Result<()> {
        let staging = self.paths.staging();
        let _ = tokio::fs::remove_dir_all(&staging).await;
        tokio::fs::create_dir_all(&staging)
            .await
            .map_err(|source| self.io_failed("stage a download", &staging, source))?;
        let archive = staging.join("archive.zip");
        self.download(url, &archive, what, events, cancel).await?;

        let target = dest.to_path_buf();
        let named = what.to_owned();
        let entries = tokio::task::spawn_blocking(move || extract(&archive, &target, &named))
            .await
            .map_err(|_| self.failed("the extraction task did not finish"))??;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        if entries == 0 {
            return Err(self.failed("the archive that was served held nothing"));
        }
        Ok(())
    }

    async fn download(
        &self,
        url: &Url,
        dest: &Path,
        what: &str,
        events: &SetupEvents,
        cancel: &CancellationToken,
    ) -> Result<()> {
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|source| self.io_failed("stage a download", parent, source))?;
        }
        // No content pin: the distribution versions these itself and the digest maps beside them are
        // what authenticates the bytes. The fetcher still refuses plain http.
        let spec = DownloadSpec::builder(url.clone(), dest, Validator::None)
            .allow_unverified()
            .build()?;
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<apogee_fetch::Progress>();
        let sink = events.clone();
        let name = what.to_owned();
        let relay = tokio::spawn(async move {
            while let Some(progress) = rx.recv().await {
                sink.emit(SetupEvent::Downloading {
                    what: name.clone(),
                    bytes_done: progress.bytes_done,
                    total: progress.total,
                });
            }
        });
        let outcome = self
            .fetcher
            .download(&spec, Some(tx.clone()), cancel.clone())
            .await;
        drop(tx);
        let _ = relay.await;
        outcome?;
        Ok(())
    }

    fn write_record(&self, record: &Installed) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(record).map_err(|source| AddonError::Io {
            what: DALAMUD.to_owned(),
            step: "record what it installed",
            source: Box::new(source),
        })?;
        write_atomic(&self.paths.record(), &bytes).map_err(|source| AddonError::Io {
            what: DALAMUD.to_owned(),
            step: "record what it installed",
            source: Box::new(source),
        })
    }

    /// One URL the distribution served, parsed at the point of use so a response that is not a URL is
    /// this crate's typed error rather than a deserializer's.
    fn absolute(&self, raw: &str) -> Result<Url> {
        Url::parse(raw).map_err(|source| AddonError::Distribution {
            injectable: DALAMUD.to_owned(),
            source: Box::new(source),
        })
    }

    fn failed(&self, detail: &'static str) -> AddonError {
        AddonError::Inject {
            injectable: DALAMUD.to_owned(),
            tier: self.tier.clone(),
            source: Box::new(std::io::Error::other(detail)),
        }
    }

    fn io_failed(&self, step: &'static str, path: &Path, source: std::io::Error) -> AddonError {
        AddonError::Io {
            what: DALAMUD.to_owned(),
            step,
            source: Box::new(std::io::Error::new(
                source.kind(),
                format!("{}: {source}", path.display()),
            )),
        }
    }
}

#[async_trait]
impl Injectable for Dalamud {
    fn name(&self) -> &str {
        DALAMUD
    }

    fn support_tier(&self) -> SupportTier {
        self.tier.clone()
    }

    async fn ensure(
        &self,
        prefix: &Prefix,
        cancel: &CancellationToken,
        events: &SetupEvents,
    ) -> Result<()> {
        self.announce(prefix, events);
        self.install(events, cancel).await
    }

    fn prepare_launch(&self, plan: &mut LaunchPlan, events: &SetupEvents) -> Result<()> {
        let decline = |note: &str| {
            events.emit(SetupEvent::Caveat {
                what: DALAMUD.to_owned(),
                note: format!("not loading into this launch: {note}"),
            });
        };
        let Some(installed) = self.installed() else {
            decline("nothing is installed");
            return Ok(());
        };
        // The one hard gate. Dalamud reads the client's memory at offsets it was built for, so loading
        // it into another version is not a degraded experience, it is a crash.
        if installed.supported_game_ver != self.config.game_version {
            decline(&format!(
                "the installed release targets game version {}, and this install is {}",
                installed.supported_game_ver, self.config.game_version
            ));
            return Ok(());
        }
        let Some(prefix) = plan.prefix_of().cloned() else {
            decline("this launch has no prefix to translate paths against");
            return Ok(());
        };
        self.wrap(&prefix, &installed, plan)
    }
}

impl Dalamud {
    /// Redirect `plan` through the injector, with every path in the form the injector reads.
    ///
    /// Translation is in-process against the prefix's own drive map, not seven `winepath` subprocesses
    /// on the launch path. The injector itself is named by its host path, since the runner is what
    /// executes it and a Windows path there would be one indirection for nothing.
    #[cfg(target_os = "linux")]
    fn wrap(&self, prefix: &Prefix, installed: &Installed, plan: &mut LaunchPlan) -> Result<()> {
        let drives = prefix.drive_map().map_err(|source| AddonError::Inject {
            injectable: DALAMUD.to_owned(),
            tier: self.tier.clone(),
            source: Box::new(source),
        })?;
        let to_windows = |path: &Path| -> Result<String> {
            drives
                .to_windows(path)
                .map_err(|source| AddonError::Inject {
                    injectable: DALAMUD.to_owned(),
                    tier: self.tier.clone(),
                    source: Box::new(source),
                })
        };

        let version_dir = self.paths.version_dir(&installed.assembly_version);
        let game = to_windows(Path::new(plan.program()))?;
        let working_directory = to_windows(&version_dir)?;
        let configuration_path = to_windows(&self.paths.config_file())?;
        let logging_path = to_windows(&self.paths.logs)?;
        let plugin_directory = to_windows(&self.paths.plugins())?;
        let asset_directory = to_windows(&self.paths.asset_dir(installed.asset_version))?;
        let runtime = to_windows(&self.paths.runtime)?;

        // The injector starts the game as a separate process, so what the launcher waits on stays the
        // game. Without this it would track the injector, see it exit, and report the launch as over
        // while the game was still starting.
        let supervised = Path::new(plan.program())
            .file_name()
            .map(|name| name.to_string_lossy().into_owned());

        plan.set_inserted_args(injector_argv(&InjectorInvocation {
            mode: self.config.mode,
            game: &game,
            working_directory: &working_directory,
            configuration_path: &configuration_path,
            logging_path: &logging_path,
            plugin_directory: &plugin_directory,
            asset_directory: &asset_directory,
            client_language: self.config.language,
            delay_initialize_ms: self
                .config
                .delay_initialize
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX),
            troubleshooting_b64: EMPTY_TROUBLESHOOTING_PACK,
            plugins: self.config.plugins,
        }));
        plan.set_program(version_dir.join("Dalamud.Injector.exe").to_string_lossy());
        if let Some(basename) = supervised {
            plan.set_supervised(basename);
        }
        // Both, and both in Windows form: the injector reads one and the runtime it starts reads the
        // other, and a Unix path in either is a runtime that does not resolve.
        let env = plan.env_mut();
        env.insert("DALAMUD_RUNTIME".to_owned(), runtime.clone());
        env.insert("DOTNET_ROOT".to_owned(), runtime);
        env.insert("DALAMUD_BRANCH".to_owned(), installed.track.clone());
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn wrap(&self, _prefix: &Prefix, _installed: &Installed, _plan: &mut LaunchPlan) -> Result<()> {
        Err(AddonError::Unsupported {
            what: "redirecting a launch through an injector is Linux-only",
        })
    }
}

/// Extract on a blocking thread. Split out so the non-Linux build has somewhere to say no: the
/// extractor is part of the runner surface, which is Linux-first.
#[cfg(target_os = "linux")]
fn extract(archive: &Path, dest: &Path, what: &str) -> Result<u64> {
    let layout = apogee_runtime::ArchiveLayout {
        format: apogee_runtime::ArchiveFormat::Zip,
        strip_prefix: None,
    };
    apogee_runtime::extract_archive(archive, &layout, dest).map_err(|source| AddonError::Unpack {
        what: what.to_owned(),
        source: Box::new(source),
    })
}

#[cfg(not(target_os = "linux"))]
fn extract(_archive: &Path, _dest: &Path, _what: &str) -> Result<u64> {
    Err(AddonError::Unsupported {
        what: "unpacking an injectable goes through a prefix runner, which is Linux-only",
    })
}

/// Write `bytes` to `path` through a temporary file, so a reader never sees a half-written record.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests;
