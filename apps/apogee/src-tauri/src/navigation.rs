//! Confined operating-system navigation and the process-local paths it may reveal.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use apogee_core::{Core, SupportBundleData, Uuid};
use serde::{Deserialize, Serialize};
use tauri_plugin_dialog::DialogExt;
use ts_rs::TS;

use crate::{IpcErrorDto, ShellState, run_blocking};

const ACTIVITY_LIMIT: usize = 200;
const LINK_REJECTED: &str = "shell.activity.open-link-rejected";
const LINK_FAILED: &str = "shell.activity.open-link-failed";

/// A path-free request for one of the locations the launcher already owns.
#[derive(Debug, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
#[ts(export, export_to = "RevealTarget.ts")]
pub(crate) enum RevealTargetDto {
    BackupDir {
        #[ts(type = "string")]
        profile: Uuid,
    },
    Recycler {
        #[ts(type = "string")]
        profile: Uuid,
    },
    Evidence {
        #[ts(type = "string")]
        run: Uuid,
        #[ts(type = "string")]
        addon: Uuid,
    },
    SecretsFile,
    SupportBundle,
    GameFolder {
        #[ts(type = "string")]
        profile: Uuid,
    },
}

/// One stable, localizable diagnostic recorded by the native shell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "ActivityEntry.ts")]
pub(crate) struct ActivityEntryDto {
    sequence: u64,
    code: &'static str,
}

#[derive(Clone, Default)]
pub(crate) struct NavigationState(Arc<Mutex<Registry>>);

#[derive(Default)]
struct Registry {
    evidence: HashMap<(Uuid, Uuid), PathBuf>,
    pending_support_bundle: Option<SupportBundleData>,
    support_bundle: Option<PathBuf>,
    activity: VecDeque<ActivityEntryDto>,
    next_sequence: u64,
}

impl NavigationState {
    pub(crate) fn register_evidence(&self, run: Uuid, path: PathBuf) -> Uuid {
        let addon = Uuid::new_v4();
        let mut registry = self.lock();
        registry.evidence.insert((run, addon), path);
        addon
    }

    pub(crate) fn set_support_bundle(&self, path: PathBuf) {
        self.lock().support_bundle = Some(path);
    }

    pub(crate) fn set_pending_support_bundle(&self, bundle: SupportBundleData) {
        self.lock().pending_support_bundle = Some(bundle);
    }

    fn pending_support_bundle(&self) -> Option<SupportBundleData> {
        self.lock().pending_support_bundle.clone()
    }

    fn evidence(&self, run: Uuid, addon: Uuid) -> Option<PathBuf> {
        self.lock().evidence.get(&(run, addon)).cloned()
    }

    fn support_bundle(&self) -> Option<PathBuf> {
        self.lock().support_bundle.clone()
    }

    fn record(&self, code: &'static str) {
        let mut registry = self.lock();
        registry.next_sequence = registry.next_sequence.saturating_add(1);
        let sequence = registry.next_sequence;
        registry
            .activity
            .push_back(ActivityEntryDto { sequence, code });
        while registry.activity.len() > ACTIVITY_LIMIT {
            registry.activity.pop_front();
        }
    }

    fn activity(&self) -> Vec<ActivityEntryDto> {
        self.lock().activity.iter().cloned().collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        match self.0.lock() {
            Ok(registry) => registry,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

trait HostActions {
    fn open_https(&self, url: &str) -> Result<(), HostActionError>;
    fn open_directory(&self, path: &Path) -> Result<(), HostActionError>;
    fn reveal_file(&self, path: &Path) -> Result<(), HostActionError>;
}

#[derive(Debug, thiserror::Error)]
enum HostActionError {
    #[error("the requested target is not a file or directory of the required kind")]
    WrongTargetKind,
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    #[error("the requested file has no containing directory")]
    NoParent,
    #[cfg(target_os = "linux")]
    #[error("the requested path cannot be represented as a file URL")]
    InvalidFileUrl,
    #[error("the platform action failed")]
    Io(#[from] std::io::Error),
    #[cfg(target_os = "linux")]
    #[error("the desktop file manager request failed")]
    Bus(#[from] zbus::Error),
}

#[derive(Clone, Copy)]
struct SystemHostActions;

impl HostActions for SystemHostActions {
    fn open_https(&self, url: &str) -> Result<(), HostActionError> {
        open::that_detached(url).map_err(Into::into)
    }

    fn open_directory(&self, path: &Path) -> Result<(), HostActionError> {
        if !path.is_dir() {
            return Err(HostActionError::WrongTargetKind);
        }
        open::that_detached(path).map_err(Into::into)
    }

    fn reveal_file(&self, path: &Path) -> Result<(), HostActionError> {
        if !path.is_file() {
            return Err(HostActionError::WrongTargetKind);
        }
        reveal_file(path)
    }
}

#[cfg(target_os = "windows")]
fn reveal_file(path: &Path) -> Result<(), HostActionError> {
    use std::ffi::OsString;
    use std::process::Command;

    let mut select = OsString::from("/select,");
    select.push(path.as_os_str());
    Command::new("explorer.exe").arg(select).spawn()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn reveal_file(path: &Path) -> Result<(), HostActionError> {
    std::process::Command::new("open")
        .arg("-R")
        .arg(path)
        .spawn()?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn reveal_file(path: &Path) -> Result<(), HostActionError> {
    let path = std::fs::canonicalize(path)?;
    let uri = url::Url::from_file_path(path).map_err(|_| HostActionError::InvalidFileUrl)?;
    let connection = zbus::blocking::Connection::session()?;
    let proxy = zbus::blocking::Proxy::new(
        &connection,
        "org.freedesktop.FileManager1",
        "/org/freedesktop/FileManager1",
        "org.freedesktop.FileManager1",
    )?;
    proxy.call_method("ShowItems", &(vec![uri.as_str()], ""))?;
    Ok(())
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
fn reveal_file(path: &Path) -> Result<(), HostActionError> {
    let parent = path.parent().ok_or(HostActionError::NoParent)?;
    open::that_detached(parent).map_err(Into::into)
}

fn ordinary_https(url: &url::Url) -> bool {
    url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && matches!(url.port(), None | Some(443))
}

fn open_link_with(
    core: &Core,
    row_id: &str,
    navigation: &NavigationState,
    host: &dyn HostActions,
) -> Result<(), IpcErrorDto> {
    let url = match core.resolve_frontier_link(row_id) {
        Ok(url) if ordinary_https(&url) => url,
        Ok(_) => {
            navigation.record(LINK_REJECTED);
            return Err(IpcErrorDto::shell("shell.open-link.rejected"));
        }
        Err(error) => {
            navigation.record(LINK_REJECTED);
            return Err(IpcErrorDto::core(&error));
        }
    };
    host.open_https(url.as_str()).map_err(|error| {
        tracing::warn!(%error, "could not open a confined external link");
        navigation.record(LINK_FAILED);
        IpcErrorDto::shell("shell.open-link.failed")
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RevealKind {
    Directory,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedReveal {
    kind: RevealKind,
    path: PathBuf,
}

fn resolve_reveal(
    core: &Core,
    navigation: &NavigationState,
    target: RevealTargetDto,
) -> Result<ResolvedReveal, IpcErrorDto> {
    let directory = |path| ResolvedReveal {
        kind: RevealKind::Directory,
        path,
    };
    let file = |path| ResolvedReveal {
        kind: RevealKind::File,
        path,
    };
    Ok(match target {
        RevealTargetDto::BackupDir { profile } => directory(
            core.backup_directory(profile)
                .map_err(|error| IpcErrorDto::core(&error))?,
        ),
        RevealTargetDto::Recycler { profile } => directory(
            core.repair_recycler_directory(profile)
                .map_err(|error| IpcErrorDto::core(&error))?,
        ),
        RevealTargetDto::Evidence { run, addon } => file(
            navigation
                .evidence(run, addon)
                .ok_or_else(|| IpcErrorDto::shell("shell.reveal.unknown-evidence"))?,
        ),
        RevealTargetDto::SecretsFile => file(core.secrets_path().to_path_buf()),
        RevealTargetDto::SupportBundle => file(
            navigation
                .support_bundle()
                .ok_or_else(|| IpcErrorDto::shell("shell.reveal.no-support-bundle"))?,
        ),
        RevealTargetDto::GameFolder { profile } => directory(
            core.game_directory(profile)
                .map_err(|error| IpcErrorDto::core(&error))?,
        ),
    })
}

fn reveal_with(
    core: &Core,
    navigation: &NavigationState,
    target: RevealTargetDto,
    host: &dyn HostActions,
) -> Result<(), IpcErrorDto> {
    let resolved = resolve_reveal(core, navigation, target)?;
    let result = match resolved.kind {
        RevealKind::Directory => host.open_directory(&resolved.path),
        RevealKind::File => host.reveal_file(&resolved.path),
    };
    result.map_err(|error| {
        tracing::warn!(%error, "could not reveal a confined launcher path");
        IpcErrorDto::shell("shell.reveal.failed")
    })
}

#[tauri::command]
pub(crate) async fn open_link(
    state: tauri::State<'_, ShellState>,
    row_id: String,
) -> Result<(), IpcErrorDto> {
    let core = state.ready_core().await?;
    let navigation = state.navigation.clone();
    run_blocking(move || open_link_with(&core, &row_id, &navigation, &SystemHostActions)).await?
}

#[tauri::command]
pub(crate) async fn reveal(
    state: tauri::State<'_, ShellState>,
    target: RevealTargetDto,
) -> Result<(), IpcErrorDto> {
    let core = state.ready_core().await?;
    let navigation = state.navigation.clone();
    run_blocking(move || reveal_with(&core, &navigation, target, &SystemHostActions)).await?
}

#[tauri::command]
pub(crate) async fn activity_log(
    state: tauri::State<'_, ShellState>,
) -> Result<Vec<ActivityEntryDto>, IpcErrorDto> {
    Ok(state.navigation.activity())
}

/// Publish the last core-produced archive beneath a Rust-owned folder choice.
#[tauri::command]
pub(crate) async fn save_support_bundle(
    app: tauri::AppHandle,
    state: tauri::State<'_, ShellState>,
) -> Result<bool, IpcErrorDto> {
    let bundle = state
        .navigation
        .pending_support_bundle()
        .ok_or_else(|| IpcErrorDto::shell("shell.support-bundle.not-ready"))?;
    let navigation = state.navigation.clone();
    run_blocking(move || {
        let Some(folder) = app.dialog().file().blocking_pick_folder() else {
            return Ok(false);
        };
        let folder = folder.into_path().map_err(|error| {
            tracing::warn!(%error, "folder picker returned an unsupported path");
            IpcErrorDto::shell("shell.folder.invalid")
        })?;
        publish_support_bundle(&bundle, &folder, &navigation)?;
        Ok(true)
    })
    .await?
}

fn publish_support_bundle(
    bundle: &SupportBundleData,
    folder: &Path,
    navigation: &NavigationState,
) -> Result<(), IpcErrorDto> {
    let destination = folder.join("apogee-support.zip");
    bundle.write_to(&destination).map_err(|error| {
        tracing::warn!(%error, "could not publish the core-produced support bundle");
        IpcErrorDto::shell("shell.support-bundle.publish-failed")
    })?;
    navigation.set_support_bundle(destination);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio_stream::StreamExt;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Action {
        Link(String),
        Directory(PathBuf),
        File(PathBuf),
    }

    #[derive(Default)]
    struct RecordingHost(Mutex<Vec<Action>>);

    impl HostActions for RecordingHost {
        fn open_https(&self, url: &str) -> Result<(), HostActionError> {
            self.0
                .lock()
                .map_err(|_| HostActionError::WrongTargetKind)?
                .push(Action::Link(url.to_owned()));
            Ok(())
        }

        fn open_directory(&self, path: &Path) -> Result<(), HostActionError> {
            self.0
                .lock()
                .map_err(|_| HostActionError::WrongTargetKind)?
                .push(Action::Directory(path.to_path_buf()));
            Ok(())
        }

        fn reveal_file(&self, path: &Path) -> Result<(), HostActionError> {
            self.0
                .lock()
                .map_err(|_| HostActionError::WrongTargetKind)?
                .push(Action::File(path.to_path_buf()));
            Ok(())
        }
    }

    fn actions(host: &RecordingHost) -> Vec<Action> {
        match host.0.lock() {
            Ok(actions) => actions.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    #[test]
    fn only_ordinary_https_urls_pass_the_last_moment_check() {
        let accepted = [
            "https://example.invalid/path",
            "https://example.invalid:443/path",
        ];
        for raw in accepted {
            assert!(ordinary_https(&url::Url::parse(raw).unwrap()), "{raw}");
        }
        let rejected = [
            "http://example.invalid",
            "file:///tmp/secret",
            "smb://server/share",
            "custom:payload",
            "https://",
            "https://person@example.invalid",
            "https://:password@example.invalid",
            "https://person:password@example.invalid",
            "https://example.invalid:444",
        ];
        for raw in rejected {
            assert!(
                !url::Url::parse(raw).is_ok_and(|url| ordinary_https(&url)),
                "{raw}"
            );
        }
    }

    #[test]
    fn unknown_link_ids_are_logged_and_never_reach_the_host() {
        let temporary = tempfile::TempDir::new().unwrap();
        let core = Core::new(apogee_core::CoreConfig::with_base(temporary.path())).unwrap();
        let navigation = NavigationState::default();
        let host = RecordingHost::default();

        assert!(open_link_with(&core, "", &navigation, &host).is_err());
        assert!(open_link_with(&core, "stale", &navigation, &host).is_err());
        assert!(actions(&host).is_empty());
        assert_eq!(
            navigation.activity(),
            vec![
                ActivityEntryDto {
                    sequence: 1,
                    code: LINK_REJECTED,
                },
                ActivityEntryDto {
                    sequence: 2,
                    code: LINK_REJECTED,
                },
            ]
        );
    }

    #[test]
    fn reveal_targets_resolve_only_from_core_and_process_state() {
        let temporary = tempfile::TempDir::new().unwrap();
        let config = apogee_core::CoreConfig::with_base(temporary.path());
        let backups = config.backups_dir.clone();
        let secrets = config.secrets_path();
        let core = Core::new(config).unwrap();
        let account = apogee_core::Account::new("person", apogee_core::AccountKind::Standard);
        let game = temporary.path().join("game");
        let profile = apogee_core::Profile::new("Main", account.id, game.clone());
        core.save_account(&account).unwrap();
        core.save_profile(&profile).unwrap();

        let navigation = NavigationState::default();
        let run = Uuid::new_v4();
        let evidence = temporary.path().join("evidence.txt");
        let addon = navigation.register_evidence(run, evidence.clone());
        let support = temporary.path().join("support.zip");
        navigation.set_support_bundle(support.clone());
        let host = RecordingHost::default();

        for target in [
            RevealTargetDto::BackupDir {
                profile: profile.id,
            },
            RevealTargetDto::Recycler {
                profile: profile.id,
            },
            RevealTargetDto::GameFolder {
                profile: profile.id,
            },
            RevealTargetDto::Evidence { run, addon },
            RevealTargetDto::SecretsFile,
            RevealTargetDto::SupportBundle,
        ] {
            reveal_with(&core, &navigation, target, &host).unwrap();
        }

        assert_eq!(
            actions(&host),
            vec![
                Action::Directory(backups.join(profile.id.to_string())),
                Action::Directory(game.join("apogee_repair_recycler")),
                Action::Directory(game),
                Action::File(evidence),
                Action::File(secrets),
                Action::File(support),
            ]
        );
    }

    #[test]
    fn unknown_dynamic_reveal_targets_never_reach_the_host() {
        let temporary = tempfile::TempDir::new().unwrap();
        let core = Core::new(apogee_core::CoreConfig::with_base(temporary.path())).unwrap();
        let navigation = NavigationState::default();
        let host = RecordingHost::default();

        assert!(
            reveal_with(
                &core,
                &navigation,
                RevealTargetDto::Evidence {
                    run: Uuid::new_v4(),
                    addon: Uuid::new_v4(),
                },
                &host,
            )
            .is_err()
        );
        assert!(reveal_with(&core, &navigation, RevealTargetDto::SupportBundle, &host,).is_err());
        assert!(actions(&host).is_empty());
    }

    #[tokio::test]
    async fn only_a_successfully_published_core_bundle_becomes_revealable() {
        let temporary = tempfile::TempDir::new().unwrap();
        let core = Core::new(apogee_core::CoreConfig::with_base(temporary.path())).unwrap();
        let mut events = core.execute(apogee_core::Command::SupportBundle {
            profile: None,
            facts: Vec::new(),
        });
        let bundle = loop {
            match events.next().await {
                Some(apogee_core::Event::SupportBundle(bundle)) => break bundle,
                Some(_) => {}
                None => panic!("support flow ended without an archive"),
            }
        };
        let navigation = NavigationState::default();
        let published = temporary.path().join("published");
        std::fs::create_dir(&published).unwrap();

        publish_support_bundle(&bundle, &published, &navigation).unwrap();
        let destination = published.join("apogee-support.zip");
        assert!(destination.is_file());
        assert_eq!(navigation.support_bundle(), Some(destination.clone()));

        let previous = temporary.path().join("previous.zip");
        std::fs::write(&previous, b"previous").unwrap();
        navigation.set_support_bundle(previous.clone());
        assert!(publish_support_bundle(&bundle, &published, &navigation).is_err());
        assert_eq!(navigation.support_bundle(), Some(previous));
        assert!(destination.is_file());
    }
}
