//! Persistence gate tests: the migration chain advances every historical version to current, a
//! corrupt file is preserved (never deleted), and entities round-trip. All inputs are synthetic.

use std::fs;

use rstest::rstest;
use tempfile::TempDir;

use super::{Migrate, Store, StoreError, UidCacheEntry};
use crate::model::{
    Account, AccountKind, ListenerSettings, ListenerSources, Profile, SecretBackend, Settings,
};

fn cache_entry(game_version: &str, expires_at: u64) -> UidCacheEntry {
    UidCacheEntry {
        unique_id: "UID-TOKEN-0123456789".to_string(),
        region: 3,
        max_expansion: 4,
        game_version: game_version.to_string(),
        expires_at,
    }
}

fn store() -> (TempDir, Store) {
    let dir = TempDir::new().unwrap();
    let store = Store::new(dir.path().to_path_buf());
    (dir, store)
}

#[test]
fn settings_round_trips_at_the_current_version() {
    let (_dir, store) = store();
    let settings = Settings {
        language: "ja".to_string(),
        close_after_launch: true,
        secret_backend: SecretBackend::EncryptedFile,
        keep_patches: true,
        backups_kept: 3,
        backup_before_patch: false,
        otp_listener: ListenerSettings::default(),
    };
    store.save_settings(&settings).unwrap();
    assert_eq!(store.load_settings().unwrap(), settings);
}

#[test]
fn missing_settings_loads_the_default() {
    let (_dir, store) = store();
    assert_eq!(store.load_settings().unwrap(), Settings::default());
}

#[rstest]
#[case(1)]
#[case(2)]
#[case(3)]
#[case(4)]
#[case(5)]
#[case(6)]
fn settings_migrate_forward_from_every_historical_version(#[case] version: u32) {
    let (dir, store) = store();
    // Each historical shape carries only the fields that existed at that version.
    let data = match version {
        1 => serde_json::json!({ "language": "fr" }),
        2 => serde_json::json!({ "language": "fr", "close_after_launch": false }),
        3 => serde_json::json!({
            "language": "fr", "close_after_launch": false, "keep_patches": false
        }),
        4 => serde_json::json!({
            "language": "fr", "close_after_launch": false, "keep_patches": false,
            "backups_kept": 5
        }),
        5 => serde_json::json!({
            "language": "fr", "close_after_launch": false, "keep_patches": false,
            "backups_kept": 5, "backup_before_patch": true
        }),
        _ => serde_json::json!({
            "language": "fr", "close_after_launch": false, "keep_patches": false,
            "backups_kept": 5, "backup_before_patch": true, "secret_backend": "platform"
        }),
    };
    let envelope = serde_json::json!({ "schema_version": version, "data": data });
    let path = dir.path().join("settings.json");
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let loaded = store.load_settings().unwrap();
    assert_eq!(loaded.language, "fr");
    assert!(!loaded.close_after_launch);
    assert!(!loaded.keep_patches);
    // Every install that predates the choice was using the platform store, so that is the only
    // answer a migration may reach: any other would move a user off the store their password is in.
    assert_eq!(loaded.secret_backend, SecretBackend::Platform);
    // The whole of the off-by-default guarantee for an install that already exists: the listener's
    // tuning appears, and nothing about it opens a port. No account is pointed at it here, and being
    // pointed at it is the only thing that binds anything.
    assert_eq!(loaded.otp_listener, ListenerSettings::default());
    assert!(loaded.otp_listener.bind.is_unspecified());
    assert_eq!(loaded.otp_listener.sources, ListenerSources::Any);

    // A re-save rewrites the envelope at the current schema version.
    store.save_settings(&loaded).unwrap();
    let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        raw["schema_version"],
        serde_json::json!(Settings::CURRENT_VERSION)
    );
}

#[test]
fn a_future_schema_version_is_corrupt_not_silently_downgraded() {
    let (dir, store) = store();
    let envelope = serde_json::json!({
        "schema_version": Settings::CURRENT_VERSION + 1,
        "data": { "language": "en", "close_after_launch": false, "unknown": 7 },
    });
    let path = dir.path().join("settings.json");
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    assert!(matches!(
        store.load_settings().unwrap_err(),
        StoreError::Corrupt { .. }
    ));
}

#[test]
fn a_corrupt_file_is_preserved_and_never_deleted() {
    let (dir, store) = store();
    let path = dir.path().join("settings.json");
    let original = b"{ this is not valid json".to_vec();
    fs::write(&path, &original).unwrap();

    let backup = match store.load_settings().unwrap_err() {
        StoreError::Corrupt {
            path: reported,
            backup,
            ..
        } => {
            assert_eq!(reported, path);
            backup
        }
        other => panic!("expected a corrupt error, got {other:?}"),
    };

    // The original survives, byte-for-byte.
    assert!(path.exists());
    assert_eq!(fs::read(&path).unwrap(), original);
    // A backup was copied aside, holding the original bytes.
    assert_ne!(backup, path);
    assert!(backup.exists());
    assert_eq!(fs::read(&backup).unwrap(), original);
}

#[test]
fn an_install_id_is_minted_once_and_kept() {
    let (dir, store) = store();
    let minted = store.install_id().unwrap();

    assert!(dir.path().join("install-id.json").exists());
    assert_eq!(store.install_id().unwrap(), minted);
    // A second run over the same directory reads it rather than minting again.
    assert_eq!(
        Store::new(dir.path().to_path_buf()).install_id().unwrap(),
        minted
    );
}

/// The one entity a damaged file replaces instead of reporting: it holds opaque randomness, so
/// there is nothing in it to recover and nothing gained by refusing to start. The bytes are still
/// copied aside on the way past.
#[test]
fn a_damaged_install_id_is_replaced_rather_than_reported() {
    let (dir, store) = store();
    let path = dir.path().join("install-id.json");
    let minted = store.install_id().unwrap();
    let damaged = b"{ this is not valid json".to_vec();
    fs::write(&path, &damaged).unwrap();

    let replacement = store.install_id().unwrap();
    assert_ne!(replacement, minted);
    assert_eq!(store.install_id().unwrap(), replacement);

    let preserved: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.to_string_lossy().ends_with(".corrupt"))
        .collect();
    assert_eq!(preserved.len(), 1);
    assert_eq!(fs::read(&preserved[0]).unwrap(), damaged);
}

#[test]
fn a_profile_round_trips_through_the_store() {
    let (_dir, store) = store();
    let account = Account::new("me@example.invalid", AccountKind::Standard);
    let profile = Profile::new("Main", account.id, "/games/ffxiv".into());
    store.save_profile(&profile).unwrap();
    assert_eq!(store.list_profiles().unwrap(), vec![profile]);
}

#[test]
fn listing_profiles_ignores_a_corrupt_backup_beside_them() {
    let (dir, store) = store();
    let account = Account::new("me@example.invalid", AccountKind::Standard);
    let profile = Profile::new("Main", account.id, "/games/ffxiv".into());
    store.save_profile(&profile).unwrap();
    // A stray backup file must not be parsed as a profile.
    fs::write(
        dir.path().join("profiles").join("stray.json.corrupt"),
        b"garbage",
    )
    .unwrap();
    assert_eq!(store.list_profiles().unwrap().len(), 1);
}

#[test]
fn deleting_a_missing_profile_reports_not_found() {
    let (_dir, store) = store();
    assert!(matches!(
        store.delete_profile(uuid::Uuid::new_v4()).unwrap_err(),
        StoreError::NotFound { .. }
    ));
}

#[test]
fn an_account_round_trips_through_serde() {
    let account = Account {
        kind: AccountKind::Steam { app_id: 39_210 },
        use_otp: true,
        ..Account::new("me@example.invalid", AccountKind::Standard)
    };
    let json = serde_json::to_value(&account).unwrap();
    assert_eq!(serde_json::from_value::<Account>(json).unwrap(), account);
}

#[test]
fn an_account_round_trips_through_the_store() {
    let (_dir, store) = store();
    let account = Account {
        use_otp: true,
        ..Account::new("me@example.invalid", AccountKind::Standard)
    };
    store.save_account(&account).unwrap();
    assert_eq!(store.load_account(account.id).unwrap(), account);
    assert_eq!(store.list_accounts().unwrap(), vec![account.clone()]);

    store.delete_account(account.id).unwrap();
    assert!(matches!(
        store.load_account(account.id).unwrap_err(),
        StoreError::NotFound { .. }
    ));
}

/// An account written before the never-store switch existed has to keep loading. Without the
/// migration step the field is simply missing from the payload, every account file fails to
/// deserialize, and a user loses every login they had configured the moment they upgrade.
#[test]
fn accounts_migrate_forward_from_every_historical_version() {
    let (dir, store) = store();
    let id = uuid::Uuid::new_v4();
    let data = serde_json::json!({
        "id": id, "sqex_id": "me@example.invalid", "kind": "Standard", "use_otp": true,
    });
    let envelope = serde_json::json!({ "schema_version": 1, "data": data });
    let path = dir.path().join("accounts").join(format!("{id}.json"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let loaded = store.load_account(id).unwrap();
    assert_eq!(loaded.sqex_id, "me@example.invalid");
    assert!(loaded.use_otp);
    // Off for an account that predates the switch: it was already saving its password, and arriving
    // with it on would look like the launcher had forgotten one it still holds.
    assert!(!loaded.never_store);

    store.save_account(&loaded).unwrap();
    let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        raw["schema_version"],
        serde_json::json!(Account::CURRENT_VERSION)
    );
}

#[test]
fn a_session_cache_entry_round_trips_and_is_absent_when_unwritten() {
    let (_dir, store) = store();
    let account = uuid::Uuid::new_v4();
    assert_eq!(store.load_uid_cache(account).unwrap(), None);

    let entry = cache_entry("2024.03.28.0000.0000", 5_000);
    store.save_uid_cache(account, &entry).unwrap();
    assert_eq!(store.load_uid_cache(account).unwrap(), Some(entry));

    store.clear_uid_cache(account).unwrap();
    assert_eq!(store.load_uid_cache(account).unwrap(), None);
    // Clearing an already-absent entry is not an error.
    store.clear_uid_cache(account).unwrap();
}

#[test]
fn a_session_cache_entry_is_valid_only_inside_its_window_and_for_its_version() {
    let entry = cache_entry("2024.03.28.0000.0000", 5_000);
    // Inside the window and matching the install version.
    assert!(entry.is_valid(4_999, "2024.03.28.0000.0000"));
    // Expired.
    assert!(!entry.is_valid(5_000, "2024.03.28.0000.0000"));
    // The install was patched to a newer version since the token was cached.
    assert!(!entry.is_valid(4_999, "2024.04.01.0000.0000"));
}

#[test]
fn a_corrupt_session_cache_entry_is_preserved_not_deleted() {
    let (dir, store) = store();
    let account = uuid::Uuid::new_v4();
    let path = dir.path().join("uid-cache").join(format!("{account}.json"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let original = b"{ not valid json".to_vec();
    fs::write(&path, &original).unwrap();

    match store.load_uid_cache(account).unwrap_err() {
        StoreError::Corrupt { backup, .. } => {
            assert!(backup.exists());
            assert_eq!(fs::read(&backup).unwrap(), original);
        }
        other => panic!("expected a corrupt error, got {other:?}"),
    }
    // The original survives byte-for-byte.
    assert!(path.exists());
    assert_eq!(fs::read(&path).unwrap(), original);
}

proptest::proptest! {
    #[test]
    fn settings_survive_a_save_load_cycle(
        language in ".*",
        close in proptest::bool::ANY,
        keep in proptest::bool::ANY,
    ) {
        let (_dir, store) = store();
        let settings = Settings {
            language,
            close_after_launch: close,
            secret_backend: SecretBackend::Platform,
            keep_patches: keep,
            backups_kept: 5,
            backup_before_patch: true,
            otp_listener: ListenerSettings::default(),
        };
        store.save_settings(&settings).unwrap();
        proptest::prop_assert_eq!(store.load_settings().unwrap(), settings);
    }
}

/// The store holds account identity, a live registration id, and the list of programs the launcher
/// executes. None of it is anyone else's business.
#[cfg(unix)]
#[test]
fn everything_written_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let (dir, store) = store();
    let account = Account::new("someone", AccountKind::Standard);
    let profile = Profile::new("main", account.id, "/tmp/ffxiv".into());
    store.save_account(&account).unwrap();
    store.save_profile(&profile).unwrap();
    store.save_settings(&Settings::default()).unwrap();

    let mut checked = 0;
    let mut walk = vec![dir.path().to_path_buf()];
    while let Some(path) = walk.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let entry = entry.unwrap();
            let mode = entry.metadata().unwrap().permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "{:?} is readable by someone else (mode {:o})",
                entry.path(),
                mode
            );
            checked += 1;
            if entry.path().is_dir() {
                walk.push(entry.path());
            }
        }
    }
    assert!(checked > 0, "nothing was written to check");
}

/// An install made before the store was owner-only must not keep exposing its files forever, so an
/// existing directory is narrowed rather than left as it was found.
#[cfg(unix)]
#[test]
fn a_directory_left_readable_by_an_earlier_build_is_narrowed() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("apogee");
    std::fs::create_dir_all(base.join("profiles")).unwrap();
    std::fs::set_permissions(
        base.join("profiles"),
        std::fs::Permissions::from_mode(0o755),
    )
    .unwrap();

    let store = Store::new(base.clone());
    let account = Account::new("someone", AccountKind::Standard);
    store
        .save_profile(&Profile::new("main", account.id, "/tmp/ffxiv".into()))
        .unwrap();

    let mode = std::fs::metadata(base.join("profiles"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "still group/other readable: {mode:o}");
}

#[rstest]
#[case(1)]
#[case(2)]
#[case(3)]
fn profiles_migrate_forward_from_every_historical_version(#[case] version: u32) {
    let (dir, store) = store();
    let id = uuid::Uuid::new_v4();
    let account = uuid::Uuid::new_v4();
    let launch = serde_json::json!({
        "region": "Global", "extra_args": [], "extra_env": [], "wrappers": []
    });
    // Each historical shape carries only the fields that existed at that version. Both carried the
    // curated component set the launcher no longer offers.
    let data = match version {
        1 => serde_json::json!({
            "id": id, "name": "Main", "account": account, "game_path": "/games/ffxiv",
            "runner": "SystemWine", "prefix": { "name": "" },
            "components": [{ "id": "ACT", "enabled": true }],
            "launch": launch,
        }),
        2 => serde_json::json!({
            "id": id, "name": "Main", "account": account, "game_path": "/games/ffxiv",
            "runner": "SystemWine", "prefix": { "name": "" },
            "components": [{ "id": "ACT", "enabled": true }],
            "external": [],
            "launch": launch,
        }),
        // By this version the component set was gone and the toggle beside the launch settings had
        // arrived, but none of the graphics or synchronization knobs existed yet.
        _ => serde_json::json!({
            "id": id, "name": "Main", "account": account, "game_path": "/games/ffxiv",
            "runner": "SystemWine", "prefix": { "name": "" },
            "external": [],
            "launch": serde_json::json!({
                "region": "Global", "extra_args": [], "extra_env": [], "wrappers": [],
                "dalamud": false
            }),
        }),
    };
    let envelope = serde_json::json!({ "schema_version": version, "data": data });
    let path = dir.path().join("profiles").join(format!("{id}.json"));
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let loaded = store.load_profile(id).unwrap();
    assert_eq!(loaded.name, "Main");
    assert!(loaded.external.is_empty());
    // The toggle a profile did not have yet arrives off. Defaulting it on would load third-party code
    // into the client of every profile that predates the setting.
    assert!(!loaded.launch.dalamud);
    // The knobs a profile never chose arrive unset, so the launch resolves them against the host and
    // the runner rather than against a value written on the profile's behalf.
    assert_eq!(loaded.launch.sync, apogee_runtime::SyncChoice::Auto);
    assert_eq!(loaded.launch.hud, apogee_runtime::Hud::None);
    assert_eq!(loaded.launch.gpu, apogee_runtime::GpuSelect::Default);
    assert!(loaded.launch.gamescope.is_none());
    assert!(!loaded.launch.gamemode);

    // A re-save rewrites the envelope at the current schema version, without the set it shed.
    store.save_profile(&loaded).unwrap();
    let raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        raw["schema_version"],
        serde_json::json!(Profile::CURRENT_VERSION)
    );
    assert!(
        raw["data"].get("components").is_none(),
        "the component set survived the migration: {raw}"
    );
}
