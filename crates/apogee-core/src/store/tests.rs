//! Persistence gate tests: the migration chain advances every historical version to current, a
//! corrupt file is preserved (never deleted), and entities round-trip. All inputs are synthetic.

use std::fs;

use rstest::rstest;
use tempfile::TempDir;

use super::{Migrate, Store, StoreError, UidCacheEntry};
use crate::model::{Account, AccountKind, Profile, Settings};

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
fn settings_migrate_forward_from_every_historical_version(#[case] version: u32) {
    let (dir, store) = store();
    let data = if version == 1 {
        // The historical shape, before the "close after launch" preference existed.
        serde_json::json!({ "language": "fr" })
    } else {
        serde_json::json!({ "language": "fr", "close_after_launch": false })
    };
    let envelope = serde_json::json!({ "schema_version": version, "data": data });
    let path = dir.path().join("settings.json");
    fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();

    let loaded = store.load_settings().unwrap();
    assert_eq!(loaded.language, "fr");
    assert!(!loaded.close_after_launch);

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
    fn settings_survive_a_save_load_cycle(language in ".*", close in proptest::bool::ANY) {
        let (_dir, store) = store();
        let settings = Settings { language, close_after_launch: close };
        store.save_settings(&settings).unwrap();
        proptest::prop_assert_eq!(store.load_settings().unwrap(), settings);
    }
}
