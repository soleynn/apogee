//! Capturing the game's settings, in one place so the command surface and the launch flow cannot
//! disagree about what a backup covers or when it prunes.

use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use apogee_addons::AddonError;
use apogee_addons::backup::{
    BackupError, BackupReport, BackupSpec, GameConfigOpts, Retain, Selection, SelectionRoot,
};

use crate::error::CoreError;
use crate::model::Profile;

/// Back up the game config in `profile`'s prefix, then prune to `kept`.
///
/// Returns the report and the trees that were not covered. A prefix can hold more than one config
/// tree; the one the game wrote to last is captured and the rest are handed back so a caller can name
/// them rather than leave them unmentioned.
///
/// # Errors
/// [`CoreError::Addons`] for anything the backup refuses, including a prefix the game has never
/// written into.
pub(crate) fn create(
    prefixes_dir: &Path,
    backups_dir: &Path,
    profile: &Profile,
    kept: u32,
    created_at: u64,
    note: Option<String>,
    cancel: &tokio_util::sync::CancellationToken,
) -> Result<(BackupReport, Vec<PathBuf>), CoreError> {
    let prefix = prefixes_dir.join(crate::flow::prefix_name(profile));
    let mut trees = apogee_addons::backup::game_config_dirs(&prefix);
    if trees.is_empty() {
        return Err(CoreError::Addons(AddonError::Backup(
            BackupError::MissingRoot { path: prefix },
        )));
    }
    let source = trees.remove(0);
    let dest = profile_dir(backups_dir, profile);
    let spec = BackupSpec {
        selection: Selection::new()
            .with_root(SelectionRoot::game_config(
                &source,
                GameConfigOpts::default(),
            ))
            .map_err(AddonError::Backup)?,
        dest_dir: dest.clone(),
        // Supplied rather than read from the clock here, so two runs are comparable in a test.
        created_at: UNIX_EPOCH + Duration::from_secs(created_at),
        note,
    };
    let report = apogee_addons::backup::create(&spec, cancel).map_err(AddonError::Backup)?;
    if let Some(keep) = std::num::NonZeroUsize::new(kept as usize) {
        // After a successful capture, never before: the new archive is what makes dropping an old
        // one safe.
        apogee_addons::backup::prune(&dest, Retain::keep(keep)).map_err(AddonError::Backup)?;
    }
    Ok((report, trees))
}

/// Where one profile's archives live.
pub(crate) fn profile_dir(backups_dir: &Path, profile: &Profile) -> PathBuf {
    backups_dir.join(profile.id.to_string())
}
