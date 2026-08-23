//! Persisted launch readiness and the credential-free action a shell may offer next.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use url::Url;

/// The primary action label selected by core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NextVerb {
    Play,
    UpdateAndPlay,
    Install,
    Resume,
    Repair,
    SignIn,
    AcceptTerms,
    WaitForMaintenance,
    CloseGameFirst,
}

/// A credential-free description of the command behind [`NextVerb`].
///
/// Credential-bearing commands are deliberately described rather than embedded. A shell supplies a
/// fresh password and one-time-password source only when the action is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum NextCommand {
    Launch,
    PatchAndPlay,
    Install,
    Repair,
    Login,
    WaitForGate,
}

/// A persisted reading of a pending patch set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingReading {
    pub count: u32,
    pub bytes: u64,
    /// Whole seconds since the Unix epoch when registration supplied this set.
    pub as_of: u64,
}

/// What the selected profile can honestly do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NextAction {
    pub verb: NextVerb,
    pub command: NextCommand,
    pub pending: Option<PendingReading>,
    pub resumable: bool,
    /// Stable presentation code for the disposition preventing ordinary play.
    pub blocked: Option<String>,
    /// Whether this build can continue the selected patch action while login is closed.
    pub patching_available: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StoredDisposition {
    #[default]
    Unknown,
    Current,
    NeedsPassword,
    NeedsOtp,
    NeedsTerms,
    NoService,
    NeedsLogin,
    NeedsBootPatch,
    PatchesPending,
    VersionNotServiced,
    Cancelled,
    Failed {
        code: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PendingRepo {
    Boot,
    Game,
    Expansion(u8),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingPatch {
    pub(crate) repo: PendingRepo,
    pub(crate) length: u64,
    pub(crate) version_id: String,
    pub(crate) url: String,
    pub(crate) block_size: Option<u64>,
    pub(crate) hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredPending {
    pub(crate) as_of: u64,
    pub(crate) patches: Vec<PendingPatch>,
}

impl StoredPending {
    pub(crate) fn reading(&self) -> PendingReading {
        PendingReading {
            count: u32::try_from(self.patches.len()).unwrap_or(u32::MAX),
            bytes: self
                .patches
                .iter()
                .fold(0u64, |total, patch| total.saturating_add(patch.length)),
            as_of: self.as_of,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StatusRecord {
    pub(crate) disposition: StoredDisposition,
    pub(crate) pending: Option<StoredPending>,
}

pub(crate) fn derive_next_action(
    record: Option<&StatusRecord>,
    install_ready: bool,
    cache_valid: bool,
    resumable: bool,
    game_running: bool,
) -> NextAction {
    if game_running {
        return action(
            NextVerb::CloseGameFirst,
            NextCommand::PatchAndPlay,
            record.and_then(|record| record.pending.as_ref()),
            resumable,
            Some("preflight-game-running"),
        );
    }
    if !install_ready {
        return action(NextVerb::Install, NextCommand::Install, None, false, None);
    }
    if let Some(pending) = record.and_then(|record| record.pending.as_ref()) {
        return action(
            if resumable {
                NextVerb::Resume
            } else {
                NextVerb::UpdateAndPlay
            },
            NextCommand::PatchAndPlay,
            Some(pending),
            resumable,
            None,
        );
    }

    let disposition = record.map(|record| &record.disposition);
    match disposition {
        Some(StoredDisposition::NeedsTerms) => action(
            NextVerb::AcceptTerms,
            NextCommand::Login,
            None,
            false,
            Some("state-needs-terms"),
        ),
        Some(StoredDisposition::NoService) => action(
            NextVerb::WaitForMaintenance,
            NextCommand::WaitForGate,
            None,
            false,
            Some("state-no-service"),
        ),
        Some(StoredDisposition::NeedsBootPatch) => action(
            NextVerb::UpdateAndPlay,
            NextCommand::PatchAndPlay,
            None,
            false,
            Some("state-needs-boot-patch"),
        ),
        Some(StoredDisposition::VersionNotServiced) => action(
            NextVerb::Install,
            NextCommand::Install,
            None,
            false,
            Some("state-version-not-serviced"),
        ),
        Some(StoredDisposition::Failed { code })
            if matches!(
                code.as_str(),
                "err-patch" | "err-patch-incomplete" | "err-repair"
            ) =>
        {
            action(
                NextVerb::Repair,
                NextCommand::Repair,
                None,
                false,
                Some(code),
            )
        }
        Some(StoredDisposition::NeedsPassword) => sign_in("state-needs-password"),
        Some(StoredDisposition::NeedsOtp) => sign_in("state-needs-otp"),
        Some(StoredDisposition::NeedsLogin) => sign_in("state-needs-login"),
        Some(StoredDisposition::Cancelled) => sign_in("state-cancelled"),
        Some(StoredDisposition::Failed { code }) => sign_in(code),
        Some(
            StoredDisposition::Unknown
            | StoredDisposition::Current
            | StoredDisposition::PatchesPending,
        )
        | None => {
            if cache_valid {
                action(NextVerb::Play, NextCommand::Launch, None, false, None)
            } else {
                sign_in("state-needs-login")
            }
        }
    }
}

pub(crate) async fn has_staged_patch(store: &Path, pending: &StoredPending) -> bool {
    for patch in &pending.patches {
        let Some(spec) = resume_spec(store, patch) else {
            continue;
        };
        match apogee_fetch::resume_reading(&spec).await {
            Ok(Some(reading)) if reading.durable_bytes > 0 => return true,
            Ok(_) => {}
            Err(error) => tracing::warn!(%error, "could not inspect staged patch progress"),
        }
    }
    false
}

fn resume_spec(store: &Path, patch: &PendingPatch) -> Option<apogee_fetch::DownloadSpec> {
    let url = Url::parse(&patch.url).ok()?;
    let destination = patch_destination(store, &patch.url)?;
    let validator = match patch.repo {
        PendingRepo::Boot => apogee_fetch::Validator::External,
        PendingRepo::Game | PendingRepo::Expansion(_) => {
            let block_size = u32::try_from(patch.block_size?).ok()?;
            if block_size == 0 {
                return None;
            }
            let hashes = patch
                .hashes
                .iter()
                .map(|hash| decode_sha1(hash))
                .collect::<Option<Vec<_>>>()?;
            apogee_fetch::Validator::BlockSha1 { block_size, hashes }
        }
    };
    apogee_fetch::DownloadSpec::builder(url, destination, validator)
        .expected_len(patch.length)
        .build()
        .ok()
}

fn decode_sha1(value: &str) -> Option<[u8; 20]> {
    if value.len() != 40 {
        return None;
    }
    let mut digest = [0u8; 20];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(digest)
}

fn patch_destination(store: &Path, raw_url: &str) -> Option<PathBuf> {
    let url = Url::parse(raw_url).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let mut destination = store.to_path_buf();
    let mut any = false;
    for segment in url.path_segments()? {
        if segment.is_empty() || segment == "." {
            continue;
        }
        if segment == ".." {
            return None;
        }
        destination.push(segment);
        any = true;
    }
    any.then_some(destination)
}

fn sign_in(code: &str) -> NextAction {
    action(
        NextVerb::SignIn,
        NextCommand::Login,
        None,
        false,
        Some(code),
    )
}

fn action(
    verb: NextVerb,
    command: NextCommand,
    pending: Option<&StoredPending>,
    resumable: bool,
    blocked: Option<&str>,
) -> NextAction {
    NextAction {
        verb,
        command,
        pending: pending.map(StoredPending::reading),
        resumable,
        blocked: blocked.map(str::to_owned),
        // A closed login gate cannot currently mint or recover the patch credential a game patch
        // needs. Keep this measured capability explicit so a shell never claims otherwise.
        patching_available: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending() -> StoredPending {
        StoredPending {
            as_of: 42,
            patches: vec![PendingPatch {
                repo: PendingRepo::Game,
                length: 1024,
                version_id: "D1".to_owned(),
                url: "http://example.invalid/game/D1.patch".to_owned(),
                block_size: Some(1024),
                hashes: vec!["00".repeat(20)],
            }],
        }
    }

    #[test]
    fn a_pending_set_is_update_or_resume_from_the_same_persisted_reading() {
        let record = StatusRecord {
            disposition: StoredDisposition::PatchesPending,
            pending: Some(pending()),
        };
        let update = derive_next_action(Some(&record), true, false, false, false);
        let resume = derive_next_action(Some(&record), true, false, true, false);

        assert_eq!(update.verb, NextVerb::UpdateAndPlay);
        assert_eq!(resume.verb, NextVerb::Resume);
        assert_eq!(update.pending, resume.pending);
        assert_eq!(update.pending.expect("pending reading").as_of, 42);
    }

    #[test]
    fn a_missing_install_outranks_stale_status() {
        let record = StatusRecord {
            disposition: StoredDisposition::NoService,
            pending: Some(pending()),
        };
        let next = derive_next_action(Some(&record), false, false, true, false);
        assert_eq!(next.verb, NextVerb::Install);
        assert!(next.pending.is_none());
        assert!(!next.resumable);
    }

    #[test]
    fn every_terminal_disposition_has_a_core_owned_verb() {
        let cases = [
            (StoredDisposition::NeedsPassword, NextVerb::SignIn),
            (StoredDisposition::NeedsOtp, NextVerb::SignIn),
            (StoredDisposition::NeedsTerms, NextVerb::AcceptTerms),
            (StoredDisposition::NoService, NextVerb::WaitForMaintenance),
            (StoredDisposition::NeedsLogin, NextVerb::SignIn),
            (StoredDisposition::NeedsBootPatch, NextVerb::UpdateAndPlay),
            (StoredDisposition::VersionNotServiced, NextVerb::Install),
            (StoredDisposition::Cancelled, NextVerb::SignIn),
        ];
        for (disposition, expected) in cases {
            let record = StatusRecord {
                disposition,
                pending: None,
            };
            assert_eq!(
                derive_next_action(Some(&record), true, false, false, false).verb,
                expected
            );
        }
    }
}
