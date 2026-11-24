//! Stable JSON lines for the core event stream, with error details explicitly redacted.

use apogee_core::{
    AddonEvent, Event, FlowState, FrontierData, Notice, Outcome, PatchProgress, ProgramStatus,
    Recoveries, Repo, RunOutcome, SetupEvent, StableCode,
};
#[cfg(test)]
use apogee_core::{BannerData, GateData, NewsData, NewsRow};
use serde_json::{Value, json};

/// Render one event as one JSON object with no embedded newline.
pub(crate) fn render_event_json(event: &Event) -> String {
    event_value(event).to_string()
}

fn event_value(event: &Event) -> Value {
    let code = event.code();
    match event {
        Event::State(state) => json!({
            "kind": "state",
            "code": code,
            "state": state_value(state),
        }),
        Event::Progress(progress) => json!({
            "kind": "progress",
            "code": code,
            "completed": progress.completed,
            "total": progress.total,
            "recoveries": recoveries_value(progress.recoveries),
        }),
        Event::Patch(progress) => json!({
            "kind": "patch",
            "code": code,
            "patch": patch_value(progress),
        }),
        Event::Addon(addon) => json!({
            "kind": "addon",
            "code": code,
            "addon": addon_value(addon),
        }),
        Event::Setup(setup) => json!({
            "kind": "setup",
            "code": code,
            "setup": setup_value(setup),
        }),
        Event::Frontier(frontier) => json!({
            "kind": "frontier",
            "code": code,
            "frontier": frontier_value(frontier),
        }),
        Event::FirstRun(checkpoint) => json!({
            "kind": "firstRun",
            "code": code,
            "firstRun": first_run_value(checkpoint),
        }),
        Event::Import(import) => json!({
            "kind": "import",
            "code": code,
            "import": import_value(import),
        }),
        Event::SupportBundle(bundle) => json!({
            "kind": "supportBundle",
            "code": code,
            "bytes": bundle.bytes(),
        }),
        Event::Prefix(report) => json!({
            "kind": "prefix",
            "code": code,
            "issues": report
                .health
                .issues
                .iter()
                .map(StableCode::code)
                .collect::<Vec<_>>(),
            "missingSetup": report.missing_setup,
        }),
        Event::Notice(notice) => json!({
            "kind": "notice",
            "code": code,
            "notice": notice_value(notice),
        }),
        Event::LaunchProgramExited(exit) => json!({
            "kind": "launchProgramExited",
            "code": code,
            "program": exit.program,
            "status": program_status_value(exit.status),
        }),
        // Error Display text can carry paths and protocol excerpts. Only explicitly selected fields
        // cross this boundary; diagnostics belong on stderr when explicitly enabled.
        Event::Error(error) => json!({
            "kind": "error",
            "code": code,
            "error": core_error_value(error),
        }),
        Event::Outcome(outcome) => json!({
            "kind": "outcome",
            "code": code,
            "outcome": outcome_label(*outcome),
        }),
        _ => json!({
            "kind": "unknown",
            "code": code,
        }),
    }
}

fn state_value(state: &FlowState) -> Value {
    match state {
        FlowState::NeedsPassword => json!({ "kind": "needsPassword" }),
        FlowState::NeedsOtp => json!({ "kind": "needsOtp" }),
        FlowState::WaitingForOtpWindow { seconds } => {
            json!({ "kind": "waitingForOtpWindow", "seconds": seconds })
        }
        FlowState::WaitingForPushedCode { port, seconds } => json!({
            "kind": "waitingForPushedCode",
            "port": port,
            "seconds": seconds,
        }),
        FlowState::PushedCodeReceived { from } => json!({
            "kind": "pushedCodeReceived",
            "from": from.to_string(),
        }),
        FlowState::NeedsTerms => json!({ "kind": "needsTerms" }),
        FlowState::NoService => json!({ "kind": "noService" }),
        FlowState::NeedsLogin => json!({ "kind": "needsLogin" }),
        FlowState::NeedsBootPatch => json!({ "kind": "needsBootPatch" }),
        FlowState::PatchesPending { count, bytes } => json!({
            "kind": "patchesPending",
            "count": count,
            "bytes": bytes,
        }),
        FlowState::VersionNotServiced => json!({ "kind": "versionNotServiced" }),
        FlowState::BackingUp => json!({ "kind": "backingUp" }),
        FlowState::PreparingPrefix => json!({ "kind": "preparingPrefix" }),
        FlowState::Patching => json!({ "kind": "patching" }),
        FlowState::Repairing => json!({ "kind": "repairing" }),
        FlowState::CheckingPrefix => json!({ "kind": "checkingPrefix" }),
        FlowState::NoPrefix => json!({ "kind": "noPrefix" }),
        FlowState::FixingPrefix => json!({ "kind": "fixingPrefix" }),
        FlowState::RecreatingPrefix => json!({ "kind": "recreatingPrefix" }),
        FlowState::Launching => json!({ "kind": "launching" }),
        FlowState::Running => json!({ "kind": "running" }),
        FlowState::SupervisingAddons => json!({ "kind": "supervisingAddons" }),
        FlowState::Exited => json!({ "kind": "exited" }),
        FlowState::Cancelled => json!({ "kind": "cancelled" }),
        _ => json!({ "kind": "unknown", "code": state.code() }),
    }
}

fn recoveries_value(recoveries: Recoveries) -> Value {
    json!({
        "retries": recoveries.retries,
        "rotations": recoveries.rotations,
        "stalls": recoveries.stalls,
        "blocksRefetched": recoveries.blocks_refetched,
        "sourcesDropped": recoveries.sources_dropped,
        "demoted": recoveries.demoted,
    })
}

fn patch_value(progress: &PatchProgress) -> Value {
    match progress {
        PatchProgress::Downloading {
            repo,
            index,
            bytes_done,
            total,
            recoveries,
        } => json!({
            "kind": "downloading",
            "repo": repo_label(*repo),
            "index": index,
            "bytesDone": bytes_done,
            "total": total,
            "recoveries": recoveries_value(*recoveries),
        }),
        PatchProgress::Applying {
            repo,
            index,
            bytes_done,
        } => json!({
            "kind": "applying",
            "repo": repo_label(*repo),
            "index": index,
            "bytesDone": bytes_done,
        }),
        PatchProgress::Applied {
            repo,
            index,
            version,
        } => json!({
            "kind": "applied",
            "repo": repo_label(*repo),
            "index": index,
            "version": version,
        }),
        PatchProgress::Verifying { repo, attempt } => json!({
            "kind": "verifying",
            "repo": repo_label(*repo),
            "attempt": attempt,
        }),
        PatchProgress::Refetching {
            repo,
            attempt,
            bytes,
        } => json!({
            "kind": "refetching",
            "repo": repo_label(*repo),
            "attempt": attempt,
            "bytes": bytes,
        }),
        PatchProgress::Quarantining { repo, count } => json!({
            "kind": "quarantining",
            "repo": repo_label(*repo),
            "count": count,
        }),
        PatchProgress::Repaired { repo, version } => json!({
            "kind": "repaired",
            "repo": repo_label(*repo),
            "version": version,
        }),
    }
}

fn repo_label(repo: Repo) -> String {
    match repo {
        Repo::Boot => "boot".to_owned(),
        Repo::Game => "game".to_owned(),
        Repo::Expansion(number) => format!("ex{number}"),
    }
}

fn addon_value(event: &AddonEvent) -> Value {
    match event {
        AddonEvent::Started { program, pid, .. } => json!({
            "kind": "started",
            "program": program.to_string_lossy(),
            "pid": pid,
        }),
        AddonEvent::AlreadyRunning { program, pid, .. } => json!({
            "kind": "alreadyRunning",
            "program": program.to_string_lossy(),
            "pid": pid,
        }),
        AddonEvent::Stopped { program, pid, .. } => json!({
            "kind": "stopped",
            "program": program.to_string_lossy(),
            "pid": pid,
        }),
        AddonEvent::Finished {
            program, outcome, ..
        } => json!({
            "kind": "finished",
            "program": program.to_string_lossy(),
            "outcome": addon_outcome_value(outcome),
        }),
        AddonEvent::Failed {
            program, reason, ..
        } => json!({
            "kind": "failed",
            "program": program.to_string_lossy(),
            "reason": reason,
        }),
        AddonEvent::StillWaiting {
            program, seconds, ..
        } => json!({
            "kind": "stillWaiting",
            "program": program.to_string_lossy(),
            "seconds": seconds,
        }),
        AddonEvent::Loaded { what, .. } => json!({
            "kind": "loaded",
            "what": what,
        }),
        AddonEvent::NotConfirmed {
            what,
            waited,
            evidence,
            ..
        } => json!({
            "kind": "notConfirmed",
            "what": what,
            "waitedSeconds": waited.as_secs(),
            "evidence": evidence.to_string_lossy(),
        }),
        _ => json!({ "kind": "unknown", "code": event.code() }),
    }
}

fn addon_outcome_value(outcome: &Outcome) -> Value {
    match outcome {
        Outcome::Started { pid, .. } => json!({ "kind": "started", "pid": pid }),
        Outcome::AlreadyRunning { pid, .. } => {
            json!({ "kind": "alreadyRunning", "pid": pid })
        }
        Outcome::Disabled => json!({ "kind": "disabled" }),
        Outcome::Completed { code, .. } => json!({ "kind": "completed", "code": code }),
        Outcome::Cancelled => json!({ "kind": "cancelled" }),
        Outcome::Failed { reason, .. } => json!({ "kind": "failed", "reason": reason }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn setup_value(event: &SetupEvent) -> Value {
    match event {
        SetupEvent::Downloading {
            what,
            bytes_done,
            total,
            recoveries,
        } => json!({
            "kind": "downloading",
            "what": what,
            "bytesDone": bytes_done,
            "total": total,
            "recoveries": recoveries_value(*recoveries),
        }),
        SetupEvent::Installing { what, version } => {
            json!({ "kind": "installing", "what": what, "version": version })
        }
        SetupEvent::Installed { what } => json!({ "kind": "installed", "what": what }),
        SetupEvent::AlreadyPresent { what } => {
            json!({ "kind": "alreadyPresent", "what": what })
        }
        SetupEvent::Applying { verb, reason } => {
            json!({ "kind": "applying", "verb": verb, "reason": reason })
        }
        SetupEvent::Reapplying { verb, because } => {
            json!({ "kind": "reapplying", "verb": verb, "because": because })
        }
        SetupEvent::Applied { verb } => json!({ "kind": "applied", "verb": verb }),
        SetupEvent::Caveat { what, note } => {
            json!({ "kind": "caveat", "what": what, "note": note })
        }
        SetupEvent::Failed { what, reason } => {
            json!({ "kind": "failed", "what": what, "reason": reason })
        }
        SetupEvent::CatalogUnavailable {
            detail,
            using_cached,
        } => json!({
            "kind": "catalogUnavailable",
            "detail": detail,
            "usingCached": using_cached,
        }),
        SetupEvent::Stopped { applied, .. } => {
            json!({ "kind": "stopped", "applied": applied })
        }
        _ => json!({ "kind": "unknown", "code": event.code() }),
    }
}

fn frontier_value(data: &FrontierData) -> Value {
    match data {
        FrontierData::News(data) => json!({
            "kind": "news",
            "value": {
                "news": data.news.iter().map(news_row_value).collect::<Vec<_>>(),
                "topics": data.topics.iter().map(news_row_value).collect::<Vec<_>>(),
                "pinned": data.pinned.iter().map(news_row_value).collect::<Vec<_>>(),
            },
        }),
        FrontierData::Gate(data) => json!({
            "kind": "gate",
            "value": {
                "open": data.open,
                "messages": data.messages,
                "news": data.news,
            },
        }),
        FrontierData::Banners(rows) => json!({
            "kind": "banners",
            "value": rows.iter().map(|row| json!({
                "id": row.id,
                "artwork": row.artwork.as_ref().map(|path| path.to_string_lossy()),
                "orderPriority": row.order_priority,
                "fixOrder": row.fix_order,
            })).collect::<Vec<_>>(),
        }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn news_row_value(row: &apogee_core::NewsRow) -> Value {
    json!({
        "id": row.id,
        "date": row.date,
        "title": row.title,
        "tag": row.tag,
    })
}

fn first_run_value(checkpoint: &apogee_core::FirstRunCheckpoint) -> Value {
    json!({
        "legibility": checkpoint.legibility.as_ref().map(legibility_value),
        "import": first_run_import_state_value(&checkpoint.import),
        "account": checkpoint.account.as_ref().map(account_choice_value),
        "gameCandidates": checkpoint.game_candidates.iter().map(game_candidate_value).collect::<Vec<_>>(),
        "game": checkpoint.game.as_ref().map(game_choice_value),
        "credentialBackends": checkpoint
            .credential_backends
            .iter()
            .map(credential_backend_reading_value)
            .collect::<Vec<_>>(),
        "credential": checkpoint.credential.as_ref().map(credential_choice_value),
        "runners": checkpoint.runners.iter().map(runner_reading_value).collect::<Vec<_>>(),
        "runnerAndPrefix": checkpoint.runner_and_prefix.as_ref().map(runner_and_prefix_value),
        "ready": ready_state_value(&checkpoint.ready),
    })
}

fn legibility_value(reading: &apogee_core::LegibilityReading) -> Value {
    json!({
        "gpu": reading.gpu,
        "driver": reading.driver,
        "session": session_label(reading.session),
        "renderTier": reading.render_tier,
    })
}

const fn session_label(session: apogee_core::SessionType) -> &'static str {
    match session {
        apogee_core::SessionType::Wayland => "wayland",
        apogee_core::SessionType::X11 => "x11",
        apogee_core::SessionType::Windows => "windows",
        apogee_core::SessionType::Unknown => "unknown",
        _ => "unknown",
    }
}

fn first_run_import_state_value(state: &apogee_core::ImportState) -> Value {
    match state {
        apogee_core::ImportState::DiscoveryPending => json!({ "state": "discoveryPending" }),
        apogee_core::ImportState::NoneFound => json!({ "state": "noneFound" }),
        apogee_core::ImportState::Candidates(candidates) => json!({
            "state": "candidates",
            "value": candidates.iter().map(first_run_import_candidate_value).collect::<Vec<_>>(),
        }),
        apogee_core::ImportState::Complete(decision) => json!({
            "state": "complete",
            "value": import_decision_value(decision),
        }),
        _ => json!({ "state": "unknown" }),
    }
}

fn first_run_import_candidate_value(candidate: &apogee_core::FirstRunImportCandidate) -> Value {
    let source = match candidate.source {
        apogee_core::FirstRunImportSource::Native => "native",
        apogee_core::FirstRunImportSource::Core => "core",
        apogee_core::FirstRunImportSource::Flatpak => "flatpak",
        _ => "unknown",
    };
    json!({
        "path": path_value(&candidate.path),
        "source": source,
    })
}

fn import_decision_value(decision: &apogee_core::ImportDecision) -> Value {
    match decision {
        apogee_core::ImportDecision::Import(path) => {
            json!({ "choice": "import", "value": path_value(path) })
        }
        apogee_core::ImportDecision::Skip => json!({ "choice": "skip" }),
        _ => json!({ "choice": "unknown" }),
    }
}

fn account_choice_value(choice: &apogee_core::AccountChoice) -> Value {
    let kind = match choice.kind {
        apogee_core::FirstRunAccountKind::Standard => "standard",
        apogee_core::FirstRunAccountKind::Steam => "steam",
        apogee_core::FirstRunAccountKind::FreeTrial => "freeTrial",
        _ => "unknown",
    };
    let steam_client = match choice.steam_client {
        apogee_core::SteamClientReading::Present => "present",
        apogee_core::SteamClientReading::Missing => "missing",
        apogee_core::SteamClientReading::NotRequired => "notRequired",
        _ => "unknown",
    };
    json!({
        "squareEnixId": choice.square_enix_id,
        "kind": kind,
        "neverSavePassword": choice.never_save_password,
        "steamClient": steam_client,
    })
}

fn game_candidate_value(candidate: &apogee_core::GameCandidate) -> Value {
    json!({
        "path": path_value(&candidate.path),
        "state": game_candidate_state_value(&candidate.state),
    })
}

fn game_candidate_state_value(state: &apogee_core::GameCandidateState) -> Value {
    match state {
        apogee_core::GameCandidateState::Current { installed_bytes } => json!({
            "state": "current",
            "value": { "installedBytes": installed_bytes },
        }),
        apogee_core::GameCandidateState::NeedsUpdate(reading) => json!({
            "state": "needsUpdate",
            "value": patch_reading_value(*reading),
        }),
        apogee_core::GameCandidateState::NotAGame => json!({ "state": "notAGame" }),
        apogee_core::GameCandidateState::Unreadable { code } => json!({
            "state": "unreadable",
            "value": { "code": code },
        }),
        _ => json!({ "state": "unknown" }),
    }
}

fn patch_reading_value(reading: apogee_core::PatchReading) -> Value {
    json!({ "count": reading.count, "bytes": reading.bytes })
}

fn game_choice_value(choice: &apogee_core::GameChoice) -> Value {
    match choice {
        apogee_core::GameChoice::Existing { path, state } => json!({
            "choice": "existing",
            "value": {
                "path": path_value(path),
                "state": existing_game_state_value(*state),
            },
        }),
        apogee_core::GameChoice::Install {
            path,
            approximate_bytes,
            exact_download_bytes,
        } => json!({
            "choice": "install",
            "value": {
                "path": path_value(path),
                "approximateBytes": approximate_bytes,
                "exactDownloadBytes": exact_download_bytes,
            },
        }),
        _ => json!({ "choice": "unknown" }),
    }
}

fn existing_game_state_value(state: apogee_core::ExistingGameState) -> Value {
    match state {
        apogee_core::ExistingGameState::Current => json!({ "state": "current" }),
        apogee_core::ExistingGameState::NeedsUpdate(reading) => json!({
            "state": "needsUpdate",
            "value": patch_reading_value(reading),
        }),
        _ => json!({ "state": "unknown" }),
    }
}

fn credential_backend_reading_value(reading: &apogee_core::CredentialBackendReading) -> Value {
    json!({
        "backend": credential_backend_label(reading.backend),
        "state": credential_backend_state_value(&reading.state),
    })
}

const fn credential_backend_label(backend: apogee_core::CredentialBackend) -> &'static str {
    match backend {
        apogee_core::CredentialBackend::SecretService => "secretService",
        apogee_core::CredentialBackend::EncryptedFile => "encryptedFile",
        apogee_core::CredentialBackend::WindowsCredentialManager => "windowsCredentialManager",
        _ => "unknown",
    }
}

fn credential_backend_state_value(state: &apogee_core::CredentialBackendState) -> Value {
    match state {
        apogee_core::CredentialBackendState::Ready => json!({ "state": "ready" }),
        apogee_core::CredentialBackendState::NeedsPassphrase => {
            json!({ "state": "needsPassphrase" })
        }
        apogee_core::CredentialBackendState::Unavailable { code } => {
            json!({ "state": "unavailable", "code": code })
        }
        _ => json!({ "state": "unknown" }),
    }
}

fn credential_choice_value(choice: &apogee_core::CredentialChoice) -> Value {
    match choice {
        apogee_core::CredentialChoice::SaveIn(backend) => json!({
            "choice": "saveIn",
            "value": credential_backend_label(*backend),
        }),
        apogee_core::CredentialChoice::DoNotSave => json!({ "choice": "doNotSave" }),
        _ => json!({ "choice": "unknown" }),
    }
}

fn runner_reading_value(reading: &apogee_core::RunnerReading) -> Value {
    json!({
        "selection": runner_selection_value(&reading.selection),
        "version": reading.version,
        "recommended": reading.recommended,
        "available": reading.available,
    })
}

fn runner_selection_value(selection: &apogee_core::FirstRunRunnerSelection) -> Value {
    match selection {
        apogee_core::FirstRunRunnerSelection::Managed { name, version } => json!({
            "kind": "managed",
            "name": name,
            "version": version,
        }),
        apogee_core::FirstRunRunnerSelection::SystemWine { version } => json!({
            "kind": "systemWine",
            "version": version,
        }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn runner_and_prefix_value(choice: &apogee_core::RunnerAndPrefixChoice) -> Value {
    json!({
        "runner": runner_selection_value(&choice.runner),
        "prefix": prefix_outcome_value(&choice.prefix),
    })
}

fn prefix_outcome_value(outcome: &apogee_core::PrefixOutcome) -> Value {
    match outcome {
        apogee_core::PrefixOutcome::Ready => json!({ "state": "ready" }),
        apogee_core::PrefixOutcome::ContinueWithoutPrefix { code } => json!({
            "state": "continueWithoutPrefix",
            "code": code,
        }),
        _ => json!({ "state": "unknown" }),
    }
}

fn ready_state_value(state: &apogee_core::ReadyState) -> Value {
    match state {
        apogee_core::ReadyState::Pending => json!({ "state": "pending" }),
        apogee_core::ReadyState::Started(action) => json!({
            "state": "started",
            "value": ready_action_value(*action),
        }),
        _ => json!({ "state": "unknown" }),
    }
}

fn ready_action_value(action: apogee_core::ReadyAction) -> Value {
    match action {
        apogee_core::ReadyAction::Play => json!({ "action": "play" }),
        apogee_core::ReadyAction::UpdateAndPlay(reading) => json!({
            "action": "updateAndPlay",
            "value": patch_reading_value(reading),
        }),
        apogee_core::ReadyAction::InstallAndPlay { bytes } => json!({
            "action": "installAndPlay",
            "value": { "bytes": bytes },
        }),
        _ => json!({ "action": "unknown" }),
    }
}

fn path_value(path: &std::path::Path) -> Value {
    let display = path.to_string_lossy().into_owned();
    let encoded = match path.to_str() {
        Some(path) => json!({ "kind": "utf8", "value": path }),
        #[cfg(unix)]
        None => {
            use std::os::unix::ffi::OsStrExt;
            json!({ "kind": "unix", "value": path.as_os_str().as_bytes() })
        }
        #[cfg(windows)]
        None => {
            use std::os::windows::ffi::OsStrExt;
            json!({ "kind": "windows", "value": path.as_os_str().encode_wide().collect::<Vec<_>>() })
        }
    };
    json!({ "display": display, "value": encoded })
}

fn import_value(data: &apogee_core::ImportData) -> Value {
    match data {
        apogee_core::ImportData::Scan(scan) => json!({
            "kind": "scan",
            "value": import_scan_value(scan),
        }),
        apogee_core::ImportData::Applied(report) => json!({
            "kind": "applied",
            "value": import_report_value(report),
        }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn import_scan_value(scan: &apogee_core::ImportScan) -> Value {
    json!({
        "source": path_value(&scan.source),
        "fingerprint": scan.fingerprint.as_str(),
        "findings": scan.findings.iter().map(import_finding_value).collect::<Vec<_>>(),
    })
}

fn import_finding_value(finding: &apogee_core::ImportFinding) -> Value {
    json!({
        "id": finding.id.as_str(),
        "location": import_location_value(finding.location),
        "result": import_finding_result_value(&finding.result),
    })
}

fn import_location_value(location: apogee_core::ImportLocation) -> Value {
    match location {
        apogee_core::ImportLocation::AccountsFile => json!({ "kind": "accountsFile" }),
        apogee_core::ImportLocation::AccountRow { index } => {
            json!({ "kind": "accountRow", "index": index })
        }
        apogee_core::ImportLocation::ConfigFile => json!({ "kind": "configFile" }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn import_finding_result_value(result: &apogee_core::ImportFindingResult) -> Value {
    match result {
        apogee_core::ImportFindingResult::Candidate(candidate) => json!({
            "kind": "candidate",
            "value": import_candidate_value(candidate),
        }),
        apogee_core::ImportFindingResult::Skipped(issue) => json!({
            "kind": "skipped",
            "value": import_issue_value(issue),
        }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn import_candidate_value(candidate: &apogee_core::ImportCandidate) -> Value {
    json!({
        "squareEnixId": candidate.sqex_id,
        "accountKind": account_kind_value(&candidate.kind),
        "useOtp": candidate.use_otp,
        "neverStore": candidate.never_store,
        "gamePath": candidate.game_path.as_deref().map(path_value),
    })
}

fn account_kind_value(kind: &apogee_core::AccountKind) -> Value {
    match kind {
        apogee_core::AccountKind::Standard => json!({ "kind": "standard" }),
        apogee_core::AccountKind::Steam { app_id } => {
            json!({ "kind": "steam", "appId": app_id })
        }
        apogee_core::AccountKind::FreeTrial => json!({ "kind": "freeTrial" }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn import_issue_value(issue: &apogee_core::ImportIssue) -> Value {
    let kind = match issue {
        apogee_core::ImportIssue::MalformedJson => "malformedJson",
        apogee_core::ImportIssue::ExpectedArray => "expectedArray",
        apogee_core::ImportIssue::ExpectedObject => "expectedObject",
        apogee_core::ImportIssue::MissingUserName => "missingUserName",
        apogee_core::ImportIssue::InvalidUserName => "invalidUserName",
        apogee_core::ImportIssue::InvalidUseOtp => "invalidUseOtp",
        apogee_core::ImportIssue::InvalidSteamAccount => "invalidSteamAccount",
        apogee_core::ImportIssue::InvalidSavePassword => "invalidSavePassword",
        apogee_core::ImportIssue::DuplicateAccount { first } => {
            return json!({ "kind": "duplicateAccount", "first": first.as_str() });
        }
        apogee_core::ImportIssue::MissingGamePath => "missingGamePath",
        apogee_core::ImportIssue::InvalidGamePath => "invalidGamePath",
        apogee_core::ImportIssue::InvalidFreeTrial => "invalidFreeTrial",
        _ => "unknown",
    };
    json!({ "kind": kind })
}

fn import_report_value(report: &apogee_core::ImportApplyReport) -> Value {
    json!({
        "applied": report.applied.iter().map(|finding| json!({
            "finding": finding.finding.as_str(),
            "account": finding.account.to_string(),
            "accountWrite": import_write_label(finding.account_write),
            "profile": finding.profile.map(|profile| profile.to_string()),
            "profileWrite": finding.profile_write.map(import_write_label),
        })).collect::<Vec<_>>(),
    })
}

const fn import_write_label(write: apogee_core::ImportWrite) -> &'static str {
    match write {
        apogee_core::ImportWrite::Created => "created",
        apogee_core::ImportWrite::Existing => "existing",
    }
}

fn notice_value(notice: &Notice) -> Value {
    match notice {
        Notice::ClockSkew { seconds } => {
            json!({ "kind": "clockSkew", "seconds": seconds })
        }
        Notice::OtpListenerFlood { from, refused } => json!({
            "kind": "otpListenerFlood",
            "from": from.to_string(),
            "refused": refused,
        }),
        _ => json!({ "kind": "unknown" }),
    }
}

fn core_error_value(error: &apogee_core::CoreError) -> Value {
    match error {
        apogee_core::CoreError::Store(store) => {
            json!({ "kind": "store", "store": store_error_value(store) })
        }
        apogee_core::CoreError::Proto(_) => json!({ "kind": "proto" }),
        apogee_core::CoreError::Fetch(_) => json!({ "kind": "fetch" }),
        apogee_core::CoreError::Patch(_) => json!({ "kind": "patch" }),
        apogee_core::CoreError::GameRunning { process } => json!({
            "kind": "gameRunning",
            "executable": process.as_ref().map(|process| &process.executable),
            "pid": process.as_ref().map(|process| process.pid),
        }),
        apogee_core::CoreError::Runtime(_) => json!({ "kind": "runtime" }),
        apogee_core::CoreError::Addons(_) => json!({ "kind": "addons" }),
        apogee_core::CoreError::Addon { .. } => json!({ "kind": "addon" }),
        apogee_core::CoreError::Config { var, reason } => json!({
            "kind": "config",
            "variable": var,
            "reason": reason,
        }),
        apogee_core::CoreError::Secrets(secrets) => json!({
            "kind": "secrets",
            "secrets": secrets_error_label(secrets),
        }),
        apogee_core::CoreError::Otp(_) => json!({ "kind": "otp" }),
        apogee_core::CoreError::Crypto(_) => json!({ "kind": "crypto" }),
        apogee_core::CoreError::NoSteam => json!({ "kind": "noSteam" }),
        apogee_core::CoreError::NoTickSource => json!({ "kind": "noTickSource" }),
        apogee_core::CoreError::NoProfile(profile) => {
            json!({ "kind": "noProfile", "profile": profile.to_string() })
        }
        apogee_core::CoreError::NoAccount(account) => {
            json!({ "kind": "noAccount", "account": account.to_string() })
        }
        apogee_core::CoreError::RemovalPlanChanged { profile } => json!({
            "kind": "removalPlanChanged",
            "profile": profile.to_string(),
        }),
        apogee_core::CoreError::InvalidCredential => json!({ "kind": "invalidCredential" }),
        apogee_core::CoreError::Import { .. } => json!({ "kind": "import" }),
        apogee_core::CoreError::XivImport(_) => json!({ "kind": "xivImport" }),
        apogee_core::CoreError::Support(_) => json!({ "kind": "support" }),
        apogee_core::CoreError::FirstRun(_) => json!({ "kind": "firstRun" }),
        apogee_core::CoreError::Init { .. } => json!({ "kind": "init" }),
        apogee_core::CoreError::Launch { .. } => json!({ "kind": "launch" }),
        apogee_core::CoreError::PatchIncomplete { .. } => json!({ "kind": "patchIncomplete" }),
        apogee_core::CoreError::Repair { .. } => json!({ "kind": "repair" }),
        apogee_core::CoreError::FrontierLink { id } => {
            json!({ "kind": "frontierLink", "id": id })
        }
        apogee_core::CoreError::Unavailable { command } => {
            json!({ "kind": "unavailable", "command": command })
        }
        _ => json!({ "kind": "unknown" }),
    }
}

fn store_error_value(error: &apogee_core::StoreError) -> Value {
    match error {
        apogee_core::StoreError::Corrupt {
            path,
            backup,
            detail: _,
        } => json!({
            "kind": "corrupt",
            "path": path_value(path),
            "backup": path_value(backup),
        }),
        apogee_core::StoreError::Io { path, .. } => {
            json!({ "kind": "io", "path": path_value(path) })
        }
        apogee_core::StoreError::NotFound { path } => {
            json!({ "kind": "notFound", "path": path_value(path) })
        }
        _ => json!({ "kind": "unknown" }),
    }
}

const fn secrets_error_label(error: &apogee_core::SecretsError) -> &'static str {
    match error {
        apogee_core::SecretsError::Locked => "locked",
        apogee_core::SecretsError::NoBackend => "noBackend",
        apogee_core::SecretsError::Denied => "denied",
        apogee_core::SecretsError::NoCollection => "noCollection",
        apogee_core::SecretsError::Ambiguous => "ambiguous",
        apogee_core::SecretsError::WrongPassphrase => "wrongPassphrase",
        apogee_core::SecretsError::Corrupt { .. } => "corrupt",
        apogee_core::SecretsError::NotStoring => "notStoring",
        apogee_core::SecretsError::Empty => "empty",
        apogee_core::SecretsError::Backend { .. } => "backend",
        apogee_core::SecretsError::Io(_) => "io",
        _ => "unknown",
    }
}

fn program_status_value(status: ProgramStatus) -> Value {
    match status {
        ProgramStatus::Code(code) => json!({ "kind": "code", "value": code }),
        ProgramStatus::Signal(signal) => json!({ "kind": "signal", "value": signal }),
    }
}

const fn outcome_label(outcome: RunOutcome) -> &'static str {
    match outcome {
        RunOutcome::Succeeded => "succeeded",
        RunOutcome::Failed => "failed",
        RunOutcome::Cancelled => "cancelled",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn goldens() -> Value {
        serde_json::from_str(include_str!("../../apogee/event-wire-golden.json"))
            .unwrap_or(Value::Null)
    }

    #[test]
    fn progress_keeps_every_machine_readable_recovery_field() {
        let line = render_event_json(&Event::Progress(apogee_core::Progress {
            completed: 64,
            total: 128,
            recoveries: Recoveries {
                retries: 1,
                rotations: 2,
                stalls: 3,
                blocks_refetched: 4,
                sources_dropped: 5,
                demoted: true,
            },
        }));
        let value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);

        assert_eq!(value["kind"], "progress");
        assert_eq!(value["code"], "event-progress");
        assert_eq!(value["completed"], 64);
        assert_eq!(value["recoveries"]["blocksRefetched"], 4);
        assert_eq!(value["recoveries"]["demoted"], true);
        assert!(!line.contains('\n'));
    }

    #[test]
    fn errors_expose_only_whitelisted_fields_and_the_stable_code() {
        let line = render_event_json(&Event::Error(apogee_core::CoreError::Launch {
            detail: "token=planted-secret".to_owned(),
        }));
        let value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);

        assert_eq!(
            value,
            json!({
                "kind": "error",
                "code": "err-launch",
                "error": { "kind": "launch" },
            })
        );
        assert!(!line.contains("planted-secret"));
    }

    #[test]
    fn state_data_and_terminal_outcome_are_not_flattened_away() {
        let state = render_event_json(&Event::State(FlowState::PatchesPending {
            count: 7,
            bytes: 4096,
        }));
        let outcome = render_event_json(&Event::Outcome(RunOutcome::Cancelled));
        let state: Value = serde_json::from_str(&state).unwrap_or(Value::Null);
        let outcome: Value = serde_json::from_str(&outcome).unwrap_or(Value::Null);

        assert_eq!(state["state"]["kind"], "patchesPending");
        assert_eq!(state["state"]["count"], 7);
        assert_eq!(state["state"]["bytes"], 4096);
        assert_eq!(outcome["outcome"], "cancelled");
        assert_eq!(outcome["code"], "event-outcome-cancelled");
    }

    #[test]
    fn first_run_checkpoint_is_structured_data() {
        let line = render_event_json(&Event::FirstRun(Box::default()));
        let value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);

        assert_eq!(value["kind"], "firstRun");
        assert_eq!(value["firstRun"]["import"]["state"], "discoveryPending");
        assert_eq!(value["firstRun"]["ready"]["state"], "pending");
    }

    #[test]
    fn representative_events_match_the_desktop_wire_contract() {
        let cases = [
            (
                "state",
                Event::State(FlowState::PatchesPending {
                    count: 7,
                    bytes: 4096,
                }),
            ),
            (
                "progress",
                Event::Progress(apogee_core::Progress {
                    completed: 64,
                    total: 128,
                    recoveries: Recoveries {
                        retries: 1,
                        rotations: 2,
                        stalls: 3,
                        blocks_refetched: 4,
                        sources_dropped: 5,
                        demoted: true,
                    },
                }),
            ),
            (
                "frontierNews",
                Event::Frontier(FrontierData::News(NewsData {
                    news: vec![NewsRow {
                        id: "headline-1".to_owned(),
                        date: "2026-08-24".to_owned(),
                        title: "Launcher news".to_owned(),
                        tag: "news".to_owned(),
                    }],
                    topics: Vec::new(),
                    pinned: Vec::new(),
                })),
            ),
            (
                "frontierGate",
                Event::Frontier(FrontierData::Gate(GateData {
                    open: false,
                    messages: vec!["Maintenance".to_owned()],
                    news: vec!["notice-1".to_owned()],
                })),
            ),
            (
                "frontierBanners",
                Event::Frontier(FrontierData::Banners(vec![BannerData {
                    id: "banner-1".to_owned(),
                    artwork: None,
                    order_priority: "1".to_owned(),
                    fix_order: Some("2".to_owned()),
                }])),
            ),
            ("firstRun", Event::FirstRun(Box::default())),
            ("notice", Event::Notice(Notice::ClockSkew { seconds: -45 })),
            (
                "error",
                Event::Error(apogee_core::CoreError::Launch {
                    detail: "token=planted-secret".to_owned(),
                }),
            ),
            ("outcome", Event::Outcome(RunOutcome::Cancelled)),
        ];
        let goldens = goldens();

        for (name, event) in cases {
            let line = render_event_json(&event);
            let value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
            assert_eq!(value, goldens[name], "{name}");
            assert!(!line.contains("planted-secret"));
        }
    }

    #[test]
    fn hostile_multiline_fields_remain_one_json_line() {
        let line = render_event_json(&Event::Setup(SetupEvent::Caveat {
            what: "renderer\nmode".to_owned(),
            note: "line one\r\nline two".to_owned(),
        }));

        assert!(!line.contains('\n'));
        assert!(!line.contains('\r'));
        let value: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        assert_eq!(value["setup"]["what"], "renderer\nmode");
        assert_eq!(value["setup"]["note"], "line one\r\nline two");
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_keep_their_exact_platform_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_vec(b"game-\xff".to_vec()));
        let value = path_value(&path);

        assert_eq!(value["value"]["kind"], "unix");
        assert_eq!(value["value"]["value"], json!([103, 97, 109, 101, 45, 255]));
    }

    #[cfg(windows)]
    #[test]
    fn non_utf8_paths_keep_their_exact_platform_units() {
        use std::ffi::OsString;
        use std::os::windows::ffi::OsStringExt;

        let path = std::path::PathBuf::from(OsString::from_wide(&[0xd800]));
        let value = path_value(&path);

        assert_eq!(value["value"]["kind"], "windows");
        assert_eq!(value["value"]["value"], json!([0xd800]));
    }
}
