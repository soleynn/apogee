//! Sealed credential-file lifecycle commands and the one-way prompt response.

use std::sync::Arc;

use apogee_core::{Consent, Core, Uuid};

use crate::ShellState;
use crate::dto::IpcErrorDto;
use crate::dto::secrets::{
    ChangeSecretsFilePassphraseRequestDto, CreateSecretsFileRequestDto, PassphraseAnswerDto,
    RemoveSecretsFileRequestDto, SecretsFileRemovalDto, SecretsFileStatusDto,
};
use crate::run_blocking;

fn status(core: &Core) -> SecretsFileStatusDto {
    SecretsFileStatusDto::new(core.secrets_file_state(), core.secrets_file_is_open())
}

async fn blocking_core_mutation<T, F>(
    core: Arc<Core>,
    lease: crate::supervisor::MutationLease,
    task: F,
) -> Result<T, IpcErrorDto>
where
    T: Send + 'static,
    F: FnOnce(&Core) -> Result<T, IpcErrorDto> + Send + 'static,
{
    run_blocking(move || {
        let _lease = lease;
        task(&core)
    })
    .await?
}

/// Inspect the sealed-file header and key-cache reading without prompting.
#[tauri::command]
pub(super) async fn secrets_file_status(
    state: tauri::State<'_, ShellState>,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    secrets_file_status_inner(&state).await
}

async fn secrets_file_status_inner(
    state: &ShellState,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    let (core, _permit) = state.ready_core_for_direct_read().await?;
    run_blocking(move || status(&core)).await
}

/// Prompt through the ambient bridge and prime the exact handle used by the selected backend.
#[tauri::command]
pub(super) async fn unlock_secrets_file(
    state: tauri::State<'_, ShellState>,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    unlock_secrets_file_inner(&state).await
}

async fn unlock_secrets_file_inner(
    state: &ShellState,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    blocking_core_mutation(core, lease, |core| {
        core.unlock_secrets_file()
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(status(core))
    })
    .await
}

/// Create an empty sealed file only after the caller's explicit confirmation.
#[tauri::command]
pub(super) async fn create_secrets_file(
    state: tauri::State<'_, ShellState>,
    request: CreateSecretsFileRequestDto,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    // Move inbound bytes into the zeroizing domain type before the first await.
    let (confirmed, passphrase) = request.into_parts();
    create_secrets_file_inner(&state, confirmed, passphrase).await
}

async fn create_secrets_file_inner(
    state: &ShellState,
    confirmed: bool,
    passphrase: apogee_core::Secret,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    if !confirmed {
        return Err(IpcErrorDto::shell("shell.confirmation.required"));
    }
    state.initial_snapshot().await?;
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    blocking_core_mutation(core, lease, move |core| {
        core.create_secrets_file(Consent::granted(), &passphrase)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(status(core))
    })
    .await
}

/// Re-seal the file under a new passphrase after proving the current one.
#[tauri::command]
pub(super) async fn change_secrets_file_passphrase(
    state: tauri::State<'_, ShellState>,
    request: ChangeSecretsFilePassphraseRequestDto,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    // Move both allocations before any scheduling point can retain the deserialized DTO.
    let (current, replacement) = request.into_parts();
    change_secrets_file_passphrase_inner(&state, current, replacement).await
}

async fn change_secrets_file_passphrase_inner(
    state: &ShellState,
    current: apogee_core::Secret,
    replacement: apogee_core::Secret,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    state.initial_snapshot().await?;
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    blocking_core_mutation(core, lease, move |core| {
        core.change_secrets_file_passphrase(&current, &replacement)
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(status(core))
    })
    .await
}

/// Delete the sealed file and report both whether it existed and the refreshed state.
#[tauri::command]
pub(super) async fn remove_secrets_file(
    state: tauri::State<'_, ShellState>,
    request: RemoveSecretsFileRequestDto,
) -> Result<SecretsFileRemovalDto, IpcErrorDto> {
    remove_secrets_file_inner(&state, request.confirmed()).await
}

async fn remove_secrets_file_inner(
    state: &ShellState,
    confirmed: bool,
) -> Result<SecretsFileRemovalDto, IpcErrorDto> {
    if !confirmed {
        return Err(IpcErrorDto::shell("shell.confirmation.required"));
    }
    state.initial_snapshot().await?;
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    blocking_core_mutation(core, lease, |core| {
        let removed = core
            .remove_secrets_file(Consent::granted())
            .map_err(|error| IpcErrorDto::core(&error))?;
        Ok(SecretsFileRemovalDto::new(removed, status(core)))
    })
    .await
}

/// Erase this process's cached derived key immediately.
#[tauri::command]
pub(super) async fn seal_secrets_file(
    state: tauri::State<'_, ShellState>,
) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    seal_secrets_file_inner(&state).await
}

async fn seal_secrets_file_inner(state: &ShellState) -> Result<SecretsFileStatusDto, IpcErrorDto> {
    let core = state.ready_core().await?;
    let lease = state.mutation_lease()?;
    run_blocking(move || {
        let _lease = lease;
        core.seal_secrets_file();
        status(&core)
    })
    .await
}

/// Answer one pending passphrase request without waiting for Core or entering the file-operation
/// gate. This is the intentionally independent half that can wake a blocking prompt.
#[tauri::command]
pub(super) async fn answer_passphrase_prompt(
    state: tauri::State<'_, ShellState>,
    request_id: String,
    answer: PassphraseAnswerDto,
) -> Result<bool, IpcErrorDto> {
    Ok(answer_passphrase_prompt_inner(&state, &request_id, answer))
}

fn answer_passphrase_prompt_inner(
    state: &ShellState,
    request_id: &str,
    answer: PassphraseAnswerDto,
) -> bool {
    let answer = answer.into_secret();
    let Ok(request_id) = Uuid::parse_str(request_id) else {
        return false;
    };
    state.passphrases.answer(request_id, answer)
}

#[cfg(test)]
mod tests {
    use apogee_core::{CoreConfig, Passphrase, Secret};

    use super::*;
    use crate::passphrase::{
        PASSPHRASE_REQUEST_EVENT, PassphrasePromptDto, PromptEmitError, PromptEmitter,
        WebviewPassphrase,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn ipc_error(error: IpcErrorDto) -> Box<dyn std::error::Error> {
        std::io::Error::other(
            serde_json::to_string(&error).unwrap_or_else(|_| "IPC failure".to_owned()),
        )
        .into()
    }

    struct Requests {
        sent: tokio::sync::mpsc::UnboundedSender<Uuid>,
    }

    impl PromptEmitter for Requests {
        fn emit(
            &self,
            event: &'static str,
            prompt: &PassphrasePromptDto,
        ) -> Result<(), PromptEmitError> {
            if event != PASSPHRASE_REQUEST_EVENT {
                return Err(PromptEmitError::new());
            }
            let request =
                Uuid::parse_str(&prompt.request_id).map_err(|_| PromptEmitError::new())?;
            self.sent.send(request).map_err(|_| PromptEmitError::new())
        }
    }

    async fn answer_next(
        state: &ShellState,
        requests: &mut tokio::sync::mpsc::UnboundedReceiver<Uuid>,
        secret: &'static [u8],
    ) -> TestResult {
        let request = requests
            .recv()
            .await
            .ok_or_else(|| std::io::Error::other("prompt event stream closed"))?;
        let answer: PassphraseAnswerDto = serde_json::from_value(serde_json::json!({
            "kind": "submit",
            "passphrase": secret,
        }))?;
        if !answer_passphrase_prompt_inner(state, &request.to_string(), answer) {
            return Err(std::io::Error::other("prompt was no longer pending").into());
        }
        let duplicate: PassphraseAnswerDto = serde_json::from_str(r#"{"kind":"cancel"}"#)?;
        assert!(!answer_passphrase_prompt_inner(
            state,
            &request.to_string(),
            duplicate
        ));
        Ok(())
    }

    #[tokio::test]
    async fn lifecycle_uses_the_bridge_and_never_caches_a_wrong_answer() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let state = Arc::new(ShellState::default());
        let (sent, mut received) = tokio::sync::mpsc::unbounded_channel();
        let bridge = Arc::new(WebviewPassphrase::new(
            Arc::clone(&state.passphrases),
            Arc::new(Requests { sent }),
            std::thread::current().id(),
        ));
        assert!(bridge.can_prompt());
        state.install_core(Ok(Core::with_passphrase(
            CoreConfig::with_base(temporary.path()),
            bridge,
        )?));
        let malformed: PassphraseAnswerDto = serde_json::from_str(r#"{"kind":"cancel"}"#)?;
        assert!(!answer_passphrase_prompt_inner(
            &state,
            "not-a-request-id",
            malformed
        ));
        let unconfirmed =
            create_secrets_file_inner(&state, false, Secret::new(b"correct passphrase".to_vec()))
                .await;
        assert!(unconfirmed.is_err());
        assert!(
            !state
                .ready_core()
                .await
                .map_err(ipc_error)?
                .secrets_path()
                .exists()
        );

        let created =
            create_secrets_file_inner(&state, true, Secret::new(b"correct passphrase".to_vec()))
                .await
                .map_err(ipc_error)?;
        assert!(serde_json::to_string(&created)?.contains(r#""isOpen":true"#));
        let sealed = seal_secrets_file_inner(&state).await.map_err(ipc_error)?;
        assert!(serde_json::to_string(&sealed)?.contains(r#""isOpen":false"#));

        let wrong = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { unlock_secrets_file_inner(&state).await })
        };
        answer_next(&state, &mut received, b"wrong passphrase").await?;
        let wrong = wrong.await?;
        let Err(error) = wrong else {
            return Err(std::io::Error::other("wrong passphrase unlocked the file").into());
        };
        assert_eq!(
            serde_json::to_string(&error)?,
            r#"{"code":"err-secrets","error":{"kind":"secrets","secrets":"wrongPassphrase"}}"#
        );

        let unlocked = {
            let state = Arc::clone(&state);
            tokio::spawn(async move { unlock_secrets_file_inner(&state).await })
        };
        answer_next(&state, &mut received, b"correct passphrase").await?;
        let opened = unlocked.await?.map_err(ipc_error)?;
        assert!(serde_json::to_string(&opened)?.contains(r#""isOpen":true"#));

        let unconfirmed_remove = remove_secrets_file_inner(&state, false).await;
        assert!(unconfirmed_remove.is_err());
        assert!(
            state
                .ready_core()
                .await
                .map_err(ipc_error)?
                .secrets_path()
                .exists()
        );
        let removed = remove_secrets_file_inner(&state, true)
            .await
            .map_err(ipc_error)?;
        let removed = serde_json::to_string(&removed)?;
        assert!(removed.contains(r#""removed":true"#));
        assert!(removed.contains(r#""kind":"absent""#));
        assert!(removed.contains(r#""isOpen":false"#));
        Ok(())
    }

    #[tokio::test]
    async fn unconfirmed_destructive_requests_do_not_wait_for_or_touch_core() {
        let state = ShellState::default();
        let create = create_secrets_file_inner(&state, false, Secret::new(b"unused".to_vec()));
        let remove = remove_secrets_file_inner(&state, false);

        assert!(create.await.is_err());
        assert!(remove.await.is_err());
    }

    #[tokio::test]
    async fn aborted_waiter_cannot_release_a_running_blocking_mutation() -> TestResult {
        let temporary = tempfile::TempDir::new()?;
        let state = Arc::new(ShellState::default());
        state.install_core(Core::new(CoreConfig::with_base(temporary.path())));
        let core = state.ready_core().await.map_err(ipc_error)?;
        let lease = state.mutation_lease().map_err(ipc_error)?;
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let waiting = tokio::spawn(blocking_core_mutation(core, lease, move |_| {
            entered_tx
                .send(())
                .map_err(|_| IpcErrorDto::shell("shell.test.enter"))?;
            release_rx
                .recv()
                .map_err(|_| IpcErrorDto::shell("shell.test.release"))?;
            Ok(())
        }));
        tauri::async_runtime::spawn_blocking(move || entered_rx.recv())
            .await
            .map_err(|_| std::io::Error::other("entry waiter panicked"))??;

        waiting.abort();
        assert!(state.mutation_lease().is_err());
        release_tx.send(())?;
        for _ in 0..1_000 {
            if state.mutation_lease().is_ok() {
                return Ok(());
            }
            tokio::task::yield_now().await;
        }
        Err(std::io::Error::other("blocking task did not release mutation admission").into())
    }
}
