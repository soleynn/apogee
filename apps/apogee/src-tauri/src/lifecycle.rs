//! Window-close coordination: freeze admission, confirm, cancel, drain, then destroy.

use std::sync::{Mutex, PoisonError};

use tauri::{Emitter, Manager};

use crate::passphrase::PromptBroker;
use crate::supervisor::Runs;
use crate::{IpcErrorDto, ShellState};

pub(crate) const CLOSE_REQUEST_EVENT: &str = "quit-during-run-request";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum ClosePhase {
    #[default]
    Idle,
    Prompting,
    Draining,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CloseDecision {
    Allow,
    Prevent,
    PreventAndPrompt,
}

#[derive(Default)]
pub(crate) struct CloseController {
    phase: Mutex<ClosePhase>,
}

impl CloseController {
    fn request(&self, runs: &Runs) -> Result<CloseDecision, ()> {
        let mut phase = self.phase.lock().map_err(|_| ())?;
        match *phase {
            ClosePhase::Idle => {
                if runs.begin_close()? {
                    *phase = ClosePhase::Prompting;
                    Ok(CloseDecision::PreventAndPrompt)
                } else {
                    *phase = ClosePhase::Closed;
                    Ok(CloseDecision::Allow)
                }
            }
            ClosePhase::Prompting | ClosePhase::Draining => Ok(CloseDecision::Prevent),
            ClosePhase::Closed => Ok(CloseDecision::Allow),
        }
    }

    fn emission_failed(&self, runs: &Runs) {
        let mut phase = self.phase.lock().unwrap_or_else(PoisonError::into_inner);
        if *phase == ClosePhase::Prompting {
            *phase = ClosePhase::Idle;
            let _ = runs.resume();
        }
    }

    async fn answer(
        &self,
        confirmed: bool,
        runs: &Runs,
        prompts: &PromptBroker,
    ) -> Result<bool, ()> {
        {
            let mut phase = self.phase.lock().map_err(|_| ())?;
            if *phase != ClosePhase::Prompting {
                return Ok(false);
            }
            if !confirmed {
                *phase = ClosePhase::Idle;
                drop(phase);
                runs.resume()?;
                return Ok(false);
            }
            *phase = ClosePhase::Draining;
        }

        runs.cancel_all()?;
        prompts.cancel_all();
        runs.wait_empty().await?;
        let mut phase = self.phase.lock().map_err(|_| ())?;
        *phase = ClosePhase::Closed;
        Ok(true)
    }
}

pub(crate) fn on_window_event<R: tauri::Runtime>(
    window: &tauri::Window<R>,
    event: &tauri::WindowEvent,
) {
    let tauri::WindowEvent::CloseRequested { api, .. } = event else {
        return;
    };
    let state = window.state::<ShellState>();
    match state.lifecycle.request(&state.runs) {
        Ok(CloseDecision::Allow) => {}
        Ok(CloseDecision::Prevent) => api.prevent_close(),
        Ok(CloseDecision::PreventAndPrompt) => {
            api.prevent_close();
            if window.emit(CLOSE_REQUEST_EVENT, ()).is_err() {
                state.lifecycle.emission_failed(&state.runs);
            }
        }
        Err(()) => {
            api.prevent_close();
            tracing::error!("could not coordinate the window close request");
        }
    }
}

/// Answer the one outstanding quit-during-work confirmation.
#[tauri::command]
pub(crate) async fn answer_close_request(
    app: tauri::AppHandle,
    state: tauri::State<'_, ShellState>,
    confirmed: bool,
) -> Result<bool, IpcErrorDto> {
    let close = state
        .lifecycle
        .answer(confirmed, &state.runs, &state.passphrases)
        .await
        .map_err(|_| IpcErrorDto::shell("shell.close.unavailable"))?;
    if close {
        if let Some(window) = app.get_webview_window("main") {
            window
                .destroy()
                .map_err(|_| IpcErrorDto::shell("shell.close.failed"))?;
        }
    }
    Ok(close)
}

/// Honor core's detach decision without a second prompt: cancel unrelated shell work, wait for its
/// terminal frames, and only then destroy the window while leaving the game process alone.
pub(crate) async fn close_after_launch(
    app: tauri::AppHandle,
    runs: Runs,
    prompts: std::sync::Arc<PromptBroker>,
) {
    if runs.cancel_all().is_err() {
        tracing::error!("could not freeze work after the game detached");
        return;
    }
    prompts.cancel_all();
    if runs.wait_empty().await.is_err() {
        tracing::error!("could not drain work after the game detached");
        return;
    }
    if let Some(window) = app.get_webview_window("main")
        && window.destroy().is_err()
    {
        tracing::error!("could not close the launcher after the game detached");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supervisor::{RunAdmissionError, RunClass};
    use apogee_core::Uuid;

    #[test]
    fn close_without_work_is_allowed_without_a_prompt() {
        let controller = CloseController::default();
        assert_eq!(controller.request(&Runs::default()), Ok(CloseDecision::Allow));
    }

    #[test]
    fn the_first_working_close_prompts_and_repeated_close_does_not_duplicate_it() {
        let runs = Runs::default();
        let _lease = runs
            .start(Uuid::new_v4(), RunClass::ReadOnly)
            .unwrap_or_else(|_| unreachable!("the read must be admitted"));
        let controller = CloseController::default();

        assert_eq!(
            controller.request(&runs),
            Ok(CloseDecision::PreventAndPrompt)
        );
        assert_eq!(controller.request(&runs), Ok(CloseDecision::Prevent));
        assert_eq!(
            runs.start(Uuid::new_v4(), RunClass::ReadOnly).err(),
            Some(RunAdmissionError::Draining)
        );
    }

    #[tokio::test]
    async fn declining_reopens_admission_without_cancelling_the_run() {
        let runs = Runs::default();
        let lease = runs
            .start(Uuid::new_v4(), RunClass::ReadOnly)
            .unwrap_or_else(|_| unreachable!("the read must be admitted"));
        let token = lease.cancellation();
        let controller = CloseController::default();
        assert_eq!(
            controller.request(&runs),
            Ok(CloseDecision::PreventAndPrompt)
        );

        assert_eq!(
            controller
                .answer(false, &runs, &PromptBroker::default())
                .await,
            Ok(false)
        );
        assert!(!token.is_cancelled());
        assert!(runs.start(Uuid::new_v4(), RunClass::ReadOnly).is_ok());
    }

    #[tokio::test]
    async fn confirmation_cancels_before_waiting_and_finishes_only_after_the_lease() {
        let runs = Runs::default();
        let lease = runs
            .start(Uuid::new_v4(), RunClass::Exclusive)
            .unwrap_or_else(|_| unreachable!("the write must be admitted"));
        let token = lease.cancellation();
        let controller = std::sync::Arc::new(CloseController::default());
        assert_eq!(
            controller.request(&runs),
            Ok(CloseDecision::PreventAndPrompt)
        );

        let answering_controller = std::sync::Arc::clone(&controller);
        let answering_runs = runs.clone();
        let answer = tokio::spawn(async move {
            answering_controller
                .answer(true, &answering_runs, &PromptBroker::default())
                .await
        });
        tokio::task::yield_now().await;
        assert!(token.is_cancelled(), "the token must fire before drain waits");
        assert!(!answer.is_finished());
        drop(lease);
        assert_eq!(answer.await.expect("close answer task"), Ok(true));
    }
}
