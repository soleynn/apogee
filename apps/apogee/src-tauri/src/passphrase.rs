//! The synchronous secret-store prompt bridged onto the webview event loop.

use std::collections::HashMap;
use std::sync::mpsc::{self, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::ThreadId;
use std::time::Duration;

use apogee_core::{Passphrase, Secret, SecretsError, Uuid};
use serde::Serialize;
use ts_rs::TS;

/// The ambient shell event that asks the webview for a sealed-store passphrase.
pub(crate) const PASSPHRASE_REQUEST_EVENT: &str = "passphrase-request";

const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// The complete outbound prompt payload. Secret material only travels back through a command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(export, export_to = "PassphrasePrompt.ts")]
pub(crate) struct PassphrasePromptDto {
    pub(crate) request_id: String,
}

/// A redacted emission failure. The underlying UI error must not be carried into secret handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PromptEmitError;

impl PromptEmitError {
    pub(crate) const fn new() -> Self {
        Self
    }
}

/// The shell event seam used by the blocking passphrase source.
pub(crate) trait PromptEmitter: Send + Sync {
    fn emit(
        &self,
        event: &'static str,
        prompt: &PassphrasePromptDto,
    ) -> Result<(), PromptEmitError>;
}

/// Routes inbound answers to the one blocking caller that owns each request identifier.
#[derive(Default)]
pub(crate) struct PromptBroker {
    pending: Mutex<HashMap<Uuid, SyncSender<Option<Secret>>>>,
}

impl PromptBroker {
    /// Answer a pending prompt. Unknown, expired, and already-answered identifiers are refused.
    pub(crate) fn answer(&self, request_id: Uuid, answer: Option<Secret>) -> bool {
        let sender = self.pending().remove(&request_id);
        sender.is_some_and(|sender| sender.send(answer).is_ok())
    }

    fn insert(&self, request_id: Uuid, sender: SyncSender<Option<Secret>>) -> bool {
        use std::collections::hash_map::Entry;

        match self.pending().entry(request_id) {
            Entry::Vacant(entry) => {
                entry.insert(sender);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    fn remove(&self, request_id: Uuid) {
        self.pending().remove(&request_id);
    }

    fn pending(&self) -> MutexGuard<'_, HashMap<Uuid, SyncSender<Option<Secret>>>> {
        self.pending.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

struct PendingRequest<'a> {
    broker: &'a PromptBroker,
    request_id: Uuid,
}

impl Drop for PendingRequest<'_> {
    fn drop(&mut self) {
        self.broker.remove(self.request_id);
    }
}

/// A synchronous [`Passphrase`] implementation backed by an ambient webview prompt.
pub(crate) struct WebviewPassphrase {
    broker: Arc<PromptBroker>,
    emitter: Arc<dyn PromptEmitter>,
    main_thread: ThreadId,
    timeout: Duration,
}

impl WebviewPassphrase {
    pub(crate) fn new(
        broker: Arc<PromptBroker>,
        emitter: Arc<dyn PromptEmitter>,
        main_thread: ThreadId,
    ) -> Self {
        Self::with_timeout(broker, emitter, main_thread, PROMPT_TIMEOUT)
    }

    pub(crate) fn with_timeout(
        broker: Arc<PromptBroker>,
        emitter: Arc<dyn PromptEmitter>,
        main_thread: ThreadId,
        timeout: Duration,
    ) -> Self {
        Self {
            broker,
            emitter,
            main_thread,
            timeout,
        }
    }

    fn register(&self, sender: SyncSender<Option<Secret>>) -> (Uuid, PendingRequest<'_>) {
        loop {
            let request_id = Uuid::new_v4();
            if self.broker.insert(request_id, sender.clone()) {
                return (
                    request_id,
                    PendingRequest {
                        broker: &self.broker,
                        request_id,
                    },
                );
            }
        }
    }
}

impl Passphrase for WebviewPassphrase {
    fn unlock(&self) -> Result<Secret, SecretsError> {
        debug_assert_ne!(
            std::thread::current().id(),
            self.main_thread,
            "the passphrase bridge must not block the main thread"
        );

        let (answer, receiver) = mpsc::sync_channel(1);
        let (request_id, pending) = self.register(answer);
        let prompt = PassphrasePromptDto {
            request_id: request_id.to_string(),
        };

        if self
            .emitter
            .emit(PASSPHRASE_REQUEST_EVENT, &prompt)
            .is_err()
        {
            return Err(SecretsError::Locked);
        }

        let result = match receiver.recv_timeout(self.timeout) {
            Ok(Some(secret)) if !secret.is_empty() => Ok(secret),
            Ok(Some(_)) | Ok(None) | Err(_) => Err(SecretsError::Locked),
        };
        drop(pending);
        result
    }

    fn can_prompt(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc::{Receiver, Sender};
    use std::thread;

    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    struct AnsweringEmitter {
        broker: Arc<PromptBroker>,
        answer: Mutex<Option<Option<Secret>>>,
        observed: Mutex<Vec<(String, PassphrasePromptDto)>>,
    }

    impl AnsweringEmitter {
        fn new(broker: Arc<PromptBroker>, answer: Option<Secret>) -> Self {
            Self {
                broker,
                answer: Mutex::new(Some(answer)),
                observed: Mutex::new(Vec::new()),
            }
        }
    }

    impl PromptEmitter for AnsweringEmitter {
        fn emit(
            &self,
            event: &'static str,
            prompt: &PassphrasePromptDto,
        ) -> Result<(), PromptEmitError> {
            self.observed
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((event.to_owned(), prompt.clone()));
            let answer = self
                .answer
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
                .flatten();
            let request_id = Uuid::parse_str(&prompt.request_id).map_err(|_| PromptEmitError)?;
            if self.broker.answer(request_id, answer) {
                Ok(())
            } else {
                Err(PromptEmitError)
            }
        }
    }

    struct FailingEmitter;

    impl PromptEmitter for FailingEmitter {
        fn emit(&self, _: &'static str, _: &PassphrasePromptDto) -> Result<(), PromptEmitError> {
            Err(PromptEmitError::new())
        }
    }

    struct CapturingEmitter {
        requests: Sender<Uuid>,
    }

    impl PromptEmitter for CapturingEmitter {
        fn emit(
            &self,
            event: &'static str,
            prompt: &PassphrasePromptDto,
        ) -> Result<(), PromptEmitError> {
            if event != PASSPHRASE_REQUEST_EVENT {
                return Err(PromptEmitError);
            }
            let request_id = Uuid::parse_str(&prompt.request_id).map_err(|_| PromptEmitError)?;
            self.requests.send(request_id).map_err(|_| PromptEmitError)
        }
    }

    fn worker_bridge(
        broker: Arc<PromptBroker>,
        emitter: Arc<dyn PromptEmitter>,
        timeout: Duration,
    ) -> WebviewPassphrase {
        WebviewPassphrase::with_timeout(broker, emitter, thread::current().id(), timeout)
    }

    fn unlock_on_worker(
        broker: Arc<PromptBroker>,
        emitter: Arc<dyn PromptEmitter>,
        timeout: Duration,
    ) -> thread::JoinHandle<Result<Secret, SecretsError>> {
        let main_thread = thread::current().id();
        thread::spawn(move || {
            WebviewPassphrase::with_timeout(broker, emitter, main_thread, timeout).unlock()
        })
    }

    fn receive_request(requests: &Receiver<Uuid>) -> Result<Uuid, Box<dyn std::error::Error>> {
        Ok(requests.recv_timeout(Duration::from_secs(2))?)
    }

    #[test]
    fn prompt_is_registered_before_emission_and_contains_only_an_identifier() -> TestResult {
        let broker = Arc::new(PromptBroker::default());
        let emitter = Arc::new(AnsweringEmitter::new(
            Arc::clone(&broker),
            Some(Secret::new(b"correct horse".to_vec())),
        ));
        let bridge = unlock_on_worker(Arc::clone(&broker), emitter.clone(), Duration::from_secs(2));

        let secret = bridge
            .join()
            .map_err(|_| std::io::Error::other("unlock worker panicked"))??;
        assert_eq!(secret.expose(), b"correct horse");
        let observed = emitter
            .observed
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].0, PASSPHRASE_REQUEST_EVENT);
        assert_eq!(
            serde_json::to_string(&observed[0].1)?,
            format!(r#"{{"requestId":"{}"}}"#, observed[0].1.request_id)
        );
        assert_eq!(broker.pending().len(), 0);
        Ok(())
    }

    #[test]
    fn another_thread_can_answer_while_unlock_waits() -> TestResult {
        let broker = Arc::new(PromptBroker::default());
        let (requests_tx, requests_rx) = mpsc::channel();
        let bridge = unlock_on_worker(
            Arc::clone(&broker),
            Arc::new(CapturingEmitter {
                requests: requests_tx,
            }),
            Duration::from_secs(2),
        );
        let request_id = receive_request(&requests_rx)?;

        assert!(broker.answer(request_id, Some(Secret::new(b"answer".to_vec()))));
        let secret = bridge
            .join()
            .map_err(|_| std::io::Error::other("unlock worker panicked"))??;
        assert_eq!(secret.expose(), b"answer");
        assert_eq!(broker.pending().len(), 0);
        Ok(())
    }

    #[test]
    fn cancellation_and_empty_answers_are_locked() -> TestResult {
        for answer in [None, Some(Secret::new(Vec::new()))] {
            let broker = Arc::new(PromptBroker::default());
            let emitter = Arc::new(AnsweringEmitter::new(Arc::clone(&broker), answer));
            let bridge = unlock_on_worker(broker, emitter, Duration::from_secs(2));
            assert!(matches!(
                bridge
                    .join()
                    .map_err(|_| std::io::Error::other("unlock worker panicked"))?,
                Err(SecretsError::Locked)
            ));
        }
        Ok(())
    }

    #[test]
    fn emission_failure_is_locked_and_cleans_the_request() -> TestResult {
        let broker = Arc::new(PromptBroker::default());
        let bridge = unlock_on_worker(
            Arc::clone(&broker),
            Arc::new(FailingEmitter),
            Duration::from_secs(2),
        );
        assert!(matches!(
            bridge
                .join()
                .map_err(|_| std::io::Error::other("unlock worker panicked"))?,
            Err(SecretsError::Locked)
        ));
        assert_eq!(broker.pending().len(), 0);
        Ok(())
    }

    #[test]
    fn timeout_is_locked_and_late_answers_are_refused() -> TestResult {
        let broker = Arc::new(PromptBroker::default());
        let (requests_tx, requests_rx) = mpsc::channel();
        let bridge = unlock_on_worker(
            Arc::clone(&broker),
            Arc::new(CapturingEmitter {
                requests: requests_tx,
            }),
            Duration::from_millis(10),
        );
        let request_id = receive_request(&requests_rx)?;
        assert!(matches!(
            bridge
                .join()
                .map_err(|_| std::io::Error::other("unlock worker panicked"))?,
            Err(SecretsError::Locked)
        ));
        assert!(!broker.answer(request_id, Some(Secret::new(b"late".to_vec()))));
        assert_eq!(broker.pending().len(), 0);
        Ok(())
    }

    #[test]
    fn disconnected_answer_channel_is_locked_and_cleaned() -> TestResult {
        struct DisconnectingEmitter {
            broker: Arc<PromptBroker>,
        }

        impl PromptEmitter for DisconnectingEmitter {
            fn emit(
                &self,
                _: &'static str,
                prompt: &PassphrasePromptDto,
            ) -> Result<(), PromptEmitError> {
                let request_id =
                    Uuid::parse_str(&prompt.request_id).map_err(|_| PromptEmitError)?;
                self.broker.remove(request_id);
                Ok(())
            }
        }

        let broker = Arc::new(PromptBroker::default());
        let bridge = unlock_on_worker(
            Arc::clone(&broker),
            Arc::new(DisconnectingEmitter {
                broker: Arc::clone(&broker),
            }),
            Duration::from_secs(2),
        );
        assert!(matches!(
            bridge
                .join()
                .map_err(|_| std::io::Error::other("unlock worker panicked"))?,
            Err(SecretsError::Locked)
        ));
        assert_eq!(broker.pending().len(), 0);
        Ok(())
    }

    #[test]
    fn an_identifier_is_answered_at_most_once() -> TestResult {
        let broker = Arc::new(PromptBroker::default());
        let (requests_tx, requests_rx) = mpsc::channel();
        let bridge = unlock_on_worker(
            Arc::clone(&broker),
            Arc::new(CapturingEmitter {
                requests: requests_tx,
            }),
            Duration::from_secs(2),
        );
        let request_id = receive_request(&requests_rx)?;
        assert!(broker.answer(request_id, Some(Secret::new(b"first".to_vec()))));
        assert!(!broker.answer(request_id, Some(Secret::new(b"second".to_vec()))));
        let secret = bridge
            .join()
            .map_err(|_| std::io::Error::other("unlock worker panicked"))??;
        assert_eq!(secret.expose(), b"first");
        Ok(())
    }

    #[test]
    fn poisoned_broker_state_is_recovered_without_losing_the_request() -> TestResult {
        let broker = Arc::new(PromptBroker::default());
        let (answer, receiver) = mpsc::sync_channel(1);
        let request_id = Uuid::new_v4();
        assert!(broker.insert(request_id, answer));
        let poisoned = Arc::clone(&broker);
        let poisoner = thread::spawn(move || {
            let _guard = poisoned.pending();
            std::panic::resume_unwind(Box::new("poison the broker"));
        });
        assert!(poisoner.join().is_err());

        assert!(broker.answer(request_id, Some(Secret::new(b"recovered".to_vec()))));
        let Some(secret) = receiver.recv_timeout(Duration::from_secs(2))? else {
            return Err(std::io::Error::other("broker delivered cancellation").into());
        };
        assert_eq!(secret.expose(), b"recovered");
        assert_eq!(broker.pending().len(), 0);
        Ok(())
    }

    #[test]
    fn bridge_advertises_prompt_support() {
        let bridge = worker_bridge(
            Arc::new(PromptBroker::default()),
            Arc::new(FailingEmitter),
            Duration::from_secs(2),
        );
        assert!(bridge.can_prompt());
    }

    #[test]
    fn production_bridge_waits_for_two_minutes() {
        let bridge = WebviewPassphrase::new(
            Arc::new(PromptBroker::default()),
            Arc::new(FailingEmitter),
            thread::current().id(),
        );
        assert_eq!(bridge.timeout, Duration::from_secs(120));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "the passphrase bridge must not block the main thread")]
    fn debug_build_rejects_main_thread_unlock() {
        let bridge = worker_bridge(
            Arc::new(PromptBroker::default()),
            Arc::new(FailingEmitter),
            Duration::from_secs(2),
        );
        let _ = bridge.unlock();
    }
}
