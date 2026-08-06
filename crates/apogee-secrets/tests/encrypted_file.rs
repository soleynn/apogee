//! The fallback store, driven end to end against real files.
//!
//! Hermetic: a temporary directory, no bus, no network, no clock beyond two assertions with an order
//! of magnitude of headroom. Every store here is sealed at the least work this build accepts, which
//! is a real production value rather than a test-only one, so the suite exercises the same band a
//! shipped store is measured against.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use apogee_secrets::{
    BackendState, Consent, EncryptedFile, FileState, KdfCost, Passphrase, Secret, SecretKind,
    SecretStore, SecretsError, Unprompted,
};
use uuid::Uuid;

const ACCOUNT: Uuid = Uuid::from_u128(0x0194_8f2c_7d3e_4a51_9b60_c2e8_1f45_a903);
const OTHER: Uuid = Uuid::from_u128(2);

/// A scripted passphrase source that counts what it was asked.
///
/// Counting is the point: "asked once and then not again" and "asked again after a failure" are
/// properties of the caching, and a store that re-derived on every call would pass every round trip
/// while making the user wait a fifth of a second per secret.
struct Scripted {
    answer: Mutex<Vec<u8>>,
    asked: AtomicUsize,
}

impl Scripted {
    fn new(answer: &[u8]) -> Arc<Self> {
        Arc::new(Self {
            answer: Mutex::new(answer.to_vec()),
            asked: AtomicUsize::new(0),
        })
    }

    fn asked(&self) -> usize {
        self.asked.load(Ordering::Relaxed)
    }

    fn now_answers(&self, answer: &[u8]) -> Result<(), String> {
        let mut held = self.answer.lock().map_err(|_| "poisoned".to_string())?;
        *held = answer.to_vec();
        Ok(())
    }
}

impl Passphrase for Scripted {
    fn unlock(&self) -> Result<Secret, SecretsError> {
        self.asked.fetch_add(1, Ordering::Relaxed);
        let held = self.answer.lock().map_err(|_| SecretsError::Locked)?;
        Ok(Secret::new(held.clone()))
    }
}

/// A scratch directory and the store path inside it. Helpers in an integration test return `Result`
/// and propagate; only a `#[test]` body may unwrap.
fn scratch() -> Result<(tempfile::TempDir, std::path::PathBuf), std::io::Error> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join(EncryptedFile::FILE_NAME);
    Ok((dir, path))
}

/// A created store over a scripted source, ready to write to.
fn created(
    path: &std::path::Path,
    passphrase: Arc<Scripted>,
) -> Result<EncryptedFile, SecretsError> {
    created_with_idle(path, passphrase, EncryptedFile::DEFAULT_IDLE)
}

/// As [`created`], with a window of the test's choosing in place of the shipped one.
fn created_with_idle(
    path: &std::path::Path,
    passphrase: Arc<Scripted>,
    idle: std::time::Duration,
) -> Result<EncryptedFile, SecretsError> {
    let store = EncryptedFile::with_idle_timeout(path, passphrase.clone(), idle);
    store.create(
        Consent::granted(),
        &Secret::new(
            passphrase
                .answer
                .lock()
                .map_err(|_| SecretsError::Locked)?
                .clone(),
        ),
        KdfCost::floor(),
    )?;
    Ok(store)
}

fn pw(text: &str) -> Secret {
    Secret::new(text.as_bytes().to_vec())
}

#[test]
fn a_written_secret_reads_back_and_a_missing_one_is_absent() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"correct horse")).expect("create");

    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    let read = store.get(ACCOUNT, SecretKind::Password).expect("read");
    assert_eq!(read.expect("present").expose(), b"hunter2");
    assert!(
        store
            .get(ACCOUNT, SecretKind::TotpSecret)
            .expect("read")
            .is_none()
    );
    assert!(
        store
            .get(OTHER, SecretKind::Password)
            .expect("read")
            .is_none()
    );
}

/// Both envelopes get a nonce of their own, drawn again for every write.
///
/// Only `create` and `change_passphrase` draw a new salt, so across ordinary writes the key is
/// stable and the nonce is the only thing keeping two sealings of one store apart. Under a stable
/// key a repeated nonce is a repeated keystream: XOR two snapshots of the file and the records fall
/// out of it, with no passphrase involved. Nothing else in the suite looks at either field, so the
/// property with the worst failure mode in the crate is observed here or nowhere.
///
/// The offsets are written out rather than imported. A test that read them from the code it guards
/// would follow a layout change instead of catching it.
#[test]
fn every_write_draws_a_fresh_nonce_for_each_envelope() {
    const CHECK_NONCE: std::ops::Range<usize> = 36..60;
    const BODY_NONCE: std::ops::Range<usize> = 76..100;

    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"correct horse")).expect("create");

    let mut seen: Vec<Vec<u8>> = Vec::new();
    for value in ["first", "second", "third"] {
        store
            .set(ACCOUNT, SecretKind::Password, pw(value))
            .expect("write");
        let bytes = std::fs::read(&path).expect("read the sealed file");
        let check = bytes[CHECK_NONCE].to_vec();
        let body = bytes[BODY_NONCE].to_vec();

        assert_ne!(
            check, body,
            "one write sealed both envelopes under the same nonce"
        );
        for nonce in [&check, &body] {
            assert!(
                !seen.contains(nonce),
                "a nonce was drawn twice across writes of one store"
            );
        }
        seen.push(check);
        seen.push(body);
    }
}

/// A write replaces the file. It never rewrites the one that is already there.
///
/// Every test written for the publish path is satisfied by an in-place write: with no temp file
/// there are trivially no strays to sweep, and the concurrent case still passes because the file
/// lock, not the rename, is what serialises it. What in-place costs is the property the rename is
/// there for, that a write which dies partway leaves the previous store whole rather than truncated,
/// and the inode is the cheapest observation of that which does not need to kill a process mid-write.
#[cfg(unix)]
#[test]
fn a_write_replaces_the_file_rather_than_rewriting_it() {
    use std::os::unix::fs::MetadataExt;

    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"correct horse")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    let before = std::fs::metadata(&path).expect("stat").ino();

    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter3"))
        .expect("write");
    let after = std::fs::metadata(&path).expect("stat").ino();

    assert_ne!(
        before, after,
        "the store was rewritten in place instead of being replaced"
    );
}

/// The report follows the path, not the key this handle happens to be holding.
///
/// Answering from the cached key alone meant a handle whose file had been deleted or clobbered
/// behind it went on saying `Ready` with `is_usable()` true, while its own `inspect()` said the
/// store was gone. One process is enough to reach that: a second handle over the same path is all
/// the CLI's destroy-file verb is.
#[test]
fn a_report_follows_the_file_and_not_the_cached_key() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"correct horse")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    assert!(store.is_open());
    assert_eq!(store.probe().state, BackendState::Ready);

    std::fs::remove_file(&path).expect("delete the store behind the handle");
    assert_eq!(store.inspect(), FileState::Absent);
    assert_eq!(store.probe().state, BackendState::NoDefaultCollection);
    assert!(!store.probe().is_usable());

    std::fs::write(&path, vec![0u8; 640]).expect("clobber the store behind the handle");
    assert_eq!(store.inspect(), FileState::Foreign);
    assert_eq!(store.probe().state, BackendState::Unreachable);
    assert!(!store.probe().is_usable());
}

/// A report must not queue behind a write that is waiting on the user.
///
/// A write holds the key cache from before the file is read until after it is re-sealed, and both
/// the passphrase prompt and the derivation are inside that window. A probe that reached for the
/// same lock waited out the whole prompt, so the call a front end makes to decide what to show
/// blocked on the dialog it was deciding whether to show.
#[test]
fn a_report_does_not_wait_for_a_write_that_is_waiting_on_the_user() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"correct horse");
    let store = Arc::new(created(&path, source.clone()).expect("create"));
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");

    // A fresh handle, so the write below has to ask, and a source that takes its time answering.
    let slow = Arc::new(Slow {
        answer: b"correct horse".to_vec(),
        takes: std::time::Duration::from_secs(3),
    });
    let waiting = Arc::new(EncryptedFile::open(&path, slow));
    let writer = {
        let waiting = waiting.clone();
        std::thread::spawn(move || waiting.set(OTHER, SecretKind::Password, pw("second")))
    };

    // Long enough that the write is inside the prompt, short enough to leave most of it left.
    std::thread::sleep(std::time::Duration::from_millis(300));
    let started = std::time::Instant::now();
    let report = waiting.probe();
    let waited = started.elapsed();

    assert!(
        waited < std::time::Duration::from_secs(1),
        "the report waited {waited:?} for a prompt that had seconds left to run"
    );
    assert_eq!(report.state, BackendState::Locked);
    writer.join().expect("writer thread").expect("write");
}

/// A passphrase source that takes its time, standing in for a modal dialog.
struct Slow {
    answer: Vec<u8>,
    takes: std::time::Duration,
}

impl Passphrase for Slow {
    fn unlock(&self) -> Result<Secret, SecretsError> {
        std::thread::sleep(self.takes);
        Ok(Secret::new(self.answer.clone()))
    }
}

/// A value with no bytes in it is refused, not stored.
///
/// An empty secret writes and reads back perfectly well, so nothing downstream notices: a front end
/// renders the account as saved and stops asking, and the login submits an empty password and fails
/// at the far end with an error that says nothing about the store. The crate already draws this line
/// twice, in `Null::set` and in `create`'s empty-passphrase refusal.
#[test]
fn a_secret_with_no_bytes_in_it_is_refused_rather_than_saved() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");

    let err = store
        .set(ACCOUNT, SecretKind::Password, Secret::new(Vec::new()))
        .expect_err("an empty value must be refused");
    assert!(matches!(err, SecretsError::Empty), "{err:?}");
    assert!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .is_none(),
        "the refused write stored something anyway"
    );

    // One byte is a bad password and a real one. Which is not this crate's call to make.
    store
        .set(ACCOUNT, SecretKind::Password, pw("x"))
        .expect("a one-byte secret is a secret");
}

/// The property the whole file exists for. A handle that only worked while it was the one that wrote
/// the file would be a cache, not a store.
#[test]
fn a_store_reopened_with_the_same_passphrase_reads_what_it_wrote() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"correct horse");
    let store = created(&path, source.clone()).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    store
        .set(ACCOUNT, SecretKind::TotpSecret, pw("JBSWY3DPEHPK3PXP"))
        .expect("write");
    drop(store);

    let reopened = EncryptedFile::open(&path, source);
    assert!(!reopened.is_open());
    assert_eq!(
        reopened
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .expect("present")
            .expose(),
        b"hunter2"
    );
    assert_eq!(
        reopened
            .get(ACCOUNT, SecretKind::TotpSecret)
            .expect("read")
            .expect("present")
            .expose(),
        b"JBSWY3DPEHPK3PXP"
    );
}

#[test]
fn a_second_write_replaces_the_first() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("first"))
        .expect("write");
    store
        .set(ACCOUNT, SecretKind::Password, pw("second"))
        .expect("write");
    assert_eq!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .expect("present")
            .expose(),
        b"second"
    );
}

/// A delete that changes nothing must write nothing. Re-sealing would draw fresh nonces and rewrite
/// the file, which to anything watching the directory is indistinguishable from a secret being saved.
#[test]
fn deleting_a_secret_that_is_not_there_leaves_the_file_untouched() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    let before = std::fs::read(&path).expect("read the file");

    store
        .delete(ACCOUNT, SecretKind::TotpSecret)
        .expect("delete");
    store.delete(OTHER, SecretKind::Password).expect("delete");
    store.forget_account(OTHER).expect("sweep");

    assert_eq!(std::fs::read(&path).expect("read the file"), before);
}

#[test]
fn deleting_what_is_there_takes_it_and_leaves_the_rest() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");
    for kind in SecretKind::ALL {
        store.set(ACCOUNT, kind, pw("a")).expect("write");
        store.set(OTHER, kind, pw("b")).expect("write");
    }

    store.delete(ACCOUNT, SecretKind::Password).expect("delete");
    assert!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .is_none()
    );
    assert!(
        store
            .get(ACCOUNT, SecretKind::TotpSecret)
            .expect("read")
            .is_some()
    );
    assert!(
        store
            .get(OTHER, SecretKind::Password)
            .expect("read")
            .is_some()
    );
}

/// Emptying an account is one rewrite here rather than one per kind, and it has to take every kind:
/// what a user asks for when they say the account should be gone is that nothing of it is left.
#[test]
fn forgetting_an_account_clears_every_kind_and_leaves_the_others() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");
    for kind in SecretKind::ALL {
        store.set(ACCOUNT, kind, pw("a")).expect("write");
        store.set(OTHER, kind, pw("b")).expect("write");
    }

    store.forget_account(ACCOUNT).expect("sweep");
    for kind in SecretKind::ALL {
        assert!(store.get(ACCOUNT, kind).expect("read").is_none());
        assert!(store.get(OTHER, kind).expect("read").is_some());
    }
}

/// A write against a path with nothing at it must refuse rather than quietly create a store under a
/// passphrase nobody confirmed. That is the silent fallback the whole design exists to refuse.
#[test]
fn writing_to_a_store_that_was_never_created_refuses_and_makes_no_file() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"pp");
    let store = EncryptedFile::open(&path, source.clone());

    assert!(matches!(
        store.set(ACCOUNT, SecretKind::Password, pw("hunter2")),
        Err(SecretsError::NoCollection)
    ));
    assert!(!path.exists());
    assert_eq!(source.asked(), 0, "a refused write must not prompt");
}

/// A read and a delete against a store that was never created are true statements about an empty
/// store, and neither is worth making a user type a passphrase for.
#[test]
fn reading_and_deleting_a_store_that_was_never_created_never_ask() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"pp");
    let store = EncryptedFile::open(&path, source.clone());

    assert!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .is_none()
    );
    store.delete(ACCOUNT, SecretKind::Password).expect("delete");
    store.forget_account(ACCOUNT).expect("sweep");
    assert_eq!(source.asked(), 0);
}

/// Overwriting an existing store destroys secrets that cannot be got back, and the passphrase that
/// opens it is not knowable from the call, so this refuses instead of asking.
#[test]
fn creating_over_an_existing_store_refuses_and_leaves_it_byte_identical() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"first")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    let before = std::fs::read(&path).expect("read the file");

    let second = EncryptedFile::open(&path, Arc::new(Unprompted));
    let err = second.create(Consent::granted(), &pw("second"), KdfCost::floor());
    match err {
        Err(SecretsError::Io(io)) => {
            assert_eq!(io.kind(), std::io::ErrorKind::AlreadyExists);
        }
        other => panic!("creating over a store must refuse: {other:?}"),
    }
    assert_eq!(std::fs::read(&path).expect("read the file"), before);
}

/// A store that opens with nothing typed is not a store, and refusing before the path is touched is
/// what stops one existing at all.
#[test]
fn an_empty_passphrase_is_refused_before_the_path_is_touched() {
    let (_dir, path) = scratch().expect("scratch");
    let store = EncryptedFile::open(&path, Arc::new(Unprompted));
    assert!(matches!(
        store.create(
            Consent::granted(),
            &Secret::new(Vec::new()),
            KdfCost::floor()
        ),
        Err(SecretsError::Locked)
    ));
    assert!(!path.exists());
    assert!(!store.is_open());
}

/// Creating leaves the handle open, so the front end that just asked for a new passphrase does not
/// immediately ask for it again.
#[test]
fn a_created_store_is_open_and_writable_without_asking_again() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"pp");
    let store = created(&path, source.clone()).expect("create");

    assert!(store.is_open());
    assert_eq!(store.probe().state, BackendState::Ready);
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    assert_eq!(source.asked(), 0);
}

/// The distinction the second envelope exists for. A front end answers a damaged file by offering to
/// start over, which destroys secrets, and it must never make that offer for a typo.
#[test]
fn a_wrong_passphrase_is_its_own_condition() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"correct horse")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    drop(store);

    let wrong = EncryptedFile::open(&path, Scripted::new(b"battery staple"));
    assert!(matches!(
        wrong.get(ACCOUNT, SecretKind::Password),
        Err(SecretsError::WrongPassphrase)
    ));
}

/// A failed attempt must not be remembered, or a user who mistyped once would be stuck with it for
/// the life of the handle.
#[test]
fn a_failed_unlock_is_not_remembered_and_the_next_attempt_is_asked_for() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"correct horse");
    let store = created(&path, source.clone()).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    store.seal();

    source.now_answers(b"wrong").expect("script");
    assert!(matches!(
        store.get(ACCOUNT, SecretKind::Password),
        Err(SecretsError::WrongPassphrase)
    ));
    assert!(!store.is_open());

    source.now_answers(b"correct horse").expect("script");
    assert_eq!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .expect("present")
            .expose(),
        b"hunter2"
    );
    assert_eq!(source.asked(), 2);
}

/// The passphrase is asked for once and the derived key is kept. Without this the user pays a
/// derivation, which is measured in hundreds of milliseconds, for every secret touched.
#[test]
fn the_passphrase_is_asked_for_once_however_many_calls_follow() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"correct horse");
    let store = created(&path, source.clone()).expect("create");
    store.seal();

    for kind in SecretKind::ALL {
        store.set(ACCOUNT, kind, pw("a")).expect("write");
        store.get(ACCOUNT, kind).expect("read");
        store.delete(ACCOUNT, kind).expect("delete");
    }
    store.forget_account(ACCOUNT).expect("sweep");
    assert_eq!(source.asked(), 1);
}

/// The one case a cached key must not be trusted for: the file was re-sealed by something else while
/// this handle held a key derived under the old salt.
///
/// Reported as a wrong passphrase it would tell a user their passphrase is wrong about a store that
/// is perfectly fine, which is the misdiagnosis the salt travelling with the cached key exists to
/// prevent. Nothing else in the suite reaches the mismatch: every other path that draws a new salt
/// refreshes the same handle's cache in the same call.
#[test]
fn a_store_re_sealed_by_something_else_is_asked_about_again_rather_than_refused() {
    let (_dir, path) = scratch().expect("scratch");
    let mine = Scripted::new(b"first");
    let store = created(&path, mine.clone()).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    store.seal();
    store.get(ACCOUNT, SecretKind::Password).expect("read");
    assert_eq!(mine.asked(), 1);
    assert!(store.is_open());

    // A second handle, as another launcher process would have, rotates the passphrase underneath.
    let elsewhere = EncryptedFile::open(&path, Scripted::new(b"first"));
    elsewhere
        .change_passphrase(&pw("first"), &pw("second"))
        .expect("rotate");

    mine.now_answers(b"second").expect("script");
    assert_eq!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("the stale key must be noticed rather than reported as a wrong passphrase")
            .expect("present")
            .expose(),
        b"hunter2"
    );
    assert_eq!(mine.asked(), 2, "the handle has to ask again, not reuse");
}

/// The window is what bounds how long the one value that opens this store without a passphrase is
/// resident in ordinary process memory. Kept for the life of the launcher it reaches disk by routes
/// nothing here chooses (a core dump attached to a bug report, a page written to swap, a hibernation
/// image), and whoever holds one of those and a copy of the file reads every stored secret with no
/// passphrase and none of the derivation work.
///
/// The sleep is three times the window, and the only way it could mislead is by returning early,
/// which is the one thing sleeping does not do. A loaded machine overshoots, and overshooting is the
/// direction that expires the key harder.
#[test]
fn a_key_left_alone_past_its_window_is_asked_for_again() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"correct horse");
    let store = created_with_idle(&path, source.clone(), std::time::Duration::from_millis(200))
        .expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    assert_eq!(
        source.asked(),
        0,
        "creating derived the key from the passphrase it was handed"
    );
    assert!(store.is_open());

    std::thread::sleep(std::time::Duration::from_millis(600));

    assert!(!store.is_open(), "the window ran out");
    assert_eq!(
        store.probe().state,
        BackendState::Locked,
        "a handle whose window ran out is locked, not ready: the next call prompts"
    );
    assert_eq!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .expect("present")
            .expose(),
        b"hunter2",
        "the store is untouched; only the key had to be derived again"
    );
    assert_eq!(
        source.asked(),
        1,
        "the key was gone, so the passphrase had to be asked for again"
    );
}

/// A zero window is the setting that keeps nothing, not the setting that keeps everything. Read the
/// other way round it would be the one value that turns the window off, silently, in the direction
/// nobody would want it turned off in.
#[test]
fn a_zero_window_keeps_no_key_between_calls() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"pp");
    let store =
        created_with_idle(&path, source.clone(), std::time::Duration::ZERO).expect("create");
    assert!(
        !store.is_open(),
        "not even the key that creating the store just derived"
    );

    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    assert_eq!(source.asked(), 1);
    store.get(ACCOUNT, SecretKind::Password).expect("read");
    assert_eq!(source.asked(), 2, "every call pays for its own derivation");
}

/// Sealing early has to be reachable through the seam the composition root holds, or the only code
/// that can shorten the key's residency is code holding this backend concretely, which the launcher
/// deliberately does not.
#[test]
fn sealing_through_the_store_seam_makes_the_next_call_ask_again() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"pp");
    let store = created(&path, source.clone()).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    assert!(store.is_open());

    let seam: &dyn SecretStore = &store;
    seam.seal();

    assert!(
        !store.is_open(),
        "the seam's seal has to reach this backend's key"
    );
    assert_eq!(source.asked(), 0);
    seam.get(ACCOUNT, SecretKind::Password).expect("read");
    assert_eq!(source.asked(), 1);
}

#[test]
fn sealing_a_store_makes_the_next_call_ask_again() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"pp");
    let store = created(&path, source.clone()).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    assert_eq!(source.asked(), 0);

    store.seal();
    assert!(!store.is_open());
    store.get(ACCOUNT, SecretKind::Password).expect("read");
    assert_eq!(source.asked(), 1);
}

/// Rotation keeps the contents and retires the old passphrase, and it draws a fresh salt so that any
/// precomputation an attacker had started against the old one is spent.
#[test]
fn changing_the_passphrase_keeps_every_secret_and_retires_the_old_one() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"first");
    let store = created(&path, source.clone()).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    store
        .set(OTHER, SecretKind::TotpSecret, pw("JBSWY3DPEHPK3PXP"))
        .expect("write");
    let salt_before = std::fs::read(&path).expect("read the file")[20..36].to_vec();

    store
        .change_passphrase(&pw("first"), &pw("second"))
        .expect("rotate");

    let salt_after = std::fs::read(&path).expect("read the file")[20..36].to_vec();
    assert_ne!(salt_before, salt_after, "a rotation has to draw a new salt");

    // The handle that rotated is still open, so the front end does not have to reprompt.
    assert!(store.is_open());
    assert_eq!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .expect("present")
            .expose(),
        b"hunter2"
    );

    let old = EncryptedFile::open(&path, Scripted::new(b"first"));
    assert!(matches!(
        old.get(ACCOUNT, SecretKind::Password),
        Err(SecretsError::WrongPassphrase)
    ));
    let new = EncryptedFile::open(&path, Scripted::new(b"second"));
    assert_eq!(
        new.get(OTHER, SecretKind::TotpSecret)
            .expect("read")
            .expect("present")
            .expose(),
        b"JBSWY3DPEHPK3PXP"
    );
}

/// A rotation that did not prove the old passphrase would let anyone at an unlocked session lock the
/// owner out of their own secrets.
#[test]
fn changing_the_passphrase_refuses_without_the_current_one() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"first")).expect("create");
    let before = std::fs::read(&path).expect("read the file");

    assert!(matches!(
        store.change_passphrase(&pw("guess"), &pw("second")),
        Err(SecretsError::WrongPassphrase)
    ));
    assert!(matches!(
        store.change_passphrase(&Secret::new(Vec::new()), &pw("second")),
        Err(SecretsError::Locked)
    ));
    assert!(matches!(
        store.change_passphrase(&pw("first"), &Secret::new(Vec::new())),
        Err(SecretsError::Locked)
    ));
    assert_eq!(std::fs::read(&path).expect("read the file"), before);
}

/// Rotation is the only route by which an existing store's work factor is raised, because it is the
/// only moment a passphrase is on hand to derive from again.
#[test]
fn changing_the_passphrase_raises_the_work_to_what_this_build_ships() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"first")).expect("create");
    assert_eq!(
        store.inspect(),
        FileState::Sealed {
            work: KdfCost::floor()
        }
    );

    store
        .change_passphrase(&pw("first"), &pw("second"))
        .expect("rotate");
    assert_eq!(
        store.inspect(),
        FileState::Sealed {
            work: KdfCost::CURRENT
        }
    );
}

/// The answer for a user who forgot the passphrase, which otherwise has none.
#[test]
fn removing_the_store_deletes_the_file_and_says_whether_there_was_one() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");

    assert!(store.remove(Consent::granted()).expect("remove"));
    assert!(!path.exists());
    assert!(!store.is_open());
    assert_eq!(store.inspect(), FileState::Absent);
    assert!(!store.remove(Consent::granted()).expect("remove again"));
}

/// The probe is what a front end asks before it offers to save anything, so it must answer without
/// making the user type a passphrase to find out.
#[test]
fn a_probe_never_asks_for_a_passphrase() {
    let (_dir, path) = scratch().expect("scratch");
    let source = Scripted::new(b"pp");
    let store = created(&path, source.clone()).expect("create");
    store.seal();

    let report = store.probe();
    assert_eq!(report.state, BackendState::Locked);
    assert!(report.is_usable());
    assert_eq!(source.asked(), 0);
    assert!(matches!(store.inspect(), FileState::Sealed { .. }));
    assert_eq!(source.asked(), 0);
}

/// A store nothing can supply a passphrase for is going to refuse every write, so it must not look
/// usable: offering to save into it and then failing is worse than not offering.
#[test]
fn a_store_with_no_way_to_ask_reports_itself_unusable() {
    let (_dir, path) = scratch().expect("scratch");
    created(&path, Scripted::new(b"pp")).expect("create");

    let store = EncryptedFile::open(&path, Arc::new(Unprompted));
    let report = store.probe();
    assert_eq!(report.state, BackendState::Unreachable);
    assert!(!report.is_usable());
    assert!(matches!(
        store.get(ACCOUNT, SecretKind::Password),
        Err(SecretsError::Locked)
    ));
}

/// Anything at the path that is not one of these has to be named as such rather than read. A front
/// end that treated another program's file as a damaged store would offer to delete it.
#[test]
fn something_else_at_the_path_is_reported_as_not_ours() {
    let (_dir, path) = scratch().expect("scratch");
    std::fs::write(&path, vec![0u8; 628]).expect("write");
    let store = EncryptedFile::open(&path, Arc::new(Unprompted));
    assert_eq!(store.inspect(), FileState::Foreign);
    assert_eq!(store.probe().state, BackendState::Unreachable);
    assert!(!store.probe().is_usable());
}

/// A crashed write leaves a temp file holding ciphertext. It must not be read as the store, and it
/// must not accumulate.
#[test]
fn a_stray_temp_file_is_ignored_and_then_swept() {
    let (dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");
    let stray = dir
        .path()
        .join(format!("{}.abc.tmp", EncryptedFile::FILE_NAME));
    std::fs::write(&stray, b"a crashed write").expect("write");

    assert!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .is_none()
    );
    assert!(stray.exists(), "a read holds no lock, so it sweeps nothing");

    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    assert!(!stray.exists());
}

/// The reason the file lock is there. Two launcher processes writing different accounts must both
/// survive, and without the lock the second read-modify-write would publish over the first.
#[test]
fn concurrent_writers_do_not_lose_an_update() {
    let (_dir, path) = scratch().expect("scratch");
    created(&path, Scripted::new(b"pp")).expect("create");

    let writers: u8 = 8;
    std::thread::scope(|scope| {
        for n in 0..writers {
            let path = path.clone();
            scope.spawn(move || {
                // A separate handle per thread, which is what two processes would have: no shared
                // cache and no shared in-process mutex, so only the file lock is holding this up.
                let store = EncryptedFile::open(&path, Scripted::new(b"pp"));
                store
                    .set(
                        Uuid::from_u128(u128::from(n) + 100),
                        SecretKind::Password,
                        pw("written"),
                    )
                    .expect("write");
            });
        }
    });

    let reader = EncryptedFile::open(&path, Scripted::new(b"pp"));
    for n in 0..writers {
        assert!(
            reader
                .get(Uuid::from_u128(u128::from(n) + 100), SecretKind::Password)
                .expect("read")
                .is_some(),
            "account {n} was lost"
        );
    }
}

/// A known limitation, pinned so it stays known. Anyone who can write the file can put an older copy
/// back and resurrect a secret that was deleted. Catching it needs a monotonic anchor somewhere the
/// same attacker could not also roll back, and there is no such place on this machine: the launcher's
/// own config sits in the same directory, under the same ownership.
#[test]
fn a_whole_file_rollback_is_not_detected() {
    let (_dir, path) = scratch().expect("scratch");
    let store = created(&path, Scripted::new(b"pp")).expect("create");
    store
        .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
        .expect("write");
    let old = std::fs::read(&path).expect("read the file");

    store.delete(ACCOUNT, SecretKind::Password).expect("delete");
    assert!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .is_none()
    );

    std::fs::write(&path, &old).expect("restore the older copy");
    store.seal();
    assert_eq!(
        store
            .get(ACCOUNT, SecretKind::Password)
            .expect("read")
            .expect("the deleted secret is back")
            .expose(),
        b"hunter2"
    );
}

#[cfg(unix)]
mod permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn mode(path: &std::path::Path) -> Result<u32, std::io::Error> {
        Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
    }

    /// The lock sidecar is opened with a guard on what it finds, like every other path in the file.
    ///
    /// A FIFO at that name parked every write inside `open(2)` for as long as nobody opened the
    /// other end, holding the process-wide key lock with it, so the store could not even be removed
    /// to recover. A symlink took the lock on some other file, leaving two writers excluding
    /// nobody. Both run under a deadline, because the failure being guarded against is a hang: a
    /// regression here would otherwise stall the suite rather than fail it.
    #[test]
    fn a_lock_sidecar_that_is_not_a_regular_file_is_refused_rather_than_waited_on() {
        for planted in ["fifo", "symlink"] {
            let (dir, path) = scratch().expect("scratch");
            let store = created(&path, Scripted::new(b"pp")).expect("create");
            store
                .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
                .expect("write");

            let sidecar = path.with_extension("apsf.lock");
            std::fs::remove_file(&sidecar).expect("the created store left one");
            if planted == "fifo" {
                let made = std::process::Command::new("mkfifo")
                    .arg(&sidecar)
                    .status()
                    .expect("mkfifo");
                assert!(made.success());
            } else {
                std::os::unix::fs::symlink(dir.path().join("elsewhere"), &sidecar)
                    .expect("symlink");
            }

            let (done, waiting) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done.send(store.set(OTHER, SecretKind::Password, pw("second")));
            });
            let answered = waiting
                .recv_timeout(std::time::Duration::from_secs(10))
                .unwrap_or_else(|_| panic!("{planted}: the write is still parked on the sidecar"));
            assert!(
                answered.is_err(),
                "{planted}: the write took a lock that excludes nobody"
            );
        }
    }

    /// A lock that was waiting is re-checked against the name when it finally gets it.
    ///
    /// The flock is on an inode, not on a name. A writer that blocked on the sidecar and woke to
    /// find it had been unlinked meanwhile was holding a lock no other process would ever open: it
    /// excluded nobody, and two writers each holding one of those both returned success with one
    /// account's secret silently gone.
    ///
    /// What makes that observable is replacing the sidecar with something the open must refuse.
    /// A writer that re-consults the name reports it; one that trusts the lock it already holds
    /// goes on to write, which is exactly the case that loses the update.
    #[test]
    fn a_lock_that_waited_is_re_checked_against_the_name_it_waited_on() {
        let (_dir, path) = scratch().expect("scratch");
        let holder = created(&path, Scripted::new(b"pp")).expect("create");
        holder
            .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
            .expect("write");

        // A second handle whose prompt takes long enough to hold the lock across the swap below.
        let slow = std::sync::Arc::new(EncryptedFile::open(
            &path,
            std::sync::Arc::new(Slow {
                answer: b"pp".to_vec(),
                takes: std::time::Duration::from_secs(3),
            }),
        ));
        let held = {
            let slow = slow.clone();
            std::thread::spawn(move || slow.set(OTHER, SecretKind::Password, pw("first")))
        };
        std::thread::sleep(std::time::Duration::from_millis(300));

        // A third writer, which now blocks on the sidecar the holder is sitting on.
        let waiting = std::sync::Arc::new(EncryptedFile::open(&path, Scripted::new(b"pp")));
        let (done, answer) = std::sync::mpsc::channel();
        {
            let waiting = waiting.clone();
            std::thread::spawn(move || {
                let _ = done.send(waiting.set(ACCOUNT, SecretKind::TotpSecret, pw("third")));
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(300));

        // Swap the sidecar for something no open may take, so the difference is visible.
        let sidecar = path.with_extension("apsf.lock");
        std::fs::remove_file(&sidecar).expect("unlink the sidecar being waited on");
        assert!(
            std::process::Command::new("mkfifo")
                .arg(&sidecar)
                .status()
                .expect("mkfifo")
                .success()
        );

        held.join()
            .expect("holder thread")
            .expect("the holder's own write");
        let answered = answer
            .recv_timeout(std::time::Duration::from_secs(15))
            .expect("the waiting writer never answered");
        assert!(
            answered.is_err(),
            "the writer kept a lock on a sidecar that had been unlinked out from under it"
        );
    }

    /// The repair puts a directory back, not just narrows it.
    ///
    /// A repair that could only clear bits left one that had lost its owner write or search bit
    /// answering `Denied` on every call forever, with nothing inside the launcher able to undo it.
    /// This is the directory the settings and the account records share, so it is not only the
    /// secrets that stop working.
    #[test]
    fn a_store_directory_missing_an_owner_bit_is_repaired_rather_than_left() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("apogee").join(EncryptedFile::FILE_NAME);
        let store = created(&path, Scripted::new(b"pp")).expect("create");
        store
            .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
            .expect("write");

        let parent = path.parent().expect("parent");
        for wrong in [0o500, 0o400, 0o750, 0o777] {
            std::fs::set_permissions(parent, PermissionsExt::from_mode(wrong)).expect("chmod");
            store
                .set(ACCOUNT, SecretKind::Password, pw("again"))
                .unwrap_or_else(|e| {
                    panic!("a store directory left at {wrong:o} stayed broken: {e}")
                });
            assert_eq!(mode(parent).expect("stat"), 0o700, "from {wrong:o}");
        }
    }

    #[test]
    fn a_created_store_and_its_directory_are_owner_only() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("apogee").join(EncryptedFile::FILE_NAME);
        created(&path, Scripted::new(b"pp")).expect("create");

        assert_eq!(mode(&path).expect("stat"), 0o600);
        assert_eq!(mode(path.parent().expect("parent")).expect("stat"), 0o700);
    }

    /// A store restored by a tool that widened it is put back rather than refused: the contents are
    /// sealed either way, and refusing would strand the user. Leaving it wide would leak forever.
    #[test]
    fn a_store_left_readable_by_something_else_is_narrowed_on_the_next_write() {
        let (_dir, path) = scratch().expect("scratch");
        let store = created(&path, Scripted::new(b"pp")).expect("create");
        std::fs::set_permissions(&path, PermissionsExt::from_mode(0o644)).expect("chmod");

        store
            .set(ACCOUNT, SecretKind::Password, pw("hunter2"))
            .expect("write");
        assert_eq!(mode(&path).expect("stat"), 0o600);
    }

    /// A read redirected through a symlink would hand back whatever the link points at, and the next
    /// write would replace it.
    #[test]
    fn a_symlink_at_the_store_path_is_refused() {
        let (dir, path) = scratch().expect("scratch");
        let elsewhere = dir.path().join("elsewhere");
        created(&elsewhere, Scripted::new(b"pp")).expect("create");
        std::os::unix::fs::symlink(&elsewhere, &path).expect("symlink");

        let store = EncryptedFile::open(&path, Scripted::new(b"pp"));
        assert_eq!(store.inspect(), FileState::Foreign);
        assert!(matches!(
            store.get(ACCOUNT, SecretKind::Password),
            Err(SecretsError::Corrupt {
                detail: "store path"
            })
        ));
    }
}
