//! The store-backed paths: what the handle reads, what it refuses, and what the reuse guard does.
//!
//! Everything here runs against the in-memory double, so no test reaches the machine's keyring.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use apogee_otp::{ClockSkew, Minted, Otp, OtpError, TotpParams};
use apogee_secrets::{
    BackendState, Call, FailAt, MemoryStore, Null, Secret, SecretKind, SecretStore, SecretsError,
};
use proptest::prelude::*;
use proptest::test_runner::TestCaseError;
use uuid::Uuid;

/// A base32 secret that decodes to twenty bytes.
const KEY: &str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";

/// Fifteen seconds into a window, so the current window's remaining time and the next window's whole
/// period are different numbers and an assertion cannot pass by accident.
const MIDWINDOW: u64 = 1_234_567_905;

/// Helpers in an integration test return `Result` and propagate; only a `#[test]` body may unwrap.
fn seeded() -> Result<(Uuid, Arc<MemoryStore>), OtpError> {
    let account = Uuid::from_u128(0x5eed);
    let store = MemoryStore::new();
    seed(&store, account, KEY)?;
    Ok((account, Arc::new(store)))
}

/// File `offered` under `account`'s one-time-password kind, in the form the handle reads back.
fn seed(store: &dyn SecretStore, account: Uuid, offered: &str) -> Result<(), OtpError> {
    store.set(
        account,
        SecretKind::TotpSecret,
        TotpParams::parse(offered)?.into_secret(),
    )?;
    Ok(())
}

fn handle(store: &Arc<MemoryStore>) -> Otp {
    Otp::new(Arc::clone(store) as Arc<dyn SecretStore + Send + Sync>)
}

fn at(seconds: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds)
}

/// Mint for `account` at `seconds`, for the property tests, which assert on an `Option` rather than
/// unwrapping: a free helper here may not.
fn mint_at(otp: &Otp, account: Uuid, seconds: u64) -> Option<Minted> {
    otp.mint_blocking_at(account, at(seconds), ClockSkew::NONE)
        .ok()
}

#[test]
fn an_account_with_nothing_stored_reports_no_secret() {
    let store = Arc::new(MemoryStore::new());
    let otp = handle(&store);
    let answer = otp.mint_blocking_at(Uuid::from_u128(1), at(MIDWINDOW), ClockSkew::NONE);
    assert!(matches!(answer, Err(OtpError::NoSecret)), "{answer:?}");
}

/// A locked store is not an account without a secret: the same call succeeds once the user unlocks,
/// so folding the two would send a caller off to import a secret it already has.
#[test]
fn a_locked_store_reports_the_store_not_a_missing_secret() -> Result<(), OtpError> {
    let account = Uuid::from_u128(0x10cced);
    let store = Arc::new(
        MemoryStore::new().failing_with(FailAt::Get(Some(SecretKind::TotpSecret)), || {
            SecretsError::Locked
        }),
    );
    store.set(
        account,
        SecretKind::TotpSecret,
        TotpParams::parse(KEY)?.into_secret(),
    )?;

    let otp = handle(&store);
    let answer = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE);
    assert!(
        matches!(answer, Err(OtpError::Secrets(SecretsError::Locked))),
        "{answer:?}"
    );

    store.now_failing(None);
    assert!(
        otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)
            .is_ok()
    );
    Ok(())
}

/// A value read back from a credential store is not integrity-protected, so it is parsed like any
/// other hostile text. The answer names it as stored rather than offered, because a caller answers
/// the two differently.
#[test]
fn garbage_in_the_store_reports_stored() -> Result<(), OtpError> {
    let account = Uuid::from_u128(7);
    let store = Arc::new(MemoryStore::new());
    store.set(
        account,
        SecretKind::TotpSecret,
        Secret::new(vec![0xff, 0x01]),
    )?;

    let answer = handle(&store).mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE);
    assert!(matches!(answer, Err(OtpError::Stored { .. })), "{answer:?}");
    Ok(())
}

#[test]
fn the_first_mint_is_current_and_waits_for_nothing() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let minted = handle(&store).mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_eq!(minted.wait(), Duration::ZERO);
    assert_eq!(minted.valid_for(), Duration::from_secs(15));
    assert_eq!(minted.code().len(), 6);
    Ok(())
}

/// The guard's whole job: the same instant asked twice, with a submission in between, yields the
/// next window's code and the wait until that window opens rather than the digits the server has
/// already refused.
#[test]
fn a_submitted_code_is_not_minted_twice() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let otp = handle(&store);

    let first = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    otp.submitted(account, first.code());
    let second = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;

    assert_eq!(second.wait(), Duration::from_secs(15));
    assert_eq!(second.valid_for(), Duration::from_secs(30));
    assert_ne!(first.code().expose(), second.code().expose());
    Ok(())
}

/// The guard tracks submission, not generation. A login abandoned before the code was sent has not
/// replayed anything, and making it wait would be a cost paid for nothing.
#[test]
fn minting_twice_without_submitting_repeats() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let otp = handle(&store);

    let first = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    let second = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_eq!(first.code().expose(), second.code().expose());
    assert_eq!(second.wait(), Duration::ZERO);
    Ok(())
}

#[test]
fn forgetting_an_account_clears_the_guard() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let otp = handle(&store);

    let first = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    otp.submitted(account, first.code());
    otp.forget(account);

    let again = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_eq!(again.code().expose(), first.code().expose());
    assert_eq!(again.wait(), Duration::ZERO);
    Ok(())
}

/// The record is the account's, not the handle's. Two accounts sharing a secret is contrived, and it
/// is the shape that fails if the record is ever keyed by anything but the account: with one key and
/// one instant, the second account has to get the code the first one has already spent.
#[test]
fn what_one_account_submitted_is_not_held_against_another() -> Result<(), OtpError> {
    let one = Uuid::from_u128(1);
    let two = Uuid::from_u128(2);
    let store = MemoryStore::new();
    seed(&store, one, KEY)?;
    seed(&store, two, KEY)?;
    let otp = handle(&Arc::new(store));

    let first = otp.mint_blocking_at(one, at(MIDWINDOW), ClockSkew::NONE)?;
    otp.submitted(one, first.code());

    let moved_on = otp.mint_blocking_at(one, at(MIDWINDOW), ClockSkew::NONE)?;
    let other = otp.mint_blocking_at(two, at(MIDWINDOW), ClockSkew::NONE)?;

    assert_ne!(moved_on.code().expose(), first.code().expose());
    assert_eq!(other.code().expose(), first.code().expose());
    assert_eq!(other.wait(), Duration::ZERO);
    Ok(())
}

/// The record lives on the handle and nowhere else. A second handle over the same store knows
/// nothing about what the first one sent, which is what "in memory only" means here: nothing was
/// written, so nothing can be read back, by this process or the next one.
#[test]
fn nothing_the_guard_remembers_reaches_the_store() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let before = store.stored(account, SecretKind::TotpSecret);
    let seeding = store.calls().len();

    let otp = handle(&store);
    let first = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    otp.submitted(account, first.code());
    otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;

    assert!(
        store.calls()[seeding..]
            .iter()
            .all(|call| matches!(call, Call::Get(_, SecretKind::TotpSecret))),
        "the guard wrote to the store: {:?}",
        store.calls()
    );
    assert_eq!(store.stored(account, SecretKind::TotpSecret), before);

    let fresh = handle(&store).mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_eq!(fresh.code().expose(), first.code().expose());
    assert_eq!(fresh.wait(), Duration::ZERO);
    Ok(())
}

/// A clone shares the record. The composition root hands a clone to every login and keeps the
/// original, and a clone with a record of its own would be a guard that never fired.
#[test]
fn a_cloned_handle_shares_what_was_submitted() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let otp = handle(&store);
    let sent = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    otp.clone().submitted(account, sent.code());

    let next = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_ne!(next.code().expose(), sent.code().expose());

    otp.clone().forget(account);
    let again = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_eq!(again.code().expose(), sent.code().expose());
    Ok(())
}

/// The timing is the stored profile's, not the usual profile's. A period read out of a secret has to
/// reach the wait and the lifetime, or a login with an unusual secret holds for the wrong number of
/// seconds and sends a code that has already turned over.
#[test]
fn the_timing_follows_the_stored_period() -> Result<(), OtpError> {
    let account = Uuid::from_u128(0x60);
    let store = MemoryStore::new();
    seed(
        &store,
        account,
        &format!("otpauth://totp/x?secret={KEY}&period=60&digits=8"),
    )?;
    let store = Arc::new(store);
    let otp = handle(&store);

    // Forty-five seconds into a sixty-second window, which is not a boundary of the usual one.
    let first = otp.mint_blocking_at(account, at(1_234_567_905), ClockSkew::NONE)?;
    assert_eq!(first.wait(), Duration::ZERO);
    assert_eq!(first.valid_for(), Duration::from_secs(15));
    assert_eq!(first.code().len(), 8);

    otp.submitted(account, first.code());
    let second = otp.mint_blocking_at(account, at(1_234_567_905), ClockSkew::NONE)?;
    assert_eq!(second.wait(), Duration::from_secs(15));
    assert_eq!(second.valid_for(), Duration::from_secs(60));
    Ok(())
}

/// A code with almost none of its window left is not the one handed back.
///
/// Two requests separate the mint from the submit, each a round trip to Square Enix, so digits that
/// turn over in flight are refused exactly as wrong ones are. The mint takes the next window's code
/// and says how long that is, which costs seconds and buys a whole period.
#[test]
fn a_code_with_no_window_left_is_stepped_over() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let otp = handle(&store);
    // The window holding MIDWINDOW closes at 1_234_567_920.
    let spent = otp.mint_blocking_at(account, at(1_234_567_919), ClockSkew::NONE)?;
    assert_eq!(spent.wait(), Duration::from_secs(1));
    assert_eq!(spent.valid_for(), Duration::from_secs(30));

    // The code is the one that window really produces, so the hold ends on digits the server takes.
    let after = otp.mint_blocking_at(account, at(1_234_567_920), ClockSkew::NONE)?;
    assert_eq!(after.wait(), Duration::ZERO);
    assert_eq!(spent.code().expose(), after.code().expose());

    // The floor exactly: three seconds is life enough, two is not.
    let floor = otp.mint_blocking_at(account, at(1_234_567_917), ClockSkew::NONE)?;
    assert_eq!(floor.wait(), Duration::ZERO);
    assert_eq!(floor.valid_for(), Duration::from_secs(3));
    let under = otp.mint_blocking_at(account, at(1_234_567_918), ClockSkew::NONE)?;
    assert_eq!(under.wait(), Duration::from_secs(2));
    Ok(())
}

/// A period shorter than the freshness floor still mints for its own window rather than holding for
/// every login: a profile whose codes never live three seconds cannot satisfy a three-second floor,
/// and a mint that stepped forward anyway would hold on every attempt and still hand back a code
/// with the same short life.
#[test]
fn a_period_under_the_freshness_floor_still_mints_now() -> Result<(), OtpError> {
    let account = Uuid::from_u128(0xf100);
    let store = MemoryStore::new();
    seed(
        &store,
        account,
        &format!("otpauth://totp/x?secret={KEY}&period=2"),
    )?;

    let minted =
        handle(&Arc::new(store)).mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_eq!(minted.wait(), Duration::ZERO);
    assert_eq!(minted.valid_for(), Duration::from_secs(1));
    Ok(())
}

/// The offset reaches the counter. Nothing else pins it: the pure path is exercised at an offset and
/// the handle is always asked at zero, so a dropped or inverted argument here would derive the local
/// window's code with the whole suite still green. It becomes load-bearing the moment a correction
/// against the login server's own clock is plumbed in.
#[test]
fn the_skew_offset_moves_the_window_the_handle_mints_for() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let otp = handle(&store);

    let shifted = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::from_seconds(30))?;
    let ahead = otp.mint_blocking_at(account, at(MIDWINDOW + 30), ClockSkew::NONE)?;
    assert_eq!(shifted.code().expose(), ahead.code().expose());
    assert_eq!(shifted.valid_for(), ahead.valid_for());

    let local = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;
    assert_ne!(
        shifted.code().expose(),
        local.code().expose(),
        "the offset was dropped on the way to the counter"
    );
    let behind = otp.mint_blocking_at(account, at(MIDWINDOW), ClockSkew::from_seconds(-30))?;
    assert_ne!(
        shifted.code().expose(),
        behind.code().expose(),
        "the offset's sign was lost on the way to the counter"
    );
    Ok(())
}

/// A store that keeps nothing answers cleanly with nothing, and that is not a failure: the account
/// is one whose codes have to be typed. Folding it into a store error would send a caller off to fix
/// a keyring that is behaving exactly as configured.
#[test]
fn a_store_that_keeps_nothing_reports_no_secret() {
    let otp = Otp::new(Arc::new(Null) as Arc<dyn SecretStore + Send + Sync>);
    let answer = otp.mint_blocking_at(Uuid::from_u128(9), at(MIDWINDOW), ClockSkew::NONE);
    assert!(matches!(answer, Err(OtpError::NoSecret)), "{answer:?}");
}

/// The store's own taxonomy is carried through rather than flattened. Each of these is answered
/// differently: one is waited out, one is never resolved by waiting, one is the user's own setting,
/// and one is a fault to triage. A handle that reported them all as one would decide for the caller.
#[test]
fn every_way_the_store_can_refuse_is_carried_through() {
    let account = Uuid::from_u128(0xbad);
    let states = [
        (BackendState::Locked, "locked"),
        (BackendState::NoDefaultCollection, "no collection"),
        (BackendState::NoSessionBus, "no backend"),
        (BackendState::SandboxDenied, "denied"),
        (BackendState::NotStoring, "keeps nothing"),
        (BackendState::Unreachable, "unreachable"),
    ];
    for (state, name) in states {
        let store = Arc::new(MemoryStore::new().in_state(state));
        let answer = Otp::new(store as Arc<dyn SecretStore + Send + Sync>).mint_blocking_at(
            account,
            at(MIDWINDOW),
            ClockSkew::NONE,
        );
        assert!(
            matches!(answer, Err(OtpError::Secrets(_))),
            "{name}: {answer:?}"
        );
    }

    let failing =
        Arc::new(
            MemoryStore::new().failing_with(FailAt::Everything, || SecretsError::Backend {
                step: "reach the secret store",
            }),
        );
    let answer = Otp::new(failing as Arc<dyn SecretStore + Send + Sync>).mint_blocking_at(
        account,
        at(MIDWINDOW),
        ClockSkew::NONE,
    );
    assert!(
        matches!(
            answer,
            Err(OtpError::Secrets(SecretsError::Backend {
                step: "reach the secret store"
            }))
        ),
        "{answer:?}"
    );
}

/// One read, of one kind. A handle that swept the account would raise an unlock prompt for a
/// password nothing here wants.
#[test]
fn only_the_one_kind_is_read() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let before = store.calls().len();

    handle(&store).mint_blocking_at(account, at(MIDWINDOW), ClockSkew::NONE)?;

    assert_eq!(
        store.calls()[before..].to_vec(),
        vec![Call::Get(account, SecretKind::TotpSecret)]
    );
    Ok(())
}

proptest! {
    /// Whatever instant a login lands on, the hold the guard asks for terminates and picks up
    /// exactly where the code it replaces ran out. The bound is what makes the caller's sleep safe:
    /// it is never zero when the guard fired, never longer than two windows, and it always lands the
    /// clock on the boundary the next code opens at.
    #[test]
    fn the_hold_after_a_repeat_runs_to_the_next_window(seconds in 1_000_000u64..2_000_000_000) {
        let Some((account, store)) = seeded().ok() else {
            return Err(TestCaseError::fail("the store could not be seeded"));
        };
        let otp = handle(&store);

        let Some(first) = mint_at(&otp, account, seconds) else {
            return Err(TestCaseError::fail("the first code was refused"));
        };
        otp.submitted(account, first.code());

        let Some(second) = mint_at(&otp, account, seconds) else {
            return Err(TestCaseError::fail("the second code was refused"));
        };

        // The second hold is the first one plus the whole of the code it replaces, whether the first
        // mint was for the current window or had already stepped past a window with nothing left.
        prop_assert_eq!(second.wait(), first.wait() + first.valid_for());
        prop_assert!(second.wait() > Duration::ZERO);
        prop_assert!(second.wait() <= Duration::from_secs(60));
        prop_assert_eq!((seconds + second.wait().as_secs()) % 30, 0);
        prop_assert_eq!(second.valid_for(), Duration::from_secs(30));
        prop_assert_ne!(second.code().expose(), first.code().expose());
    }

    /// A code with nothing recorded against it and room left in its window is the current window's,
    /// whatever the instant: the guard costs a login that has not repeated anything nothing at all.
    /// In the last seconds of a window the mint steps to the next one instead, because digits that
    /// expire between here and the submit are refused exactly as wrong ones are.
    #[test]
    fn an_unrepeated_code_waits_only_out_of_a_spent_window(seconds in 1_000_000u64..2_000_000_000) {
        let Some((account, store)) = seeded().ok() else {
            return Err(TestCaseError::fail("the store could not be seeded"));
        };
        let Some(minted) = mint_at(&handle(&store), account, seconds) else {
            return Err(TestCaseError::fail("the code was refused"));
        };

        let left = 30 - seconds % 30;
        if left >= 3 {
            prop_assert_eq!(minted.wait(), Duration::ZERO);
            prop_assert_eq!(minted.valid_for(), Duration::from_secs(left));
        } else {
            prop_assert_eq!(minted.wait(), Duration::from_secs(left));
            prop_assert_eq!(minted.valid_for(), Duration::from_secs(30));
        }
        prop_assert_eq!(minted.code().len(), 6);
    }
}

/// The async wrapper runs the same read off the runtime's workers and answers like the blocking call
/// reading the same clock. The blocking call is the contract; this is the one a caller on a runtime
/// uses.
#[tokio::test]
async fn the_async_mint_answers_like_the_blocking_one() -> Result<(), OtpError> {
    let (account, store) = seeded()?;
    let otp = handle(&store);

    let spawned = otp.mint(account, ClockSkew::NONE).await?;
    let direct = otp.mint_blocking(account, ClockSkew::NONE)?;
    assert_eq!(direct.code().len(), spawned.code().len());
    // Both read the clock themselves, so they agree unless a window turned over between them, in
    // which case the second one is the later window's and neither has waited for anything.
    assert!(
        direct.code().expose() == spawned.code().expose()
            || direct.valid_for() > spawned.valid_for(),
        "the two calls disagreed about more than the window"
    );

    let missing = otp.mint(Uuid::from_u128(2), ClockSkew::NONE).await;
    assert!(matches!(missing, Err(OtpError::NoSecret)), "{missing:?}");
    Ok(())
}

/// A store that takes its time answering, which is what a locked keyring's unlock prompt or an
/// encrypted store's key derivation is: a read bounded only by how long the user takes.
struct SlowStore {
    inner: MemoryStore,
    delay: Duration,
}

impl SecretStore for SlowStore {
    fn get(&self, account: Uuid, kind: SecretKind) -> Result<Option<Secret>, SecretsError> {
        std::thread::sleep(self.delay);
        self.inner.get(account, kind)
    }

    fn set(&self, account: Uuid, kind: SecretKind, value: Secret) -> Result<(), SecretsError> {
        self.inner.set(account, kind, value)
    }

    fn delete(&self, account: Uuid, kind: SecretKind) -> Result<(), SecretsError> {
        self.inner.delete(account, kind)
    }

    fn probe(&self) -> apogee_secrets::BackendReport {
        self.inner.probe()
    }
}

/// How much of the current window is left, once there is at least `least` of it.
fn window_with_room(least: u64) -> Result<u64, OtpError> {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OtpError::Clock)?
            .as_secs();
        let left = 30 - (now % 30);
        if left >= least {
            return Ok(left);
        }
        std::thread::sleep(Duration::from_secs(left));
    }
}

/// The instant a code is derived from is read after the store has answered, not before the call.
///
/// That read is the one that raises the unlock prompt, and a prompt lasts as long as the user takes
/// to notice it. Anchored to the instant the call started, a mint hands back the code for a window
/// that closed while the dialog was on screen and reports a lifetime it no longer has. Measured on
/// the lifetime rather than on the digits: two windows' codes are equal once in a million, and an
/// assertion that codes differ is a rare false failure waiting to happen.
#[test]
fn the_clock_is_read_once_the_key_is_in_hand() -> Result<(), OtpError> {
    const DELAY: u64 = 2;
    let account = Uuid::from_u128(0x5104);
    let inner = MemoryStore::new();
    seed(&inner, account, KEY)?;
    let store = Arc::new(SlowStore {
        inner,
        delay: Duration::from_secs(DELAY),
    });
    let otp = Otp::new(store as Arc<dyn SecretStore + Send + Sync>);

    // Enough window left that the slow read cannot cross a boundary or land inside the freshness
    // floor, so the lifetime below can only be measuring when the clock was read.
    let left = window_with_room(DELAY + 5)?;
    let minted = otp.mint_blocking(account, ClockSkew::NONE)?;

    assert_eq!(minted.wait(), Duration::ZERO);
    assert!(
        minted.valid_for().as_secs() + DELAY <= left,
        "the clock was read before the store answered: {left}s of window left at the call, \
         {}s reported after a {DELAY}s read",
        minted.valid_for().as_secs()
    );
    Ok(())
}
