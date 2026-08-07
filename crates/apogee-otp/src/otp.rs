//! The handle the composition root holds: the store read, the mint, and the reuse guard.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use apogee_secrets::{SecretKind, SecretStore};
use uuid::Uuid;

use crate::code::{Code, Minted};
use crate::error::OtpError;
use crate::guard::Guard;
use crate::params::TotpParams;
use crate::skew::ClockSkew;
use crate::window;

/// How many windows past the current one the guard will walk before it gives up and hands the last
/// candidate back anyway. Four consecutive codes colliding is not a case worth an error path: a
/// guard that can refuse to produce a code at all is worse than a resubmission the login server
/// would simply reject.
const REUSE_SCAN_LIMIT: u64 = 3;

/// The least life a returned code may have left, in seconds.
///
/// A caller submits over the network: two requests separate the mint from the wire, each a round
/// trip to Square Enix. A code minted in the last moments of its window is dead by the time it
/// arrives, so a mint that lands there takes the next window's code and says how long that is
/// instead, which costs at most this many seconds and buys a whole period of validity. A profile
/// whose whole period is this short is exempt, because no window of it would satisfy the floor.
const MIN_LIFE_SECS: u64 = 3;

/// The one-time-password service the composition root holds.
///
/// Two reference-counted handles: the secret store, and the per-account record of the last code that
/// was submitted. Cloning shares both, which is what lets a clone be moved onto a blocking task
/// while the original stays on the runtime.
///
/// The guard is against reuse across sequential attempts, which is what the login server rejects.
/// Two logins racing for one account can both mint the same code, because minting computes and does
/// not reserve.
#[derive(Clone)]
pub struct Otp {
    store: Arc<dyn SecretStore + Send + Sync>,
    guard: Arc<Guard>,
}

impl Otp {
    /// Wrap the store secrets are read from.
    #[must_use]
    pub fn new(store: Arc<dyn SecretStore + Send + Sync>) -> Self {
        Self {
            store,
            guard: Arc::new(Guard::default()),
        }
    }

    /// Read the stored secret and produce the code to submit for `account`, for the clock as it
    /// reads once the key is in hand.
    ///
    /// The instant is taken after the store has answered, not before. The read is what raises the
    /// platform's unlock prompt or derives an encrypted store's key, and it is bounded only by how
    /// long the user takes: a counter derived from the instant the call started would name a window
    /// that closed while the prompt was on screen. A caller pinning its own instant uses
    /// [`Otp::mint_blocking_at`].
    ///
    /// The decoded key never crosses an await point, because it never leaves this one synchronous
    /// call.
    ///
    /// # Blocking
    /// Reads the secret store, which blocks and may raise the platform's unlock prompt. A caller on
    /// an async runtime uses [`Otp::mint`] instead.
    ///
    /// # Errors
    /// [`OtpError::NoSecret`] if nothing is stored, [`OtpError::Stored`] if what is stored does not
    /// parse, [`OtpError::Secrets`] if the store failed or is locked, [`OtpError::Clock`] if the
    /// clock plus `skew` is not an instant a counter is defined for.
    pub fn mint_blocking(&self, account: Uuid, skew: ClockSkew) -> Result<Minted, OtpError> {
        let params = self.read_params(account)?;
        self.derive(account, &params, SystemTime::now(), skew)
    }

    /// [`Otp::mint_blocking`] for a named instant rather than for the clock.
    ///
    /// For a caller that has an instant of its own: a test pinning one, or a login correcting
    /// against a server clock. The store read still happens first, so an instant named before a
    /// prompt is answered is a stale instant and this is the call that lets one be passed anyway.
    ///
    /// # Blocking
    /// As [`Otp::mint_blocking`].
    ///
    /// # Errors
    /// As [`Otp::mint_blocking`], reading `at` for the clock.
    pub fn mint_blocking_at(
        &self,
        account: Uuid,
        at: SystemTime,
        skew: ClockSkew,
    ) -> Result<Minted, OtpError> {
        let params = self.read_params(account)?;
        self.derive(account, &params, at, skew)
    }

    /// [`Otp::mint_blocking`], run off the runtime's workers.
    ///
    /// # Errors
    /// As [`Otp::mint_blocking`], plus [`OtpError::Interrupted`] if the task was dropped before it
    /// answered.
    pub async fn mint(&self, account: Uuid, skew: ClockSkew) -> Result<Minted, OtpError> {
        let handle = self.clone();
        tokio::task::spawn_blocking(move || handle.mint_blocking(account, skew))
            .await
            .map_err(|_| OtpError::Interrupted)?
    }

    /// Read this account's stored secret back into a profile.
    fn read_params(&self, account: Uuid) -> Result<TotpParams, OtpError> {
        let stored = self
            .store
            .get(account, SecretKind::TotpSecret)?
            .ok_or(OtpError::NoSecret)?;
        let params = TotpParams::from_secret(&stored)?;
        drop(stored);
        Ok(params)
    }

    /// Pick the window to submit for and derive its code. Pure arithmetic, so nothing waits on
    /// anything: what the caller gets back is the code for the window it lands in, how long until
    /// that window opens, and how long it lasts once it does.
    fn derive(
        &self,
        account: Uuid,
        params: &TotpParams,
        at: SystemTime,
        skew: ClockSkew,
    ) -> Result<Minted, OtpError> {
        let period = params.period();
        let seconds = window::shifted_seconds(at, skew)?;
        let current = window::counter(seconds, period)?;
        let left = window::remaining(seconds, period)?;

        // A code with almost none of its window left does not survive the requests between here and
        // the submit, so the mint steps past it exactly as it steps past one the server has seen.
        // A profile whose whole period is inside the floor is exempt: every code it makes is that
        // short-lived, so holding would delay each login and hand back the same short life anyway.
        let floor = if u64::from(period) > MIN_LIFE_SECS {
            MIN_LIFE_SECS
        } else {
            0
        };
        let mut counter = if left < floor {
            current.checked_add(1).ok_or(OtpError::Clock)?
        } else {
            current
        };

        // Walk forward a window at a time until a code the server has not already seen turns up.
        let mut code = params.code_for_counter(counter)?;
        let mut scanned = 0;
        while scanned < REUSE_SCAN_LIMIT && self.guard.repeats(account, &code) {
            counter = counter.checked_add(1).ok_or(OtpError::Clock)?;
            code = params.code_for_counter(counter)?;
            scanned += 1;
        }

        let now = u64::try_from(seconds).map_err(|_| OtpError::Clock)?;
        let opens_at = window::window_start(counter, period)?;
        let wait = Duration::from_secs(opens_at.saturating_sub(now));
        let valid_for = if counter == current {
            Duration::from_secs(left)
        } else {
            Duration::from_secs(u64::from(period))
        };
        Ok(Minted::new(code, wait, valid_for))
    }

    /// Record that `code` went to the login server for `account`. In memory only, never persisted.
    ///
    /// Separate from minting on purpose. A login that fails before the code is sent has not replayed
    /// anything, and recording at mint time would make every abandoned attempt cost a wait on the
    /// retry. The caller records on the failure path too: the server has seen the code either way,
    /// and it is the server's replay rule this guards against.
    pub fn submitted(&self, account: Uuid, code: &Code) {
        self.guard.record(account, code);
    }

    /// Drop what is remembered for `account`, for when its secrets are swept.
    pub fn forget(&self, account: Uuid) {
        self.guard.forget(account);
    }
}

/// How many accounts are tracked, never a code and never which accounts they are.
impl fmt::Debug for Otp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Otp")
            .field("tracked", &self.guard.tracked())
            .finish_non_exhaustive()
    }
}
