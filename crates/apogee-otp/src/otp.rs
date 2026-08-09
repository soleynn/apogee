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
/// A caller submits over the network: a code minted in the last moments of its window is dead by the
/// time it arrives, so a mint that lands there takes the next window's code and says how long that is
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
///
/// # Examples
/// The read and the derive are two calls, and the login server's answer is what belongs between them:
/// ```
/// use std::sync::Arc;
/// use std::time::{Duration, UNIX_EPOCH};
///
/// use apogee_otp::{ClockSkew, Otp, TotpParams};
/// use apogee_secrets::{MemoryStore, SecretKind, SecretStore};
/// use uuid::Uuid;
///
/// let account = Uuid::from_u128(0x5eed);
/// let store = Arc::new(MemoryStore::new());
/// store.set(
///     account,
///     SecretKind::TotpSecret,
///     TotpParams::parse("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")?.into_secret(),
/// )?;
/// let otp = Otp::new(store as Arc<dyn SecretStore + Send + Sync>);
///
/// // One: the store read. This is the call that raises the platform's unlock prompt, and how long
/// // it takes is up to the user.
/// let prepared = otp.prepare_blocking(account)?;
///
/// // ... a login server round trip happens here, and only afterwards is its clock known ...
/// let skew = ClockSkew::from_seconds(2);
///
/// // Two: the derive, against the window that clock is in.
/// let minted = prepared.mint_at(UNIX_EPOCH + Duration::from_secs(1_234_567_905), skew)?;
/// assert_eq!(minted.code().len(), 6);
/// assert_eq!(minted.wait(), Duration::ZERO);
///
/// // Recorded once it has actually gone to the server, never at mint time: an attempt abandoned
/// // before the code was sent has replayed nothing.
/// otp.submitted(account, minted.code());
/// # Ok::<(), apogee_otp::OtpError>(())
/// ```
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

    /// Read `account`'s stored secret into something that can derive its codes.
    ///
    /// The read is separate from the derive because they answer to different clocks. This is the call
    /// that raises the platform's unlock prompt, and it is bounded only by how long the user takes to
    /// notice it; the derive names a thirty-second window and has to happen once the caller knows
    /// which window the server is in. A fused call would put an unbounded wait between those two
    /// facts.
    ///
    /// # Blocking
    /// Reads the secret store, which blocks and may raise the platform's unlock prompt. A caller on
    /// an async runtime uses [`Otp::prepare`] instead.
    ///
    /// # Errors
    /// [`OtpError::NoSecret`] if nothing is stored, [`OtpError::Stored`] if what is stored does not
    /// parse, [`OtpError::Secrets`] if the store failed or is locked.
    pub fn prepare_blocking(&self, account: Uuid) -> Result<Prepared, OtpError> {
        let stored = self
            .store
            .get(account, SecretKind::TotpSecret)?
            .ok_or(OtpError::NoSecret)?;
        let params = TotpParams::from_secret(&stored)?;
        drop(stored);
        Ok(Prepared {
            account,
            params,
            guard: Arc::clone(&self.guard),
        })
    }

    /// [`Otp::prepare_blocking`], run off the runtime's workers.
    ///
    /// # Errors
    /// As [`Otp::prepare_blocking`], plus [`OtpError::Interrupted`] if the task was dropped before it
    /// answered.
    pub async fn prepare(&self, account: Uuid) -> Result<Prepared, OtpError> {
        let handle = self.clone();
        tokio::task::spawn_blocking(move || handle.prepare_blocking(account))
            .await
            .map_err(|_| OtpError::Interrupted)?
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

/// One account's secret, read back and ready to derive codes from.
///
/// Held by a caller between the store read and the moment it knows what the login server's clock
/// reads, which is the one stretch where the correction can still be applied. It is not `Clone` (a
/// clone is a second copy of the key with its own lifetime) and there is no way to read the key back
/// out; the key is erased when this drops, so a caller drops it as soon as the code exists.
///
/// Nothing here enforces that anything happens in between, and nothing can: the fact that separates
/// the two calls is which window the login server is in, which is not a value this crate could
/// demand as an argument without inventing a token for it. Writing
/// `otp.prepare(id).await?.mint(ClockSkew::NONE)?` compiles and is the shape to avoid, because it
/// puts the unlock prompt's unbounded wait inside the thirty seconds the code is good for.
pub struct Prepared {
    account: Uuid,
    params: TotpParams,
    guard: Arc<Guard>,
}

impl Prepared {
    /// The code to submit, for this host's clock as `skew` corrects it.
    ///
    /// Pure arithmetic against the clock read here: nothing waits, nothing reads the store again, and
    /// what comes back says both which code to send and how long to hold before sending it.
    ///
    /// # Errors
    /// [`OtpError::Clock`] if the clock plus `skew` is not an instant a counter is defined for.
    pub fn mint(&self, skew: ClockSkew) -> Result<Minted, OtpError> {
        self.mint_at(SystemTime::now(), skew)
    }

    /// [`Prepared::mint`] for a named instant rather than for the clock, for a caller that has one of
    /// its own: a test pinning it, or a caller correcting against a clock it already read.
    ///
    /// # Examples
    /// A code the account has already submitted is stepped past rather than handed back, and what
    /// that costs the caller is a wait it is told about:
    /// ```
    /// use std::sync::Arc;
    /// use std::time::{Duration, UNIX_EPOCH};
    ///
    /// use apogee_otp::{ClockSkew, Otp, TotpParams};
    /// use apogee_secrets::{MemoryStore, SecretKind, SecretStore};
    /// use uuid::Uuid;
    ///
    /// let account = Uuid::from_u128(0x5eed);
    /// let store = Arc::new(MemoryStore::new());
    /// store.set(
    ///     account,
    ///     SecretKind::TotpSecret,
    ///     TotpParams::parse("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")?.into_secret(),
    /// )?;
    /// let otp = Otp::new(store as Arc<dyn SecretStore + Send + Sync>);
    ///
    /// // Fifteen seconds into a window, so the two answers below are different numbers.
    /// let at = UNIX_EPOCH + Duration::from_secs(1_234_567_905);
    ///
    /// let first = otp.prepare_blocking(account)?.mint_at(at, ClockSkew::NONE)?;
    /// assert_eq!(first.wait(), Duration::ZERO);
    /// assert_eq!(first.valid_for(), Duration::from_secs(15));
    /// otp.submitted(account, first.code());
    ///
    /// // Same account, same instant: the guard recognizes the code and takes the next window's.
    /// let again = otp.prepare_blocking(account)?.mint_at(at, ClockSkew::NONE)?;
    /// assert_eq!(again.wait(), Duration::from_secs(15));
    /// assert_eq!(again.valid_for(), Duration::from_secs(30));
    /// # Ok::<(), apogee_otp::OtpError>(())
    /// ```
    ///
    /// # Errors
    /// As [`Prepared::mint`], reading `at` for the clock.
    pub fn mint_at(&self, at: SystemTime, skew: ClockSkew) -> Result<Minted, OtpError> {
        let period = self.params.period();
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
        let mut code = self.params.code_for_counter(counter)?;
        let mut scanned = 0;
        while scanned < REUSE_SCAN_LIMIT && self.guard.repeats(self.account, &code) {
            counter = counter.checked_add(1).ok_or(OtpError::Clock)?;
            code = self.params.code_for_counter(counter)?;
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
}

/// The account, never the key and never a code derived from it.
impl fmt::Debug for Prepared {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Prepared")
            .field("account", &self.account)
            .finish_non_exhaustive()
    }
}
