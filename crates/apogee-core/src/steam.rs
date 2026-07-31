//! The Steam seam: where a service account's authentication ticket comes from.
//!
//! A Steam-licensed account proves itself with a ticket only the running Steam client can mint,
//! through the native Steamworks library against the app id the account is entitled to. Nothing here
//! links that library, so the flow reads the ticket through this seam and the composition root wires
//! [`NoSteam`], which refuses. Keeping the seam and refusing at it means a Steam login says what is
//! missing, instead of sending a login SE will reject for a reason the user cannot act on.

use apogee_secrets::Secret;

use crate::error::CoreError;

/// A minted authentication ticket and the clock it was minted against.
pub(crate) struct AuthTicket {
    /// The ticket bytes as the Steam client produced them. A bearer credential, so it travels in the
    /// zeroizing wrapper rather than a bare `Vec`.
    pub(crate) raw: Secret,
    /// Steam's own server time, in Unix seconds. The obfuscation rounds it into the cipher key and SE
    /// checks the result against its own clock, so a host clock is not a substitute: a machine a few
    /// minutes out would produce a well-formed ticket keyed to a time nobody else agrees with.
    pub(crate) server_time: u32,
}

/// The source of authentication tickets.
#[async_trait::async_trait]
pub(crate) trait SteamBackend: Send + Sync {
    /// Mint a ticket for `app_id`.
    ///
    /// # Errors
    ///
    /// [`CoreError::NoSteam`] when this build cannot reach a Steam client, and the wrapped subsystem
    /// error when one is reachable but refuses.
    async fn auth_ticket(&self, app_id: u32) -> Result<AuthTicket, CoreError>;
}

/// The backend a build with no Steam integration wires: every request is refused.
pub(crate) struct NoSteam;

#[async_trait::async_trait]
impl SteamBackend for NoSteam {
    async fn auth_ticket(&self, _app_id: u32) -> Result<AuthTicket, CoreError> {
        Err(CoreError::NoSteam)
    }
}

#[cfg(test)]
pub(crate) mod fake {
    //! A scripted ticket source for the headless flow tests: it records the app ids it was asked for
    //! and hands back fixed bytes at a fixed clock, so a Steam login is drivable without a client.

    use std::sync::{Mutex, PoisonError};

    use super::{AuthTicket, CoreError, Secret, SteamBackend};

    /// The bytes the fake mints, long enough that the obfuscated ticket spans more than one chunk.
    pub(crate) const RAW_TICKET: &[u8] = &[0xA5; 204];
    /// The clock the fake mints against.
    pub(crate) const SERVER_TIME: u32 = 1_700_000_000;

    #[derive(Default)]
    pub(crate) struct FakeSteam {
        requested: Mutex<Vec<u32>>,
    }

    impl FakeSteam {
        pub(crate) fn new() -> Self {
            Self::default()
        }

        /// The app ids a ticket was minted for, in order.
        pub(crate) fn requested(&self) -> Vec<u32> {
            self.requested
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl SteamBackend for FakeSteam {
        async fn auth_ticket(&self, app_id: u32) -> Result<AuthTicket, CoreError> {
            self.requested
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(app_id);
            Ok(AuthTicket {
                raw: Secret::new(RAW_TICKET.to_vec()),
                server_time: SERVER_TIME,
            })
        }
    }
}
