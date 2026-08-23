//! The shell-owned request shape and its one-way conversion into core commands.

use apogee_core::{Command, OtpSource, PasswordSource, Secret, Uuid};
use serde::Deserialize;
use zeroize::Zeroizing;

/// Bytes that arrived over IPC and are erased when the request leaves scope.
///
/// `Zeroizing` owns deserialization, so the allocation becomes guarded as it is constructed. The
/// buffer is moved into core's `Secret` without making a second copy.
#[derive(Deserialize)]
#[serde(transparent)]
pub(crate) struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    fn into_secret(mut self) -> Secret {
        Secret::new(std::mem::take(&mut *self.0))
    }

    #[cfg(test)]
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

/// Where the core should get the account password for this run.
#[derive(Deserialize)]
#[serde(tag = "kind", content = "bytes", rename_all = "camelCase")]
pub(crate) enum PasswordSourceDto {
    Stored,
    Provided(SecretBytes),
}

impl PasswordSourceDto {
    fn into_core(self) -> PasswordSource {
        match self {
            Self::Stored => PasswordSource::Stored,
            Self::Provided(bytes) => PasswordSource::Provided(bytes.into_secret()),
        }
    }
}

/// Where the core should get a one-time password for this run.
#[derive(Deserialize)]
#[serde(tag = "kind", content = "bytes", rename_all = "camelCase")]
pub(crate) enum OtpSourceDto {
    Totp,
    Manual(SecretBytes),
    Listener,
}

impl OtpSourceDto {
    fn into_core(self) -> OtpSource {
        match self {
            Self::Totp => OtpSource::Totp,
            Self::Manual(bytes) => OtpSource::Manual(bytes.into_secret()),
            Self::Listener => OtpSource::Listener,
        }
    }
}

/// Commands accepted from the webview.
///
/// This starts with the primary login-to-play path. Each arm is only a shape conversion; all
/// decisions about authentication, patching, and launch remain in `apogee-core`.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum CommandDto {
    PatchAndPlay {
        profile: Uuid,
        password: PasswordSourceDto,
        otp: OtpSourceDto,
    },
}

impl CommandDto {
    pub(crate) fn into_core(self) -> Command {
        match self {
            Self::PatchAndPlay {
                profile,
                password,
                otp,
            } => Command::PatchAndPlay {
                profile,
                password: password.into_core(),
                otp: otp.into_core(),
            },
        }
    }
}
