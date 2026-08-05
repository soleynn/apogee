//! Print what the credential-store probe found, as one line of codes.
//!
//! This exists so the probe can be driven inside a real Flatpak sandbox, which is the one condition
//! the test suite cannot reach: that path needs an actual bus proxy, and no hermetic job has one. It
//! prints the report and nothing else, so it cannot disclose a stored secret.
//!
//! Build it statically, because the sandbox carries its own libc and it will not be the host's:
//!
//! ```text
//! cargo build -p apogee-secrets --example report --target x86_64-unknown-linux-musl
//! flatpak run --devel --filesystem=DIR --command=DIR/report org.freedesktop.Platform//25.08
//! ```
//!
//! Adding `--talk-name=org.freedesktop.secrets` or `--socket=session-bus` to that second command is
//! what flips the sandbox from refused to reachable, and the report should follow.

use apogee_secrets::{OsKeyring, SecretStore};

fn main() {
    println!("{:?}", OsKeyring::new().probe());
}
