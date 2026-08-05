//! Reporting the Secret Service's condition without touching a secret.
//!
//! Nothing here reads, writes, or unlocks: connecting, resolving a collection, and reading its
//! `Locked` property are all plain calls that raise no prompt. A probe that popped the keyring's
//! password dialog on every launch would be worse than no probe.
//!
//! The probe deliberately does not go through `keyring::Entry`. Constructing one performs no I/O at
//! all, so a probe built on it reports a healthy store from inside a sandbox that cannot reach one,
//! which is the exact failure this is here to name.

use std::path::Path;

use secret_service::EncryptionType;
use secret_service::blocking::SecretService;

use crate::keyring_store::BACKEND;
use crate::{BackendReport, BackendState, Sandbox};

/// Sections of `/.flatpak-info` this reads.
const CONTEXT: &str = "Context";
const APPLICATION: &str = "Application";
const SESSION_BUS_POLICY: &str = "Session Bus Policy";

/// The bus name a credential store owns.
const SECRETS_NAME: &str = "org.freedesktop.secrets";

/// What a D-Bus level failure means, once its error name is read.
pub(crate) enum BusFailure {
    /// Nothing owns the name on this bus.
    NoName,
    /// The bus refused the call.
    Denied,
    /// The store answered and said it is locked.
    Locked,
}

pub(crate) fn probe() -> BackendReport {
    let sandbox = detect_sandbox();
    BackendReport {
        backend: BACKEND,
        state: probe_state(sandbox.as_ref()),
        sandbox,
    }
}

fn probe_state(sandbox: Option<&Sandbox>) -> BackendState {
    let service = match SecretService::connect(EncryptionType::Dh) {
        Ok(service) => service,
        Err(err) => return classify(&err, sandbox),
    };
    // The default alias, and only it: that is the one collection the store itself addresses, and it
    // cannot create it either. Resolving any other collection here would report a keyring that has
    // never been initialized as healthy, because the in-memory session collection is always present
    // and always unlocked, while every read and write went on failing. A passwordless or autologin
    // session is exactly the case, and it is the one this has to name.
    let collection = match service.get_default_collection() {
        Ok(collection) => collection,
        Err(secret_service::Error::NoResult) => return BackendState::NoDefaultCollection,
        Err(err) => return classify(&err, sandbox),
    };
    match collection.is_locked() {
        Ok(true) => BackendState::Locked,
        Ok(false) => BackendState::Ready,
        Err(err) => classify(&err, sandbox),
    }
}

/// Fold a Secret Service failure and the sampled sandbox facts into one condition.
///
/// The sandbox is an input rather than a decoration: from inside a Flatpak whose bus policy
/// withholds the name, the bus is indistinguishable from a machine with no keyring installed. The
/// name simply has no owner either way, so `/.flatpak-info` is the only thing that separates them.
fn classify(err: &secret_service::Error, sandbox: Option<&Sandbox>) -> BackendState {
    match bus_failure(err) {
        Some(BusFailure::NoName) => {
            if bus_is_filtered(sandbox) {
                BackendState::SandboxDenied
            } else {
                BackendState::NoProvider
            }
        }
        Some(BusFailure::Denied) => BackendState::SandboxDenied,
        Some(BusFailure::Locked) => BackendState::Locked,
        None => match err {
            secret_service::Error::Unavailable => BackendState::NoSessionBus,
            secret_service::Error::Locked | secret_service::Error::Prompt => BackendState::Locked,
            secret_service::Error::NoResult => BackendState::NoDefaultCollection,
            _ => BackendState::Unreachable,
        },
    }
}

fn bus_is_filtered(sandbox: Option<&Sandbox>) -> bool {
    matches!(
        sandbox,
        Some(Sandbox::Flatpak {
            bus_filtered: true,
            ..
        })
    )
}

/// Read the D-Bus error name out of a Secret Service failure.
///
/// Both shapes have to be matched. The same condition arrives as the typed `fdo` error on some
/// paths and as a raw method error carrying the name on others, and matching only one of them would
/// silently drop half the cases into the unclassified bucket.
pub(crate) fn bus_failure(err: &secret_service::Error) -> Option<BusFailure> {
    match err {
        secret_service::Error::Zbus(zbus::Error::MethodError(name, ..)) => {
            bus_failure_for_name(name.as_str())
        }
        secret_service::Error::ZbusFdo(zbus::fdo::Error::ServiceUnknown(_)) => {
            Some(BusFailure::NoName)
        }
        secret_service::Error::ZbusFdo(zbus::fdo::Error::NameHasNoOwner(_)) => {
            Some(BusFailure::NoName)
        }
        secret_service::Error::ZbusFdo(zbus::fdo::Error::AccessDenied(_)) => {
            Some(BusFailure::Denied)
        }
        _ => None,
    }
}

fn bus_failure_for_name(name: &str) -> Option<BusFailure> {
    match name {
        "org.freedesktop.DBus.Error.ServiceUnknown"
        | "org.freedesktop.DBus.Error.NameHasNoOwner" => Some(BusFailure::NoName),
        "org.freedesktop.DBus.Error.AccessDenied" => Some(BusFailure::Denied),
        // A write to a locked collection is refused by the store itself rather than by a prompt, so
        // it never reaches the error the read path produces. Without this it lands on the
        // unclassified bucket, and a user with a locked keyring is told the store simply broke.
        "org.freedesktop.Secret.Error.IsLocked" => Some(BusFailure::Locked),
        _ => None,
    }
}

fn detect_sandbox() -> Option<Sandbox> {
    if let Some(info) = read_flatpak_info() {
        return Some(flatpak_sandbox(&info));
    }
    if Path::new("/run/.containerenv").exists() || Path::new("/.dockerenv").exists() {
        return Some(Sandbox::Container);
    }
    None
}

fn read_flatpak_info() -> Option<String> {
    std::fs::read_to_string("/.flatpak-info").ok()
}

fn flatpak_sandbox(info: &str) -> Sandbox {
    Sandbox::Flatpak {
        app_id: flatpak_app_id(info).or_else(|| std::env::var("FLATPAK_ID").ok()),
        bus_filtered: !flatpak_can_talk_to_secrets(info),
    }
}

fn flatpak_app_id(info: &str) -> Option<String> {
    entries(info)
        .find(|(section, key, _)| *section == APPLICATION && *key == "name")
        .map(|(_, _, value)| value.to_owned())
}

/// Whether a `/.flatpak-info` body permits method calls to the credential-store name.
///
/// Two independent grants. Either the sandbox holds the session bus socket itself, in which case no
/// proxy filters anything, or its bus policy names the service `talk` or `own`. A policy of `see` is
/// not a grant: it makes the name visible without making it callable, which is precisely the
/// configuration that produces a store that looks present and answers nothing.
fn flatpak_can_talk_to_secrets(info: &str) -> bool {
    entries(info).any(|(section, key, value)| match section {
        CONTEXT => key == "sockets" && value.split(';').any(|s| s.trim() == "session-bus"),
        SESSION_BUS_POLICY => key == SECRETS_NAME && matches!(value, "talk" | "own"),
        _ => false,
    })
}

/// Walk the file as `(section, key, value)`, ignoring blanks, comments, and anything before the
/// first section header.
fn entries(info: &str) -> impl Iterator<Item = (&str, &str, &str)> {
    let mut section = "";
    info.lines().filter_map(move |line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            section = header;
            return None;
        }
        let (key, value) = line.split_once('=')?;
        Some((section, key.trim(), value.trim()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bodies captured from a real Flatpak sandbox, trimmed to the sections that decide the answer.
    const DENIED: &str = "[Context]\nsockets=x11;pulseaudio;\n\n[Session Bus Policy]\ncom.canonical.AppMenu.Registrar=talk\n";
    const GRANTED: &str = "[Context]\nsockets=x11;pulseaudio;\n\n[Session Bus Policy]\ncom.canonical.AppMenu.Registrar=talk\norg.freedesktop.secrets=talk\n";
    const OWNS_IT: &str = "[Session Bus Policy]\norg.freedesktop.secrets=own\n";
    const UNFILTERED_SOCKET: &str = "[Context]\nsockets=x11;pulseaudio;session-bus;\n\n[Session Bus Policy]\ncom.canonical.AppMenu.Registrar=talk\n";
    const SEE_ONLY: &str = "[Session Bus Policy]\norg.freedesktop.secrets=see\n";

    #[test]
    fn a_policy_that_names_the_service_is_a_grant() {
        assert!(flatpak_can_talk_to_secrets(GRANTED));
        assert!(flatpak_can_talk_to_secrets(OWNS_IT));
    }

    #[test]
    fn holding_the_session_bus_socket_is_a_grant() {
        assert!(flatpak_can_talk_to_secrets(UNFILTERED_SOCKET));
    }

    /// `see` makes the name visible without making it callable, so it must not read as a grant. A
    /// sandbox configured this way is the one whose store looks present and answers nothing.
    #[test]
    fn visibility_alone_is_not_a_grant() {
        assert!(!flatpak_can_talk_to_secrets(SEE_ONLY));
    }

    #[test]
    fn a_policy_without_the_service_is_not_a_grant() {
        assert!(!flatpak_can_talk_to_secrets(DENIED));
        assert!(!flatpak_can_talk_to_secrets(""));
    }

    /// The socket grant lives under `[Context]` and the policy grant under `[Session Bus Policy]`.
    /// A parser that ignored sections would read a `sockets=` line anywhere as a grant.
    #[test]
    fn a_grant_only_counts_under_its_own_section() {
        let misplaced = "[Session Bus Policy]\nsockets=session-bus;\n";
        assert!(!flatpak_can_talk_to_secrets(misplaced));
        let misplaced = "[Context]\norg.freedesktop.secrets=talk\n";
        assert!(!flatpak_can_talk_to_secrets(misplaced));
    }

    #[test]
    fn the_application_name_is_the_app_id() {
        let info = "[Application]\nname=dev.apogee.Launcher\nruntime=org.freedesktop.Platform\n";
        assert_eq!(flatpak_app_id(info).as_deref(), Some("dev.apogee.Launcher"));
        assert_eq!(flatpak_app_id(DENIED), None);
    }

    #[test]
    fn a_sandbox_without_the_grant_is_marked_filtered() {
        assert!(matches!(
            flatpak_sandbox(DENIED),
            Sandbox::Flatpak {
                bus_filtered: true,
                ..
            }
        ));
        assert!(matches!(
            flatpak_sandbox(GRANTED),
            Sandbox::Flatpak {
                bus_filtered: false,
                ..
            }
        ));
    }

    fn flatpak(bus_filtered: bool) -> Sandbox {
        Sandbox::Flatpak {
            app_id: None,
            bus_filtered,
        }
    }

    fn no_name() -> secret_service::Error {
        secret_service::Error::ZbusFdo(zbus::fdo::Error::NameHasNoOwner(SECRETS_NAME.to_owned()))
    }

    /// The whole point of sampling the sandbox: an unowned name is a missing keyring on a normal
    /// desktop and a permission problem inside a filtered sandbox, and the bus cannot tell them
    /// apart. The classification has to flip on that flag alone.
    #[test]
    fn an_unowned_name_reads_differently_inside_a_filtered_sandbox() {
        assert_eq!(classify(&no_name(), None), BackendState::NoProvider);
        assert_eq!(
            classify(&no_name(), Some(&flatpak(false))),
            BackendState::NoProvider
        );
        assert_eq!(
            classify(&no_name(), Some(&flatpak(true))),
            BackendState::SandboxDenied
        );
        assert_eq!(
            classify(&no_name(), Some(&Sandbox::Container)),
            BackendState::NoProvider
        );
    }

    #[test]
    fn a_refused_call_is_the_sandbox_regardless_of_what_was_sampled() {
        let denied =
            secret_service::Error::ZbusFdo(zbus::fdo::Error::AccessDenied("no".to_owned()));
        assert_eq!(classify(&denied, None), BackendState::SandboxDenied);
    }

    #[test]
    fn the_remaining_conditions_map_one_for_one() {
        let cases = [
            (
                secret_service::Error::Unavailable,
                BackendState::NoSessionBus,
            ),
            (secret_service::Error::Locked, BackendState::Locked),
            (secret_service::Error::Prompt, BackendState::Locked),
            (
                secret_service::Error::NoResult,
                BackendState::NoDefaultCollection,
            ),
            (
                secret_service::Error::Crypto("bad session"),
                BackendState::Unreachable,
            ),
        ];
        for (err, expected) in cases {
            assert_eq!(classify(&err, None), expected);
        }
    }

    /// The raw method-error form carries the name as a string, and it is the form a live bus was
    /// observed to use for an unowned name. Matching only the typed form would miss it.
    #[test]
    fn raw_bus_error_names_classify_too() {
        assert!(matches!(
            bus_failure_for_name("org.freedesktop.DBus.Error.ServiceUnknown"),
            Some(BusFailure::NoName)
        ));
        assert!(matches!(
            bus_failure_for_name("org.freedesktop.DBus.Error.NameHasNoOwner"),
            Some(BusFailure::NoName)
        ));
        assert!(matches!(
            bus_failure_for_name("org.freedesktop.DBus.Error.AccessDenied"),
            Some(BusFailure::Denied)
        ));
        assert!(bus_failure_for_name("org.freedesktop.DBus.Error.NoReply").is_none());
    }

    /// The store refuses a write to a locked collection with its own error rather than by raising a
    /// prompt, so this name is the only signal on that path. A live run reported it as an
    /// unclassified backend failure until it was handled here.
    #[test]
    fn a_store_that_says_it_is_locked_classifies_as_locked() {
        assert!(matches!(
            bus_failure_for_name("org.freedesktop.Secret.Error.IsLocked"),
            Some(BusFailure::Locked)
        ));
    }
}
