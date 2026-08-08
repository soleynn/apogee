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

/// How long the bus gets to answer before the probe gives up on it.
///
/// A provider that is there answers in milliseconds. What this bounds is a socket that accepts the
/// connection and then never speaks: the handshake underneath has no deadline of its own, so without
/// this the one call whose whole job is to say what the store is doing is the one call that can
/// never return. A wedged bus proxy and a hung `dbus-daemon` both produce it.
const BUS_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

pub(crate) fn probe() -> BackendReport {
    let (state, sandbox) = probe_within(BUS_DEADLINE);
    BackendReport {
        backend: BACKEND,
        state,
        sandbox,
    }
}

/// Sample the store and the sandbox it is being reached from, giving up on both after `deadline`.
///
/// Separate from [`probe`] so the wiring is provable rather than merely written down. A deadline
/// that is declared and then not applied leaves this function looking exactly as it does with
/// `within` taken back out of it, and the call it wraps is the one that never returns.
///
/// The sandbox is sampled inside the deadline rather than beside it, so what the deadline bounds is
/// the whole call rather than most of it: reading `/.flatpak-info` blocks as thoroughly as a bus
/// handshake when whatever is behind that name does not answer. The cost is that a probe that runs
/// out of time reports no sandbox, which is the honest answer for a sample that never finished.
fn probe_within(deadline: std::time::Duration) -> (BackendState, Option<Sandbox>) {
    within(deadline, (BackendState::Unreachable, None), || {
        let sandbox = detect_sandbox();
        (probe_state(sandbox.as_ref()), sandbox)
    })
}

/// Run `work` on a worker thread and answer `on_timeout` if it has not finished within `deadline`.
///
/// The worker is abandoned rather than cancelled, because a blocking D-Bus handshake has no
/// cancellation point and the alternative is a call that cannot return. What is abandoned holds no
/// lock of this crate's and owns nothing a later call needs, so the cost is the thread, and it ends
/// when the connection attempt underneath it does.
fn within<T: Send + 'static>(
    deadline: std::time::Duration,
    on_timeout: T,
    work: impl FnOnce() -> T + Send + 'static,
) -> T {
    let (answer, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // A send that fails is a probe that already gave up and stopped listening.
        let _ = answer.send(work());
    });
    wait.recv_timeout(deadline).unwrap_or(on_timeout)
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
        None if is_dead_session_bus(err) => BackendState::NoSessionBus,
        None => match err {
            secret_service::Error::Unavailable => BackendState::NoSessionBus,
            secret_service::Error::Locked | secret_service::Error::Prompt => BackendState::Locked,
            secret_service::Error::NoResult => BackendState::NoDefaultCollection,
            _ => BackendState::Unreachable,
        },
    }
}

/// Whether the session bus address names something that is not a working bus.
///
/// The library folds only a *missing* socket into `Unavailable`
/// (`secret-service-5.1.0/src/util.rs:149` takes `ErrorKind::NotFound` alone), so a socket that
/// exists and will not take a connection arrives unnamed and used to report as an unclassified store
/// failure. From a caller's point of view it is the same condition: the address names something that
/// is not a working bus. A `dbus-daemon` that died leaving its socket, and a stale address inherited
/// through tmux, ssh or `sudo -E`, are the ordinary ways to arrive here.
///
/// Shared with the store path rather than written twice, because the two drifted: the probe named
/// this condition and the store did not, so a launcher told the user storage was unavailable and
/// then refused to delete the account, on the grounds that the store it had just called dead might
/// still be holding the secret.
pub(crate) fn is_dead_session_bus(err: &secret_service::Error) -> bool {
    matches!(
        err,
        secret_service::Error::Zbus(zbus::Error::InputOutput(io))
            if matches!(
                io.kind(),
                std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::PermissionDenied
            )
    )
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

/// Read the sandbox's own description of itself.
fn read_flatpak_info() -> Option<String> {
    let bytes = std::fs::read("/.flatpak-info").ok()?;
    Some(decode_flatpak_info(&bytes))
}

/// Decode a `/.flatpak-info` body, lossily.
///
/// Lossily, and infallibly, because the alternative was worse than a mangled value. `read_to_string`
/// fails on a single byte that is not UTF-8 anywhere in the file, a `filesystems=` entry naming a
/// path in some other encoding for instance, and the failure erased the whole sandbox:
/// `detect_sandbox` fell through to `None` and a confined process was reported as unconfined with no
/// keyring installed. Every section that decides the answer here is ASCII, so a replacement
/// character in an unrelated value costs nothing.
///
/// Split from the read so that property is testable at all: the path above it is fixed, and the one
/// machine that can supply the body is the one already running inside the sandbox.
fn decode_flatpak_info(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn flatpak_sandbox(info: &str) -> Sandbox {
    Sandbox::Flatpak {
        app_id: flatpak_app_id(info).or_else(|| std::env::var("FLATPAK_ID").ok()),
        bus_filtered: !flatpak_can_talk_to_secrets(info),
    }
}

fn flatpak_app_id(info: &str) -> Option<String> {
    // Last rather than first, as GLib's `KeyFile` resolves a repeated key. See `policy_permits`.
    entries(info)
        .filter(|(section, key, _)| *section == APPLICATION && *key == "name")
        .last()
        .map(|(_, _, value)| value.to_owned())
}

/// Whether a `/.flatpak-info` body permits method calls to the credential-store name.
///
/// Two independent grants. Either the sandbox holds the session bus socket itself, in which case no
/// proxy filters anything, or its bus policy names the service `talk` or `own`. A policy of `see` is
/// not a grant: it makes the name visible without making it callable, which is precisely the
/// configuration that produces a store that looks present and answers nothing.
fn flatpak_can_talk_to_secrets(info: &str) -> bool {
    holds_the_session_bus(info) || policy_permits(info)
}

/// Whether the sandbox was handed the session bus socket itself, so no proxy filters anything.
///
/// A negated entry (`!session-bus`, which is what `--nosocket=session-bus` writes) is not the name,
/// so it is not a grant.
fn holds_the_session_bus(info: &str) -> bool {
    entries(info)
        .filter(|(section, key, _)| *section == CONTEXT && *key == "sockets")
        .last()
        .is_some_and(|(_, _, value)| value.split(';').any(|s| s.trim() == "session-bus"))
}

/// Whether the bus policy permits method calls to the credential-store name.
///
/// Two things an exact-match test over every entry got wrong, both measured against a real sandbox.
/// Flatpak writes a wildcard permission as a key of its own (`org.freedesktop.*=talk`), which the
/// proxy resolves by prefix, so comparing against the full name alone reads a granted sandbox as
/// denied and tells the user to grant a permission they already hold. And a repeated key is
/// last-wins in GLib's `KeyFile`, which is the parser flatpak itself reads this file with, so
/// stopping at the first match reads `talk` followed by `see` as a grant where flatpak sees none.
///
/// Between two keys that both match, the more specific one decides, which is what the proxy does: an
/// exact name beats any wildcard, and a longer wildcard beats a shorter one.
fn policy_permits(info: &str) -> bool {
    let mut best: Option<(usize, &str)> = None;
    for (section, key, value) in entries(info) {
        if section != SESSION_BUS_POLICY {
            continue;
        }
        let Some(specificity) = policy_reaches_secrets(key) else {
            continue;
        };
        // Greater *or equal*: equality is the same key written twice, and the later one wins.
        if best.is_none_or(|(held, _)| specificity >= held) {
            best = Some((specificity, value));
        }
    }
    matches!(best, Some((_, "talk" | "own")))
}

/// How specifically a policy key names the credential store, if it names it at all. Larger is more
/// specific, and `None` is a key about some other name.
///
/// `a.b.*` covers every name under `a.b.` and not `a.b` itself, which is how the proxy resolves it:
/// so `org.freedesktop.*` reaches the store and `org.freedesktop.secrets.*` does not.
fn policy_reaches_secrets(key: &str) -> Option<usize> {
    if key == SECRETS_NAME {
        return Some(usize::MAX);
    }
    let prefix = key.strip_suffix('*')?;
    SECRETS_NAME.starts_with(prefix).then_some(prefix.len())
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

    /// The form flatpak actually writes for a wildcard talk permission. Comparing against the full
    /// name alone read this as a denial, so a sandbox that could reach the store was told to grant a
    /// permission it already held, and one with no keyring installed was told the same thing.
    #[test]
    fn a_wildcard_policy_that_covers_the_service_is_a_grant() {
        assert!(flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.freedesktop.*=talk\n"
        ));
        assert!(flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.*=own\n"
        ));
        assert!(flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\n*=talk\n"
        ));
    }

    /// A wildcard covers the names under a prefix, not the prefix's own parent, and a key that
    /// merely looks similar covers nothing.
    #[test]
    fn a_wildcard_that_does_not_reach_the_service_is_not_a_grant() {
        for body in [
            "[Session Bus Policy]\norg.freedesktop.secrets.*=talk\n",
            "[Session Bus Policy]\norg.freedesktop.secretsX=talk\n",
            "[Session Bus Policy]\nx.org.freedesktop.secrets=talk\n",
            "[Session Bus Policy]\ncom.*=talk\n",
        ] {
            assert!(!flatpak_can_talk_to_secrets(body), "{body}");
        }
    }

    /// Between two keys that both match, the more specific one decides, as the proxy resolves it.
    #[test]
    fn an_exact_policy_beats_a_wildcard_either_way_round() {
        assert!(!flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.freedesktop.*=talk\norg.freedesktop.secrets=see\n"
        ));
        assert!(!flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.freedesktop.secrets=see\norg.freedesktop.*=talk\n"
        ));
        assert!(flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.freedesktop.*=see\norg.freedesktop.secrets=talk\n"
        ));
        assert!(flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.*=see\norg.freedesktop.*=talk\n"
        ));
    }

    /// A repeated key is last-wins in GLib's `KeyFile`, which is what flatpak reads this file with.
    /// Stopping at the first match made `talk` then `see` a grant here and a denial to flatpak.
    #[test]
    fn a_repeated_key_is_resolved_the_way_flatpak_resolves_it() {
        assert!(!flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.freedesktop.secrets=talk\norg.freedesktop.secrets=see\n"
        ));
        assert!(flatpak_can_talk_to_secrets(
            "[Session Bus Policy]\norg.freedesktop.secrets=see\norg.freedesktop.secrets=talk\n"
        ));
        assert!(!flatpak_can_talk_to_secrets(
            "[Context]\nsockets=session-bus;\nsockets=x11;\n"
        ));
        assert_eq!(
            flatpak_app_id("[Application]\nname=first\nname=second\n").as_deref(),
            Some("second")
        );
    }

    /// What `--nosocket=session-bus` writes. It is not the name, so it is not a grant.
    #[test]
    fn a_negated_socket_is_not_a_grant() {
        assert!(!flatpak_can_talk_to_secrets(
            "[Context]\nsockets=x11;!session-bus;\n"
        ));
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

    /// A socket that is there and refuses, or that the process may not open, is not a working bus.
    /// The library names only a missing one, so these arrived unclassified and a user with a dead
    /// `dbus-daemon` was told the store had simply broken.
    #[test]
    fn a_socket_that_will_not_take_a_connection_is_a_missing_bus() {
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::PermissionDenied,
        ] {
            let err = secret_service::Error::Zbus(zbus::Error::InputOutput(std::sync::Arc::new(
                std::io::Error::new(kind, "socket"),
            )));
            assert_eq!(classify(&err, None), BackendState::NoSessionBus, "{kind:?}");
        }

        // Anything else on that socket is still an unclassified failure rather than a guess.
        let err = secret_service::Error::Zbus(zbus::Error::InputOutput(std::sync::Arc::new(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "socket"),
        )));
        assert_eq!(classify(&err, None), BackendState::Unreachable);
    }

    /// The probe's own deadline. Without it a socket that accepts and never speaks blocks the call
    /// forever, and that call is the one a front end makes to decide what to say about storage.
    #[test]
    fn work_that_outruns_the_deadline_answers_the_fallback() {
        let slow = within(
            std::time::Duration::from_millis(50),
            BackendState::Unreachable,
            || {
                std::thread::sleep(std::time::Duration::from_secs(30));
                BackendState::Ready
            },
        );
        assert_eq!(slow, BackendState::Unreachable);

        let prompt = within(
            std::time::Duration::from_secs(30),
            BackendState::Unreachable,
            || BackendState::Ready,
        );
        assert_eq!(prompt, BackendState::Ready);
    }

    /// The deadline is wired to the sample rather than declared beside it. `within` answering for
    /// work that outruns it is one property and the probe actually going through `within` is
    /// another: with the wrapper taken back out, this function answers whatever the bus says,
    /// however long that takes, which is the state the deadline exists to replace.
    ///
    /// A deadline of no time at all is what decides it without a wedged bus to hang on: the sample
    /// runs on a thread that has not been scheduled yet, and it has a file to read before it even
    /// reaches the socket, so the only answer available to the caller is the fallback.
    #[test]
    fn the_sample_runs_under_the_deadline() {
        assert_eq!(
            probe_within(std::time::Duration::ZERO),
            (BackendState::Unreachable, None)
        );
    }

    /// One byte that is not UTF-8 anywhere in the file used to erase the whole sandbox: the read
    /// failed, `detect_sandbox` fell through to `None`, and a confined process was reported as an
    /// ordinary desktop with no keyring installed. Here the byte sits in a value nothing reads,
    /// which is where a path in some other encoding lands, and the grant two sections away still has
    /// to survive it.
    #[test]
    fn a_body_that_is_not_utf8_still_yields_its_grant() {
        let mut body = b"[Context]\nfilesystems=/media/".to_vec();
        body.push(0xff);
        body.extend_from_slice(b";\n\n[Session Bus Policy]\norg.freedesktop.secrets=talk\n");

        let info = decode_flatpak_info(&body);
        assert!(flatpak_can_talk_to_secrets(&info));
        assert!(matches!(
            flatpak_sandbox(&info),
            Sandbox::Flatpak {
                bus_filtered: false,
                ..
            }
        ));
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
