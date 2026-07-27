//! The error taxonomy, frozen.
//!
//! Three enums leave this crate: [`AddonError`] for the launch path, and the two the parser and the
//! backup engine keep to themselves so they stay total and cross-platform. Every one of them reaches a
//! user as a rendered string, because each seam the layer reports through carries a `String` rather
//! than the error itself, and the shell prints what it is handed. That makes the messages part of the
//! contract, and nothing was checking them: renaming a field, reordering a chain, or interpolating a
//! `Debug` where a sentence belonged was a silent change to what a user reads.
//!
//! One list per enum does both halves of the freeze, which is the point of the macro below. Written as
//! two lists, a match and a table, the pair fails open: the compiler forces an arm for a new variant,
//! and the edit that adds the arm is the same edit that would have to remember the table, so a variant
//! could be named and never rendered. Here a variant is a pattern and its sample and its expected line
//! in one entry, so the exhaustiveness check and the rendering check cannot disagree.
//!
//! [`AddonError`] renders through [`AddonError::chain`] rather than `Display`, because that is what the
//! seams call and therefore what a user sees. Its two transparent arms are why the difference matters:
//! their `Display` is their inner error, and their chain is the sentence a shell prints.

use std::path::PathBuf;

use super::*;
use crate::backup::BackupError;
use crate::manifest::ManifestError;

/// The three enums are carried across task boundaries and stored in `Box<dyn Error + Send + Sync>`
/// chains, so they have to be `Send + Sync + 'static`. Nothing else in the workspace pins it: the
/// `Send` half is proven incidentally by the `async_trait` on [`Injectable`] and the `Sync` half by
/// nothing at all, which means a boxed source with an `Rc` in it would be caught at the first caller
/// rather than here.
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<AddonError>();
    assert_send_sync_static::<ManifestError>();
    assert_send_sync_static::<BackupError>();
};

/// Freeze one taxonomy: every variant as a pattern, a value built from it, and the line it renders as.
///
/// The `match` is exhaustive with no wildcard arm, so a variant added to the enum stops this compiling
/// until it gains an entry, and an entry is a pattern *and* a sample *and* an expected string. That is
/// the whole reason the three are written together rather than as a match beside a table.
///
/// Each sample is also checked against its own pattern, so an entry cannot be filed under one variant
/// while building another.
macro_rules! frozen {
    ($test:ident, $ty:ty, $render:expr, {
        $( $pat:pat => ($sample:expr, $expected:expr $(,)?) ),+ $(,)?
    }) => {
        #[test]
        fn $test() {
            #[allow(dead_code)]
            fn every_variant_has_an_entry(value: &$ty) {
                match value { $( $pat => () ),+ }
            }
            let render: fn(&$ty) -> String = $render;
            $({
                let sample: $ty = $sample;
                // The pattern goes in as an argument, never as the format string: it contains braces.
                assert!(
                    matches!(sample, $pat),
                    "the sample filed under {} builds a different variant",
                    stringify!($pat),
                );
                assert_eq!(render(&sample), $expected, "{}", stringify!($pat));
            })+
        }
    };
}

/// A source with a message this file chose, so a pinned chain is not also pinning `std`'s wording.
fn cause(text: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(text.to_owned()))
}

fn path() -> PathBuf {
    PathBuf::from("/tmp/a")
}

// ---- AddonError ------------------------------------------------------------------------------

frozen!(
    every_addon_error_renders_as_recorded,
    AddonError,
    |err| err.chain(),
    {
        AddonError::Download(_) => (
            AddonError::Download(apogee_fetch::FetchError::LengthMismatch { expected: 10, got: 9 }),
            "download failed: length mismatch: expected 10, got 9",
        ),
        AddonError::Spec(_) => (
            AddonError::Spec(apogee_fetch::SpecError::UnverifiedNotAcknowledged),
            "invalid download request: unverified downloads must be acknowledged explicitly",
        ),
        // Transparent: the catalog's own taxonomy says what happened, and an outer sentence over nine
        // schema variants plus a forged signature can only read as tampering.
        AddonError::Manifest(_) => (
            AddonError::Manifest(ManifestError::UnsupportedVersion { found: 2, expected: 1 }),
            "unsupported manifest version 2 (expected 1)",
        ),
        AddonError::IntegrityMismatch { .. } => (
            AddonError::IntegrityMismatch {
                verb: "a-verb".to_owned(),
                expected: "aa".to_owned(),
                got: "bb".to_owned(),
            },
            "a-verb: the bytes fetched are not the ones it pins (expected aa, got bb)",
        ),
        AddonError::Io { .. } => (
            AddonError::Io {
                what: "the signed catalog".to_owned(),
                step: "make a staging directory",
                source: cause("read-only file system"),
            },
            "the signed catalog: could not make a staging directory: read-only file system",
        ),
        AddonError::Unpack { .. } => (
            AddonError::Unpack {
                what: "a-verb".to_owned(),
                source: cause("the archive held nothing"),
            },
            "a-verb: the archive did not unpack: the archive held nothing",
        ),
        // The tier renders as the tier. Its note is a caveat of its own on the event stream, and a
        // paragraph of it inline buries the failure it is attached to.
        AddonError::Inject { .. } => (
            AddonError::Inject {
                injectable: "Dalamud".to_owned(),
                tier: SupportTier::BestEffort {
                    note: "a note nobody wants inside this sentence".to_owned(),
                },
                source: cause("built for another game version"),
            },
            "injection of Dalamud failed (best effort tier): built for another game version",
        ),
        AddonError::Distribution { .. } => (
            AddonError::Distribution {
                injectable: "Dalamud".to_owned(),
                source: cause("relative url without a base"),
            },
            "Dalamud's distribution answered with something this launcher cannot read: \
             relative url without a base",
        ),
        AddonError::VerbFailed { .. } => (
            AddonError::VerbFailed {
                verb: "a-verb".to_owned(),
                source: cause("it finished without producing apogee/thing"),
            },
            "verb a-verb failed: it finished without producing apogee/thing",
        ),
        AddonError::InvalidAddon { .. } => (
            AddonError::InvalidAddon {
                program: path(),
                index: 2,
                reason: "the program path must be absolute",
            },
            "addon 2 (\"/tmp/a\") cannot be run: the program path must be absolute",
        ),
        AddonError::PrefixRequired { .. } => (
            AddonError::PrefixRequired { program: path() },
            "\"/tmp/a\" runs inside a prefix, but this launch has no prefix",
        ),
        AddonError::UnsupportedField { .. } => (
            AddonError::UnsupportedField {
                program: path(),
                field: "runAsAdmin".to_owned(),
            },
            "\"/tmp/a\" asks for \"runAsAdmin\", which this launcher does not support",
        ),
        AddonError::ExternalSpawn { .. } => (
            AddonError::ExternalSpawn {
                program: path(),
                source: Box::new(apogee_runtime::RuntimeError::RunnerUnavailable {
                    name: "wine".to_owned(),
                    version: "10".to_owned(),
                }),
            },
            "failed to start \"/tmp/a\": runner wine 10 unavailable",
        ),
        // Transparent, and for one more reason than the catalog: this arm carries restore and pruning
        // as well as capture, so any outer sentence naming one is wrong about the others.
        AddonError::Backup(_) => (
            AddonError::Backup(BackupError::NothingSelected),
            "no source tree held anything to back up",
        ),
        AddonError::Cancelled => (AddonError::Cancelled, "cancelled"),
        AddonError::Unsupported { .. } => (
            AddonError::Unsupported {
                what: "redirecting a launch through an injector is Linux-only",
            },
            "unsupported: redirecting a launch through an injector is Linux-only",
        ),
    }
);

// ---- ManifestError ---------------------------------------------------------------------------

// The parser's own taxonomy is what the transparent `AddonError::Manifest` arm renders, so these are
// the sentences a launch prints when a catalog is refused.
frozen!(
    every_manifest_error_renders_as_recorded,
    ManifestError,
    |err| err.to_string(),
    {
        ManifestError::Malformed(_) => (
            ManifestError::Malformed(
                serde_json::from_str::<serde_json::Value>("{")
                    .expect_err("an unterminated object does not parse"),
            ),
            "manifest is not valid JSON or violates the schema",
        ),
        ManifestError::BadSignature => (
            ManifestError::BadSignature,
            "manifest signature did not verify against any trusted key",
        ),
        ManifestError::TrustedKeyUnusable { .. } => (
            ManifestError::TrustedKeyUnusable { position: 1 },
            "the trusted key at position 1 in this build is not a usable ed25519 key",
        ),
        ManifestError::UnsupportedVersion { .. } => (
            ManifestError::UnsupportedVersion { found: 2, expected: 1 },
            "unsupported manifest version 2 (expected 1)",
        ),
        ManifestError::UnknownValue { .. } => (
            ManifestError::UnknownValue {
                component: "a-verb".to_owned(),
                field: "op",
                value: "run".to_owned(),
            },
            "a-verb: unknown op \"run\"",
        ),
        ManifestError::BadPin { .. } => (
            ManifestError::BadPin { component: "a-verb".to_owned() },
            "a-verb: sha256 pin is not 32 hex bytes",
        ),
        ManifestError::BadUrl { .. } => (
            ManifestError::BadUrl {
                component: "a-verb".to_owned(),
                url: "/relative".to_owned(),
            },
            "a-verb: \"/relative\" is not a valid absolute url",
        ),
        ManifestError::BadPath { .. } => (
            ManifestError::BadPath {
                component: "a-verb".to_owned(),
                path: "../out".to_owned(),
                reason: "it climbs out of its root",
            },
            "a-verb: path \"../out\" is not one a component may write: it climbs out of its root",
        ),
        ManifestError::BadIdentifier { .. } => (
            ManifestError::BadIdentifier {
                field: "name",
                value: "a/b".to_owned(),
                reason: "it would not survive being part of a filename",
            },
            "name \"a/b\" is not usable: it would not survive being part of a filename",
        ),
        ManifestError::BadRegistryEdit { .. } => (
            ManifestError::BadRegistryEdit {
                component: "a-verb".to_owned(),
                key: "NOPE\\x".to_owned(),
                reason: "it is not rooted at a registry root",
            },
            "a-verb: registry edit \"NOPE\\\\x\" is not one this launcher will write: \
             it is not rooted at a registry root",
        ),
        ManifestError::DuplicateName { .. } => (
            ManifestError::DuplicateName { name: "a-verb".to_owned() },
            "two components are both named \"a-verb\"",
        ),
    }
);

// ---- BackupError -----------------------------------------------------------------------------

// Backup failures are the one part of this taxonomy a consumer handles by value rather than renders:
// `apogee-core` builds every one of them, and pruning reads them to decide whether an archive is one of
// ours. Frozen for both reasons. Rendered through `Display` rather than a chain, because they reach a
// shell through the transparent arm: what it prints is this string followed by whatever source it has.
frozen!(
    every_backup_error_renders_as_recorded,
    BackupError,
    |err| err.to_string(),
    {
        BackupError::Io { .. } => (
            BackupError::Io {
                path: path(),
                source: std::io::Error::other("permission denied"),
            },
            "\"/tmp/a\" could not be read or written",
        ),
        BackupError::MissingRoot { .. } => (
            BackupError::MissingRoot { path: path() },
            "source tree \"/tmp/a\" is missing",
        ),
        BackupError::RuleMatchedNothing { .. } => (
            BackupError::RuleMatchedNothing {
                rule: "files *.cfg".to_owned(),
                root: path(),
            },
            "files *.cfg matched nothing under \"/tmp/a\"",
        ),
        BackupError::DuplicateRule { .. } => (
            BackupError::DuplicateRule {
                rule: "files *.cfg".to_owned(),
                root: path(),
            },
            "files *.cfg is listed twice for \"/tmp/a\"",
        ),
        BackupError::DuplicateRoot { .. } => (
            BackupError::DuplicateRoot {
                path: path(),
                first: PathBuf::from("/tmp/b"),
            },
            "\"/tmp/a\" is the same directory as \"/tmp/b\"",
        ),
        BackupError::NonUtf8Name { .. } => (
            BackupError::NonUtf8Name { path: path() },
            "\"/tmp/a\" has a name that is not valid UTF-8",
        ),
        BackupError::TooDeep { .. } => (
            BackupError::TooDeep { path: path(), limit: 32 },
            "\"/tmp/a\" nests deeper than 32 directories",
        ),
        BackupError::NothingSelected => (
            BackupError::NothingSelected,
            "no source tree held anything to back up",
        ),
        BackupError::Archive { .. } => (
            BackupError::Archive {
                entry: "user/FFXIV.cfg".to_owned(),
                source: cause("short write"),
            },
            "writing archive entry user/FFXIV.cfg failed",
        ),
        BackupError::Manifest { .. } => (
            BackupError::Manifest { source: cause("trailing comma") },
            "the archive record could not be read or written",
        ),
        BackupError::NotAnArchive { .. } => (
            BackupError::NotAnArchive { path: path() },
            "\"/tmp/a\" is not one of our archives",
        ),
        BackupError::UnsupportedFormat { .. } => (
            BackupError::UnsupportedFormat { path: path(), found: 3, supported: 1 },
            "\"/tmp/a\" is format 3, and this build reads up to 1",
        ),
        BackupError::TooManyEntries { .. } => (
            BackupError::TooManyEntries { found: 9, limit: 8 },
            "9 entries selected, more than the 8 an archive may hold",
        ),
        BackupError::TooLarge { .. } => (
            BackupError::TooLarge { found: 9, limit: 8 },
            "9 bytes selected, more than the 8 an archive may hold",
        ),
        // The reject reason renders as prose: it is the only part of this message worth reading, since
        // the entry name it is about is attacker-chosen.
        BackupError::RejectedEntry { .. } => (
            BackupError::RejectedEntry {
                entry: "..\\..\\x".to_owned(),
                reason: crate::backup::RejectReason::Traversal,
            },
            "archive entry ..\\..\\x refused: it contains a parent reference",
        ),
        BackupError::ContentMismatch { .. } => (
            BackupError::ContentMismatch { entry: "user/FFXIV.cfg".to_owned() },
            "archive entry user/FFXIV.cfg does not match the hash the archive recorded for it",
        ),
    }
);

/// Every reject reason has a sentence of its own. The enum is interpolated into a refusal, so a variant
/// added without one would render as an identifier in a message a user reads.
#[test]
fn every_reject_reason_reads_as_a_sentence() {
    use crate::backup::RejectReason::{
        Absolute, Collision, ComponentTooLong, DriveLetter, Empty, NameTooLong, NotAFileOrDir,
        NotInRecord, TooDeep, Traversal, UnknownRoot, WindowsHostile,
    };
    let mut rendered: Vec<String> = Vec::new();
    for reason in [
        NotAFileOrDir,
        Absolute,
        Traversal,
        DriveLetter,
        Empty,
        UnknownRoot,
        NameTooLong,
        ComponentTooLong,
        TooDeep,
        WindowsHostile,
        Collision,
        NotInRecord,
    ] {
        let text = reason.to_string();
        assert!(
            text.contains(' ') && text != format!("{reason:?}"),
            "{reason:?} renders as its own identifier rather than as prose: {text}"
        );
        rendered.push(text);
    }
    let mut unique = rendered.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        rendered.len(),
        "two reject reasons share a sentence, so a refusal cannot say which: {rendered:?}"
    );
}
