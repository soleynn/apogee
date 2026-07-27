//! The error taxonomy, frozen.
//!
//! Three enums leave this crate: [`AddonError`] for the launch path, and the two the parser and the
//! backup engine keep to themselves so they stay total and cross-platform. Every one of them reaches a
//! user as a rendered string, because each seam the layer reports through carries a `String` rather
//! than the error itself, and the shell prints what it is handed. That makes the messages part of the
//! contract, and nothing was checking them: renaming a field, reordering a chain, or interpolating a
//! `Debug` where a sentence belonged was a silent change to what a user reads.
//!
//! Three parts, and each catches a different way the taxonomy can move.
//!
//! `name` is an exhaustive match with no wildcard arm, so a new variant does not compile until it is
//! named here. The coverage assertions then fail until the table below actually builds one, so a
//! variant cannot be named and then left unrendered. And the table pins the rendered chain exactly, so
//! a message edit is a deliberate edit to this file rather than something noticed in the field.
//!
//! Renders through [`AddonError::chain`] rather than `Display`, because that is what the seams call and
//! therefore what a user sees. The two transparent arms are the reason the difference matters: their
//! `Display` is their inner error, and their chain is the sentence a shell prints.

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

/// A source with a message this file chose, so a pinned chain is not also pinning `std`'s wording.
fn cause(text: &str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(text.to_owned()))
}

fn path() -> PathBuf {
    PathBuf::from("/tmp/a")
}

// ---- AddonError ------------------------------------------------------------------------------

/// Exhaustive, with no wildcard: a variant added to the taxonomy stops this compiling until it is
/// named, which is the half of the freeze a test alone cannot give.
fn name(err: &AddonError) -> &'static str {
    match err {
        AddonError::Download(_) => "Download",
        AddonError::Spec(_) => "Spec",
        AddonError::Manifest(_) => "Manifest",
        AddonError::IntegrityMismatch { .. } => "IntegrityMismatch",
        AddonError::Io { .. } => "Io",
        AddonError::Unpack { .. } => "Unpack",
        AddonError::Inject { .. } => "Inject",
        AddonError::Distribution { .. } => "Distribution",
        AddonError::VerbFailed { .. } => "VerbFailed",
        AddonError::InvalidAddon { .. } => "InvalidAddon",
        AddonError::PrefixRequired { .. } => "PrefixRequired",
        AddonError::UnsupportedField { .. } => "UnsupportedField",
        AddonError::ExternalSpawn { .. } => "ExternalSpawn",
        AddonError::Backup(_) => "Backup",
        AddonError::Cancelled => "Cancelled",
        AddonError::Unsupported { .. } => "Unsupported",
    }
}

/// Every variant, and the line a shell prints for it.
fn addon_errors() -> Vec<(AddonError, &'static str)> {
    vec![
        (
            AddonError::Download(apogee_fetch::FetchError::LengthMismatch {
                expected: 10,
                got: 9,
            }),
            "download failed: length mismatch: expected 10, got 9",
        ),
        (
            AddonError::Spec(apogee_fetch::SpecError::UnverifiedNotAcknowledged),
            "invalid download request: unverified downloads must be acknowledged explicitly",
        ),
        (
            // Transparent: the catalog's own taxonomy says what happened, and an outer sentence over
            // nine schema variants plus a forged signature can only read as tampering.
            AddonError::Manifest(ManifestError::UnsupportedVersion {
                found: 2,
                expected: 1,
            }),
            "unsupported manifest version 2 (expected 1)",
        ),
        (
            AddonError::IntegrityMismatch {
                verb: "a-verb".to_owned(),
                expected: "aa".to_owned(),
                got: "bb".to_owned(),
            },
            "a-verb: the bytes fetched are not the ones it pins (expected aa, got bb)",
        ),
        (
            AddonError::Io {
                what: "the signed catalog".to_owned(),
                step: "make a staging directory",
                source: cause("read-only file system"),
            },
            "the signed catalog: could not make a staging directory: read-only file system",
        ),
        (
            AddonError::Unpack {
                what: "a-verb".to_owned(),
                source: cause("the archive held nothing"),
            },
            "a-verb: the archive did not unpack: the archive held nothing",
        ),
        (
            // The tier renders as the tier. Its note is a caveat of its own on the event stream, and a
            // paragraph of it inline buries the failure it is attached to.
            AddonError::Inject {
                injectable: "Dalamud".to_owned(),
                tier: SupportTier::BestEffort {
                    note: "a note nobody wants inside this sentence".to_owned(),
                },
                source: cause("built for another game version"),
            },
            "injection of Dalamud failed (best effort tier): built for another game version",
        ),
        (
            AddonError::Distribution {
                injectable: "Dalamud".to_owned(),
                source: cause("relative url without a base"),
            },
            "Dalamud's distribution answered with something this launcher cannot read: \
             relative url without a base",
        ),
        (
            AddonError::VerbFailed {
                verb: "a-verb".to_owned(),
                source: cause("it finished without producing apogee/thing"),
            },
            "verb a-verb failed: it finished without producing apogee/thing",
        ),
        (
            AddonError::InvalidAddon {
                program: path(),
                index: 2,
                reason: "the program path must be absolute",
            },
            "addon 2 (\"/tmp/a\") cannot be run: the program path must be absolute",
        ),
        (
            AddonError::PrefixRequired { program: path() },
            "\"/tmp/a\" runs inside a prefix, but this launch has no prefix",
        ),
        (
            AddonError::UnsupportedField {
                program: path(),
                field: "runAsAdmin".to_owned(),
            },
            "\"/tmp/a\" asks for \"runAsAdmin\", which this launcher does not support",
        ),
        (
            AddonError::ExternalSpawn {
                program: path(),
                source: Box::new(apogee_runtime::RuntimeError::RunnerUnavailable {
                    name: "wine".to_owned(),
                    version: "10".to_owned(),
                }),
            },
            "failed to start \"/tmp/a\": runner wine 10 unavailable",
        ),
        (
            // Transparent, and for one more reason than the catalog: this arm carries restore and
            // pruning as well as capture, so any outer sentence naming one is wrong about the others.
            AddonError::Backup(BackupError::NothingSelected),
            "no source tree held anything to back up",
        ),
        (AddonError::Cancelled, "cancelled"),
        (
            AddonError::Unsupported {
                what: "redirecting a launch through an injector is Linux-only",
            },
            "unsupported: redirecting a launch through an injector is Linux-only",
        ),
    ]
}

/// The rendering half of the freeze. An edit here should be a decision about what a user reads, which
/// is exactly what it costs.
#[test]
fn every_addon_error_renders_as_recorded() {
    for (err, expected) in addon_errors() {
        assert_eq!(err.chain(), expected, "{}", name(&err));
    }
}

/// The coverage half. `name` refusing to compile catches a variant nobody thought about; this catches
/// one somebody named and did not render, which would otherwise leave a hole in the table above that
/// looks exactly like completeness.
#[test]
fn the_recorded_renderings_cover_every_addon_error() {
    let mut covered: Vec<&str> = addon_errors().iter().map(|(e, _)| name(e)).collect();
    covered.sort_unstable();
    let mut expected = vec![
        "Backup",
        "Cancelled",
        "Distribution",
        "Download",
        "ExternalSpawn",
        "IntegrityMismatch",
        "Inject",
        "InvalidAddon",
        "Io",
        "Manifest",
        "PrefixRequired",
        "Spec",
        "Unpack",
        "Unsupported",
        "UnsupportedField",
        "VerbFailed",
    ];
    expected.sort_unstable();
    assert_eq!(covered, expected);
}

// ---- ManifestError ---------------------------------------------------------------------------

fn manifest_name(err: &ManifestError) -> &'static str {
    match err {
        ManifestError::Malformed(_) => "Malformed",
        ManifestError::BadSignature => "BadSignature",
        ManifestError::TrustedKeyUnusable { .. } => "TrustedKeyUnusable",
        ManifestError::UnsupportedVersion { .. } => "UnsupportedVersion",
        ManifestError::UnknownValue { .. } => "UnknownValue",
        ManifestError::BadPin { .. } => "BadPin",
        ManifestError::BadUrl { .. } => "BadUrl",
        ManifestError::BadPath { .. } => "BadPath",
        ManifestError::BadIdentifier { .. } => "BadIdentifier",
        ManifestError::BadRegistryEdit { .. } => "BadRegistryEdit",
        ManifestError::DuplicateName { .. } => "DuplicateName",
    }
}

fn manifest_errors() -> Vec<(ManifestError, &'static str)> {
    let malformed = serde_json::from_str::<serde_json::Value>("{")
        .expect_err("an unterminated object does not parse");
    vec![
        (
            ManifestError::Malformed(malformed),
            "manifest is not valid JSON or violates the schema",
        ),
        (
            ManifestError::BadSignature,
            "manifest signature did not verify against any trusted key",
        ),
        (
            ManifestError::TrustedKeyUnusable { position: 1 },
            "the trusted key at position 1 in this build is not a usable ed25519 key",
        ),
        (
            ManifestError::UnsupportedVersion {
                found: 2,
                expected: 1,
            },
            "unsupported manifest version 2 (expected 1)",
        ),
        (
            ManifestError::UnknownValue {
                component: "a-verb".to_owned(),
                field: "op",
                value: "run".to_owned(),
            },
            "a-verb: unknown op \"run\"",
        ),
        (
            ManifestError::BadPin {
                component: "a-verb".to_owned(),
            },
            "a-verb: sha256 pin is not 32 hex bytes",
        ),
        (
            ManifestError::BadUrl {
                component: "a-verb".to_owned(),
                url: "/relative".to_owned(),
            },
            "a-verb: \"/relative\" is not a valid absolute url",
        ),
        (
            ManifestError::BadPath {
                component: "a-verb".to_owned(),
                path: "../out".to_owned(),
                reason: "it climbs out of its root",
            },
            "a-verb: path \"../out\" is not one a component may write: it climbs out of its root",
        ),
        (
            ManifestError::BadIdentifier {
                field: "name",
                value: "a/b".to_owned(),
                reason: "it would not survive being part of a filename",
            },
            "name \"a/b\" is not usable: it would not survive being part of a filename",
        ),
        (
            ManifestError::BadRegistryEdit {
                component: "a-verb".to_owned(),
                key: "NOPE\\x".to_owned(),
                reason: "it is not rooted at a registry root",
            },
            "a-verb: registry edit \"NOPE\\\\x\" is not one this launcher will write: \
             it is not rooted at a registry root",
        ),
        (
            ManifestError::DuplicateName {
                name: "a-verb".to_owned(),
            },
            "two components are both named \"a-verb\"",
        ),
    ]
}

/// The parser's own taxonomy is what the transparent [`AddonError::Manifest`] arm renders, so these are
/// the sentences a launch prints when a catalog is refused.
#[test]
fn every_manifest_error_renders_as_recorded() {
    for (err, expected) in manifest_errors() {
        assert_eq!(err.to_string(), expected, "{}", manifest_name(&err));
    }
}

#[test]
fn the_recorded_renderings_cover_every_manifest_error() {
    let mut covered: Vec<&str> = manifest_errors()
        .iter()
        .map(|(e, _)| manifest_name(e))
        .collect();
    covered.sort_unstable();
    let mut expected = vec![
        "BadIdentifier",
        "BadPath",
        "BadPin",
        "BadRegistryEdit",
        "BadSignature",
        "BadUrl",
        "DuplicateName",
        "Malformed",
        "TrustedKeyUnusable",
        "UnknownValue",
        "UnsupportedVersion",
    ];
    expected.sort_unstable();
    assert_eq!(covered, expected);
}

// ---- BackupError -----------------------------------------------------------------------------

fn backup_name(err: &BackupError) -> &'static str {
    match err {
        BackupError::Io { .. } => "Io",
        BackupError::MissingRoot { .. } => "MissingRoot",
        BackupError::RuleMatchedNothing { .. } => "RuleMatchedNothing",
        BackupError::DuplicateRule { .. } => "DuplicateRule",
        BackupError::DuplicateRoot { .. } => "DuplicateRoot",
        BackupError::NonUtf8Name { .. } => "NonUtf8Name",
        BackupError::TooDeep { .. } => "TooDeep",
        BackupError::NothingSelected => "NothingSelected",
        BackupError::Archive { .. } => "Archive",
        BackupError::Manifest { .. } => "Manifest",
        BackupError::NotAnArchive { .. } => "NotAnArchive",
        BackupError::UnsupportedFormat { .. } => "UnsupportedFormat",
        BackupError::TooManyEntries { .. } => "TooManyEntries",
        BackupError::TooLarge { .. } => "TooLarge",
        BackupError::RejectedEntry { .. } => "RejectedEntry",
        BackupError::ContentMismatch { .. } => "ContentMismatch",
    }
}

fn backup_errors() -> Vec<(BackupError, &'static str)> {
    vec![
        (
            BackupError::Io {
                path: path(),
                source: std::io::Error::other("permission denied"),
            },
            "\"/tmp/a\" could not be read or written",
        ),
        (
            BackupError::MissingRoot { path: path() },
            "source tree \"/tmp/a\" is missing",
        ),
        (
            BackupError::RuleMatchedNothing {
                rule: "files *.cfg".to_owned(),
                root: path(),
            },
            "files *.cfg matched nothing under \"/tmp/a\"",
        ),
        (
            BackupError::DuplicateRule {
                rule: "files *.cfg".to_owned(),
                root: path(),
            },
            "files *.cfg is listed twice for \"/tmp/a\"",
        ),
        (
            BackupError::DuplicateRoot {
                path: path(),
                first: PathBuf::from("/tmp/b"),
            },
            "\"/tmp/a\" is the same directory as \"/tmp/b\"",
        ),
        (
            BackupError::NonUtf8Name { path: path() },
            "\"/tmp/a\" has a name that is not valid UTF-8",
        ),
        (
            BackupError::TooDeep {
                path: path(),
                limit: 32,
            },
            "\"/tmp/a\" nests deeper than 32 directories",
        ),
        (
            BackupError::NothingSelected,
            "no source tree held anything to back up",
        ),
        (
            BackupError::Archive {
                entry: "user/FFXIV.cfg".to_owned(),
                source: cause("short write"),
            },
            "writing archive entry user/FFXIV.cfg failed",
        ),
        (
            BackupError::Manifest {
                source: cause("trailing comma"),
            },
            "the archive record could not be read or written",
        ),
        (
            BackupError::NotAnArchive { path: path() },
            "\"/tmp/a\" is not one of our archives",
        ),
        (
            BackupError::UnsupportedFormat {
                path: path(),
                found: 3,
                supported: 1,
            },
            "\"/tmp/a\" is format 3, and this build reads up to 1",
        ),
        (
            BackupError::TooManyEntries { found: 9, limit: 8 },
            "9 entries selected, more than the 8 an archive may hold",
        ),
        (
            BackupError::TooLarge { found: 9, limit: 8 },
            "9 bytes selected, more than the 8 an archive may hold",
        ),
        (
            // The reject reason renders as prose: it is the only part of this message worth reading,
            // since the entry name it is about is attacker-chosen.
            BackupError::RejectedEntry {
                entry: "..\\..\\x".to_owned(),
                reason: crate::backup::RejectReason::Traversal,
            },
            "archive entry ..\\..\\x refused: it contains a parent reference",
        ),
        (
            BackupError::ContentMismatch {
                entry: "user/FFXIV.cfg".to_owned(),
            },
            "archive entry user/FFXIV.cfg does not match the hash the archive recorded for it",
        ),
    ]
}

/// Backup failures are the one part of this taxonomy a consumer handles by value rather than renders:
/// `apogee-core` builds every one of them, and pruning reads them to decide whether an archive is one
/// of ours. Frozen for both reasons.
#[test]
fn every_backup_error_renders_as_recorded() {
    for (err, expected) in backup_errors() {
        // Display rather than the chain: these are wrapped by the transparent arm, so what a shell
        // prints for one is this string followed by whatever source it carries.
        assert_eq!(err.to_string(), expected, "{}", backup_name(&err));
    }
}

#[test]
fn the_recorded_renderings_cover_every_backup_error() {
    let mut covered: Vec<&str> = backup_errors()
        .iter()
        .map(|(e, _)| backup_name(e))
        .collect();
    covered.sort_unstable();
    let mut expected = vec![
        "Archive",
        "ContentMismatch",
        "DuplicateRoot",
        "DuplicateRule",
        "Io",
        "Manifest",
        "MissingRoot",
        "NonUtf8Name",
        "NotAnArchive",
        "NothingSelected",
        "RejectedEntry",
        "RuleMatchedNothing",
        "TooDeep",
        "TooLarge",
        "TooManyEntries",
        "UnsupportedFormat",
    ];
    expected.sort_unstable();
    assert_eq!(covered, expected);
}

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
