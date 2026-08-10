use std::path::PathBuf;

use super::*;
use crate::backup::BackupError;
use crate::manifest::ManifestError;

// The three enums are carried across task boundaries and stored in `Box<dyn Error + Send + Sync>`
// chains, so they have to be `Send + Sync + 'static`. Nothing else in the workspace pins it: the
// `Send` half is proven incidentally by the `async_trait` on `Injectable` and the `Sync` half by
// nothing at all, which means a boxed source with an `Rc` in it would be caught at the first caller
// rather than here.
const _: fn() = || {
    fn assert_send_sync_static<T: Send + Sync + 'static>() {}
    assert_send_sync_static::<AddonError>();
    assert_send_sync_static::<ManifestError>();
    assert_send_sync_static::<BackupError>();
};

/// Freeze one taxonomy: every variant as a pattern, a value built from it, and the line it renders
/// as.
///
/// The `match` is exhaustive with no wildcard arm, so a variant added to the enum stops this
/// compiling until it gains an entry, and an entry is a pattern *and* a sample *and* an expected
/// string. That is why the three are written together rather than as a match beside a table.
///
/// Each sample is also checked against its own pattern, so an entry cannot be filed under one
/// variant while building another.
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
        // The one download failure with an answer the user can act on, so it does not sit inside
        // `Download` with `ENOSPC` three links down the chain.
        AddonError::OutOfSpace { .. } => (
            AddonError::from_fetch(
                apogee_fetch::FetchError::Io {
                    path: PathBuf::from("/tmp/a.part"),
                    source: std::io::Error::new(std::io::ErrorKind::StorageFull, "the disk is full"),
                },
                "dalamud",
                &path(),
            ),
            "dalamud: out of disk space at \"/tmp/a.part\": the disk is full",
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
                what: "a-verb".to_owned(),
                file: path(),
                expected: "aa".to_owned(),
                got: "bb".to_owned(),
            },
            "a-verb: \"/tmp/a\" is not the bytes it was published as (expected aa, got bb)",
        ),
        // The path is the first thing anybody reading a filesystem failure looks for, and an io error
        // does not carry one.
        AddonError::Io { .. } => (
            AddonError::Io {
                what: "the signed catalog".to_owned(),
                step: "make a staging directory",
                path: path(),
                source: cause("read-only file system"),
            },
            "the signed catalog: could not make a staging directory at \"/tmp/a\": read-only file system",
        ),
        AddonError::EmptyArchive { .. } => (
            AddonError::EmptyArchive { what: "a-verb".to_owned() },
            "a-verb: the archive that was served held nothing under the layout declared for it",
        ),
        AddonError::BadDistribution { .. } => (
            AddonError::BadDistribution {
                injectable: "Dalamud".to_owned(),
                pointer: url::Url::parse("https://example.invalid/x").expect("a url"),
            },
            "Dalamud: https://example.invalid/x is not a pointer its other endpoints can be derived from",
        ),
        AddonError::VerbIncomplete { .. } => (
            AddonError::VerbIncomplete {
                verb: "a-verb".to_owned(),
                missing: path(),
            },
            "verb a-verb finished without producing \"/tmp/a\"",
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
        // Both companions are named, and neither is at fault: the sentence is about the launch having
        // one program, not about either of them being broken.
        AddonError::LaunchAlreadyRedirected { .. } => (
            AddonError::LaunchAlreadyRedirected {
                injectable: "Perigee".to_owned(),
                redirector: "Dalamud".to_owned(),
            },
            "Perigee cannot redirect this launch: Dalamud already did, \
             and a launch spawns one program",
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
            "a-verb: no blake3 or sha256 pin of 32 hex bytes",
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
        BackupError::NoIncludeRules { .. } => (
            BackupError::NoIncludeRules { path: path() },
            "\"/tmp/a\" has no include rules, so it would cover nothing",
        ),
        // Names the operation rather than the platform: which platforms can do it is this build's
        // business, and what the reader asked for is the part they can act on.
        BackupError::Unsupported { .. } => (
            BackupError::Unsupported { what: "restoring a backup" },
            "restoring a backup is not supported on this platform",
        ),
        // One word, like the crate's own cancellation: there is no path, entry or limit to name,
        // because nothing about the work is wrong.
        BackupError::Cancelled => (BackupError::Cancelled, "cancelled"),
    }
);

/// The reasons a foreign backup was refused are interpolated into a message a user reads, so a
/// variant added without a sentence of its own would render as an identifier.
#[test]
fn every_foreign_reason_reads_as_a_sentence() {
    use crate::backup::ForeignReason::{
        CouldNotRead, NoRecord, NotARegularFile, NotAnArchive, UnreadableRecord,
        UnsupportedFormatVersion, WrongExtension,
    };
    let mut rendered: Vec<String> = Vec::new();
    for reason in [
        NotARegularFile,
        WrongExtension,
        NotAnArchive,
        NoRecord,
        UnreadableRecord,
        UnsupportedFormatVersion(9),
        CouldNotRead,
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
        "two reasons share a sentence, so a prune cannot say which: {rendered:?}"
    );
}

/// The same for the reasons a prune left a file alone, which are read in the same place and by the
/// same person: a directory that still has files in it after a prune, and a line per file saying
/// why.
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

/// A verify failure has a home of its own, and the conversion is what puts it there.
///
/// This is why [`AddonError::Download`] carries no `#[from]`. The impl one generates is invisible at
/// the call site: a `?` on a fetch, written by somebody who never thought about integrity, would
/// flatten a pin that did not match into "download failed" and lose both digests. Every fetch in
/// this crate is unpinned today, so that arm is unreachable; a `From` that is wrong only once a
/// validator is added is a `From` that will be wrong quietly.
#[test]
fn a_verify_failure_converts_to_the_integrity_arm_and_the_rest_pass_through() {
    let verify = AddonError::from_fetch(
        apogee_fetch::FetchError::FileVerifyFailed {
            expected: "aa".to_owned(),
            got: "bb".to_owned(),
        },
        "a-verb",
        &path(),
    );
    assert!(
        matches!(&verify, AddonError::IntegrityMismatch { file, expected, got, .. }
            if *file == path() && expected == "aa" && got == "bb"),
        "{verify:?}"
    );

    let stalled = AddonError::from_fetch(
        apogee_fetch::FetchError::LengthMismatch {
            expected: 10,
            got: 9,
        },
        "a-verb",
        &path(),
    );
    assert!(matches!(stalled, AddonError::Download(_)), "{stalled:?}");
}
