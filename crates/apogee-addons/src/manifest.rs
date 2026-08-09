//! The signed component manifest: which companions and prefix verbs exist, as data.
//!
//! A JSON body whose Ed25519 signature is verified against compiled-in keys **before** any `sha256`
//! pin inside it is trusted. [`ComponentManifest::from_json_bytes`] is a pure, total parser over
//! untrusted input and carries no authenticity guarantee on its own. [`VerifiedManifest`] is the
//! shape that has been through the signature check, and the only one the apply path accepts.
//!
//! Everything the launcher sets up is a row, so adding a prefix-setup verb, correcting where a
//! verb's files land, or repointing an injectable's distribution is an edit to this file rather than
//! a release. A key the schema no longer defines is ignored rather than refused, which is what lets
//! one manifest serve an older build while a newer one stops reading a list it has retired.
//!
//! Two lists, because two kinds of bytes. A verb's [`VerbOp::Files`] pins what it places by
//! `sha256`, since the launcher names the archive it fetches. An [`InjectableEntry`] carries a
//! distribution endpoint instead, for a component whose own versioned, integrity-checked
//! distribution is what authenticates its bytes and whose current version this manifest is in no
//! position to pin.
//!
//! # Examples
//!
//! ```
//! # fn main() -> Result<(), apogee_addons::ManifestError> {
//! use apogee_addons::ComponentManifest;
//!
//! let json = br#"{
//!     "version": 1,
//!     "verbs": [
//!         { "name": "renderer", "reason": "the game needs a d3d runtime", "ops": [] }
//!     ]
//! }"#;
//!
//! let manifest = ComponentManifest::from_json_bytes(json)?;
//! assert!(manifest.verb("renderer").is_some());
//! # Ok(())
//! # }
//! ```

use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use apogee_runtime::{ArchiveFormat, ArchiveLayout, RegistryDelete, RegistryEdit, RegistryValue};

use crate::SupportTier;

/// The manifest schema version this build understands.
pub const COMPONENT_MANIFEST_VERSION: u32 = 1;

/// The public keys a component manifest may be authenticated against, the one it is signed with
/// today first.
///
/// Its own keys, not the runner catalog's: the two are published on different cadences by different
/// steps, and one compromised signer should not authenticate both. The matching private seeds are
/// held offline.
///
/// **A list, because a single constant cannot be rotated without an outage.** With one key,
/// replacing it means both re-signing the hosted file and shipping a build that trusts the new key,
/// and one of those has to happen first: re-sign first and every client in the field rejects the
/// catalog until it updates, ship first and every updated client rejects it until the re-sign. A
/// list removes the ordering. The new key is added here and released, the file is re-signed once
/// that build is in the field, and the retired key is dropped in a later release.
// It widens nothing. Every entry was compiled into this binary by the same build, so anyone who can
// append one can already replace the first, and a retired key is dropped rather than kept forever:
// the window is for finishing a rotation, not for keeping an old signer trusted.
pub const COMPONENT_PUBLIC_KEYS: &[[u8; 32]] = &[[
    0x6d, 0x35, 0x68, 0x49, 0x3e, 0x56, 0x73, 0xb1, 0xa3, 0x10, 0xfa, 0xe7, 0x20, 0x1b, 0xec, 0xd2,
    0x21, 0xd6, 0x70, 0xb9, 0x28, 0x6a, 0xa9, 0xfd, 0x3f, 0xc7, 0x6c, 0xdf, 0xc7, 0xb9, 0x94, 0x00,
]];

// A build with no key admits nothing, and would say so as a signature that did not verify, at a
// launch, on a user's machine. It is a typo, so it is caught here instead.
const _: () = assert!(
    !COMPONENT_PUBLIC_KEYS.is_empty(),
    "a build with no trusted key can admit no catalog at all"
);

/// Which of the trusted keys admitted a manifest.
///
/// The answer stops being uninteresting the moment [`COMPONENT_PUBLIC_KEYS`] holds more than one. A
/// manifest that only ever verifies against a retired key is a rotation whose re-sign never
/// happened, and the release that drops that key from the list is where it becomes an outage.
///
/// # Examples
///
/// ```
/// use apogee_addons::manifest::TrustedKey;
///
/// assert!(TrustedKey::Current.is_current());
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TrustedKey {
    /// The key the catalog is signed with today.
    Current,
    /// A key still inside its overlap window. Whatever served this manifest has not been re-signed
    /// since the rotation started.
    #[non_exhaustive]
    Retired {
        /// Its index in [`COMPONENT_PUBLIC_KEYS`], which is what locates it in a release.
        position: usize,
    },
}

impl TrustedKey {
    fn at(position: usize) -> Self {
        if position == 0 {
            Self::Current
        } else {
            Self::Retired { position }
        }
    }

    /// Whether the signature came from the key in use today.
    #[must_use]
    pub fn is_current(&self) -> bool {
        matches!(self, Self::Current)
    }
}

/// The keys compiled into this build.
///
/// One place, so every path that admits a manifest against a shipping key goes through the same
/// constant and no field anywhere holds a key that could have been substituted.
pub(crate) fn default_keys() -> &'static [[u8; 32]] {
    COMPONENT_PUBLIC_KEYS
}

/// Decompress raw key bytes into usable ones, preserving order.
///
/// Takes any list rather than reading [`COMPONENT_PUBLIC_KEYS`], so the failure and the position it
/// names are testable without a build whose own constant is broken.
///
/// # Errors
/// [`ManifestError::TrustedKeyUnusable`] if an entry is not a point on the curve.
fn trusted_keys(raw: &[[u8; 32]]) -> Result<Vec<VerifyingKey>, ManifestError> {
    raw.iter()
        .enumerate()
        .map(|(position, bytes)| {
            VerifyingKey::from_bytes(bytes)
                .map_err(|_| ManifestError::TrustedKeyUnusable { position })
        })
        .collect()
}

/// Components a name may nest, and bytes one component may hold. A real destination is two or three
/// deep; these exist only so a hostile row cannot describe a path no filesystem would take.
const MAX_PATH_DEPTH: usize = 32;
const MAX_NAME_BYTES: usize = 255;

/// Why a component manifest was rejected.
///
/// Its own taxonomy, like the runner catalog's, so the pure parser stays total and cross-platform.
/// [`crate::AddonError`] wraps it.
///
/// # Examples
///
/// ```
/// use apogee_addons::{ComponentManifest, ManifestError};
///
/// let result = ComponentManifest::from_json_bytes(br#"{"version": 2}"#);
/// assert!(matches!(result, Err(ManifestError::UnsupportedVersion { found: 2, .. })));
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ManifestError {
    /// The body is not JSON, or it is JSON the schema does not admit.
    #[error("manifest is not valid JSON or violates the schema")]
    Malformed(#[source] serde_json::Error),
    /// The signature is not 64 bytes, or it verifies against none of the trusted keys.
    #[error("manifest signature did not verify against any trusted key")]
    BadSignature,
    /// A key compiled into this build is not a point on the curve, so it can admit nothing.
    ///
    /// A build problem, and the one failure on this path the hosted file cannot be the cause of.
    /// Reporting it as a bad signature would send whoever reads it to check the one thing that is
    /// not wrong.
    #[error("the trusted key at position {position} in this build is not a usable ed25519 key")]
    #[non_exhaustive]
    TrustedKeyUnusable {
        /// Its index in the key list, which is the only part of the message that locates the typo.
        position: usize,
    },
    /// A schema version this build does not implement.
    #[error("unsupported manifest version {found} (expected {expected})")]
    #[non_exhaustive]
    UnsupportedVersion {
        /// The version the body declares.
        found: u32,
        /// [`COMPONENT_MANIFEST_VERSION`].
        expected: u32,
    },
    /// A field whose value is outside the set this build knows: a kind, a tier, an archive format.
    #[error("{component}: unknown {field} {value:?}")]
    #[non_exhaustive]
    UnknownValue {
        /// The row it appears in.
        component: String,
        /// The field name.
        field: &'static str,
        /// The value as published.
        value: String,
    },
    /// A `sha256` pin that is not 64 hex digits.
    #[error("{component}: sha256 pin is not 32 hex bytes")]
    #[non_exhaustive]
    BadPin {
        /// The row it appears in.
        component: String,
    },
    /// A URL that does not parse as an absolute one.
    #[error("{component}: {url:?} is not a valid absolute url")]
    #[non_exhaustive]
    BadUrl {
        /// The row it appears in.
        component: String,
        /// The URL as published.
        url: String,
    },
    /// A destination path a component may not write to.
    #[error("{component}: path {path:?} is not one a component may write: {reason}")]
    #[non_exhaustive]
    BadPath {
        /// The row it appears in.
        component: String,
        /// The path as published.
        path: String,
        /// Which rule it broke.
        reason: &'static str,
    },
    /// A name that would not survive being part of a filename.
    ///
    /// It ends up in one, since a verb's scratch file is named after it, so it is held to the same
    /// standard as the destinations.
    #[error("{field} {value:?} is not usable: {reason}")]
    #[non_exhaustive]
    BadIdentifier {
        /// Which name it is: a component name, a verb name.
        field: &'static str,
        /// The name as published.
        value: String,
        /// Which rule it broke.
        reason: &'static str,
    },
    /// A registry edit this launcher will not perform.
    #[error("{component}: registry edit {key:?} is not one this launcher will write: {reason}")]
    #[non_exhaustive]
    BadRegistryEdit {
        /// The row it appears in.
        component: String,
        /// The key, and the value name where the edit names one.
        key: String,
        /// Which rule it broke.
        reason: &'static str,
    },
    /// Two rows offering the same name, in either list.
    ///
    /// A component name is what the prefix records, so a duplicate would make "is it applied?"
    /// unanswerable.
    #[error("two components are both named {name:?}")]
    #[non_exhaustive]
    DuplicateName {
        /// The name both rows claim.
        name: String,
    },
}

/// The injection-shaped companions: the ones that reach the game by wrapping its launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InjectableKind {
    /// Dalamud, the plugin loader.
    Dalamud,
}

/// A relative path a verb's files may be written to, already confined.
///
/// Rooted at the prefix's `C:`. Validated when the manifest is parsed, so nothing downstream
/// re-derives a path from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComponentPath(PathBuf);

impl ComponentPath {
    /// The path, relative to whatever root its component installs under.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }

    /// Validate one manifest-supplied relative path.
    ///
    /// A backslash is folded to `/` first. On Linux it is an ordinary character, so a Windows-shaped
    /// path in a manifest would otherwise arrive as a single filename, sail past every check below,
    /// and land somewhere nobody intended.
    ///
    /// # Errors
    /// [`ManifestError::BadPath`] if it is empty, absolute, climbs out of its root, carries a drive
    /// letter, a null byte or a control character, nests deeper than [`MAX_PATH_DEPTH`], or has a
    /// component longer than [`MAX_NAME_BYTES`].
    fn parse(raw: &str, component: &str) -> Result<Self, ManifestError> {
        let bad = |reason: &'static str| ManifestError::BadPath {
            component: component.to_owned(),
            path: raw.to_owned(),
            reason,
        };
        if raw.is_empty() {
            return Err(bad("it is empty"));
        }
        if raw.contains('\0') {
            return Err(bad("it carries a null byte"));
        }
        let folded = raw.replace('\\', "/");
        let mut out = PathBuf::new();
        for part in Path::new(&folded).components() {
            match part {
                Component::CurDir => {}
                Component::RootDir => return Err(bad("it is absolute")),
                Component::ParentDir => return Err(bad("it climbs out of its root")),
                // A drive letter is a `Normal` component off Windows, so it needs naming explicitly.
                Component::Prefix(_) => return Err(bad("it carries a drive letter")),
                Component::Normal(name) => {
                    let name = name.to_string_lossy();
                    if name.len() > MAX_NAME_BYTES {
                        return Err(bad("one of its components is too long"));
                    }
                    if name.len() == 2
                        && name.ends_with(':')
                        && name.starts_with(|c: char| c.is_ascii_alphabetic())
                    {
                        return Err(bad("it carries a drive letter"));
                    }
                    if name.chars().any(char::is_control) {
                        return Err(bad("it carries a control character"));
                    }
                    if out.components().count() == MAX_PATH_DEPTH {
                        return Err(bad("it nests deeper than a component tree does"));
                    }
                    out.push(name.as_ref());
                }
            }
        }
        if out.as_os_str().is_empty() {
            return Err(bad("it resolves to nothing"));
        }
        Ok(Self(out))
    }
}

/// A pinned artifact: where to get it, what its bytes must hash to, and how to lay it down.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Artifact {
    /// Where to fetch it.
    pub url: Url,
    /// What the fetched bytes must hash to.
    pub sha256: [u8; 32],
    /// How to unpack it, and which prefix of the archive to strip.
    pub archive: ArchiveLayout,
}

/// One injectable companion. Its bytes come from its own distribution, so there is no pin here.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct InjectableEntry {
    /// What it is recorded and reported under.
    pub name: String,
    /// Which built-in pipeline installs it.
    pub kind: InjectableKind,
    /// The upstream endpoint its versioned, integrity-checked distribution is served from. Reached
    /// only when the component is enabled.
    pub distribution: Url,
    /// How well it is supported here.
    pub tier: SupportTier,
    /// Things the user should know before enabling it, beyond what the tier says.
    pub caveats: Vec<String>,
}

/// One step of a verb.
///
/// Every kind is idempotent by construction: the write overwrites, the removal treats "it was not
/// there" as success, and the placement overwrites. That is the selection criterion rather than a
/// happy accident, because the only thing between a re-apply and a re-run is the prefix's own
/// record.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerbOp {
    /// Write one registry value.
    Registry(RegistryEdit),
    /// Remove a registry value, or a key and its subtree.
    ///
    /// The one registry operation that can destroy something the launcher did not create, so a row
    /// naming a key too shallow to be ours is refused at parse time. Naming the value makes the same
    /// key fine: it then removes exactly what it names.
    RegistryDelete(RegistryDelete),
    /// Place a pinned artifact's files under the prefix's `C:`.
    Files {
        /// What to fetch, and what its bytes must be.
        artifact: Artifact,
        /// Where its files land, relative to the prefix's `C:`.
        into: ComponentPath,
    },
}

/// A curated prefix-setup step, described entirely by the manifest so it is auditable and ships as
/// data.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Verb {
    /// What the prefix records it under.
    pub name: String,
    /// Why it exists, shown when it is applied. A verb with no reason is a verb nobody can review.
    pub reason: String,
    /// Paths under the prefix's `C:` that must exist once this verb has been applied.
    ///
    /// What makes a verb's effect checkable rather than merely recorded, and it does three jobs at
    /// once. A verb whose ops succeeded without producing these is a failure, so a half-finished
    /// install is not remembered as done. A verb the prefix records but whose paths have since gone
    /// is applied again, which is how something a runner upgrade removed from under us comes back.
    /// And it is the evidence a health check wants.
    ///
    /// Empty is allowed, and is what a verb whose whole effect is a registry value states: there is
    /// no file to look for. Such a verb is not thereby unchecked. Its ops already declare the key,
    /// name and value, so the setup layer derives the question from the op and reads the prefix's
    /// own registry files. This field is for the effects that cannot be derived that way, such as
    /// what a placement put somewhere, which its op names only the destination directory of.
    pub verify: Vec<ComponentPath>,
    /// What to do, in order.
    pub ops: Vec<VerbOp>,
}

/// The rows a manifest carries.
///
/// No schema version field: a parsed manifest can only ever be [`COMPONENT_MANIFEST_VERSION`],
/// since anything else is refused before this is built, and a field holding one reachable value
/// would have made `Default` produce a version the parser rejects.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ComponentManifest {
    /// The companions that reach the game by wrapping its launch.
    pub injectables: Vec<InjectableEntry>,
    /// The prefix-setup steps the launch path applies on its own.
    pub verbs: Vec<Verb>,
}

impl ComponentManifest {
    /// Parse a manifest from untrusted JSON.
    ///
    /// Pure and total: any byte sequence yields a manifest or a typed [`ManifestError`], never a
    /// panic. This is the fuzz entry point, and it carries **no** authenticity guarantee. A caller
    /// that is going to act on the rows wants [`VerifiedManifest`] instead.
    ///
    /// # Errors
    /// Any [`ManifestError`] except [`ManifestError::BadSignature`].
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), apogee_addons::ManifestError> {
    /// use apogee_addons::ComponentManifest;
    ///
    /// let manifest = ComponentManifest::from_json_bytes(br#"{"version": 1}"#)?;
    /// assert!(manifest.verbs.is_empty());
    /// assert!(manifest.injectables.is_empty());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let raw: RawManifest = serde_json::from_slice(bytes).map_err(ManifestError::Malformed)?;
        Self::try_from(raw)
    }

    /// Verify `signature` over the exact `manifest_json` bytes against `keys`, in order, then parse.
    ///
    /// The signature is checked **first**, so no `sha256` pin is trusted before authenticity is
    /// established. Returns which key admitted it.
    ///
    /// # Errors
    /// [`ManifestError::BadSignature`] if the signature is not exactly 64 bytes or verifies against
    /// none of `keys`, then anything [`Self::from_json_bytes`] raises.
    pub(crate) fn parse_and_verify(
        manifest_json: &[u8],
        signature: &[u8],
        keys: &[VerifyingKey],
    ) -> Result<(Self, TrustedKey), ManifestError> {
        let sig = Signature::from_slice(signature).map_err(|_| ManifestError::BadSignature)?;
        let position = keys
            .iter()
            .position(|key| key.verify_strict(manifest_json, &sig).is_ok())
            .ok_or(ManifestError::BadSignature)?;
        Ok((
            Self::from_json_bytes(manifest_json)?,
            TrustedKey::at(position),
        ))
    }

    /// [`Self::parse_and_verify`] against the keys compiled into this build.
    ///
    /// # Errors
    /// [`ManifestError::TrustedKeyUnusable`] if this build's own key list is malformed, then
    /// anything [`Self::parse_and_verify`] raises.
    pub(crate) fn verify_trusted(
        manifest_json: &[u8],
        signature: &[u8],
    ) -> Result<(Self, TrustedKey), ManifestError> {
        Self::parse_and_verify(manifest_json, signature, &trusted_keys(default_keys())?)
    }

    /// The verb row named `name`.
    #[must_use]
    pub fn verb(&self, name: &str) -> Option<&Verb> {
        self.verbs.iter().find(|v| v.name == name)
    }

    /// The injectable row of `kind`.
    ///
    /// By kind rather than by name, because the kind is what selects which built-in pipeline runs
    /// and a name is a label on it. Two lookup keys for one list would let a caller find a row the
    /// launch path would not.
    #[must_use]
    pub fn injectable(&self, kind: InjectableKind) -> Option<&InjectableEntry> {
        self.injectables.iter().find(|i| i.kind == kind)
    }

    /// Every name the manifest offers, sorted. What the duplicate check reads.
    fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .injectables
            .iter()
            .map(|i| i.name.as_str())
            .chain(self.verbs.iter().map(|v| v.name.as_str()))
            .collect();
        names.sort_unstable();
        names
    }
}

// ---- raw deserialization + validation --------------------------------------------------------

#[derive(Deserialize)]
struct RawManifest {
    version: u32,
    #[serde(default)]
    injectables: Vec<RawInjectable>,
    #[serde(default)]
    verbs: Vec<RawVerb>,
}

#[derive(Deserialize)]
struct RawInjectable {
    name: String,
    kind: String,
    distribution: String,
    tier: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    caveats: Vec<String>,
}

#[derive(Deserialize)]
struct RawArchive {
    format: String,
    #[serde(default)]
    strip_prefix: Option<String>,
}

#[derive(Deserialize)]
struct RawVerb {
    name: String,
    reason: String,
    #[serde(default)]
    verify: Vec<String>,
    #[serde(default)]
    ops: Vec<RawOp>,
}

/// A verb op. Externally tagged, so exactly one kind is named per entry and an entry naming none or
/// two is a parse error rather than a silently-chosen default.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawOp {
    Registry(RawRegistry),
    RegistryDelete(RawRegistryDelete),
    Files(RawFiles),
}

#[derive(Deserialize)]
struct RawRegistryDelete {
    key: String,
    /// Absent removes the key and its subtree; present removes just that value.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Deserialize)]
struct RawRegistry {
    key: String,
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Deserialize)]
struct RawFiles {
    url: String,
    sha256: String,
    archive: RawArchive,
    into: String,
}

impl TryFrom<RawManifest> for ComponentManifest {
    type Error = ManifestError;

    fn try_from(raw: RawManifest) -> Result<Self, ManifestError> {
        if raw.version != COMPONENT_MANIFEST_VERSION {
            return Err(ManifestError::UnsupportedVersion {
                found: raw.version,
                expected: COMPONENT_MANIFEST_VERSION,
            });
        }
        let injectables = raw
            .injectables
            .into_iter()
            .map(build_injectable)
            .collect::<Result<Vec<_>, _>>()?;
        let verbs = raw
            .verbs
            .into_iter()
            .map(build_verb)
            .collect::<Result<Vec<_>, _>>()?;

        let manifest = Self { injectables, verbs };
        manifest.check_names()?;
        Ok(manifest)
    }
}

impl ComponentManifest {
    /// Every name is unique across both lists.
    ///
    /// A cross-row property, so it is checked once the rows are built rather than while building
    /// one.
    ///
    /// # Errors
    /// [`ManifestError::DuplicateName`] naming the first repeat.
    fn check_names(&self) -> Result<(), ManifestError> {
        let mut seen: Vec<&str> = Vec::new();
        for name in self.names() {
            if seen.last() == Some(&name) {
                return Err(ManifestError::DuplicateName {
                    name: name.to_owned(),
                });
            }
            seen.push(name);
        }
        Ok(())
    }
}

/// Refuse a name that would not survive being part of a filename.
///
/// A name becomes one: a verb's scratch file is named after it. Everything else derived from
/// manifest data is confined by [`ComponentPath`], so leaving this unchecked would be the one place
/// a row could name a path component the rest of the parser exists to prevent. The manifest is
/// signed, so this is depth rather than a boundary, but a signed row can still be a mistaken one.
///
/// # Errors
/// [`ManifestError::BadIdentifier`] if it is empty, is `.` or `..`, carries a path separator, a
/// control character or a null byte, or is longer than [`MAX_NAME_BYTES`].
fn check_identifier(field: &'static str, value: &str) -> Result<(), ManifestError> {
    let bad = |reason: &'static str| ManifestError::BadIdentifier {
        field,
        value: value.to_owned(),
        reason,
    };
    if value.is_empty() {
        return Err(bad("it is empty"));
    }
    if value == "." || value == ".." {
        return Err(bad("it names a directory rather than a component"));
    }
    if value.contains('/') || value.contains('\\') {
        return Err(bad("it carries a path separator"));
    }
    if value.chars().any(char::is_control) || value.contains('\0') {
        return Err(bad("it carries a control character"));
    }
    if value.len() > MAX_NAME_BYTES {
        return Err(bad("it is too long to be part of a filename"));
    }
    Ok(())
}

fn build_injectable(raw: RawInjectable) -> Result<InjectableEntry, ManifestError> {
    check_identifier("component name", &raw.name)?;
    let kind = match raw.kind.as_str() {
        "dalamud" => InjectableKind::Dalamud,
        _ => return Err(unknown(&raw.name, "injectable kind", raw.kind)),
    };
    let tier = match (raw.tier.as_str(), raw.note) {
        ("first_class", None) => SupportTier::FirstClass,
        // Refused rather than dropped. A first-class tier has nothing to warn about, so a note on one
        // would never be shown, and a row that carries one is a row whose author expected it to be.
        ("first_class", Some(_)) => {
            return Err(unknown(&raw.name, "tier", "first_class with a note"));
        }
        ("best_effort", Some(note)) => SupportTier::BestEffort { note },
        // A best-effort tier with no note would present as "not first class" with no statement of what
        // that costs, which is the opposite of the point of tiering it.
        ("best_effort", None) => {
            return Err(unknown(&raw.name, "tier", "best_effort without a note"));
        }
        (other, _) => return Err(unknown(&raw.name, "tier", other)),
    };
    Ok(InjectableEntry {
        distribution: parse_url(&raw.name, &raw.distribution)?,
        name: raw.name,
        kind,
        tier,
        caveats: raw.caveats,
    })
}

fn build_verb(raw: RawVerb) -> Result<Verb, ManifestError> {
    check_identifier("verb name", &raw.name)?;
    let ops = raw
        .ops
        .into_iter()
        .map(|op| build_op(&raw.name, op))
        .collect::<Result<Vec<_>, _>>()?;
    let verify = raw
        .verify
        .iter()
        .map(|path| ComponentPath::parse(path, &raw.name))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Verb {
        name: raw.name,
        reason: raw.reason,
        verify,
        ops,
    })
}

fn build_op(component: &str, raw: RawOp) -> Result<VerbOp, ManifestError> {
    match raw {
        RawOp::Registry(entry) => {
            let value = match (entry.value_type.as_str(), entry.value) {
                ("string", Some(value)) => RegistryValue::String(value),
                ("expand_string", Some(value)) => RegistryValue::ExpandString(value),
                ("dword", Some(value)) => match value.parse::<u32>() {
                    Ok(number) => RegistryValue::Dword(number),
                    Err(_) => return Err(unknown(component, "dword value", value)),
                },
                // Spelled as a type rather than as an empty string, so a row that means "load neither
                // library" says so and a row that lost its value is still refused.
                ("disabled", None) => RegistryValue::Disabled,
                ("disabled", Some(value)) => {
                    return Err(unknown(component, "disabled value", value));
                }
                (other, None) => {
                    return Err(unknown(
                        component,
                        "registry value",
                        format!("{other} without a value"),
                    ));
                }
                (other, Some(_)) => return Err(unknown(component, "registry type", other)),
            };
            let edit = RegistryEdit {
                key: entry.key,
                name: entry.name,
                value,
            };
            // Checked here so a typo names the row it is in, rather than surfacing later as a non-zero
            // exit from `reg` at the moment of the write.
            edit.validate()
                .map_err(|reason| ManifestError::BadRegistryEdit {
                    component: component.to_owned(),
                    key: format!("{}\\{}", edit.key, edit.name),
                    reason,
                })?;
            Ok(VerbOp::Registry(edit))
        }
        RawOp::RegistryDelete(entry) => {
            let delete = RegistryDelete {
                key: entry.key,
                name: entry.name,
            };
            delete
                .validate()
                .map_err(|reason| ManifestError::BadRegistryEdit {
                    component: component.to_owned(),
                    key: delete.key.clone(),
                    reason,
                })?;
            Ok(VerbOp::RegistryDelete(delete))
        }
        RawOp::Files(files) => Ok(VerbOp::Files {
            artifact: build_artifact(component, &files.url, &files.sha256, files.archive)?,
            into: ComponentPath::parse(&files.into, component)?,
        }),
    }
}

fn build_artifact(
    component: &str,
    url: &str,
    sha256: &str,
    archive: RawArchive,
) -> Result<Artifact, ManifestError> {
    Ok(Artifact {
        url: parse_url(component, url)?,
        sha256: decode_sha256_hex(sha256).ok_or_else(|| ManifestError::BadPin {
            component: component.to_owned(),
        })?,
        archive: ArchiveLayout {
            format: parse_format(component, &archive.format)?,
            strip_prefix: archive.strip_prefix,
        },
    })
}

/// Map an archive-format string to a layout format.
///
/// No default: a component archive is as likely to be a zip as a tarball, so the row states which,
/// and a row that forgets is a parse error rather than a guess that fails at extraction.
fn parse_format(component: &str, format: &str) -> Result<ArchiveFormat, ManifestError> {
    match format {
        "zip" => Ok(ArchiveFormat::Zip),
        "tar.gz" => Ok(ArchiveFormat::TarGz),
        "tar.xz" => Ok(ArchiveFormat::TarXz),
        "tar.zst" => Ok(ArchiveFormat::TarZst),
        other => Err(unknown(component, "archive format", other)),
    }
}

fn parse_url(component: &str, raw: &str) -> Result<Url, ManifestError> {
    Url::parse(raw).map_err(|_| ManifestError::BadUrl {
        component: component.to_owned(),
        url: raw.to_owned(),
    })
}

fn unknown(component: &str, field: &'static str, value: impl Into<String>) -> ManifestError {
    ManifestError::UnknownValue {
        component: component.to_owned(),
        field,
        value: value.into(),
    }
}

/// Decode exactly 64 hex digits into 32 bytes; any other length or a non-hex digit is `None`.
fn decode_sha256_hex(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = hex_val(bytes[2 * i])?;
        let lo = hex_val(bytes[2 * i + 1])?;
        *slot = (hi << 4) | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use apogee_test_support::catalog_sign::{sign_manifest, test_verifying_key};

    const GOOD_PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// A manifest with the injectable the launcher drives and two verbs, one of them placing a pinned
    /// tree, so the pointer row and the pinned row both have a subject.
    fn manifest() -> String {
        format!(
            r#"{{
              "version": 1,
              "injectables": [
                {{ "name": "Dalamud", "kind": "dalamud",
                   "distribution": "https://kamori.goats.dev/Dalamud/Release/VersionInfo",
                   "tier": "best_effort", "note": "Best with the wine-xiv runner.",
                   "caveats": ["Third-party code is loaded into the game client."] }}
              ],
              "verbs": [
                {{ "name": "no-desktop-integration", "reason": "Keeps installs out of the host menu.",
                   "ops": [
                     {{ "registry": {{ "key": "HKCU\\Software\\Wine\\DllOverrides",
                                       "name": "winemenubuilder.exe", "type": "disabled" }} }}
                   ] }},
                {{ "name": "placed-files", "reason": "It lays a pinned tree under the prefix.",
                   "verify": ["apogee/placed/thing.dll"],
                   "ops": [
                     {{ "files": {{ "url": "https://example.invalid/files.zip", "sha256": "{GOOD_PIN}",
                                    "archive": {{ "format": "zip", "strip_prefix": "top" }},
                                    "into": "apogee/placed" }} }}
                   ] }}
              ]
            }}"#
        )
    }

    fn parse(json: &str) -> Result<ComponentManifest, ManifestError> {
        ComponentManifest::from_json_bytes(json.as_bytes())
    }

    /// The pinned artifact of the fixture's file-placing verb.
    fn placed_artifact(parsed: &ComponentManifest) -> &Artifact {
        match parsed
            .verb("placed-files")
            .expect("row")
            .ops
            .first()
            .expect("one op")
        {
            VerbOp::Files { artifact, .. } => artifact,
            other => panic!("expected a files op, got {other:?}"),
        }
    }

    /// Every field of every row survives the round trip, against a real signature.
    #[test]
    fn a_signed_manifest_parses_every_row() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        let (parsed, trusted) =
            ComponentManifest::parse_and_verify(json.as_bytes(), &sig, &[test_verifying_key()])
                .expect("valid signature");
        assert_eq!(trusted, TrustedKey::Current);

        let dalamud = parsed
            .injectable(InjectableKind::Dalamud)
            .expect("Dalamud row");
        assert_eq!(dalamud.kind, InjectableKind::Dalamud);
        assert_eq!(dalamud.distribution.host_str(), Some("kamori.goats.dev"));
        assert!(matches!(dalamud.tier, SupportTier::BestEffort { .. }));
        assert_eq!(dalamud.caveats.len(), 1);

        let verb = parsed.verb("no-desktop-integration").expect("verb row");
        assert!(!verb.reason.is_empty());
        match verb.ops.as_slice() {
            [VerbOp::Registry(edit)] => {
                assert_eq!(edit.name, "winemenubuilder.exe");
                assert_eq!(edit.value, RegistryValue::Disabled);
            }
            other => panic!("expected one registry op, got {other:?}"),
        }

        let placed = parsed.verb("placed-files").expect("verb row");
        assert_eq!(
            placed.verify.first().map(ComponentPath::as_path),
            Some(Path::new("apogee/placed/thing.dll"))
        );
        let artifact = placed_artifact(&parsed);
        assert_eq!(artifact.archive.format, ArchiveFormat::Zip);
        assert_eq!(artifact.archive.strip_prefix.as_deref(), Some("top"));

        assert_eq!(
            parsed.names(),
            ["Dalamud", "no-desktop-integration", "placed-files"]
        );
    }

    /// A body edited after signing verifies against nothing.
    #[test]
    fn signature_rejects_a_tampered_manifest() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        let mut tampered = json.into_bytes();
        // Flip a byte in the body; the detached signature no longer matches.
        tampered[40] ^= 0x01;
        assert!(matches!(
            ComponentManifest::parse_and_verify(&tampered, &sig, &[test_verifying_key()]),
            Err(ManifestError::BadSignature)
        ));
    }

    /// A valid signature by a key this build does not trust is still a refusal.
    #[test]
    fn signature_rejects_the_wrong_key() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        // The compiled-in key is a different key than the test signer.
        assert!(matches!(
            ComponentManifest::verify_trusted(json.as_bytes(), &sig),
            Err(ManifestError::BadSignature)
        ));
    }

    /// A signature that is not exactly 64 bytes is refused before any key is tried.
    #[test]
    fn signature_rejects_absent_or_short() {
        let json = manifest();
        for sig in [b"".as_slice(), b"too-short".as_slice()] {
            assert!(matches!(
                ComponentManifest::parse_and_verify(json.as_bytes(), sig, &[test_verifying_key()]),
                Err(ManifestError::BadSignature)
            ));
        }
    }

    /// Both halves of the pin decoder: the length, and the digits. A pin of the right length made of
    /// wrong characters is the one that would otherwise decode to a silently wrong 32 bytes, and it is
    /// also the likelier mistake: a typo'd digit, or a digest in the wrong encoding.
    #[test]
    fn a_bad_pin_is_refused() {
        for bad in [
            "not-hex".to_owned(),
            "g".repeat(64),
            format!("{}Z", &GOOD_PIN[1..]),
            GOOD_PIN[1..].to_owned(),
            format!("{GOOD_PIN}0"),
            String::new(),
        ] {
            let json = manifest().replace(GOOD_PIN, &bad);
            assert!(
                matches!(parse(&json), Err(ManifestError::BadPin { .. })),
                "{bad:?} must be refused"
            );
        }
    }

    /// A pin is compared as bytes, so its hex has to decode the same either way it is written.
    #[test]
    fn a_pin_decodes_the_same_in_either_case() {
        let lower = "0123456789abcdef".repeat(4);
        let upper = lower.to_uppercase();
        let of = |pin: &str| {
            let json = manifest().replace(GOOD_PIN, pin);
            placed_artifact(&parse(&json).expect("parse")).sha256
        };
        assert_eq!(of(&lower), of(&upper));
        assert_eq!(of(&lower)[0], 0x01);
    }

    /// A value outside the set this build knows is refused by name rather than defaulted.
    #[test]
    fn an_unknown_kind_format_or_registry_type_is_a_typed_error() {
        for (from, to) in [
            ("\"kind\": \"dalamud\"", "\"kind\": \"telepathy\""),
            ("\"format\": \"zip\"", "\"format\": \"tar.brotli\""),
            ("\"type\": \"disabled\"", "\"type\": \"reg_binary\""),
        ] {
            let json = manifest().replace(from, to);
            assert!(
                matches!(parse(&json), Err(ManifestError::UnknownValue { .. })),
                "{to} must be refused"
            );
        }
    }

    /// A name is what the prefix records, so two rows sharing one would make "is it applied?"
    /// unanswerable.
    #[test]
    fn two_rows_with_one_name_are_refused_across_every_list() {
        let json = manifest().replace("\"name\": \"placed-files\"", "\"name\": \"Dalamud\"");
        assert!(matches!(
            parse(&json),
            Err(ManifestError::DuplicateName { .. })
        ));
        // Also within one list, not only across two.
        let json = manifest().replace(
            "\"name\": \"placed-files\"",
            "\"name\": \"no-desktop-integration\"",
        );
        assert!(matches!(
            parse(&json),
            Err(ManifestError::DuplicateName { .. })
        ));
    }

    /// A name becomes part of a filename: a verb's scratch file is named after it. Leaving it unchecked
    /// would be the one place a row could name a path component the rest of this parser exists to
    /// refuse.
    #[test]
    fn a_name_that_would_not_survive_a_filename_is_refused() {
        for to in [
            "\"name\": \"../../etc/x\"",
            "\"name\": \"..\"",
            "\"name\": \"a/b\"",
            r#""name": "a\\b""#,
            "\"name\": \"\"",
        ] {
            let json = manifest().replacen("\"name\": \"Dalamud\"", to, 1);
            assert!(
                matches!(parse(&json), Err(ManifestError::BadIdentifier { .. })),
                "{to} must be refused as an injectable name"
            );
            let json = manifest().replacen("\"name\": \"placed-files\"", to, 1);
            assert!(
                matches!(parse(&json), Err(ManifestError::BadIdentifier { .. })),
                "{to} must be refused as a verb name"
            );
        }
    }

    /// The destination is where a verb's bytes land, so it is the one field a hostile row would most
    /// want to control.
    #[test]
    fn a_destination_that_escapes_its_root_is_refused() {
        for path in [
            "/etc",
            "../../etc",
            "apogee/../../etc",
            "C:/windows",
            "c:",
            "",
            ".",
        ] {
            let json = manifest().replace(
                "\"into\": \"apogee/placed\"",
                &format!("\"into\": {path:?}"),
            );
            assert!(
                matches!(parse(&json), Err(ManifestError::BadPath { .. })),
                "{path:?} must be refused"
            );
        }
    }

    /// A backslash is an ordinary character on Linux, so a Windows-shaped destination would arrive as
    /// one filename and pass every check while landing somewhere nobody meant.
    #[test]
    fn a_backslash_destination_is_folded_before_it_is_checked() {
        let json = manifest().replace(
            "\"into\": \"apogee/placed\"",
            r#""into": "apogee\\placed\\Plugins""#,
        );
        let parsed = parse(&json).expect("a windows-shaped path is still a path");
        match parsed.verb("placed-files").expect("row").ops.as_slice() {
            [VerbOp::Files { into, .. }] => {
                assert_eq!(into.as_path(), Path::new("apogee/placed/Plugins"));
            }
            other => panic!("expected one files op, got {other:?}"),
        }

        let json = manifest().replace(
            "\"into\": \"apogee/placed\"",
            r#""into": "apogee\\..\\..\\etc""#,
        );
        assert!(matches!(parse(&json), Err(ManifestError::BadPath { .. })));
    }

    /// A registry row is checked when the manifest is parsed, so the error names the row rather than
    /// arriving later as an opaque non-zero exit from `reg`.
    #[test]
    fn a_registry_op_that_is_not_writable_is_refused_at_parse_time() {
        let json = manifest().replace(
            "\"key\": \"HKCU\\\\Software\\\\Wine\\\\DllOverrides\"",
            "\"key\": \"Software\\\\Wine\"",
        );
        match parse(&json) {
            Err(ManifestError::BadRegistryEdit { component, .. }) => {
                assert_eq!(component, "no-desktop-integration");
            }
            other => panic!("expected BadRegistryEdit, got {other:?}"),
        }
    }

    /// An op entry naming no kind, or two, is a parse error rather than a silently-chosen default.
    #[test]
    fn an_op_must_name_exactly_one_kind() {
        let json = manifest().replace(
            r#"{ "registry": { "key": "HKCU\\Software\\Wine\\DllOverrides",
                                       "name": "winemenubuilder.exe", "type": "disabled" } }"#,
            r#"{ }"#,
        );
        assert!(matches!(parse(&json), Err(ManifestError::Malformed(_))));
    }

    /// A best-effort tier with no note presents as "not first class" with no statement of what that
    /// costs, which is the opposite of what tiering it is for.
    #[test]
    fn a_best_effort_injectable_must_say_what_it_costs() {
        let parsed = parse(&manifest()).expect("parse");
        let entry = parsed.injectable(InjectableKind::Dalamud).expect("row");
        assert!(matches!(entry.tier, SupportTier::BestEffort { .. }));

        let without = manifest().replace(r#", "note": "Best with the wine-xiv runner.""#, "");
        assert!(matches!(
            parse(&without),
            Err(ManifestError::UnknownValue { .. })
        ));
    }

    /// The symmetric refusal. A first-class tier has nothing to warn about, so its note would never be
    /// shown, and silently dropping one leaves the author of the row believing it was.
    #[test]
    fn a_first_class_injectable_may_not_carry_a_note_that_would_be_dropped() {
        let with_note = manifest().replace(r#""tier": "best_effort""#, r#""tier": "first_class""#);
        assert!(matches!(
            parse(&with_note),
            Err(ManifestError::UnknownValue { .. })
        ));

        let without = with_note.replace(r#", "note": "Best with the wine-xiv runner.""#, "");
        let parsed = parse(&without).expect("a first-class row with no note is fine");
        assert!(matches!(
            parsed
                .injectable(InjectableKind::Dalamud)
                .expect("row")
                .tier,
            SupportTier::FirstClass
        ));
    }

    /// A verb whose whole effect is a registry value has nothing on disk to look for, so it names
    /// nothing to verify. What checks it is its own op, which already says what it wrote.
    #[test]
    fn a_verb_whose_effect_is_a_registry_value_names_nothing_to_verify() {
        let parsed = parse(&manifest()).expect("parse");
        let verb = parsed.verb("no-desktop-integration").expect("row");
        assert!(verb.verify.is_empty());
    }

    /// A key removal is the one registry operation that can destroy something the launcher did not
    /// create, so a row naming a key too shallow to be ours is refused. Naming the value makes the same
    /// key fine: it then removes exactly what it names.
    #[test]
    fn a_key_removal_too_shallow_to_be_ours_is_refused() {
        let row = |key: &str, name: &str| {
            format!(
                r#"{{ "version": 1, "verbs": [ {{ "name": "v", "reason": "why",
                    "ops": [ {{ "registry_delete": {{ "key": "{key}"{name} }} }} ] }} ] }}"#
            )
        };
        let deep = row(
            r"HKLM\\Software\\Wow6432Node\\Microsoft\\NET Framework Setup\\NDP\\v4",
            "",
        );
        match parse(&deep)
            .expect("parse")
            .verb("v")
            .expect("row")
            .ops
            .as_slice()
        {
            [VerbOp::RegistryDelete(delete)] => assert!(delete.name.is_none()),
            other => panic!("expected one delete op, got {other:?}"),
        }

        for shallow in [r"HKLM\\Software", r"HKLM\\Software\\Microsoft", "HKLM"] {
            assert!(
                matches!(
                    parse(&row(shallow, "")),
                    Err(ManifestError::BadRegistryEdit { .. })
                ),
                "{shallow} must be refused as a subtree removal"
            );
        }
        assert!(parse(&row(r"HKCU\\Software\\Wine", r#", "name": "Version""#)).is_ok());
    }

    /// A schema version this build does not implement is refused before any row is read.
    #[test]
    fn an_unsupported_version_is_refused() {
        let json = manifest().replace("\"version\": 1", "\"version\": 999");
        assert!(matches!(
            parse(&json),
            Err(ManifestError::UnsupportedVersion {
                found: 999,
                expected: 1
            })
        ));
    }

    /// The parser is total over arbitrary bytes, which is what makes it a fuzz target.
    #[test]
    fn malformed_json_is_a_typed_error_not_a_panic() {
        for bytes in [
            b"".as_slice(),
            b"not json".as_slice(),
            b"{\"version\":".as_slice(),
            b"[]".as_slice(),
        ] {
            assert!(matches!(
                ComponentManifest::from_json_bytes(bytes),
                Err(ManifestError::Malformed(_))
            ));
        }
    }

    /// An empty manifest is well-formed: a build with nothing to offer is a valid state, and refusing
    /// it would make "no rows yet" indistinguishable from a broken manifest.
    #[test]
    fn a_manifest_with_no_rows_parses() {
        let parsed = parse(r#"{ "version": 1 }"#).expect("parse");
        assert!(parsed.names().is_empty());
    }

    /// A key the schema no longer defines is ignored rather than refused, which is what lets a manifest
    /// serve an older build while a newer one stops reading a list it has retired.
    #[test]
    fn a_list_this_build_no_longer_reads_is_ignored() {
        let json = r#"{ "version": 1, "tools": [ { "name": "gone" } ],
                        "verbs": [ { "name": "v", "reason": "why", "ops": [] } ] }"#;
        let parsed = parse(json).expect("parse");
        assert_eq!(parsed.names(), ["v"]);
    }

    /// Every key this build would accept has to be usable, or it can admit nothing and the build says
    /// so as a signature failure on a user's machine instead.
    #[test]
    fn every_compiled_in_key_parses() {
        trusted_keys(default_keys())
            .expect("every trusted key in this build is a usable ed25519 key");
    }

    /// Reported as a bad signature it would send whoever hits it to go and check the hosted file, which
    /// is the one thing that cannot be at fault. The position matters too: with a list, "which entry"
    /// is the only part of the message that locates the typo.
    #[test]
    fn a_key_that_is_not_a_key_is_a_build_problem_rather_than_a_bad_signature() {
        // Not a decompressable compressed Edwards point, so it can never verify anything.
        let mut unusable = [0u8; 32];
        unusable[0] = 0x02;

        assert!(matches!(
            trusted_keys(&[test_verifying_key().to_bytes(), unusable]),
            Err(ManifestError::TrustedKeyUnusable { position: 1 })
        ));
    }

    /// The property the overlap window buys. Without the second half a rotation nobody finished looks
    /// exactly like one that is done, right up until the retiring release.
    #[test]
    fn a_retired_key_still_admits_a_manifest_and_says_it_did() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        let successor = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();

        let (_, trusted) = ComponentManifest::parse_and_verify(
            json.as_bytes(),
            &sig,
            &[successor, test_verifying_key()],
        )
        .expect("a key inside its overlap window still admits the catalog");
        assert_eq!(trusted, TrustedKey::Retired { position: 1 });
        assert!(!trusted.is_current());
    }

    /// The order is the whole design: position zero is what the publisher signs with today, and a
    /// retired key must never be reported as the current one.
    #[test]
    fn the_first_accepted_key_is_the_current_one() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        let retired = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]).verifying_key();

        let (_, trusted) = ComponentManifest::parse_and_verify(
            json.as_bytes(),
            &sig,
            &[test_verifying_key(), retired],
        )
        .expect("valid signature");
        assert!(trusted.is_current());
    }

    /// An empty accepted list admits nothing. It cannot be reached from a shipping build (a const
    /// assertion refuses one), so what this pins is that the loop does not fall through to success.
    #[test]
    fn a_build_that_trusts_no_key_admits_nothing() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        assert!(matches!(
            ComponentManifest::parse_and_verify(json.as_bytes(), &sig, &[]),
            Err(ManifestError::BadSignature)
        ));
    }

    /// The hosted manifest and its detached signature, embedded at build time, must verify against the
    /// key this build signs with **today**, not merely against one it still accepts. This catches a
    /// mistyped key, a manifest reformatted after signing, a row dropped by an edit, and the rotation
    /// failure an accepted-key list otherwise hides: a new key added and released while the hosted file
    /// was never re-signed, which works everywhere until the retired key is dropped and then works
    /// nowhere.
    ///
    /// It asserts what every row has to carry rather than naming rows, so the file stays editable.
    #[test]
    fn the_hosted_manifest_is_signed_by_the_key_in_use_today() {
        let manifest = include_bytes!("../../../site/components/manifest.json");
        let signature = include_bytes!("../../../site/components/manifest.json.sig");
        let (parsed, trusted) = ComponentManifest::verify_trusted(manifest, signature)
            .expect("the hosted manifest verifies and parses against a trusted key");
        assert_eq!(
            trusted,
            TrustedKey::Current,
            "the hosted catalog is still signed by a retired key: finish the rotation by re-signing it"
        );

        assert!(!parsed.verbs.is_empty(), "the catalog offers prefix setup");
        for verb in &parsed.verbs {
            assert!(
                !verb.reason.is_empty(),
                "verb {:?} is offered without a reason",
                verb.name
            );
        }
        // The row behind the Dalamud launch setting. Without it the setting has no endpoint to reach
        // and no tier note to state, so a build that dropped it would silently offer nothing.
        let dalamud = parsed
            .injectable(InjectableKind::Dalamud)
            .expect("the Dalamud row is what the launch setting reads");
        assert_eq!(dalamud.kind, InjectableKind::Dalamud);
        assert!(
            matches!(&dalamud.tier, SupportTier::BestEffort { note } if !note.is_empty()),
            "the tier has to say what it costs"
        );
    }
}

/// Proof that a manifest verified against a trusted key, and the only shape the apply path accepts.
///
/// Applying a manifest is not a read: it sets values inside a prefix's registry and lays files into
/// it from URLs the manifest names. So a manifest that reaches
/// [`Addons::apply_setup`](crate::Addons::apply_setup) has to be one somebody verified rather than
/// one somebody parsed. Parsing is public, total and fuzzed
/// ([`ComponentManifest::from_json_bytes`]) and carries no authenticity whatsoever, which would
/// leave a signature check that is only a convention one call site away from not happening.
///
/// Minted here and nowhere else, by verifying.
///
/// # Examples
///
/// ```
/// # fn main() -> Result<(), apogee_addons::ManifestError> {
/// use apogee_addons::VerifiedManifest;
/// use ed25519_dalek::{Signer, SigningKey};
///
/// let signing = SigningKey::from_bytes(&[7u8; 32]);
/// let json = br#"{"version": 1}"#;
/// let signature = signing.sign(json).to_bytes();
///
/// let verified = VerifiedManifest::verify(json, &signature, &[signing.verifying_key().to_bytes()])?;
/// assert!(verified.key().is_current());
/// assert!(verified.rows().verbs.is_empty());
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedManifest {
    manifest: ComponentManifest,
    key: TrustedKey,
}

impl VerifiedManifest {
    /// Verify `signature` over the exact `manifest_json` bytes against `keys`, in order, then parse.
    ///
    /// The keys are an argument rather than this build's own, so the fetch path can be driven
    /// against a key a test signs with. Nothing about that weakens the gate: a caller cannot verify
    /// against keys it does not have, and the launcher passes the ones compiled into it.
    ///
    /// Raw 32-byte keys, the shape [`COMPONENT_PUBLIC_KEYS`] is compiled in as, rather than a type
    /// from the signature crate. A key is 32 bytes on any implementation, and naming that crate's
    /// type here would put its major version in this one's surface for nothing.
    ///
    /// # Errors
    /// [`ManifestError::TrustedKeyUnusable`] if one of `keys` is not a usable key, then
    /// [`ManifestError::BadSignature`] if the signature is not exactly 64 bytes or verifies against
    /// none of `keys`, then anything [`ComponentManifest::from_json_bytes`] raises.
    pub fn verify(
        manifest_json: &[u8],
        signature: &[u8],
        keys: &[[u8; 32]],
    ) -> Result<Self, ManifestError> {
        let keys = trusted_keys(keys)?;
        let (manifest, key) = ComponentManifest::parse_and_verify(manifest_json, signature, &keys)?;
        Ok(Self { manifest, key })
    }

    /// The same, against the keys compiled into this build.
    ///
    /// # Errors
    /// [`ManifestError::TrustedKeyUnusable`] if this build's own key list is malformed, then
    /// anything [`Self::verify`] raises.
    pub fn verify_trusted(manifest_json: &[u8], signature: &[u8]) -> Result<Self, ManifestError> {
        let (manifest, key) = ComponentManifest::verify_trusted(manifest_json, signature)?;
        Ok(Self { manifest, key })
    }

    /// The rows it carries. Reading them is not applying them, so this is ordinary access.
    #[must_use]
    pub fn rows(&self) -> &ComponentManifest {
        &self.manifest
    }

    /// Which of this build's trusted keys admitted it, for a caller that wants to know whether a
    /// rotation is finished. Most do not: the point of an overlap window is that a launch works
    /// either way.
    #[must_use]
    pub fn key(&self) -> TrustedKey {
        self.key
    }
}

#[cfg(test)]
impl VerifiedManifest {
    /// Mint one for this crate's own unit tests, which drive the machinery below the gate.
    ///
    /// `cfg(test)` rather than a feature. A feature is a build somebody can ship and a second public
    /// way to reach the apply path, and it would not even help: the tests that need a manifest are
    /// spread across the ones a feature gate is on and the ones it is not. The tests that drive the
    /// seam itself are integration tests, and those sign a fixture with a key they made and verify
    /// it, which is the same call the launcher makes.
    pub(crate) fn minted_for_tests(manifest: ComponentManifest) -> Self {
        Self {
            manifest,
            key: TrustedKey::Current,
        }
    }
}
