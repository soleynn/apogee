//! The signed component manifest: what companions and prefix verbs exist, as data.
//!
//! Same discipline as the runner and index catalogs, with its own key: a JSON manifest whose Ed25519
//! signature is verified against a compiled-in verifying key **before** any `sha256` pin inside it is
//! trusted. [`ComponentManifest::from_json_bytes`] is a pure, total parser over untrusted input (the
//! fuzz entry point) and carries no authenticity guarantee on its own;
//! [`ComponentManifest::verify_default`] is what a caller should reach for.
//!
//! Everything a component installation needs is in a row, so adding a companion, moving where its files
//! land, or changing the arguments it runs with is a manifest edit. That is load-bearing rather than
//! aspirational here: several of these placements are educated guesses about where a Windows program
//! looks for its own plugins, and a guess that lives in signed data can be corrected without a release.
//!
//! Dalamud is the one row that is a pointer rather than a pin, because its bytes come from goatcorp's
//! own versioned, integrity-checked distribution and Apogee never hosts them.

use std::path::{Component, Path, PathBuf};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

use apogee_runtime::{ArchiveFormat, ArchiveLayout, RegistryEdit, RegistryValue};

use crate::SupportTier;
use crate::external::Trigger;

/// The manifest schema version this build understands.
pub const COMPONENT_MANIFEST_VERSION: u32 = 1;

/// The compiled-in public key component manifests are authenticated against.
///
/// Its own key, not the runner catalog's: the two are published on different cadences by different
/// steps, and one compromised signer should not authenticate both. The matching private key is held
/// offline; rotating it is a change to this constant plus a re-sign.
pub const COMPONENT_PUBLIC_KEY: [u8; 32] = [
    0x6d, 0x35, 0x68, 0x49, 0x3e, 0x56, 0x73, 0xb1, 0xa3, 0x10, 0xfa, 0xe7, 0x20, 0x1b, 0xec, 0xd2,
    0x21, 0xd6, 0x70, 0xb9, 0x28, 0x6a, 0xa9, 0xfd, 0x3f, 0xc7, 0x6c, 0xdf, 0xc7, 0xb9, 0x94, 0x00,
];

/// Components a name may nest, and bytes one component may hold. A real destination is two or three
/// deep; these only exist so a hostile row cannot describe a path no filesystem would take.
const MAX_PATH_DEPTH: usize = 32;
const MAX_NAME_BYTES: usize = 255;

/// Why a component manifest was rejected.
///
/// Its own taxonomy, like the runner catalog's, so the pure parser stays total and cross-platform;
/// [`crate::AddonError`] wraps it.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ManifestError {
    #[error("manifest is not valid JSON or violates the schema")]
    Malformed(#[source] serde_json::Error),
    #[error("manifest signature did not verify against the trusted key")]
    BadSignature,
    #[error("unsupported manifest version {found} (expected {expected})")]
    UnsupportedVersion { found: u32, expected: u32 },
    #[error("{component}: unknown {field} {value:?}")]
    UnknownValue {
        component: String,
        field: &'static str,
        value: String,
    },
    #[error("{component}: sha256 pin is not 32 hex bytes")]
    BadPin { component: String },
    #[error("{component}: {url:?} is not a valid absolute url")]
    BadUrl { component: String, url: String },
    #[error("{component}: path {path:?} is not one a component may write: {reason}")]
    BadPath {
        component: String,
        path: String,
        reason: &'static str,
    },
    /// A name or version that would not survive being part of a filename. Both end up in one: a
    /// component's scratch file and its install marker are named after them, so they are held to the
    /// same standard as the destinations, which are validated a few lines away.
    #[error("{field} {value:?} is not usable: {reason}")]
    BadIdentifier {
        field: &'static str,
        value: String,
        reason: &'static str,
    },
    #[error("{component}: registry edit {key:?} is not one this launcher will write: {reason}")]
    BadRegistryEdit {
        component: String,
        key: String,
        reason: &'static str,
    },
    /// Two rows offering the same name, anywhere across the three lists. A component name is what a
    /// profile stores and what `prefix.json` records, so a duplicate would make "is it installed?"
    /// ambiguous.
    #[error("two components are both named {name:?}")]
    DuplicateName { name: String },
    /// A tool naming a verb no row defines. Caught here rather than at install time, because a tool
    /// that installs and then cannot be set up is worse than one that was never offered.
    #[error("{component} requires verb {verb:?}, which the manifest does not define")]
    UnknownVerb { component: String, verb: String },
}

/// Which companion a component name refers to, and what installing it means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ToolKind {
    /// A Windows program installed into the prefix and run through its runner.
    PrefixTool,
    /// A native program installed outside the prefix and run directly on the host.
    ExternalNative,
}

/// The injection-shaped companions. Modelled here so the schema does not change when the code that
/// drives them lands; nothing consumes these rows yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum InjectableKind {
    Dalamud,
}

/// How a companion reaches an already-running game.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Attach {
    /// Its loader takes the resolved game process id.
    GamePid,
}

/// A relative path a component's files may be written to, already confined.
///
/// Rooted at the prefix's `C:` for a prefix tool and at the host component directory for a native one.
/// Validated when the manifest is parsed, so nothing downstream re-derives a path from a string.
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
    /// `\` is folded to `/` first. On Linux a backslash is an ordinary character, so a Windows-shaped
    /// path in a manifest would otherwise arrive as a single filename and sail past every check below
    /// while landing somewhere nobody intended.
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
pub struct Artifact {
    pub url: Url,
    pub sha256: [u8; 32],
    pub archive: ArchiveLayout,
}

/// How an installed component joins a launch.
#[derive(Debug, Clone)]
pub struct Registration {
    /// The program to run, relative to the component's install directory.
    pub program: ComponentPath,
    /// Its arguments, passed verbatim.
    pub args: Vec<String>,
    /// When it runs and what the game's exit does to it.
    pub trigger: Trigger,
}

/// One companion tool.
#[derive(Debug, Clone)]
pub struct ToolEntry {
    pub name: String,
    pub version: String,
    pub kind: ToolKind,
    pub artifact: Artifact,
    /// Where its files land, under the prefix's `C:` or the host component directory.
    pub into: ComponentPath,
    /// Verbs the prefix needs before this tool is installed, in order.
    pub verbs: Vec<String>,
    /// What the user is told at install time. Not a log line: these are the things that otherwise show
    /// up later as "it installed fine and does nothing".
    pub caveats: Vec<String>,
    /// How it joins a launch, if it does. A component may be worth installing without being worth
    /// starting automatically.
    pub register: Option<Registration>,
    /// Set for a companion whose loader takes the resolved game process id. Carried for the phase that
    /// drives it; nothing reads it yet.
    pub attach: Option<Attach>,
}

/// One injectable companion. Its bytes come from its own distribution, so there is no pin here.
#[derive(Debug, Clone)]
pub struct InjectableEntry {
    pub name: String,
    pub kind: InjectableKind,
    /// The upstream endpoint its versioned, integrity-checked distribution is served from. Reached only
    /// when the component is enabled.
    pub distribution: Url,
    pub tier: SupportTier,
    pub caveats: Vec<String>,
}

/// One step of a verb.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum VerbOp {
    /// Write one registry value. Idempotent by construction.
    Registry(RegistryEdit),
    /// Place a pinned artifact's files under the prefix's `C:`. Idempotent by overwrite.
    Files {
        artifact: Artifact,
        into: ComponentPath,
    },
}

/// A curated prefix-setup step, described entirely by the manifest so it is auditable and ships as
/// data.
#[derive(Debug, Clone)]
pub struct Verb {
    pub name: String,
    /// Why it exists, shown when it is applied. A verb with no reason is a verb nobody can review.
    pub reason: String,
    pub ops: Vec<VerbOp>,
}

/// A verified component manifest.
#[derive(Debug, Clone, Default)]
pub struct ComponentManifest {
    pub version: u32,
    pub injectables: Vec<InjectableEntry>,
    pub tools: Vec<ToolEntry>,
    pub verbs: Vec<Verb>,
}

impl ComponentManifest {
    /// Parse a manifest from untrusted JSON. Pure and total: any byte sequence yields a manifest or a
    /// typed [`ManifestError`], never a panic. This is the fuzz target and carries **no** authenticity
    /// guarantee — callers must have verified the signature.
    ///
    /// # Errors
    /// Any [`ManifestError`] except [`ManifestError::BadSignature`].
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        let raw: RawManifest = serde_json::from_slice(bytes).map_err(ManifestError::Malformed)?;
        Self::try_from(raw)
    }

    /// Verify `signature` over the exact `manifest_json` bytes against `key`, then parse. The signature
    /// is checked **first**, so no `sha256` pin is trusted before authenticity is established.
    ///
    /// # Errors
    /// [`ManifestError::BadSignature`] if the signature is not exactly 64 bytes or does not verify,
    /// then anything [`Self::from_json_bytes`] raises.
    pub fn parse_and_verify(
        manifest_json: &[u8],
        signature: &[u8],
        key: &VerifyingKey,
    ) -> Result<Self, ManifestError> {
        let sig = Signature::from_slice(signature).map_err(|_| ManifestError::BadSignature)?;
        key.verify_strict(manifest_json, &sig)
            .map_err(|_| ManifestError::BadSignature)?;
        Self::from_json_bytes(manifest_json)
    }

    /// [`Self::parse_and_verify`] against the compiled-in key. What the composition root calls.
    ///
    /// # Errors
    /// As [`Self::parse_and_verify`].
    pub fn verify_default(manifest_json: &[u8], signature: &[u8]) -> Result<Self, ManifestError> {
        let key = VerifyingKey::from_bytes(&COMPONENT_PUBLIC_KEY)
            .map_err(|_| ManifestError::BadSignature)?;
        Self::parse_and_verify(manifest_json, signature, &key)
    }

    /// The tool row named `name`.
    #[must_use]
    pub fn tool(&self, name: &str) -> Option<&ToolEntry> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// The verb row named `name`.
    #[must_use]
    pub fn verb(&self, name: &str) -> Option<&Verb> {
        self.verbs.iter().find(|v| v.name == name)
    }

    /// The injectable row named `name`.
    #[must_use]
    pub fn injectable(&self, name: &str) -> Option<&InjectableEntry> {
        self.injectables.iter().find(|i| i.name == name)
    }

    /// Every component name the manifest offers, sorted. What a "what can I enable?" listing reads.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self
            .injectables
            .iter()
            .map(|i| i.name.as_str())
            .chain(self.tools.iter().map(|t| t.name.as_str()))
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
    tools: Vec<RawTool>,
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
struct RawTool {
    name: String,
    version: String,
    kind: String,
    url: String,
    sha256: String,
    archive: RawArchive,
    into: String,
    #[serde(default)]
    verbs: Vec<String>,
    #[serde(default)]
    caveats: Vec<String>,
    #[serde(default)]
    register: Option<RawRegister>,
    #[serde(default)]
    attach: Option<String>,
}

#[derive(Deserialize)]
struct RawRegister {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    trigger: String,
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
    ops: Vec<RawOp>,
}

/// A verb op. Externally tagged, so exactly one kind is named per entry and an entry naming none or
/// two is a parse error rather than a silently-chosen default.
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum RawOp {
    Registry(RawRegistry),
    Files(RawFiles),
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
        let tools = raw
            .tools
            .into_iter()
            .map(build_tool)
            .collect::<Result<Vec<_>, _>>()?;
        let verbs = raw
            .verbs
            .into_iter()
            .map(build_verb)
            .collect::<Result<Vec<_>, _>>()?;

        let manifest = Self {
            version: raw.version,
            injectables,
            tools,
            verbs,
        };
        manifest.check_names()?;
        Ok(manifest)
    }
}

impl ComponentManifest {
    /// Every name is unique across the three lists, and every verb a tool asks for exists.
    ///
    /// Both are cross-row properties, so they are checked once the rows are built rather than while
    /// building one.
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
        for tool in &self.tools {
            for verb in &tool.verbs {
                if self.verb(verb).is_none() {
                    return Err(ManifestError::UnknownVerb {
                        component: tool.name.clone(),
                        verb: verb.clone(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Refuse a name or version that would not survive being part of a filename.
///
/// Both become one: a component's scratch file is named after it, and a native component's install marker
/// is `<name>-<version>`. Everything else derived from manifest data is confined by [`ComponentPath`], so
/// leaving these two unchecked would be the one place a row could name a path component the rest of the
/// parser exists to prevent. The manifest is signed, so this is depth rather than a boundary — but a
/// signed row can still be a mistaken one.
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
        ("first_class", _) => SupportTier::FirstClass,
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

fn build_tool(raw: RawTool) -> Result<ToolEntry, ManifestError> {
    check_identifier("component name", &raw.name)?;
    check_identifier("component version", &raw.version)?;
    let kind = match raw.kind.as_str() {
        "prefix_tool" => ToolKind::PrefixTool,
        "external_native" => ToolKind::ExternalNative,
        _ => return Err(unknown(&raw.name, "tool kind", raw.kind)),
    };
    let attach = match raw.attach.as_deref() {
        None => None,
        Some("game_pid") => Some(Attach::GamePid),
        Some(other) => return Err(unknown(&raw.name, "attach", other)),
    };
    let register = match raw.register {
        None => None,
        Some(register) => Some(Registration {
            program: ComponentPath::parse(&register.program, &raw.name)?,
            args: register.args,
            trigger: match register.trigger.as_str() {
                "with_game" => Trigger::WithGame {
                    keep_after_close: false,
                },
                "with_game_keep_running" => Trigger::WithGame {
                    keep_after_close: true,
                },
                "on_close" => Trigger::OnClose,
                other => return Err(unknown(&raw.name, "trigger", other)),
            },
        }),
    };
    Ok(ToolEntry {
        artifact: build_artifact(&raw.name, &raw.url, &raw.sha256, raw.archive)?,
        into: ComponentPath::parse(&raw.into, &raw.name)?,
        name: raw.name,
        version: raw.version,
        kind,
        verbs: raw.verbs,
        caveats: raw.caveats,
        register,
        attach,
    })
}

fn build_verb(raw: RawVerb) -> Result<Verb, ManifestError> {
    check_identifier("verb name", &raw.name)?;
    let ops = raw
        .ops
        .into_iter()
        .map(|op| build_op(&raw.name, op))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Verb {
        name: raw.name,
        reason: raw.reason,
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

/// Map an archive-format string to a layout format. No default: a component archive is as likely to be
/// a zip as a tarball, so the row states which and a row that forgets is a parse error rather than a
/// guess that fails at extraction.
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

    /// A manifest with one prefix tool, one native tool, and the verb the first one asks for.
    fn manifest() -> String {
        format!(
            r#"{{
              "version": 1,
              "tools": [
                {{ "name": "ACT", "version": "3.8.5.288", "kind": "prefix_tool",
                   "url": "https://example.invalid/ACTv3.zip", "sha256": "{GOOD_PIN}",
                   "archive": {{ "format": "zip" }},
                   "into": "apogee/ACT",
                   "verbs": ["no-desktop-integration"],
                   "caveats": ["It needs a .NET Framework this launcher does not install."],
                   "register": {{ "program": "Advanced Combat Tracker.exe",
                                  "args": ["-portable"], "trigger": "with_game" }} }},
                {{ "name": "Triggevent", "version": "1.0-10", "kind": "external_native",
                   "url": "https://example.invalid/triggevent-linux.zip", "sha256": "{GOOD_PIN}",
                   "archive": {{ "format": "zip", "strip_prefix": "triggevent" }},
                   "into": "Triggevent",
                   "register": {{ "program": "triggevent.sh", "args": [], "trigger": "with_game" }} }}
              ],
              "verbs": [
                {{ "name": "no-desktop-integration", "reason": "Keeps installs out of the host menu.",
                   "ops": [
                     {{ "registry": {{ "key": "HKCU\\Software\\Wine\\DllOverrides",
                                       "name": "winemenubuilder.exe", "type": "disabled" }} }}
                   ] }}
              ]
            }}"#
        )
    }

    fn parse(json: &str) -> Result<ComponentManifest, ManifestError> {
        ComponentManifest::from_json_bytes(json.as_bytes())
    }

    #[test]
    fn a_signed_manifest_parses_every_row() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        let parsed =
            ComponentManifest::parse_and_verify(json.as_bytes(), &sig, &test_verifying_key())
                .expect("valid signature");

        let act = parsed.tool("ACT").expect("ACT row");
        assert_eq!(act.kind, ToolKind::PrefixTool);
        assert_eq!(act.artifact.archive.format, ArchiveFormat::Zip);
        assert_eq!(act.into.as_path(), Path::new("apogee/ACT"));
        assert_eq!(act.verbs, ["no-desktop-integration"]);
        assert_eq!(act.caveats.len(), 1);
        let register = act.register.as_ref().expect("registered");
        assert_eq!(
            register.program.as_path(),
            Path::new("Advanced Combat Tracker.exe")
        );
        assert_eq!(register.args, ["-portable"]);
        assert_eq!(
            register.trigger,
            Trigger::WithGame {
                keep_after_close: false
            }
        );

        let triggevent = parsed.tool("Triggevent").expect("Triggevent row");
        assert_eq!(triggevent.kind, ToolKind::ExternalNative);
        assert_eq!(
            triggevent.artifact.archive.strip_prefix.as_deref(),
            Some("triggevent")
        );

        let verb = parsed.verb("no-desktop-integration").expect("verb row");
        assert!(!verb.reason.is_empty());
        match verb.ops.as_slice() {
            [VerbOp::Registry(edit)] => {
                assert_eq!(edit.name, "winemenubuilder.exe");
                assert_eq!(edit.value, RegistryValue::Disabled);
            }
            other => panic!("expected one registry op, got {other:?}"),
        }
        assert_eq!(
            parsed.names(),
            ["ACT", "Triggevent", "no-desktop-integration"]
        );
    }

    #[test]
    fn signature_rejects_a_tampered_manifest() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        let mut tampered = json.into_bytes();
        // Flip a byte in the body; the detached signature no longer matches.
        tampered[40] ^= 0x01;
        assert!(matches!(
            ComponentManifest::parse_and_verify(&tampered, &sig, &test_verifying_key()),
            Err(ManifestError::BadSignature)
        ));
    }

    #[test]
    fn signature_rejects_the_wrong_key() {
        let json = manifest();
        let sig = sign_manifest(json.as_bytes());
        // The compiled-in key is a different key than the test signer.
        assert!(matches!(
            ComponentManifest::verify_default(json.as_bytes(), &sig),
            Err(ManifestError::BadSignature)
        ));
    }

    #[test]
    fn signature_rejects_absent_or_short() {
        let json = manifest();
        for sig in [b"".as_slice(), b"too-short".as_slice()] {
            assert!(matches!(
                ComponentManifest::parse_and_verify(json.as_bytes(), sig, &test_verifying_key()),
                Err(ManifestError::BadSignature)
            ));
        }
    }

    /// Both halves of the pin decoder: the length, and the digits. A pin of the right length made of
    /// wrong characters is the one that would otherwise decode to a silently wrong 32 bytes, and it is
    /// also the likelier mistake — a typo'd digit, or a digest in the wrong encoding.
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
            parse(&json).expect("parse").tools[0].artifact.sha256
        };
        assert_eq!(of(&lower), of(&upper));
        assert_eq!(of(&lower)[0], 0x01);
    }

    #[test]
    fn an_unknown_kind_format_trigger_or_attach_is_a_typed_error() {
        for (from, to) in [
            ("\"kind\": \"prefix_tool\"", "\"kind\": \"prefix_flatpak\""),
            ("\"format\": \"zip\"", "\"format\": \"tar.brotli\""),
            ("\"trigger\": \"with_game\"", "\"trigger\": \"whenever\""),
            ("\"type\": \"disabled\"", "\"type\": \"reg_binary\""),
        ] {
            let json = manifest().replace(from, to);
            assert!(
                matches!(parse(&json), Err(ManifestError::UnknownValue { .. })),
                "{to} must be refused"
            );
        }
        let json = manifest().replace(
            "\"into\": \"Triggevent\"",
            "\"into\": \"Triggevent\", \"attach\": \"telepathy\"",
        );
        assert!(matches!(
            parse(&json),
            Err(ManifestError::UnknownValue { .. })
        ));
    }

    /// A name is what a profile stores and what the prefix records, so two rows sharing one would make
    /// "is it installed?" unanswerable.
    #[test]
    fn two_rows_with_one_name_are_refused_across_every_list() {
        let json = manifest().replace("\"name\": \"Triggevent\"", "\"name\": \"ACT\"");
        assert!(matches!(
            parse(&json),
            Err(ManifestError::DuplicateName { .. })
        ));
        // Also across lists, not only within one.
        let json = manifest().replace("\"name\": \"no-desktop-integration\"", "\"name\": \"ACT\"");
        assert!(matches!(
            parse(&json),
            Err(ManifestError::DuplicateName { .. })
        ));
    }

    /// A tool that installs and then cannot be set up is worse than one that was never offered, so the
    /// dangling reference is caught before anything is downloaded.
    #[test]
    fn a_tool_requiring_a_verb_that_does_not_exist_is_refused() {
        let json = manifest().replace(
            "\"verbs\": [\"no-desktop-integration\"]",
            "\"verbs\": [\"dotnet48\"]",
        );
        match parse(&json) {
            Err(ManifestError::UnknownVerb { verb, component }) => {
                assert_eq!(verb, "dotnet48");
                assert_eq!(component, "ACT");
            }
            other => panic!("expected UnknownVerb, got {other:?}"),
        }
    }

    /// A name and a version both become part of a filename: a component's scratch file is named after it
    /// and a native install marker is `<name>-<version>`. Leaving them unchecked would be the one place a
    /// row could name a path component the rest of this parser exists to refuse.
    #[test]
    fn a_name_or_version_that_would_not_survive_a_filename_is_refused() {
        for (from, to) in [
            ("\"name\": \"ACT\"", "\"name\": \"../../etc/x\""),
            ("\"name\": \"ACT\"", "\"name\": \"..\""),
            ("\"name\": \"ACT\"", "\"name\": \"a/b\""),
            ("\"name\": \"ACT\"", r#""name": "a\\b""#),
            ("\"name\": \"ACT\"", "\"name\": \"\""),
            ("\"version\": \"3.8.5.288\"", "\"version\": \"../../etc\""),
            ("\"version\": \"3.8.5.288\"", "\"version\": \"\""),
        ] {
            let json = manifest().replacen(from, to, 1);
            assert!(
                matches!(parse(&json), Err(ManifestError::BadIdentifier { .. })),
                "{to} must be refused"
            );
        }
        // A verb's name reaches the same places.
        let json = manifest().replace("\"name\": \"no-desktop-integration\"", "\"name\": \"../x\"");
        assert!(matches!(
            parse(&json),
            Err(ManifestError::BadIdentifier { .. })
        ));
    }

    /// The destination is where a component's bytes land, so it is the one field a hostile row would
    /// most want to control.
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
            let json =
                manifest().replace("\"into\": \"apogee/ACT\"", &format!("\"into\": {path:?}"));
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
            "\"into\": \"apogee/ACT\"",
            r#""into": "apogee\\ACT\\Plugins""#,
        );
        let parsed = parse(&json).expect("a windows-shaped path is still a path");
        assert_eq!(
            parsed.tool("ACT").expect("row").into.as_path(),
            Path::new("apogee/ACT/Plugins")
        );

        let json = manifest().replace(
            "\"into\": \"apogee/ACT\"",
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
        let with_note = r#"{ "version": 1, "injectables": [
            { "name": "Dalamud", "kind": "dalamud",
              "distribution": "https://kamori.goats.dev/Dalamud/Release/VersionInfo",
              "tier": "best_effort", "note": "Best with the wine-xiv runner." } ] }"#;
        let parsed = parse(with_note).expect("parse");
        let entry = parsed.injectable("Dalamud").expect("row");
        assert_eq!(entry.kind, InjectableKind::Dalamud);
        assert!(matches!(entry.tier, SupportTier::BestEffort { .. }));

        let without = with_note.replace(r#", "note": "Best with the wine-xiv runner.""#, "");
        assert!(matches!(
            parse(&without),
            Err(ManifestError::UnknownValue { .. })
        ));
    }

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

    /// An empty manifest is well-formed: a build with nothing to offer is a valid state, and refusing it
    /// would make "no components yet" indistinguishable from a broken manifest.
    #[test]
    fn a_manifest_with_no_rows_parses() {
        let parsed = parse(r#"{ "version": 1 }"#).expect("parse");
        assert!(parsed.names().is_empty());
    }

    #[test]
    fn the_compiled_in_key_parses() {
        assert!(VerifyingKey::from_bytes(&COMPONENT_PUBLIC_KEY).is_ok());
    }

    /// The hosted manifest and its detached signature, embedded at build time, must verify against the
    /// compiled-in key and expose the components the launcher offers. This catches a mistyped key, a
    /// manifest reformatted after signing, or a row dropped by an edit.
    #[test]
    fn the_hosted_manifest_verifies_against_the_compiled_in_key() {
        let manifest = include_bytes!("../../../site/components/manifest.json");
        let signature = include_bytes!("../../../site/components/manifest.json.sig");
        let parsed = ComponentManifest::verify_default(manifest, signature)
            .expect("the hosted manifest verifies and parses against the compiled-in key");

        let act = parsed.tool("ACT").expect("ACT is offered");
        assert_eq!(act.kind, ToolKind::PrefixTool);
        assert!(
            !act.caveats.is_empty(),
            "ACT cannot be offered without stating what it needs"
        );
        let triggevent = parsed.tool("Triggevent").expect("Triggevent is offered");
        assert_eq!(triggevent.kind, ToolKind::ExternalNative);
        // Nothing may be offered that this build cannot drive.
        assert!(
            parsed.injectables.is_empty(),
            "an injectable row would advertise a component nothing installs yet"
        );
    }
}
