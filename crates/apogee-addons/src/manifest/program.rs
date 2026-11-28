//! Program rows: a curated program run beside the game in its wine session, as signed data.
//!
//! A row carries everything needed to install, gate and start one program, so supporting a new
//! release is an edit and a re-sign rather than a build. Its install steps live inside the row and are
//! planned only for a program a profile enabled, never as top-level verbs: a build that predates the
//! list would apply top-level verbs to every prefix.
//!
//! **A row this build cannot read costs that row, never the manifest.** The list is read row by row
//! and a row that breaks a rule is kept as a [`RefusedProgram`] naming why, so a later row shape, an
//! unknown key in a row, or one author's mistake leaves Dalamud and the base verbs standing. Unknown
//! keys inside a row are refused rather than ignored, the opposite of the top level: a key a later
//! build adds to a row is most likely a control on what the program may do, and starting the program
//! without the control is the wrong way to fail.

use std::collections::BTreeMap;
use std::time::Duration;

use apogee_runtime::RunnerRef;
use serde::Deserialize;

use super::{
    ComponentPath, ManifestError, PathRoot, RawOp, Verb, build_op, check_identifier, parse_tier,
    unknown,
};
use crate::SupportTier;
use crate::external::Trigger;

/// The longest evidence window a row may ask for. Ten minutes covers a cold prefix and a slow zone
/// load with room to spare; a longer one is a row asking the launcher to watch a file for a session.
const MAX_EVIDENCE_WINDOW_S: u64 = 600;
/// The window a row that names none gets, matching the injectable default.
const DEFAULT_EVIDENCE_WINDOW_S: u64 = 90;
/// How long a game version, a claim or a runner field may be. Real ones are a few dozen bytes.
const MAX_SHORT_FIELD: usize = 64;

/// A runner a program has been validated on, by the identity its catalog row carries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunnerPin {
    /// The runner's name, as its catalog row spells it.
    pub name: String,
    /// The runner's version, as its catalog row spells it.
    pub version: String,
}

impl RunnerPin {
    /// Whether `runner` is this one. Exact on both halves: a rebuilt runner is a different runner
    /// until somebody validates it.
    #[must_use]
    pub fn matches(&self, runner: &RunnerRef) -> bool {
        self.name == runner.name && self.version == runner.version
    }
}

/// How a program is started once the game is up.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProgramStart {
    /// The executable, under `C:\Apogee\…`. Always one of the files the row's own steps place, so a
    /// copy the user installed somewhere else is never what is started or checked.
    pub program: ComponentPath,
    /// Its argument vector, passed verbatim.
    pub args: Vec<String>,
    /// When it runs. Always [`Trigger::WithGame`] with the game's lifetime: a curated program is never
    /// kept past the game and never runs after it.
    pub trigger: Trigger,
    /// Environment it needs, already checked against the companion allowlist.
    pub env: BTreeMap<String, String>,
}

/// How a setting file stores the key an updater is switched by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdaterKeyFormat {
    /// A JSON object; the key is a top-level member, compared by its string, number or boolean form.
    Json,
    /// An XML document of settings elements, each carrying `Name="<key>"` and `Value="<value>"`.
    XmlSetting,
}

/// One setting that switches a program's own self-updater, and the value that means off.
///
/// A program that updates itself replaces pinned bytes with whatever its publisher serves next, with
/// none of the checks the row's pins carry. The row's seeded configuration turns each one off once;
/// this is what is read each time a launch is planned, before the game is spawned, because the user
/// can turn it back on inside the program.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct UpdaterKey {
    /// The settings file.
    pub file: ComponentPath,
    /// How that file stores its keys.
    pub format: UpdaterKeyFormat,
    /// The key.
    pub key: String,
    /// The value it holds when the updater is off. Compared without regard to ASCII case or
    /// surrounding whitespace, since the programs this covers write booleans as `False` or `false`.
    pub off: String,
}

/// Where a program leaves proof it came up, and how long to wait for it.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProgramEvidence {
    /// A file or directory the program writes once it is working. Only its modification time is read.
    pub path: ComponentPath,
    /// How long absence stays "not yet".
    pub window: Duration,
}

/// One install step of a program.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProgramStep {
    /// What the step does, in the same shape as a base verb.
    pub verb: Verb,
    /// Whether this step seeds configuration the program then owns.
    ///
    /// A seeded step is applied when the prefix does not record it or a path it states is gone, and is
    /// otherwise left alone: not reinstalled when the row's version moves, and not re-hashed when a
    /// launch is planned. The program rewrites its own settings as the user changes them, so treating
    /// them as pinned bytes would either undo the user's settings or disable the program on its next
    /// start.
    pub seeded: bool,
}

/// A curated program: installed by pinned steps, gated when each launch is planned, run beside the
/// game.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ProgramEntry {
    /// What the setting and the prefix record name it by.
    pub name: String,
    /// The row's version. A prefix records each step against it, so moving it reinstalls the program.
    pub version: String,
    /// How well it is supported here.
    pub tier: SupportTier,
    /// Things the user should know before enabling it, beyond what the tier says.
    pub caveats: Vec<String>,
    /// The game versions it has been validated on. On any other it is not started.
    pub game_versions: Vec<String>,
    /// The runners it has been validated on. Under any other it is not started.
    pub runners: Vec<RunnerPin>,
    /// Fixed names it holds while it runs, such as a named pipe or a port, spelled `kind:name`. Two
    /// enabled programs claiming the same name cannot run in one session.
    pub claims: Vec<String>,
    /// What installs it, in order.
    pub steps: Vec<ProgramStep>,
    /// How it is started.
    pub start: ProgramStart,
    /// Self-updater switches that must read off when a launch is planned, or it is not started.
    pub updater_keys: Vec<UpdaterKey>,
    /// Where it proves it came up, if it leaves any proof.
    pub evidence: Option<ProgramEvidence>,
}

impl ProgramEntry {
    /// Whether it has been validated on `game_version`.
    #[must_use]
    pub fn supports_game(&self, game_version: &str) -> bool {
        self.game_versions.iter().any(|v| v == game_version)
    }

    /// Whether it has been validated on `runner`.
    #[must_use]
    pub fn supports_runner(&self, runner: &RunnerRef) -> bool {
        self.runners.iter().any(|pin| pin.matches(runner))
    }
}

/// A program row this build could not read, kept so an enabled program can say why it is absent.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RefusedProgram {
    /// The row's name, or empty when the row did not carry a usable one.
    pub name: String,
    /// Why it was refused, as one line.
    pub reason: String,
}

// ---- raw deserialization + validation --------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProgram {
    name: String,
    version: String,
    tier: String,
    #[serde(default)]
    note: Option<String>,
    #[serde(default)]
    caveats: Vec<String>,
    game_versions: Vec<String>,
    runners: Vec<RawRunnerPin>,
    #[serde(default)]
    claims: Vec<String>,
    steps: Vec<RawStep>,
    start: RawStart,
    #[serde(default)]
    updater_keys: Vec<RawUpdaterKey>,
    #[serde(default)]
    evidence: Option<RawEvidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRunnerPin {
    name: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    name: String,
    reason: String,
    #[serde(default)]
    verify: Vec<String>,
    #[serde(default)]
    seeded: bool,
    ops: Vec<RawOp>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStart {
    program: String,
    #[serde(default)]
    args: Vec<String>,
    trigger: String,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawUpdaterKey {
    file: String,
    format: String,
    key: String,
    off: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvidence {
    path: String,
    #[serde(default)]
    window_s: Option<u64>,
}

/// Read one row of the `programs` list, or say why it cannot be used.
pub(super) fn read_row(value: serde_json::Value) -> Result<ProgramEntry, RefusedProgram> {
    let name = value
        .get("name")
        .and_then(serde_json::Value::as_str)
        .filter(|name| check_identifier("program name", name).is_ok())
        .unwrap_or_default()
        .to_owned();
    let refuse = |err: &ManifestError| RefusedProgram {
        name: name.clone(),
        reason: crate::chain_of(err),
    };
    let raw: RawProgram =
        serde_json::from_value(value).map_err(|err| refuse(&ManifestError::Malformed(err)))?;
    build_program(raw).map_err(|err| refuse(&err))
}

/// The refusal recorded when the `programs` value is not a list, so there are no rows to read.
pub(super) fn not_a_list() -> RefusedProgram {
    RefusedProgram {
        name: String::new(),
        reason: "the programs value is not a list of rows".to_owned(),
    }
}

/// Refuse every program row whose name, or one of whose step names, is not its alone.
///
/// Each name is recorded in the prefix beside the base verbs, so a shared one makes the record
/// ambiguous. The cost falls on program rows only, and is decided from the list as it was written
/// rather than row by row, so the order of the rows never changes the outcome:
///
/// - a row naming itself or a step like an injectable or a base verb (`base`) is refused, and the
///   injectable or verb stands;
/// - rows that share a name with each other, as a program name or a step name on either side, are
///   all refused, since nothing says which of them the name belongs to;
/// - a row sharing its name or a step name with a row already refused is refused as well, because
///   the name would otherwise answer both for a program and for why one is absent;
/// - a row using one name twice among its own name and steps is refused.
///
/// A row that was already refused stays refused under its own reason. Rows keep their order.
pub(super) fn settle_names(
    rows: Vec<Result<ProgramEntry, RefusedProgram>>,
    base: &[&str],
) -> (Vec<ProgramEntry>, Vec<RefusedProgram>) {
    let mut uses: BTreeMap<String, usize> = BTreeMap::new();
    for row in &rows {
        match row {
            Ok(entry) => {
                for name in names_of(entry) {
                    *uses.entry(name.to_owned()).or_default() += 1;
                }
            }
            // An unreadable row's steps were never read, so its name is all it holds.
            Err(refused) if !refused.name.is_empty() => {
                *uses.entry(refused.name.clone()).or_default() += 1;
            }
            Err(_) => {}
        }
    }

    let mut programs = Vec::new();
    let mut refused_programs = Vec::new();
    for row in rows {
        match row {
            Ok(entry) => {
                let shared = names_of(&entry)
                    .find(|name| base.contains(name) || uses.get(*name).is_some_and(|n| *n > 1))
                    .map(str::to_owned);
                match shared {
                    Some(name) => refused_programs.push(RefusedProgram {
                        name: entry.name,
                        reason: crate::chain_of(&ManifestError::DuplicateName { name }),
                    }),
                    None => programs.push(entry),
                }
            }
            Err(refused) => refused_programs.push(refused),
        }
    }
    (programs, refused_programs)
}

/// A program's own name, then each of its step names.
fn names_of(entry: &ProgramEntry) -> impl Iterator<Item = &str> {
    std::iter::once(entry.name.as_str()).chain(entry.steps.iter().map(|s| s.verb.name.as_str()))
}

fn build_program(raw: RawProgram) -> Result<ProgramEntry, ManifestError> {
    check_identifier("program name", &raw.name)?;
    let name = raw.name;
    check_identifier("program version", &raw.version)?;
    let tier = parse_tier(&name, &raw.tier, raw.note)?;

    if raw.game_versions.is_empty() {
        return Err(unknown(&name, "game_versions", "an empty list"));
    }
    for version in &raw.game_versions {
        if version.is_empty()
            || version.len() > MAX_SHORT_FIELD
            || !version.chars().all(|c| c.is_ascii_digit() || c == '.')
        {
            return Err(unknown(&name, "game version", version.as_str()));
        }
    }

    if raw.runners.is_empty() {
        return Err(unknown(&name, "runners", "an empty list"));
    }
    let runners = raw
        .runners
        .into_iter()
        .map(|pin| {
            for field in [&pin.name, &pin.version] {
                if field.is_empty()
                    || field.len() > MAX_SHORT_FIELD
                    || field.chars().any(char::is_control)
                {
                    return Err(unknown(&name, "runner", field.as_str()));
                }
            }
            Ok(RunnerPin {
                name: pin.name,
                version: pin.version,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    for claim in &raw.claims {
        let well_formed = claim.len() <= MAX_SHORT_FIELD
            && claim
                .split_once(':')
                .is_some_and(|(kind, rest)| !kind.is_empty() && !rest.is_empty())
            && claim.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, ':' | '.' | '_' | '-')
            });
        if !well_formed {
            return Err(unknown(&name, "claim", claim.as_str()));
        }
    }

    if raw.steps.is_empty() {
        return Err(unknown(&name, "steps", "an empty list"));
    }
    let steps = raw
        .steps
        .into_iter()
        .map(build_step)
        .collect::<Result<Vec<_>, _>>()?;

    let start = build_start(&name, raw.start)?;
    let updater_keys = raw
        .updater_keys
        .into_iter()
        .map(|key| build_updater_key(&name, key))
        .collect::<Result<Vec<_>, _>>()?;
    let evidence = raw
        .evidence
        .map(|evidence| build_evidence(&name, &evidence))
        .transpose()?;

    Ok(ProgramEntry {
        name,
        version: raw.version,
        tier,
        caveats: raw.caveats,
        game_versions: raw.game_versions,
        runners,
        claims: raw.claims,
        steps,
        start,
        updater_keys,
        evidence,
    })
}

fn build_step(raw: RawStep) -> Result<ProgramStep, ManifestError> {
    check_identifier("verb name", &raw.name)?;
    let ops = raw
        .ops
        .into_iter()
        .map(|op| build_op(&raw.name, op, true))
        .collect::<Result<Vec<_>, _>>()?;
    let verify = raw
        .verify
        .iter()
        .map(|path| ComponentPath::parse_rooted(path, &raw.name))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ProgramStep {
        verb: Verb {
            name: raw.name,
            reason: raw.reason,
            verify,
            ops,
        },
        seeded: raw.seeded,
    })
}

fn build_start(component: &str, raw: RawStart) -> Result<ProgramStart, ManifestError> {
    let program = ComponentPath::parse_rooted(&raw.program, component)?;
    let bad = |reason: &'static str| ManifestError::BadPath {
        component: component.to_owned(),
        path: raw.program.clone(),
        reason,
    };
    // Under the launcher's own directory and nowhere else, so a copy the user installed at the
    // program's usual place is neither overwritten by an install nor mistaken for the pinned one.
    let owned = program.root() == PathRoot::DriveC
        && program
            .as_path()
            .components()
            .next()
            .is_some_and(|first| first.as_os_str().eq_ignore_ascii_case("Apogee"));
    if !owned || program.as_path().components().count() < 2 {
        return Err(bad("a program starts from under C:\\Apogee"));
    }
    if raw.args.iter().any(|arg| arg.contains('\0')) {
        return Err(unknown(component, "argument", "one carrying a null byte"));
    }
    let trigger = match raw.trigger.as_str() {
        "with_game" => Trigger::WithGame {
            keep_after_close: false,
        },
        other => return Err(unknown(component, "trigger", other)),
    };
    crate::env_rules::check(&raw.env, &crate::env_rules::GameOverrides::none()).map_err(
        |refused| ManifestError::BadEnv {
            component: component.to_owned(),
            key: refused.key,
            reason: refused.reason,
        },
    )?;
    Ok(ProgramStart {
        program,
        args: raw.args,
        trigger,
        env: raw.env,
    })
}

fn build_updater_key(component: &str, raw: RawUpdaterKey) -> Result<UpdaterKey, ManifestError> {
    let format = match raw.format.as_str() {
        "json" => UpdaterKeyFormat::Json,
        "xml_setting" => UpdaterKeyFormat::XmlSetting,
        other => return Err(unknown(component, "updater key format", other)),
    };
    for (field, value) in [("updater key", &raw.key), ("updater off value", &raw.off)] {
        if value.trim().is_empty()
            || value.len() > MAX_SHORT_FIELD
            || value
                .chars()
                .any(|c| c.is_control() || matches!(c, '"' | '<' | '>'))
        {
            return Err(unknown(component, field, value.as_str()));
        }
    }
    Ok(UpdaterKey {
        file: ComponentPath::parse_rooted(&raw.file, component)?,
        format,
        key: raw.key,
        off: raw.off,
    })
}

fn build_evidence(component: &str, raw: &RawEvidence) -> Result<ProgramEvidence, ManifestError> {
    let window_s = raw.window_s.unwrap_or(DEFAULT_EVIDENCE_WINDOW_S);
    if window_s == 0 || window_s > MAX_EVIDENCE_WINDOW_S {
        return Err(unknown(
            component,
            "evidence window",
            format!("{window_s} seconds"),
        ));
    }
    Ok(ProgramEvidence {
        path: ComponentPath::parse_rooted(&raw.path, component)?,
        window: Duration::from_secs(window_s),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::manifest::{ComponentManifest, VerbOp};
    use std::path::Path;

    /// A program row in the shape a real one takes, over `url` pinned to `pin`.
    pub(crate) fn act_row(url: &str, pin: &str) -> serde_json::Value {
        serde_json::json!({
            "name": "act",
            "version": "3.8.5.288+plugin-3.0.3.5",
            "tier": "best_effort",
            "note": "Runs in the game's wine session.",
            "caveats": ["Third-party code."],
            "game_versions": ["2026.11.03.0000.0000"],
            "runners": [{ "name": "GE-Proton", "version": "11-12+remote-thread-actctx" }],
            "claims": ["pipe:deucalion"],
            "steps": [
                { "name": "act-files", "reason": "ACT itself.",
                  "verify": ["Apogee/ACT/Advanced Combat Tracker.exe"],
                  "ops": [{ "files": { "url": url, "sha256": pin,
                                       "archive": { "format": "zip", "strip_prefix": "top" },
                                       "into": "Apogee/ACT" } }] },
                { "name": "act-config", "reason": "Its updater off.", "seeded": true,
                  "verify": ["{appdata}/Advanced Combat Tracker/Config/act.json"],
                  "ops": [{ "files": { "url": url, "sha256": pin,
                                       "archive": { "format": "zip", "strip_prefix": "top" },
                                       "into": "{appdata}/Advanced Combat Tracker/Config" } }] }
            ],
            "start": { "program": "Apogee/ACT/Advanced Combat Tracker.exe",
                       "args": ["-noicon"], "trigger": "with_game",
                       "env": { "WINEDLLOVERRIDES": "mscoree=b" } },
            "updater_keys": [{ "file": "{appdata}/Advanced Combat Tracker/Config/act.json",
                               "format": "json", "key": "cbAutoCheck", "off": "False" }],
            "evidence": { "path": "{appdata}/Advanced Combat Tracker/FFXIVLogs", "window_s": 180 }
        })
    }

    pub(crate) const PIN: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn with_programs(programs: &[serde_json::Value]) -> ComponentManifest {
        let json = serde_json::json!({
            "version": 1,
            "injectables": [{ "name": "Dalamud", "kind": "dalamud",
                              "distribution": "https://kamori.goats.dev/Dalamud/Release/VersionInfo",
                              "tier": "first_class" }],
            "verbs": [{ "name": "base", "reason": "r", "ops": [] }],
            "programs": programs,
        });
        ComponentManifest::from_json_bytes(json.to_string().as_bytes()).expect("parses")
    }

    /// Every field of a real-shaped row survives, with each path rooted where its token says.
    #[test]
    fn a_program_row_parses_every_field() {
        let manifest = with_programs(&[act_row("https://example.invalid/act.zip", PIN)]);
        assert!(
            manifest.refused_programs.is_empty(),
            "{:?}",
            manifest.refused_programs
        );
        let act = manifest.program("act").expect("row");
        assert!(act.supports_game("2026.11.03.0000.0000"));
        assert!(!act.supports_game("2026.11.03.0000.0001"));
        assert!(act.supports_runner(&RunnerRef {
            name: "GE-Proton".to_owned(),
            version: "11-12+remote-thread-actctx".to_owned(),
        }));
        assert!(!act.supports_runner(&RunnerRef {
            name: "GE-Proton".to_owned(),
            version: "11-12".to_owned(),
        }));
        assert_eq!(act.steps.len(), 2);
        assert!(!act.steps[0].seeded && act.steps[1].seeded);
        match act.steps[1].verb.ops.as_slice() {
            [VerbOp::Files { into, .. }] => {
                assert_eq!(into.root(), PathRoot::AppData);
                assert_eq!(into.as_path(), Path::new("Advanced Combat Tracker/Config"));
            }
            other => panic!("expected one files op, got {other:?}"),
        }
        assert_eq!(act.start.program.root(), PathRoot::DriveC);
        assert_eq!(
            act.start.trigger,
            Trigger::WithGame {
                keep_after_close: false
            }
        );
        assert_eq!(act.updater_keys[0].format, UpdaterKeyFormat::Json);
        assert_eq!(
            act.evidence.as_ref().map(|e| e.window),
            Some(Duration::from_secs(180))
        );
    }

    /// A row this build cannot read costs that row and nothing else: the injectable and the base verb
    /// a profile depends on are still there, and the refused row says which rule it broke.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn a_row_that_breaks_a_rule_costs_only_that_row() {
        let good = || act_row("https://example.invalid/act.zip", PIN);
        let edit = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut row = good();
            f(&mut row);
            row
        };
        let cases: Vec<(&str, serde_json::Value)> = vec![
            (
                "a key this build does not know",
                edit(&|r| {
                    r["overlay"] = serde_json::json!({ "steps": [] });
                }),
            ),
            (
                "a program kept past the game",
                edit(&|r| {
                    r["start"]["trigger"] = "on_close".into();
                }),
            ),
            (
                "an environment key outside the allowlist",
                edit(&|r| {
                    r["start"]["env"] = serde_json::json!({ "PYTHONPATH": "/tmp" });
                }),
            ),
            (
                "an override of the game's renderer",
                edit(&|r| {
                    r["start"]["env"] = serde_json::json!({ "WINEDLLOVERRIDES": "dxgi=n" });
                }),
            ),
            (
                "a start outside the launcher's own directory",
                edit(&|r| {
                    r["start"]["program"] = "Program Files/ACT/act.exe".into();
                }),
            ),
            (
                "a start in application data",
                edit(&|r| {
                    r["start"]["program"] = "{appdata}/Apogee/act.exe".into();
                }),
            ),
            (
                "a destination that climbs out",
                edit(&|r| {
                    r["steps"][0]["ops"][0]["files"]["into"] = "{appdata}/../../../x".into();
                }),
            ),
            (
                "an unknown token",
                edit(&|r| {
                    r["steps"][0]["ops"][0]["files"]["into"] = "{localappdata}/x".into();
                }),
            ),
            (
                "a run op",
                edit(&|r| {
                    r["steps"][0]["ops"] = serde_json::json!([{ "run": { "program": "x" } }]);
                }),
            ),
            (
                "no game version",
                edit(&|r| r["game_versions"] = serde_json::json!([])),
            ),
            (
                "a game version that is not one",
                edit(&|r| {
                    r["game_versions"] = serde_json::json!(["latest"]);
                }),
            ),
            ("no runner", edit(&|r| r["runners"] = serde_json::json!([]))),
            (
                "a malformed claim",
                edit(&|r| r["claims"] = serde_json::json!(["Pipe Name"])),
            ),
            (
                "an unknown updater format",
                edit(&|r| r["updater_keys"][0]["format"] = "ini".into()),
            ),
            (
                "an endless evidence window",
                edit(&|r| r["evidence"]["window_s"] = 86_400.into()),
            ),
            (
                "no pin",
                edit(&|r| {
                    r["steps"][0]["ops"][0]["files"]["sha256"] = serde_json::Value::Null;
                }),
            ),
        ];
        for (what, row) in cases {
            let manifest = with_programs(&[row]);
            assert!(
                manifest.program("act").is_none(),
                "{what}: the row must be refused"
            );
            let refused = manifest
                .refused_program("act")
                .unwrap_or_else(|| panic!("{what}: the refusal must be kept under the row's name"));
            assert!(!refused.reason.is_empty(), "{what}");
            assert!(
                manifest.verb("base").is_some(),
                "{what}: the base verb survives"
            );
            assert_eq!(manifest.injectables.len(), 1, "{what}: Dalamud survives");
        }
    }

    /// A step is recorded in the prefix under its own name beside the base verbs, so a step named like
    /// a verb would make the record ambiguous. It costs the program row; the verb still stands.
    #[test]
    fn a_step_named_like_a_base_verb_costs_the_row_and_not_the_verb() {
        let mut row = act_row("https://example.invalid/act.zip", PIN);
        row["steps"][0]["name"] = "base".into();
        let manifest = with_programs(&[row]);
        assert!(manifest.program("act").is_none());
        let refused = manifest.refused_program("act").expect("kept as refused");
        assert!(refused.reason.contains("\"base\""), "{}", refused.reason);
        assert!(manifest.verb("base").is_some());
        assert_eq!(manifest.injectables.len(), 1);
    }

    /// Two rows under one name are both refused whichever comes first, and so are two rows that
    /// share only a step; a third row that shares nothing is untouched.
    #[test]
    fn rows_that_share_a_name_are_all_refused_and_the_rest_stand() {
        let act = || act_row("https://example.invalid/act.zip", PIN);
        let renamed = |name: &str, steps: [&str; 2]| {
            let mut row = act();
            row["name"] = name.into();
            row["steps"][0]["name"] = steps[0].into();
            row["steps"][1]["name"] = steps[1].into();
            row
        };
        let other = renamed("other", ["other-files", "other-config"]);

        // The same program name, with no step in common.
        let twin = renamed("act", ["twin-files", "twin-config"]);
        for rows in [
            [act(), twin.clone(), other.clone()],
            [twin, other.clone(), act()],
        ] {
            let manifest = with_programs(&rows);
            assert!(manifest.program("act").is_none());
            assert_eq!(manifest.refused_programs.len(), 2);
            assert!(manifest.refused_programs.iter().all(|r| r.name == "act"));
            assert!(manifest.program("other").is_some());
            assert!(manifest.verb("base").is_some());
        }

        // One step in common, and a step named like the other program.
        for shared in [
            renamed("second", ["act-files", "second-config"]),
            renamed("second", ["second-files", "act"]),
        ] {
            let manifest = with_programs(&[act(), shared, other.clone()]);
            assert!(
                manifest
                    .programs
                    .iter()
                    .map(|p| p.name.as_str())
                    .eq(["other"])
            );
            assert!(manifest.refused_program("act").is_some());
            assert!(manifest.refused_program("second").is_some());
        }

        // One name used twice inside a single row.
        let manifest = with_programs(&[renamed("act", ["act", "act-config"]), other]);
        assert!(manifest.refused_program("act").is_some());
        assert!(manifest.program("other").is_some());
    }

    /// A row that could not be read still holds its name, so a readable row under the same name is
    /// refused with it rather than standing in for it. Each keeps its own reason.
    #[test]
    fn a_refused_rows_name_refuses_a_readable_row_that_shares_it() {
        let mut unreadable = act_row("https://example.invalid/act.zip", PIN);
        unreadable["tier"] = "unheard_of".into();
        let good = act_row("https://example.invalid/act.zip", PIN);
        for rows in [[unreadable.clone(), good.clone()], [good, unreadable]] {
            let manifest = with_programs(&rows);
            assert!(manifest.programs.is_empty());
            let reasons: Vec<&str> = manifest
                .refused_programs
                .iter()
                .filter(|r| r.name == "act")
                .map(|r| r.reason.as_str())
                .collect();
            assert_eq!(reasons.len(), 2);
            assert_eq!(
                reasons.iter().filter(|r| r.contains("both named")).count(),
                1,
                "{reasons:?}"
            );
            assert!(manifest.verb("base").is_some());
        }
    }

    /// A `programs` value that is not a list has no rows to read. That is recorded as one refusal
    /// under no name, and the injectables and verbs are read as if the key were absent.
    #[test]
    fn a_programs_value_that_is_not_a_list_costs_only_the_programs() {
        for programs in [
            serde_json::json!({ "act": {} }),
            serde_json::json!("act"),
            serde_json::json!(7),
        ] {
            let json = serde_json::json!({
                "version": 1,
                "verbs": [{ "name": "base", "reason": "r", "ops": [] }],
                "programs": programs,
            });
            let manifest = ComponentManifest::from_json_bytes(json.to_string().as_bytes())
                .expect("the rest of the manifest still parses");
            assert!(manifest.programs.is_empty());
            assert_eq!(manifest.refused_programs.len(), 1);
            assert!(manifest.verb("base").is_some());
        }
    }

    /// The token means something only at the head of a program row's path, and a base verb is read by
    /// builds that predate it, so there it stays the literal directory name those builds see.
    #[test]
    fn the_appdata_token_is_read_only_where_it_is_defined() {
        for (raw, expect) in [
            ("{appdata}/a/b", Some((PathRoot::AppData, "a/b"))),
            ("{appdata}\\a\\b", Some((PathRoot::AppData, "a/b"))),
            ("Apogee/a", Some((PathRoot::DriveC, "Apogee/a"))),
            ("{appdata}", None),
            ("{appdata}/", None),
            ("{appdata}x/a", None),
            ("a/{appdata}/b", None),
            ("{appdata}/../a", None),
        ] {
            let parsed = ComponentPath::parse_rooted(raw, "row").ok();
            assert_eq!(
                parsed.as_ref().map(|p| (p.root(), p.as_path())),
                expect.map(|(root, path)| (root, Path::new(path))),
                "{raw}"
            );
        }
        let base = ComponentPath::parse("{appdata}/a", "verb").expect("literal in a base verb");
        assert_eq!(base.root(), PathRoot::DriveC);
    }
}
