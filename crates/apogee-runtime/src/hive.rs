//! Reading a prefix's own registry files, so a caller can ask what is in the registry without
//! starting the runner.
//!
//! `reg query` is the accurate way to ask a *live* prefix, and it is what the write path uses to
//! read a removal it could not report on. It is the wrong way to ask a prefix that is not running:
//! every query is a windows program launched through the runner, and under Proton that means umu
//! bringing up its whole container for a single answer (measured at roughly four seconds). A caller
//! that asks on every launch, about a value that is almost always still there, would pay that every
//! time to be told nothing changed.
//!
//! # The file
//!
//! A prefix keeps its registry as UTF-8 text at its root, one file per root: `user.reg` holds
//! `HKEY_CURRENT_USER` and `system.reg` holds `HKEY_LOCAL_MACHINE`, each opening with the line
//! `WINE REGISTRY Version 2`. Keys are spelled relative to the root their file holds, so
//! `HKCU\Software\Wine` is written `[Software\\Wine] 1785455678`, the trailing number being a
//! modification time. A key's values follow it, one per line, as `"name"=data`, with its default
//! value written `@=data`. Data is a quoted string for `REG_SZ`, `str(2):` and a quoted string for
//! `REG_EXPAND_SZ`, `dword:` and hex digits for `REG_DWORD`, and a `hex` form of comma-separated
//! bytes for everything else, wrapping onto indented continuation lines when it is long. Key names,
//! value names and strings are escaped: `\\`, `\"`, the usual `\n`-style control escapes, and `\x`
//! with four hex digits for anything else. Names are case-insensitive. Blank lines, `;;` comments
//! and `#arch=`/`#time=` directives carry nothing this reads.
//!
//! Two properties make that read trustworthy at the point it is taken. Nothing has run in the prefix
//! yet, so the files are what the last wineserver flushed and there is no in-memory registry they
//! are behind. And an unreadable file is a distinct answer rather than an absence, the same
//! distinction the live path draws with its control probe, since "it is gone" and "nothing could be
//! read" have opposite consequences for a caller that reapplies what is missing.
//!
//! **The flush is asynchronous**, which is what confines this to that moment. A wineserver persists
//! the registry on an idle shutdown some time after the program that wrote it exited, so a read
//! taken straight after a write can still show the old file. Reading these files to check what a
//! write just did would therefore report a value that landed as missing; that check belongs to
//! `reg add`'s own exit status, which the write path already reads.
//!
//! Only the two roots a prefix keeps in a file of their own are answerable here. `HKEY_CLASSES_ROOT`
//! is a merge of two subtrees rather than a file, and `HKEY_CURRENT_CONFIG` is volatile, so a
//! question about either is reported as unanswerable instead of guessed at.

use std::path::{Path, PathBuf};

use crate::registry::{RegistryDelete, RegistryEdit, RegistryValue};

/// Whether a prefix still carries what a registry op declared it would produce.
///
/// Three answers rather than two. A registry file that cannot be read and a root this build does
/// not locate are always [`Self::Unknown`], and reading either as an absence would have a caller
/// reapply a step forever against a prefix it cannot see into. A value in an encoding this build
/// does not decode is [`Self::Unknown`] for an edit, where the question is whether the data matches,
/// and counts as found for a removal, where the question is only whether anything is there. Produced by [`crate::Prefix::registry_effect`] and
/// [`crate::Prefix::registry_removal_effect`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegistryEffect {
    /// The prefix's registry holds what the op declared.
    Present,
    /// The registry was read and does not hold it.
    Absent,
    /// It could not be answered from the prefix's own files.
    Unknown {
        /// The reading that says why there is no answer.
        reason: &'static str,
    },
}

/// The registry file holding `HKEY_CURRENT_USER`.
const USER_HIVE: &str = "user.reg";
/// The registry file holding `HKEY_LOCAL_MACHINE`.
const MACHINE_HIVE: &str = "system.reg";

/// The first line of every wine registry file. Its absence means whatever is at that path is not
/// one.
const HIVE_HEADER: &str = "WINE REGISTRY Version 2";

/// The readings that make an answer [`RegistryEffect::Unknown`].
const NO_SUCH_ROOT: &str = "that registry root is not one a prefix keeps in a file of its own";
const UNREADABLE: &str = "this prefix has no registry file that can be read for that root";
const NOT_A_HIVE: &str = "the prefix's registry file is not in a form this build reads";
const UNDECODED: &str = "the value is stored in an encoding this build does not decode";

/// Whether `edit`'s value is in `wine_root`'s registry, as it was written.
///
/// The value is compared, not merely looked for: type and data both have to match, so an override
/// overwritten with something else this build decodes is [`RegistryEffect::Absent`] just as surely
/// as one that was removed, while one it cannot decode is [`RegistryEffect::Unknown`]. An empty `REG_SZ` reads back as [`RegistryValue::Disabled`], which is how the writer
/// spells it.
pub(crate) fn edit_effect(wine_root: &Path, edit: &RegistryEdit) -> RegistryEffect {
    let (path, key) = match locate(wine_root, &edit.key) {
        Ok(located) => located,
        Err(reason) => return RegistryEffect::Unknown { reason },
    };
    match scan(&path, &key, Some(&edit.name)) {
        Err(reason) => RegistryEffect::Unknown { reason },
        Ok(found) => match found.value {
            None => RegistryEffect::Absent,
            Some(Stored::Opaque) => RegistryEffect::Unknown { reason: UNDECODED },
            Some(Stored::Known(value)) if value == edit.value => RegistryEffect::Present,
            Some(Stored::Known(_)) => RegistryEffect::Absent,
        },
    }
}

/// Whether what `delete` removes is still gone from `wine_root`'s registry.
///
/// A removal's effect is an absence, so the readings are inverted: finding the target is what says
/// the effect is gone. A whole-key removal is answered by the key or anything below it, and a value
/// in an encoding this build cannot decode is still a value that is there, so it counts as found
/// rather than as no answer.
pub(crate) fn removal_effect(wine_root: &Path, delete: &RegistryDelete) -> RegistryEffect {
    let (path, key) = match locate(wine_root, &delete.key) {
        Ok(located) => located,
        Err(reason) => return RegistryEffect::Unknown { reason },
    };
    let found = match scan(&path, &key, delete.name.as_deref()) {
        Ok(found) => found,
        Err(reason) => return RegistryEffect::Unknown { reason },
    };
    let still_there = match delete.name {
        Some(_) => found.value.is_some(),
        None => found.key_seen,
    };
    if still_there {
        RegistryEffect::Absent
    } else {
        RegistryEffect::Present
    }
}

/// The registry file `key` lives in, and `key` with its root stripped, since a file's keys are
/// stored relative to the root it holds.
///
/// # Errors
/// [`NO_SUCH_ROOT`] for a root no prefix keeps in a file of its own.
fn locate(wine_root: &Path, key: &str) -> Result<(PathBuf, String), &'static str> {
    let (root, rest) = key.split_once('\\').unwrap_or((key, ""));
    let file = match root.to_ascii_uppercase().as_str() {
        "HKCU" | "HKEY_CURRENT_USER" => USER_HIVE,
        "HKLM" | "HKEY_LOCAL_MACHINE" => MACHINE_HIVE,
        _ => return Err(NO_SUCH_ROOT),
    };
    Ok((wine_root.join(file), rest.to_owned()))
}

/// What one value under one key turned out to be.
enum Stored {
    /// Decoded into a value of a type this launcher writes.
    Known(RegistryValue),
    /// There, but written in a form this build does not decode.
    Opaque,
}

/// What a pass over a registry file found out about one key and one of its values.
#[derive(Default)]
struct Found {
    /// The key itself, or something below it, was declared.
    key_seen: bool,
    /// What the key held under the name asked about, if anything.
    value: Option<Stored>,
}

/// Read `path` for `key`, and for `name` within it when one is asked about.
///
/// A streaming pass rather than a parse into a tree: a machine hive is a few megabytes of keys
/// nothing here is asking about, and the question is always one value.
///
/// # Errors
/// [`UNREADABLE`] if the file cannot be read, [`NOT_A_HIVE`] if it does not open with the wine
/// registry header.
fn scan(path: &Path, key: &str, name: Option<&str>) -> Result<Found, &'static str> {
    let text = std::fs::read_to_string(path).map_err(|_| UNREADABLE)?;
    let mut lines = text.lines();
    if !lines
        .next()
        .is_some_and(|first| first.starts_with(HIVE_HEADER))
    {
        return Err(NOT_A_HIVE);
    }

    let mut found = Found::default();
    let mut in_key = false;
    // Nothing tracks which lines continue an earlier one. Long data is the only thing written over
    // several lines, it is always hex, and its continuations are indented, so such a line matches
    // neither the key shape nor the value shape and falls through like a comment or a blank.
    for line in lines {
        if let Some(rest) = line.strip_prefix('[') {
            in_key = false;
            // The last one on the line: a key name may itself carry a bracket, and what follows the
            // closing one is the key's modification time rather than part of its name.
            let Some(end) = rest.rfind(']') else { continue };
            let Some(declared) = unescape(&rest[..end]) else {
                continue;
            };
            in_key = declared.eq_ignore_ascii_case(key);
            if in_key || is_below(&declared, key) {
                found.key_seen = true;
            }
            continue;
        }
        let (Some(name), true) = (name, in_key) else {
            continue;
        };
        if let Some(stored) = value_on(line, name) {
            found.value = Some(stored);
            // The key's values are written once, in one block, so the answer cannot change later in
            // the file.
            break;
        }
    }
    Ok(found)
}

/// Whether `declared` names a key below `key`, by whole component rather than by string prefix.
fn is_below(declared: &str, key: &str) -> bool {
    declared
        .get(..key.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(key))
        && declared[key.len()..].starts_with('\\')
}

/// What `line` stores for `name`, or `None` when it is not that value's line.
///
/// A value line is `"name"=data`. The default value is written `@=data`, which no op can name: both
/// [`RegistryEdit`] and [`RegistryDelete`] refuse an empty value name.
fn value_on(line: &str, name: &str) -> Option<Stored> {
    let (declared, rest) = split_quoted(line.strip_prefix('"')?)?;
    let data = rest.strip_prefix('=')?;
    // An escape this build does not know makes the name unreadable, which means it is not the one
    // being looked for rather than that the line is undecodable.
    if !unescape(declared)?.eq_ignore_ascii_case(name) {
        return None;
    }
    Some(decode(data))
}

/// Decode the right-hand side of a value line.
///
/// Wine writes a quoted string for `REG_SZ`, a `str(2):`-tagged quoted string for `REG_EXPAND_SZ`,
/// `dword:` for `REG_DWORD`, and a comma-separated `hex` form for everything else. Only the hex
/// forms are left [`Stored::Opaque`]: nothing this launcher writes comes back in one, and a decoder
/// for a form no verb produces would be a guess with no subject.
fn decode(data: &str) -> Stored {
    if let Some(body) = quoted_body(data) {
        return match unescape(body) {
            // An empty `REG_SZ` is spelled as its own value: `RegistryValue::String` is documented as
            // never empty, and decoding one into it would produce a value the writer refuses.
            Some(text) if text.is_empty() => Stored::Known(RegistryValue::Disabled),
            Some(text) => Stored::Known(RegistryValue::String(text)),
            None => Stored::Opaque,
        };
    }
    if let Some(body) = data.strip_prefix("str(2):").and_then(quoted_body) {
        return match unescape(body) {
            Some(text) => Stored::Known(RegistryValue::ExpandString(text)),
            None => Stored::Opaque,
        };
    }
    if let Some(digits) = data.strip_prefix("dword:") {
        return match u32::from_str_radix(digits, 16) {
            Ok(number) => Stored::Known(RegistryValue::Dword(number)),
            Err(_) => Stored::Opaque,
        };
    }
    Stored::Opaque
}

/// The contents of `data` when it is exactly one quoted string and nothing else.
fn quoted_body(data: &str) -> Option<&str> {
    let (body, rest) = split_quoted(data.strip_prefix('"')?)?;
    rest.is_empty().then_some(body)
}

/// Split at the first unescaped quote: the still-escaped contents, and whatever follows the quote.
/// `s` starts just after the opening one.
fn split_quoted(s: &str) -> Option<(&str, &str)> {
    let mut escaped = false;
    for (at, c) in s.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == '"' {
            return Some((&s[..at], &s[at + 1..]));
        }
    }
    None
}

/// Undo the escaping wine writes key names, value names and strings with, or `None` for an escape
/// this build does not know.
///
/// `None` rather than a lossy best effort: every caller is comparing the result against something,
/// and a dropped escape would make two different strings compare equal.
fn unescape(raw: &str) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            '\\' => '\\',
            '"' => '"',
            'a' => '\u{7}',
            'b' => '\u{8}',
            'e' => '\u{1b}',
            'f' => '\u{c}',
            'n' => '\n',
            'r' => '\r',
            't' => '\t',
            'v' => '\u{b}',
            // Four hex digits, which is what the writer emits for anything else.
            'x' => {
                let mut code = 0u32;
                for _ in 0..4 {
                    code = code * 16 + chars.next()?.to_digit(16)?;
                }
                char::from_u32(code)?
            }
            _ => return None,
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape of a real `user.reg`, down to the header comment and the per-key modification
    /// times. Written out rather than generated, because what these tests are about is reading the
    /// format wine writes rather than one this file also produces.
    const USER_REG: &str = concat!(
        "WINE REGISTRY Version 2\n",
        ";; All keys relative to REGISTRY\\\\User\\\\S-1-5-21-0-0-0-1000\n",
        "\n",
        "#arch=win64\n",
        "\n",
        "[Console] 1785455689\n",
        "#time=1dd207ecec3e60e\n",
        "\"ColorTable00\"=dword:00000000\n",
        "\"CaptionFont\"=hex:0a,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,90,01,\\\n",
        "  00,00,00,00,00,01,00,00,00,00,54,00,61,00,68,00,6f,00,6d,00,61,00,00,00\n",
        "\"CursorSize\"=dword:00000019\n",
        "\"FaceName\"=str(2):\"%SystemRoot%\\\\fonts\"\n",
        "\n",
        "[Software\\\\Wine\\\\DllOverrides] 1785455678\n",
        "#time=1dd207ec7eef92c\n",
        "\"winemenubuilder.exe\"=\"\"\n",
        "\"d3d11\"=\"native,builtin\"\n",
        "\"Path\"=\"C:\\\\\"\n",
        "\n",
        "[Software\\\\Wine\\\\Drivers\\\\winepulse.drv] 1784353449\n",
        "\"guid\"=hex:9f,7f,7e,2d,b6,01,1b,47\n",
    );

    /// A prefix root holding `contents` as its user hive, plus whatever else a case needs.
    fn hive(contents: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(USER_HIVE), contents).expect("write the hive");
        dir
    }

    fn edit(key: &str, name: &str, value: RegistryValue) -> RegistryEdit {
        RegistryEdit {
            key: key.to_owned(),
            name: name.to_owned(),
            value,
        }
    }

    /// The op the hosted catalog actually ships.
    fn shipped() -> RegistryEdit {
        edit(
            r"HKCU\Software\Wine\DllOverrides",
            "winemenubuilder.exe",
            RegistryValue::Disabled,
        )
    }

    /// The reading the whole thing exists for: the value a shipped verb writes is found in the file
    /// wine wrote it to, in each of the types this decodes, with no runner started.
    #[test]
    fn the_value_a_verb_wrote_is_read_back_out_of_the_prefix() {
        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(dir.path(), &shipped()),
            RegistryEffect::Present,
            "an empty REG_SZ is what `disabled` means, and it has to read back as one"
        );
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCU\Software\Wine\DllOverrides",
                    "d3d11",
                    RegistryValue::String("native,builtin".to_owned())
                )
            ),
            RegistryEffect::Present
        );
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(r"HKCU\Console", "CursorSize", RegistryValue::Dword(0x19))
            ),
            RegistryEffect::Present
        );
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCU\Console",
                    "FaceName",
                    RegistryValue::ExpandString(r"%SystemRoot%\fonts".to_owned())
                )
            ),
            RegistryEffect::Present,
            "an expand string is written quoted with its type, and its escapes have to come back out"
        );
    }

    /// The failure this reader was built for, proved live: the value removed from under the launcher
    /// with `wine reg delete`, which leaves the key and its neighbours in place.
    #[test]
    fn a_value_removed_from_a_key_that_is_still_there_reads_as_absent() {
        let dir = hive(&USER_REG.replace("\"winemenubuilder.exe\"=\"\"\n", ""));
        assert_eq!(edit_effect(dir.path(), &shipped()), RegistryEffect::Absent);
    }

    /// A whole key removed takes its values with it, and an absent key is an absent value rather
    /// than a file that could not answer.
    #[test]
    fn a_key_that_is_not_in_the_file_reads_as_absent() {
        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCU\Software\Wine\NotAKey",
                    "any",
                    RegistryValue::Dword(1)
                )
            ),
            RegistryEffect::Absent
        );
    }

    /// Overwritten is undone. A verb's effect is the value it wrote, so a key still carrying the
    /// name under a different value has lost that effect exactly as a removal would.
    #[test]
    fn a_value_overwritten_with_something_else_is_not_the_effect_that_was_applied() {
        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCU\Software\Wine\DllOverrides",
                    "winemenubuilder.exe",
                    RegistryValue::String("builtin".to_owned())
                )
            ),
            RegistryEffect::Absent
        );
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(r"HKCU\Console", "CursorSize", RegistryValue::Dword(1))
            ),
            RegistryEffect::Absent
        );
    }

    /// Registry names are case-insensitive, and a hive records whichever spelling the writer used. A
    /// case-sensitive comparison would report a verb's own value as gone.
    #[test]
    fn a_key_or_name_that_differs_only_in_case_is_the_same_one() {
        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"hkcu\SOFTWARE\wine\dllOVERRIDES",
                    "WineMenuBuilder.EXE",
                    RegistryValue::Disabled
                )
            ),
            RegistryEffect::Present
        );
    }

    /// The three ways there is no answer, none of which a caller may read as an absence: it would
    /// reapply a verb on every launch against a prefix it cannot see into.
    #[test]
    fn nothing_that_could_not_be_read_is_reported_as_gone() {
        let empty = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            edit_effect(empty.path(), &shipped()),
            RegistryEffect::Unknown { reason: UNREADABLE },
            "a prefix with no registry file has not answered"
        );

        let not_a_hive = hive("[Software\\\\Wine\\\\DllOverrides]\n\"winemenubuilder.exe\"=\"\"\n");
        assert_eq!(
            edit_effect(not_a_hive.path(), &shipped()),
            RegistryEffect::Unknown { reason: NOT_A_HIVE },
            "a file with no wine header is not a hive, however much it looks like one"
        );

        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCR\CLSID\Something",
                    "Value",
                    RegistryValue::String("x".to_owned())
                )
            ),
            RegistryEffect::Unknown {
                reason: NO_SUCH_ROOT
            },
            "HKCR is a merge of two subtrees, so no one file holds the answer"
        );
    }

    /// A value stored in an encoding this build does not decode is there but unreadable, which is
    /// not the same as gone. Reading it as gone would rewrite it on every launch.
    #[test]
    fn a_value_in_an_encoding_this_build_does_not_decode_is_not_an_absence() {
        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCU\Software\Wine\Drivers\winepulse.drv",
                    "guid",
                    RegistryValue::String("anything".to_owned())
                )
            ),
            RegistryEffect::Unknown { reason: UNDECODED }
        );
    }

    /// Binary data runs over many lines, each continuing the last. The pass has to walk through one
    /// without losing the key it is in or picking up a line of hex as a value.
    #[test]
    fn a_value_written_over_several_lines_does_not_derail_the_pass() {
        let dir = hive(USER_REG);
        // Both of these sit after the multi-line value: the first inside the same key, the second in
        // the next one.
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(r"HKCU\Console", "CursorSize", RegistryValue::Dword(0x19))
            ),
            RegistryEffect::Present,
            "the key it was in is still the key after it"
        );
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCU\Software\Wine\DllOverrides",
                    "d3d11",
                    RegistryValue::String("native,builtin".to_owned())
                )
            ),
            RegistryEffect::Present,
            "the key after the continuation is still found"
        );
    }

    /// A backslash inside a value is written escaped, and so is the separator between key
    /// components. Comparing the escaped text instead of the value would make `C:\` and `C:\\`
    /// different strings.
    #[test]
    fn an_escaped_backslash_is_one_backslash() {
        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKCU\Software\Wine\DllOverrides",
                    "Path",
                    RegistryValue::String(r"C:\".to_owned())
                )
            ),
            RegistryEffect::Present
        );
    }

    /// The machine hive is a separate file, so a question about `HKLM` must not be answered out of
    /// the user one, and both spellings of a root name the same file.
    #[test]
    fn each_root_is_read_from_its_own_file() {
        let dir = hive(USER_REG);
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKLM\Software\Wine\DllOverrides",
                    "winemenubuilder.exe",
                    RegistryValue::Disabled
                )
            ),
            RegistryEffect::Unknown { reason: UNREADABLE },
            "there is no machine hive here to answer from"
        );

        std::fs::write(
            dir.path().join(MACHINE_HIVE),
            concat!(
                "WINE REGISTRY Version 2\n",
                ";; All keys relative to REGISTRY\\\\Machine\n",
                "\n",
                "[Software\\\\Wine\\\\DllOverrides] 1\n",
                "\"winemenubuilder.exe\"=\"\"\n",
            ),
        )
        .expect("write the machine hive");
        assert_eq!(
            edit_effect(
                dir.path(),
                &edit(
                    r"HKEY_LOCAL_MACHINE\Software\Wine\DllOverrides",
                    "winemenubuilder.exe",
                    RegistryValue::Disabled
                )
            ),
            RegistryEffect::Present,
            "and the long spelling of the root names the same file"
        );
    }

    fn removal(key: &str, name: Option<&str>) -> RegistryDelete {
        RegistryDelete {
            key: key.to_owned(),
            name: name.map(str::to_owned),
        }
    }

    /// A removal's effect is an absence, so the readings invert: what is still in the file is the
    /// effect being gone.
    #[test]
    fn a_removals_effect_is_present_exactly_when_its_target_is_not() {
        let dir = hive(USER_REG);
        assert_eq!(
            removal_effect(
                dir.path(),
                &removal(r"HKCU\Software\Wine\DllOverrides", Some("d3d11"))
            ),
            RegistryEffect::Absent,
            "the value it removes is back, so the removal no longer holds"
        );
        assert_eq!(
            removal_effect(
                dir.path(),
                &removal(r"HKCU\Software\Wine\DllOverrides", Some("d3d9"))
            ),
            RegistryEffect::Present
        );
    }

    /// A whole-key removal is answered by the key, not by any value in it, and a key is still there
    /// while anything below it is.
    #[test]
    fn a_key_removal_reads_the_subtree_rather_than_a_value() {
        let dir = hive(USER_REG);
        assert_eq!(
            removal_effect(dir.path(), &removal(r"HKCU\Software\Wine\Drivers", None)),
            RegistryEffect::Absent,
            "the key itself has no line, but a key below it does, so the subtree is still there"
        );
        assert_eq!(
            removal_effect(dir.path(), &removal(r"HKCU\Software\Wine\Gone", None)),
            RegistryEffect::Present
        );
        assert_eq!(
            removal_effect(
                dir.path(),
                &removal(r"HKCU\Software\Wine\DllOverride", None)
            ),
            RegistryEffect::Present,
            "a key whose name is a prefix of another's is not that other one"
        );
    }

    /// An unreadable value is still a value that is there. A removal that read it as no answer would
    /// leave a caller unable to tell the removal never happened.
    #[test]
    fn a_removals_target_counts_as_there_even_when_it_cannot_be_decoded() {
        let dir = hive(USER_REG);
        assert_eq!(
            removal_effect(
                dir.path(),
                &removal(r"HKCU\Software\Wine\Drivers\winepulse.drv", Some("guid"))
            ),
            RegistryEffect::Absent
        );
    }

    /// The escapes the writer emits, round-tripped. An unknown one yields nothing rather than a
    /// string missing a character, since every caller compares what comes back.
    #[test]
    fn unescaping_covers_what_the_writer_emits_and_refuses_what_it_does_not() {
        assert_eq!(unescape("plain").as_deref(), Some("plain"));
        assert_eq!(unescape(r"a\\b").as_deref(), Some(r"a\b"));
        assert_eq!(unescape(r#"a\"b"#).as_deref(), Some("a\"b"));
        assert_eq!(unescape(r"a\nb\tc").as_deref(), Some("a\nb\tc"));
        assert_eq!(unescape(r"\x00e9").as_deref(), Some("é"));
        assert_eq!(unescape(r"a\q"), None, "an escape the writer never emits");
        assert_eq!(unescape(r"a\x00"), None, "a truncated hex escape");
        assert_eq!(unescape(r"trailing\"), None);
        assert_eq!(unescape(r"\xd800"), None, "a lone surrogate is not a char");
    }

    /// A file with no keys at all is a readable answer, not a broken one: a prefix can legitimately
    /// have nothing under the key being asked about.
    #[test]
    fn a_hive_with_nothing_in_it_still_answers() {
        let dir = hive("WINE REGISTRY Version 2\n");
        assert_eq!(edit_effect(dir.path(), &shipped()), RegistryEffect::Absent);
        assert_eq!(
            removal_effect(
                dir.path(),
                &removal(r"HKCU\Software\Wine\DllOverrides", None)
            ),
            RegistryEffect::Present
        );
    }
}
