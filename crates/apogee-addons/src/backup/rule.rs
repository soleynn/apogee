//! What a selection rule matches.
//!
//! A rule is a kind plus a test over one filename component. Both halves exist to close off a way of
//! matching nothing without saying so. The kind is written down by the author and compared against
//! the kind the walk observed, rather than being whatever the enumerator behind the rule happened to
//! return; and the test folds case on both sides, so a rule cannot work on a case-insensitive
//! filesystem and quietly match nothing on a case-sensitive one.

use std::fmt;

/// The kind of directory entry a rule matches, and the kind a walk found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory. Selecting one selects everything under it.
    Dir,
}

/// How a rule tests one filename component. Every variant folds ASCII case on both sides, and there
/// is no case-sensitive variant to reach for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameMatch {
    /// Every name, leaving the rule's kind as the only test.
    Any,
    /// The whole component.
    Exact(String),
    /// A leading run, for a name that ends in an id.
    Prefix(String),
    /// A trailing run. A doubled extension belongs to the outer one, so `ADDON.DAT.old` is matched by
    /// `Suffix(".old")` and never by `Suffix(".DAT")`.
    Suffix(String),
}

impl NameMatch {
    /// Test one component. Slicing goes through `str::get` so a multi-byte name whose boundaries do
    /// not line up with the pattern length answers `false` instead of panicking.
    fn test(&self, name: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(want) => name.eq_ignore_ascii_case(want),
            Self::Prefix(want) => name
                .get(..want.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(want)),
            Self::Suffix(want) => name
                .len()
                .checked_sub(want.len())
                .and_then(|at| name.get(at..))
                .is_some_and(|tail| tail.eq_ignore_ascii_case(want)),
        }
    }
}

impl fmt::Display for NameMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("*"),
            Self::Exact(name) => f.write_str(name),
            Self::Prefix(head) => write!(f, "{head}*"),
            Self::Suffix(tail) => write!(f, "*{tail}"),
        }
    }
}

/// What zero matches for a rule means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// Zero matches fails the backup, naming the rule.
    Required,
    /// Zero matches is recorded with a count of zero and the backup continues.
    Optional,
}

/// One selection rule: the kind of entry it can match, and the test its name must pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    kind: EntryKind,
    name: NameMatch,
    expect: Expect,
}

impl Rule {
    /// A rule that can only ever match a directory.
    #[must_use]
    pub fn dir(name: NameMatch, expect: Expect) -> Self {
        Self {
            kind: EntryKind::Dir,
            name,
            expect,
        }
    }

    /// A rule that can only ever match a regular file.
    #[must_use]
    pub fn file(name: NameMatch, expect: Expect) -> Self {
        Self {
            kind: EntryKind::File,
            name,
            expect,
        }
    }

    /// The kind of entry this rule matches.
    #[must_use]
    pub fn kind(&self) -> EntryKind {
        self.kind
    }

    /// What zero matches means for this rule.
    #[must_use]
    pub fn expect(&self) -> Expect {
        self.expect
    }

    /// Whether `name` of `kind` matches. `kind` is what the walk observed, so a rule written for one
    /// kind cannot silently be applied to the other.
    #[must_use]
    pub fn matches(&self, name: &str, kind: EntryKind) -> bool {
        self.kind == kind && self.name.test(name)
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.kind {
            EntryKind::File => "file",
            EntryKind::Dir => "dir",
        };
        write!(f, "{kind} {}", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kind is compared against what the walk found, so neither kind of rule can pick up the
    /// other. Pairing a rule written for directories with a traversal that only ever yields files
    /// makes it match nothing while still looking like it covers something.
    #[test]
    fn a_rule_never_matches_the_other_kind_of_entry() {
        let names = [
            NameMatch::Any,
            NameMatch::Exact("cfgcopy".into()),
            NameMatch::Prefix("FFXIV_CHR".into()),
            NameMatch::Suffix(".DAT".into()),
        ];
        for name in names {
            let as_dir = Rule::dir(name.clone(), Expect::Optional);
            let as_file = Rule::file(name, Expect::Optional);
            assert!(!as_dir.matches("cfgcopy", EntryKind::File));
            assert!(!as_dir.matches("FFXIV_CHR004000174C116E58", EntryKind::File));
            assert!(!as_file.matches("cfgcopy", EntryKind::Dir));
            assert!(!as_file.matches("FFXIV_CHR004000174C116E58", EntryKind::Dir));
        }
    }

    /// Case folds on both sides. The real config tree mixes casings within one subtree: character
    /// payloads are uppercase `.DAT` while the `cfgcopy` payload is lowercase `.dat`, so neither
    /// picking a case nor normalizing to one would do.
    #[test]
    fn matching_folds_case_across_the_casings_the_game_actually_writes() {
        let cases = [
            ("HOTBAR.DAT", NameMatch::Suffix(".dat".into())),
            (
                "FFXIV_CFGCPYB4E9C66C1760C0EE.dat",
                NameMatch::Suffix(".DAT".into()),
            ),
            ("FFXIV.cfg", NameMatch::Suffix(".CFG".into())),
            ("ADDON.DAT.old", NameMatch::Suffix(".OLD".into())),
            (
                "FFXIV_CHR004000174C116E58",
                NameMatch::Prefix("ffxiv_chr".into()),
            ),
            ("Accounts.JSON", NameMatch::Exact("accounts.json".into())),
        ];
        for (name, matcher) in cases {
            assert!(
                Rule::file(matcher.clone(), Expect::Optional).matches(name, EntryKind::File),
                "{matcher} should match {name}"
            );
        }
    }

    /// A doubled extension belongs to its outer half, so a rule for the payload extension does not
    /// also sweep in the game's previous-generation shadows.
    #[test]
    fn a_rotation_shadow_is_not_matched_by_the_extension_it_shadows() {
        let dat = Rule::file(NameMatch::Suffix(".dat".into()), Expect::Optional);
        assert!(dat.matches("ADDON.DAT", EntryKind::File));
        assert!(!dat.matches("ADDON.DAT.old", EntryKind::File));
    }

    /// A pattern longer than the name, or one landing mid-character, answers false rather than
    /// panicking on a slice.
    #[test]
    fn a_pattern_longer_than_the_name_or_astride_a_character_is_just_a_miss() {
        let long = Rule::file(NameMatch::Prefix("FFXIV_CHR".into()), Expect::Optional);
        assert!(!long.matches("FF", EntryKind::File));
        let tail = Rule::file(NameMatch::Suffix(".dat".into()), Expect::Optional);
        assert!(!tail.matches("d", EntryKind::File));
        // The pattern length falls inside the multi-byte character rather than on a boundary.
        let mid = Rule::file(NameMatch::Prefix("ab".into()), Expect::Optional);
        assert!(!mid.matches("a\u{00e9}b", EntryKind::File));
    }

    /// The rendering is the report and manifest key, so it has to separate the kinds and survive a
    /// round trip through a human reading it.
    #[test]
    fn a_rule_renders_its_kind_and_its_test() {
        assert_eq!(
            Rule::dir(NameMatch::Prefix("FFXIV_CHR".into()), Expect::Optional).to_string(),
            "dir FFXIV_CHR*"
        );
        assert_eq!(
            Rule::file(NameMatch::Suffix(".old".into()), Expect::Optional).to_string(),
            "file *.old"
        );
        assert_eq!(
            Rule::dir(NameMatch::Any, Expect::Optional).to_string(),
            "dir *"
        );
        assert_eq!(
            Rule::file(NameMatch::Exact("accounts.json".into()), Expect::Optional).to_string(),
            "file accounts.json"
        );
    }
}
