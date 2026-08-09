//! The one walk that produces every candidate entry.
//!
//! Rules are predicates over what this walk found, never enumerators of their own. That is what keeps
//! a rule from being paired with a traversal that cannot return the kind of entry it was written for,
//! and it means no rule can cover for another by sweeping the same subtree twice.

use std::path::Path;

use super::error::BackupError;
use super::root::{Presence, SelectionRoot};
use super::rule::{EntryKind, Expect, Rule};
use super::{RootReport, RuleReport, RuleRole, SelectedEntry};

/// How deep a config tree may nest before it is treated as hostile rather than merely unusual. The
/// real tree is three levels.
const MAX_WALK_DEPTH: usize = 32;

/// Per-rule match counts, kept positionally alongside the rule lists they belong to.
struct Counts {
    include: Vec<usize>,
    prune: Vec<usize>,
    deny: Vec<usize>,
}

/// Walk one root, returning its entries in discovery order and a report of what every rule did.
///
/// # Errors
/// [`BackupError::MissingRoot`] if a required root is absent, [`BackupError::RuleMatchedNothing`] if
/// a required rule matched no entry, and [`BackupError::Io`], [`BackupError::NonUtf8Name`] or
/// [`BackupError::TooDeep`] from reading the tree.
pub(super) fn walk(
    root: &SelectionRoot,
    deny: &[Rule],
) -> Result<(Vec<SelectedEntry>, RootReport), BackupError> {
    let mut counts = Counts {
        include: vec![0; root.include().len()],
        prune: vec![0; root.prune().len()],
        deny: vec![0; deny.len()],
    };
    let mut report = RootReport {
        label: root.label(),
        path: root.path().to_path_buf(),
        present: root.path().is_dir(),
        files: 0,
        dirs: 0,
        bytes: 0,
        links_skipped: 0,
        specials_skipped: 0,
        rules: Vec::new(),
    };
    let mut entries = Vec::new();

    if !report.present {
        if root.presence() == Presence::Required {
            return Err(BackupError::MissingRoot {
                path: root.path().to_path_buf(),
            });
        }
        report.rules = rule_reports(root, deny, &counts);
        return Ok((entries, report));
    }

    descend(
        root.path(),
        root.label().prefix(),
        0,
        true,
        root,
        deny,
        &mut counts,
        &mut report,
        &mut entries,
    )?;

    for (_, rules, tally) in role_lists(root, deny, &counts) {
        for (rule, matched) in rules.iter().zip(tally) {
            if rule.expect() == Expect::Required && *matched == 0 {
                return Err(BackupError::RuleMatchedNothing {
                    rule: rule.to_string(),
                    root: root.path().to_path_buf(),
                });
            }
        }
    }

    report.rules = rule_reports(root, deny, &counts);
    Ok((entries, report))
}

/// Read one directory, testing each entry deny, then prune, then include.
#[expect(
    clippy::too_many_arguments,
    reason = "one recursive walk, no shared state"
)]
fn descend(
    dir: &Path,
    archive_prefix: &str,
    depth: usize,
    at_root: bool,
    root: &SelectionRoot,
    deny: &[Rule],
    counts: &mut Counts,
    report: &mut RootReport,
    entries: &mut Vec<SelectedEntry>,
) -> Result<(), BackupError> {
    if depth > MAX_WALK_DEPTH {
        return Err(BackupError::TooDeep {
            path: dir.to_path_buf(),
            limit: MAX_WALK_DEPTH,
        });
    }
    let listing = std::fs::read_dir(dir).map_err(|source| BackupError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    for entry in listing {
        let entry = entry.map_err(|source| BackupError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let raw = entry.file_name();
        let Some(name) = raw.to_str() else {
            // Dropping a file because its name is not UTF-8 would be exactly the silent loss this
            // selection exists to rule out, so it stops the backup instead.
            return Err(BackupError::NonUtf8Name { path: entry.path() });
        };
        // `DirEntry::file_type` does not traverse a symlink, so this is the kind of the entry itself
        // rather than of whatever it points at.
        let file_type = entry.file_type().map_err(|source| BackupError::Io {
            path: entry.path(),
            source,
        })?;
        let kind = if file_type.is_file() {
            EntryKind::File
        } else if file_type.is_dir() {
            EntryKind::Dir
        } else if file_type.is_symlink() {
            // A prefix reaches one config tree through several links, so following them would
            // archive the same settings more than once under different names.
            report.links_skipped += 1;
            continue;
        } else {
            report.specials_skipped += 1;
            continue;
        };

        if let Some(at) = deny.iter().position(|r| r.matches(name, kind)) {
            counts.deny[at] += 1;
            continue;
        }
        if let Some(at) = root.prune().iter().position(|r| r.matches(name, kind)) {
            counts.prune[at] += 1;
            continue;
        }
        // Include applies only to a root's immediate children: below that, membership follows from
        // the directory above having been selected, so no include rule can mask another's miss.
        if at_root {
            let Some(at) = root.include().iter().position(|r| r.matches(name, kind)) else {
                continue;
            };
            counts.include[at] += 1;
        }

        let archive_name = format!("{archive_prefix}/{name}");
        match kind {
            EntryKind::File => {
                let size = entry
                    .metadata()
                    .map_err(|source| BackupError::Io {
                        path: entry.path(),
                        source,
                    })?
                    .len();
                report.files += 1;
                report.bytes += size;
                entries.push(SelectedEntry {
                    name: archive_name,
                    source: entry.path(),
                    kind,
                });
            }
            EntryKind::Dir => {
                report.dirs += 1;
                // The trailing separator is what marks a directory in the archive, and carrying it
                // here rather than at write time keeps one name and therefore one sort order. It also
                // keeps a directory ahead of its contents under a byte sort even when a sibling name
                // would otherwise fall between them, since `/` outranks the characters that could.
                entries.push(SelectedEntry {
                    name: format!("{archive_name}/"),
                    source: entry.path(),
                    kind,
                });
                descend(
                    &entry.path(),
                    &archive_name,
                    depth + 1,
                    false,
                    root,
                    deny,
                    counts,
                    report,
                    entries,
                )?;
            }
        }
    }
    Ok(())
}

/// The three rule lists paired with their roles and counts, in precedence order.
fn role_lists<'a>(
    root: &'a SelectionRoot,
    deny: &'a [Rule],
    counts: &'a Counts,
) -> [(RuleRole, &'a [Rule], &'a [usize]); 3] {
    [
        (RuleRole::Deny, deny, &counts.deny),
        (RuleRole::Prune, root.prune(), &counts.prune),
        (RuleRole::Include, root.include(), &counts.include),
    ]
}

/// Every rule of every role with its count, so a rule that matched nothing is a zero on the report
/// rather than an absence nobody can see.
fn rule_reports(root: &SelectionRoot, deny: &[Rule], counts: &Counts) -> Vec<RuleReport> {
    role_lists(root, deny, counts)
        .into_iter()
        .flat_map(|(role, rules, tally)| {
            rules
                .iter()
                .zip(tally)
                .map(move |(rule, matched)| RuleReport {
                    role,
                    rule: rule.to_string(),
                    matched: *matched,
                })
        })
        .collect()
}
