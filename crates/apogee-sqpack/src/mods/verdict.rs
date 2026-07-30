//! What the comparison says, and how exactly it says it.
//!
//! Deliberately not [`crate::integrity::Defect`]. That taxonomy's contract is one variant per rule a
//! pristine install keeps, so every one of its arms is a fault; these arms include *pristine*, and
//! two of the others describe an install that is working exactly as its owner intended. A modded
//! install is not a damaged one, and a vocabulary that cannot say so would push the launcher into the
//! worst mistake available to it.

use std::fmt;

use crate::integrity::ContainerRef;

/// How a file stands against the map.
///
/// Not `#[non_exhaustive]`: these five are the whole answer, and a renderer has to be able to match
/// them exhaustively to say anything useful to a user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Standing {
    /// Every byte the file is made of is where the map says, and is what the map says.
    Pristine,
    /// The file's bytes sit where the map explains them, and some of them differ. Something rewrote
    /// this file in the space the archive already held for it.
    Modified,
    /// The file's bytes are where the map explains nothing: past the end a data file should have, or
    /// in a data file the pristine install did not have at all. Appending and repointing is what
    /// every mod tool does, so this is the arm that carries them.
    Foreign,
    /// The entry does not hold together as an entry, so what it would deliver cannot be judged.
    Broken,
    /// Nothing is known. The map does not speak for this archive, or the container could not be read.
    Unknown,
}

impl Standing {
    /// Whether repairing the install would replace what is here with something else. This is the
    /// question the pre-repair prompt asks, and the reason [`Standing::Unknown`] answers `false`: a
    /// warning is only worth making about files something actually measured.
    #[must_use]
    pub fn repair_would_replace(self) -> bool {
        matches!(self, Standing::Modified | Standing::Foreign)
    }

    /// A stable machine key.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Standing::Pristine => "pristine",
            Standing::Modified => "modified",
            Standing::Foreign => "foreign",
            Standing::Broken => "broken",
            Standing::Unknown => "unknown",
        }
    }
}

/// How exactly a verdict names this file rather than its neighbours.
///
/// The map's dirty runs are as fine as whatever measured them, and a patch-derived one is as fine as
/// a patch write. Measured over a real chain those writes are mostly smaller than one file, so most
/// verdicts name one file exactly; the tail is long enough to matter, so a verdict that cannot
/// separate a file from the ones beside it has to say so rather than accuse all of them equally.
///
/// A [`Standing::Foreign`] verdict is always [`Confidence::Exact`], whatever the run lengths: it
/// comes from the length a container should have, not from a run of bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Confidence {
    /// No other file's bytes lie in the runs this verdict rests on.
    Exact,
    /// The runs this verdict rests on also cover other files, so which of them changed is not
    /// decided here. Every file sharing a run gets the same verdict.
    Shared,
}

impl Confidence {
    /// A stable machine key.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            Confidence::Exact => "exact",
            Confidence::Shared => "shared",
        }
    }
}

/// One file, as the index named it and the map judged it.
///
/// Identified by hash, not by name: SqPack lookups are hash-based and this crate bundles no path
/// dictionary, so a caller wanting names supplies its own hashlist. The archive is still nameable,
/// which is enough for "four files in `chara`, two in `bg`".
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FileStanding {
    /// The data file holding it.
    pub container: ContainerRef,
    /// The index key that named it.
    pub key: u64,
    /// Where its entry begins in that container.
    pub offset: u64,
    /// How many bytes the entry is made of: its header and the data it stores, which is what an
    /// extraction reads. Not the slot, which reserves more.
    pub len: u64,
    /// How it stands against the map.
    pub standing: Standing,
    /// How exactly that names this file rather than its neighbours.
    pub confidence: Confidence,
}

/// One self-contained line: the container, the key, the extent and the verdict.
impl fmt::Display for FileStanding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} key={:#018x} +{:#x}..{:#x}: {}",
            self.container.relative_path().display(),
            self.key,
            self.offset,
            self.offset.saturating_add(self.len),
            self.standing.slug(),
        )?;
        if self.confidence == Confidence::Shared {
            f.write_str(" (shared with other files)")?;
        }
        Ok(())
    }
}

/// How a whole container stands, which is a different question from how its files do: an index
/// container holds no files at all, and a data file can be untouched while the index that points into
/// it was rewritten.
///
/// Not `#[non_exhaustive]`, for the same reason as [`Standing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContainerStanding {
    /// The map vouches for it end to end.
    Pristine,
    /// It is the length it should be and some of its bytes differ.
    Rewritten,
    /// It is longer than it should be. Everything past the length the map declares is bytes no patch
    /// wrote, which is where an appending mod tool puts what it adds.
    Grown,
    /// It is shorter than it should be.
    Truncated,
    /// The map describes no such container, in a repository it claims to describe exhaustively: the
    /// pristine install did not have this file.
    Added,
    /// Something should have this container and the tree does not have it: the map describes it, or
    /// an index sends entries into it. A repair restores this rather than reverting it.
    Missing,
    /// The map does not speak for this container's repository, or the container would not be read.
    Unknown,
}

impl ContainerStanding {
    /// A stable machine key.
    #[must_use]
    pub fn slug(self) -> &'static str {
        match self {
            ContainerStanding::Pristine => "pristine",
            ContainerStanding::Rewritten => "rewritten",
            ContainerStanding::Grown => "grown",
            ContainerStanding::Truncated => "truncated",
            ContainerStanding::Added => "added",
            ContainerStanding::Missing => "missing",
            ContainerStanding::Unknown => "unknown",
        }
    }

    /// Whether something has rewritten, added or removed this container. `Unknown` answers no: what
    /// nothing measured is [`crate::mods::ModReport::is_exhaustive`]'s to say, not this.
    #[must_use]
    pub fn is_altered(self) -> bool {
        match self {
            ContainerStanding::Rewritten
            | ContainerStanding::Grown
            | ContainerStanding::Truncated
            | ContainerStanding::Added
            | ContainerStanding::Missing => true,
            ContainerStanding::Pristine | ContainerStanding::Unknown => false,
        }
    }
}

/// One container and how it stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerVerdict {
    /// Which container.
    pub container: ContainerRef,
    /// How it stands.
    pub standing: ContainerStanding,
    /// The length the map says it should be, when the map describes it.
    pub pristine_len: Option<u64>,
    /// The length it has, when it was reached at all.
    pub actual_len: Option<u64>,
}

/// One self-contained line.
impl fmt::Display for ContainerVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}",
            self.container.relative_path().display(),
            self.standing.slug(),
        )?;
        if let (Some(pristine), Some(actual)) = (self.pristine_len, self.actual_len)
            && pristine != actual
        {
            write!(f, " ({actual} bytes, should be {pristine})")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveId;
    use crate::game::Repo;
    use crate::integrity::ContainerId;

    fn at(file: ContainerId) -> ContainerRef {
        ContainerRef::new(Repo::Ex(1), ArchiveId::new(0x02, 1, 1), file)
    }

    #[test]
    fn only_a_measured_difference_is_worth_warning_about_before_a_repair() {
        // Unknown deliberately answers no. Warning about files nothing measured would make the
        // prompt useless on the common case of a map that covers one repository.
        assert!(Standing::Modified.repair_would_replace());
        assert!(Standing::Foreign.repair_would_replace());
        assert!(!Standing::Pristine.repair_would_replace());
        assert!(!Standing::Unknown.repair_would_replace());
        assert!(!Standing::Broken.repair_would_replace());
    }

    #[test]
    fn a_rendered_verdict_names_the_container_the_key_and_the_extent() {
        let file = FileStanding {
            container: at(ContainerId::Dat(1)),
            key: 0x0123_4567_89ab_cdef,
            offset: 0x1000,
            len: 0x280,
            standing: Standing::Foreign,
            confidence: Confidence::Exact,
        };
        assert_eq!(
            file.to_string(),
            "sqpack/ex1/020101.win32.dat1 key=0x0123456789abcdef +0x1000..0x1280: foreign"
        );
        // A verdict that cannot separate this file from its neighbours has to say so on the line
        // itself, not only in a field a renderer may drop.
        let shared = FileStanding {
            standing: Standing::Modified,
            confidence: Confidence::Shared,
            ..file
        };
        assert!(
            shared
                .to_string()
                .ends_with("modified (shared with other files)")
        );
    }

    #[test]
    fn a_container_line_gives_both_lengths_only_when_they_differ() {
        let grown = ContainerVerdict {
            container: at(ContainerId::Dat(0)),
            standing: ContainerStanding::Grown,
            pristine_len: Some(4096),
            actual_len: Some(8192),
        };
        assert_eq!(
            grown.to_string(),
            "sqpack/ex1/020101.win32.dat0: grown (8192 bytes, should be 4096)"
        );
        let same = ContainerVerdict {
            standing: ContainerStanding::Rewritten,
            actual_len: Some(4096),
            ..grown
        };
        assert_eq!(same.to_string(), "sqpack/ex1/020101.win32.dat0: rewritten");
        let unknown = ContainerVerdict {
            standing: ContainerStanding::Unknown,
            pristine_len: None,
            actual_len: None,
            ..grown
        };
        assert_eq!(unknown.to_string(), "sqpack/ex1/020101.win32.dat0: unknown");
    }

    #[test]
    fn every_slug_is_a_distinct_kebab_case_key() {
        let mut seen: Vec<&str> = Vec::new();
        for standing in [
            Standing::Pristine,
            Standing::Modified,
            Standing::Foreign,
            Standing::Broken,
            Standing::Unknown,
        ] {
            seen.push(standing.slug());
        }
        for standing in [
            ContainerStanding::Pristine,
            ContainerStanding::Rewritten,
            ContainerStanding::Grown,
            ContainerStanding::Truncated,
            ContainerStanding::Added,
            ContainerStanding::Unknown,
        ] {
            seen.push(standing.slug());
        }
        seen.push(Confidence::Exact.slug());
        seen.push(Confidence::Shared.slug());
        assert!(
            seen.iter()
                .all(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
        );
        // The two standing enums share three words on purpose; within each set the keys are distinct.
        let mut files = seen[..5].to_vec();
        files.sort_unstable();
        files.dedup();
        assert_eq!(files.len(), 5);
        let mut containers = seen[5..11].to_vec();
        containers.sort_unstable();
        containers.dedup();
        assert_eq!(containers.len(), 6);
    }
}
