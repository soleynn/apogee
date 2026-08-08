//! The patchlist parser.
//!
//! A patchlist is the multipart body SE returns from a version check: a boundary line, a few part
//! headers, a blank line, one tab-separated entry per patch, then a closing boundary and a trailing
//! line. The reference launcher consumes the envelope positionally, skipping the first five lines
//! and the last two (`PatchListParser.cs:19,26`); [`parse_patch_list`] frames it the same way but
//! additionally validates that the first line opens a multipart boundary and the trailer closes the
//! same one, so a format change that shifts the entry window fails loudly instead of silently
//! mis-slicing.
//!
//! Each entry is tab-separated. A game entry has exactly nine fields and carries per-block SHA1
//! hashes ([`BlockHashes`]); a boot entry has exactly six and carries none (boot integrity rides on
//! ZiPatch chunk CRCs instead). Fields 1-3 are not consumed by the reference launcher and their
//! meaning is not pinned, so they are captured only as position and then ignored
//! (`PatchListParser.cs:31-39`). The declared part length is left un-cross-checked: whether it
//! counts the patchlist body's bytes or the summed patch size is not yet pinned against live
//! output, so validating it here would risk a false alarm; the multipart frame is validated instead
//! (this is still open — pin the check once a live capture settles it).
//!
//! The two field counts are matched exactly, which is where this parser diverges from the
//! reference: its parser treats *any* count other than nine as a boot entry
//! (`PatchListParser.cs:31-39`), so a nine-field game entry carrying one stray trailing tab reads
//! field 5 (the hash type, `sha1`) as the URL and silently drops the block hashes with no error.
//! That is exactly the kind of silent mis-slice this module exists to refuse, so here a field count
//! that is neither six nor nine is a parse error instead.
//!
//! The body is bounded before it is parsed: SE serves the boot-version check over plain HTTP, so
//! the entry count is attacker-chosen on that path, and every entry is materialized into an owned
//! [`PatchListEntry`]; without a bound, wire bytes would amplify several times over into resident
//! memory (see [`parse_patch_list`]'s doc for the bound and its rationale).

use url::Url;

use crate::error::ProtoError;

const HEADER_LINES: usize = 5;
const TRAILER_LINES: usize = 2;
const GAME_FIELDS: usize = 9;
const BOOT_FIELDS: usize = 6;
const SHA1_HEX_LEN: usize = 40;

// See parse_patch_list's doc for this bound's rationale.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 16_384;
const MAX_LINES: usize = HEADER_LINES + MAX_ENTRIES + TRAILER_LINES;

/// Per-block SHA1 hashes for a game patch, used to verify downloaded blocks.
///
/// Only game entries carry this (boot integrity rides on ZiPatch chunk CRCs instead), so
/// [`PatchListEntry::hashes`] is `None` for a boot entry.
///
/// # Examples
///
/// ```
/// use sqex_proto::BlockHashes;
///
/// let hashes = BlockHashes {
///     hash_type: "sha1".to_owned(),
///     block_size: 50_000_000,
///     hashes: vec!["a".repeat(40)],
/// };
/// assert_eq!(hashes.hashes.len(), 1);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashes {
    /// The hash algorithm name as SE sends it (observed value: `sha1`).
    pub hash_type: String,
    /// The byte size of each hashed block.
    pub block_size: u64,
    /// One lowercase-hex SHA1 digest per block, in block order.
    pub hashes: Vec<String>,
}

/// One patch named by a patchlist: its download size, version, URL, and (for a game patch) its
/// per-block hashes.
///
/// # Examples
///
/// ```
/// use sqex_proto::PatchListEntry;
///
/// let entry = PatchListEntry {
///     length: 1024,
///     version_id: "2024.01.01.0000.0001".to_owned(),
///     url: "http://example.invalid/boot.patch".to_owned(),
///     hashes: None,
/// };
/// assert!(entry.hashes.is_none());
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchListEntry {
    /// The patch's byte length.
    pub length: u64,
    /// The patch's version string.
    pub version_id: String,
    /// The URL to download the patch from.
    ///
    /// Only well-formedness (`http`/`https`, parseable) is checked, never that the URL's path
    /// resolves to a repository this crate recognizes: that classification is left to the
    /// consumer, so a repository SE adds without telling this crate first (an `ex6`, say) does not
    /// turn into a hard parse failure.
    pub url: String,
    /// Per-block SHA1 hashes, present for a game entry and `None` for a boot entry.
    pub hashes: Option<BlockHashes>,
}

fn parse_error(line: u32, reason: &'static str) -> ProtoError {
    ProtoError::PatchListParse { line, reason }
}

/// Parse a patchlist body into its patch entries, in list order.
///
/// A well-formed line has either nine tab-separated fields (a game entry, carrying block hashes) or
/// six (a boot entry, carrying none); any other field count is a parse error, matching the same
/// distinction the reference launcher's parser makes (see the module doc for why this crate matches
/// the count exactly rather than treating any non-nine count as boot, the way the reference does).
///
/// The body is bounded before it is parsed, at roughly an order of magnitude above the largest
/// plausible real body: the largest list SE can serve is a fresh install's game chain (every patch
/// since 2.0 across the base game and all expansions), whose lines are dominated by the block-hash
/// field (41 bytes per 50 MB block, so even a 20 GB patch line stays under 20 KB), and a live boot
/// chain from the base sentinel is 449 bytes. SE serves the boot-version check over plain HTTP, so
/// the entry count is attacker-chosen on that path, and every entry is materialized into an owned
/// [`PatchListEntry`]; without a bound, wire bytes would amplify several times over into resident
/// memory.
///
/// # Errors
///
/// Returns [`ProtoError::PatchListParse`] if the body exceeds the crate's size or entry-count
/// bound, if the multipart envelope's opening or closing boundary is missing or mismatched, if
/// content follows the closing boundary, or if any entry line has a field count other than six or
/// nine, an unparseable length or hash block size, a malformed `http`/`https` URL, or a malformed
/// block hash.
///
/// # Examples
///
/// ```
/// use sqex_proto::parse_patch_list;
///
/// // 5 header lines (an opening "--BOUNDARY" boundary plus 4 unchecked lines), 1 boot entry (6
/// // tab-separated fields), then the closing "--BOUNDARY--" and a blank trailer line.
/// let body = "--BOUNDARY\nheader1\nheader2\nheader3\nheader4\n\
///     100\tunused\tunused\tunused\t2024.01.01.0000.0001\thttp://example.invalid/boot.patch\n\
///     --BOUNDARY--\n";
/// let entries = parse_patch_list(body).unwrap();
/// assert_eq!(entries.len(), 1);
/// assert_eq!(entries[0].url, "http://example.invalid/boot.patch");
/// assert!(entries[0].hashes.is_none());
///
/// // A malformed envelope fails loudly rather than silently mis-slicing.
/// assert!(parse_patch_list("not a patchlist").is_err());
/// ```
pub fn parse_patch_list(body: &str) -> Result<Vec<PatchListEntry>, ProtoError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(parse_error(1, "patchlist body too large"));
    }
    let normalized = normalize_newlines(body);

    // Counted before collecting: a `Vec<&str>` over the lines costs 16 bytes per line, so a body of
    // nothing but newlines would allocate the bulk of its amplification before any cap could reject
    // it. Counting allocates nothing, which lets the cap run first.
    let line_count = normalized.split('\n').count();
    if line_count < HEADER_LINES + TRAILER_LINES {
        return Err(parse_error(1, "patchlist too short"));
    }
    if line_count > MAX_LINES {
        return Err(parse_error(1, "too many patchlist entries"));
    }
    let lines: Vec<&str> = normalized.split('\n').collect();

    let opening = lines[0];
    if !opening.starts_with("--") {
        return Err(parse_error(1, "missing opening multipart boundary"));
    }

    let closing_index = lines.len() - TRAILER_LINES;
    if lines[closing_index] != format!("{opening}--") {
        return Err(parse_error(
            line_number(closing_index),
            "missing or mismatched closing multipart boundary",
        ));
    }

    // The trailer past the closing boundary is the envelope's final blank. XL never looks at it
    // (`PatchListParser.cs:26` stops two lines early), so a full entry line landing there is dropped
    // with no signal, the same silent mis-slice the frame check above exists to refuse. Validating
    // its shape does not change what a well-formed list parses to; it makes a malformed one loud.
    for (offset, &line) in lines[closing_index + 1..].iter().enumerate() {
        if !line.trim().is_empty() {
            return Err(parse_error(
                line_number(closing_index + 1 + offset),
                "unexpected content after closing multipart boundary",
            ));
        }
    }

    let mut entries = Vec::with_capacity(closing_index - HEADER_LINES);
    for (offset, &line) in lines[HEADER_LINES..closing_index].iter().enumerate() {
        entries.push(parse_entry(line, line_number(HEADER_LINES + offset))?);
    }
    Ok(entries)
}

fn line_number(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

fn normalize_newlines(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut chars = body.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            out.push('\n');
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn parse_entry(line: &str, line_no: u32) -> Result<PatchListEntry, ProtoError> {
    // Counted before collecting, the same technique `parse_patch_list` uses one level up for the line
    // count: a `Vec<&str>` over a line's fields costs 16 bytes per field, so a single line within the
    // overall body cap could still amplify by itself if collected before its count is checked.
    let field_count = line.matches('\t').count() + 1;
    match field_count {
        GAME_FIELDS | BOOT_FIELDS => {
            let fields: Vec<&str> = line.split('\t').collect();
            if field_count == GAME_FIELDS {
                parse_game_entry(&fields, line_no)
            } else {
                parse_boot_entry(&fields, line_no)
            }
        }
        n if n < BOOT_FIELDS => Err(parse_error(line_no, "too few tab-separated fields")),
        _ => Err(parse_error(line_no, "unexpected tab-separated field count")),
    }
}

fn parse_game_entry(fields: &[&str], line_no: u32) -> Result<PatchListEntry, ProtoError> {
    let block_size = fields[6]
        .parse::<u64>()
        .map_err(|_| parse_error(line_no, "invalid hash block size"))?;
    let hashes = parse_hashes(fields[7], line_no)?;
    Ok(PatchListEntry {
        length: parse_length(fields[0], line_no)?,
        version_id: fields[4].to_string(),
        url: parse_url(fields[8], line_no)?,
        hashes: Some(BlockHashes {
            hash_type: fields[5].to_string(),
            block_size,
            hashes,
        }),
    })
}

fn parse_boot_entry(fields: &[&str], line_no: u32) -> Result<PatchListEntry, ProtoError> {
    Ok(PatchListEntry {
        length: parse_length(fields[0], line_no)?,
        version_id: fields[4].to_string(),
        url: parse_url(fields[5], line_no)?,
        hashes: None,
    })
}

fn parse_length(field: &str, line_no: u32) -> Result<u64, ProtoError> {
    field
        .parse::<u64>()
        .map_err(|_| parse_error(line_no, "invalid patch length"))
}

// Only well-formedness is checked here, not the `/(game|boot)/{repoId}/` rule that resolves a URL to
// its repo. That rule stays with the consumer on purpose: resolving a repo means deciding what an
// *unrecognized* segment is, and the answer is a policy the parser cannot make (XL's GetRepo falls
// back to the base game, which apogee_core::patch::classify_repo mirrors), while the recognized set is
// not pinned either (SE can ship an ex6 without telling us). Rejecting an unknown-but-fetchable URL
// here would turn a new repo into a hard patch-day failure for a classification this crate never makes.
fn parse_url(field: &str, line_no: u32) -> Result<String, ProtoError> {
    match Url::parse(field) {
        Ok(url) if matches!(url.scheme(), "http" | "https") => Ok(url.to_string()),
        _ => Err(parse_error(line_no, "malformed patch URL")),
    }
}

fn parse_hashes(field: &str, line_no: u32) -> Result<Vec<String>, ProtoError> {
    let mut out = Vec::new();
    for hash in field.split(',') {
        if hash.len() != SHA1_HEX_LEN || !hash.bytes().all(is_lower_hex) {
            return Err(parse_error(line_no, "malformed block hash"));
        }
        out.push(hash.to_string());
    }
    Ok(out)
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || matches!(b, b'a'..=b'f')
}

#[cfg(test)]
mod tests;
