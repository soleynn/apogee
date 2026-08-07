//! The patchlist parser.
//!
//! A patchlist is the multipart body SE returns from a version check: a boundary line, a few part
//! headers, a blank line, one tab-separated entry per patch, then a closing boundary and a trailing
//! line. XL consumes the envelope positionally, skipping the first five lines and the last two
//! (`PatchListParser.cs:19,26`). We frame it the same way but validate that the first line opens a
//! multipart boundary and the trailer closes the same one, so a format change that shifts the entry
//! window fails loudly instead of silently mis-slicing.
//!
//! Each entry is tab-separated. A game entry has exactly nine fields and carries per-block SHA1
//! hashes; a boot entry has exactly six and carries none (boot integrity rides on ZiPatch chunk CRCs
//! instead). Fields 1-3 are not consumed by XL and their meaning is not pinned, so they are captured
//! only as position and then ignored (`PatchListParser.cs:31-39`). The declared part length is left
//! un-cross-checked: whether it counts the patchlist body's bytes or the summed patch size is not yet
//! pinned against live output, so validating it here would risk a false alarm; the multipart frame is
//! validated instead.
//!
//! The two field counts are matched exactly, which is where we diverge from XL: its parser treats
//! *any* count other than nine as a boot entry (`PatchListParser.cs:31-39`), so a nine-field game
//! entry carrying one stray trailing tab reads field 5 (the hash type, `sha1`) as the URL and drops
//! the block hashes with no error. That is a silent mis-slice of the kind this module exists to
//! refuse, so a count that is neither six nor nine is a parse error here.
//!
//! The body is bounded before it is parsed. SE serves this over plain HTTP (`bootver.rs`), so the
//! entry count is attacker-chosen on the boot path, and every entry is materialized into an owned
//! `PatchListEntry`; without a bound, wire bytes amplify several times over into resident memory.

use url::Url;

use crate::error::ProtoError;

/// Lines of multipart preamble XL skips before the first entry.
const HEADER_LINES: usize = 5;
/// Trailing lines (closing boundary + final blank) XL skips after the last entry.
const TRAILER_LINES: usize = 2;
/// Field count of a game entry, matched exactly.
const GAME_FIELDS: usize = 9;
/// Field count of a boot entry, matched exactly: it reads through field index 5.
const BOOT_FIELDS: usize = 6;
/// A SHA1 digest is 40 lowercase-hex characters.
const SHA1_HEX_LEN: usize = 40;

/// Largest patchlist body accepted, in bytes.
///
/// The largest list SE can serve is a fresh install's game chain (every patch since 2.0 across the
/// base game and all expansions), whose lines are dominated by the block-hash field: 41 bytes per
/// 50 MB block, so even a 20 GB patch line stays under 20 KB. A live boot chain from the base
/// sentinel is 449 bytes. This is roughly an order of magnitude above the largest plausible real
/// body, so it bounds a hostile one without being reachable by a legitimate patch day.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Largest number of entries accepted, likewise far above any real chain (a full install is
/// hundreds; a boot chain is single digits).
const MAX_ENTRIES: usize = 16_384;
/// Line budget the entry cap implies, checked before the lines are collected.
const MAX_LINES: usize = HEADER_LINES + MAX_ENTRIES + TRAILER_LINES;

/// The per-block hashes of a game patch: the digest algorithm, the block size each digest covers, and
/// one lowercase-hex digest per block (the final block is short).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashes {
    /// The digest algorithm, as SE names it. Every capture observed so far is `sha1`.
    pub hash_type: String,
    /// The byte span each hash in [`Self::hashes`] covers (commonly 50 MB). The final block is short.
    pub block_size: u64,
    /// One lowercase-hex digest per block, in block order.
    pub hashes: Vec<String>,
}

/// One patch to download and apply, in list order. Boot entries carry no block hashes, so `hashes` is
/// `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchListEntry {
    /// The patch's length in bytes.
    pub length: u64,
    /// SE's version identifier for this patch (e.g. `D2023.04.28.0000.0001`).
    pub version_id: String,
    /// The download URL: a well-formed absolute HTTP(S) URL, validated but not classified into a
    /// repo — that resolution is left to the consumer (see the module docs).
    pub url: String,
    /// The per-block hashes, or `None` for a boot entry (whose integrity check is ZiPatch chunk CRCs).
    pub hashes: Option<BlockHashes>,
}

fn parse_error(line: u32, reason: &'static str) -> ProtoError {
    ProtoError::PatchListParse { line, reason }
}

/// Parse a patchlist body into its ordered entries.
///
/// The body's line endings may be any of CRLF, CR, or LF (SE mixes them); they are normalized before
/// splitting so line numbering matches the source.
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

/// 1-based line number for a 0-based line index, saturating so a pathological length can never wrap.
fn line_number(index: usize) -> u32 {
    u32::try_from(index + 1).unwrap_or(u32::MAX)
}

/// Normalize CRLF, CR, and LF line endings to LF in a single pass (SE mixes them). A CRLF collapses to
/// one LF and a lone CR (including mid-line) becomes an LF, so line numbering matches the source.
/// Identical output to `replace("\r\n", "\n").replace('\r', "\n")`, without the second full-body pass.
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

/// A nine-field game entry: hash type, block size, and one SHA1 per block, with the URL in field 8.
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

/// A six-field boot entry: no hashes, and the URL is field 5 (the same slot a game entry uses for the
/// hash type) (`PatchListParser.cs:39`).
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

/// Check that a URL field is an absolute HTTP(S) URL, and return `Url::parse`'s normalized form.
///
/// Only well-formedness is checked here, not the `/(game|boot)/{repoId}/` rule that resolves a URL
/// to its repo. That rule stays with the consumer on purpose: resolving a repo means deciding what an
/// *unrecognized* segment is, and the answer is a policy the parser cannot make (XL's `GetRepo`
/// falls back to the base game, which `apogee_core::patch::classify_repo` mirrors), while the
/// recognized set is not pinned either (SE can ship an `ex6` without telling us). XL likewise
/// applies its regex at point of use, not at parse. Rejecting an unknown-but-fetchable URL here
/// would turn a new repo into a hard patch-day failure for a classification this crate never makes.
///
/// Well-formedness is a different question and belongs here: the URL's only purpose is to be
/// fetched, `apogee-patcher` already `Url::parse`s it before doing so, and failing on the line that
/// carried it reports a line number instead of a bare parse error several layers later. It is kept
/// as a `String` rather than a `Url` so the entry stays cheap to clone and the consumer owns the
/// parse it actually needs. The stored string is `url.to_string()`, the parsed and normalized form,
/// not the raw field: `Url::parse` can trim surrounding whitespace or rewrite a minor malformation
/// (e.g. filling in an absent `//` authority separator), so storing the raw field would let a byte
/// sequence reach the consumer that was never actually what got validated.
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
