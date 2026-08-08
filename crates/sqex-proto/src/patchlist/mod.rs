// The patchlist parser. A patchlist is the multipart body SE returns from a version check: a boundary
// line, a few part headers, a blank line, one tab-separated entry per patch, then a closing boundary
// and a trailing line. XL consumes the envelope positionally, skipping the first five lines and the
// last two (PatchListParser.cs:19,26). We frame it the same way but validate that the first line opens
// a multipart boundary and the trailer closes the same one, so a format change that shifts the entry
// window fails loudly instead of silently mis-slicing.
//
// Each entry is tab-separated. A game entry has exactly nine fields and carries per-block SHA1 hashes;
// a boot entry has exactly six and carries none (boot integrity rides on ZiPatch chunk CRCs instead).
// Fields 1-3 are not consumed by XL and their meaning is not pinned, so they are captured only as
// position and then ignored (PatchListParser.cs:31-39). The declared part length is left
// un-cross-checked: whether it counts the patchlist body's bytes or the summed patch size is not yet
// pinned against live output, so validating it here would risk a false alarm; the multipart frame is
// validated instead. (Still open -- pin this once a live capture settles it.)
//
// The two field counts are matched exactly, which is where we diverge from XL: its parser treats *any*
// count other than nine as a boot entry (PatchListParser.cs:31-39), so a nine-field game entry
// carrying one stray trailing tab reads field 5 (the hash type, `sha1`) as the URL and drops the block
// hashes with no error. That is a silent mis-slice of the kind this module exists to refuse, so a
// count that is neither six nor nine is a parse error here.
//
// The body is bounded before it is parsed. SE serves this over plain HTTP (bootver.rs), so the entry
// count is attacker-chosen on the boot path, and every entry is materialized into an owned
// PatchListEntry; without a bound, wire bytes amplify several times over into resident memory.

use url::Url;

use crate::error::ProtoError;

const HEADER_LINES: usize = 5;
const TRAILER_LINES: usize = 2;
const GAME_FIELDS: usize = 9;
const BOOT_FIELDS: usize = 6;
const SHA1_HEX_LEN: usize = 40;

// The largest list SE can serve is a fresh install's game chain (every patch since 2.0 across the base
// game and all expansions), whose lines are dominated by the block-hash field: 41 bytes per 50 MB
// block, so even a 20 GB patch line stays under 20 KB. A live boot chain from the base sentinel is 449
// bytes. This is roughly an order of magnitude above the largest plausible real body, so it bounds a
// hostile one without being reachable by a legitimate patch day.
const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 16_384;
const MAX_LINES: usize = HEADER_LINES + MAX_ENTRIES + TRAILER_LINES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashes {
    pub hash_type: String,
    pub block_size: u64,
    pub hashes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PatchListEntry {
    pub length: u64,
    pub version_id: String,
    pub url: String,
    pub hashes: Option<BlockHashes>,
}

fn parse_error(line: u32, reason: &'static str) -> ProtoError {
    ProtoError::PatchListParse { line, reason }
}

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
