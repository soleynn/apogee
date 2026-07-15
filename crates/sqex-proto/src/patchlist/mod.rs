//! The patchlist parser.
//!
//! A patchlist is the multipart body SE returns from a version check: a boundary line, a few part
//! headers, a blank line, one tab-separated entry per patch, then a closing boundary and a trailing
//! line. XL consumes the envelope positionally, skipping the first five lines and the last two
//! (`PatchListParser.cs:19,26`). We frame it the same way but validate that the first line opens a
//! multipart boundary and the trailer closes the same one, so a format change that shifts the entry
//! window fails loudly instead of silently mis-slicing.
//!
//! Each entry is tab-separated. A game entry has nine fields and carries per-block SHA1 hashes; a boot
//! entry has six and carries none (boot integrity rides on ZiPatch chunk CRCs instead). Fields 1-3 are
//! not consumed by XL and their meaning is not pinned, so they are captured only as position and then
//! ignored (`PatchListParser.cs:31-39`). The declared part length is left un-cross-checked: whether it
//! counts the patchlist body's bytes or the summed patch size is not yet pinned against live output,
//! so validating it here would risk a false alarm; the multipart frame is validated instead.

use crate::error::ProtoError;

/// Lines of multipart preamble XL skips before the first entry.
const HEADER_LINES: usize = 5;
/// Trailing lines (closing boundary + final blank) XL skips after the last entry.
const TRAILER_LINES: usize = 2;
/// Field count of a game entry; anything else (but at least six) is treated as a boot entry.
const GAME_FIELDS: usize = 9;
/// Minimum fields any entry needs: a boot entry reads through field index 5.
const MIN_FIELDS: usize = 6;
/// A SHA1 digest is 40 lowercase-hex characters.
const SHA1_HEX_LEN: usize = 40;

/// The per-block hashes of a game patch: the digest algorithm, the block size each digest covers, and
/// one lowercase-hex digest per block (the final block is short).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHashes {
    pub hash_type: String,
    pub block_size: u64,
    pub hashes: Vec<String>,
}

/// One patch to download and apply, in list order. Boot entries carry no block hashes, so `hashes` is
/// `None`.
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

/// Parse a patchlist body into its ordered entries.
///
/// The body's line endings may be any of CRLF, CR, or LF (SE mixes them); they are normalized before
/// splitting so line numbering matches the source.
pub fn parse_patch_list(body: &str) -> Result<Vec<PatchListEntry>, ProtoError> {
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = normalized.split('\n').collect();

    if lines.len() < HEADER_LINES + TRAILER_LINES {
        return Err(parse_error(1, "patchlist too short"));
    }

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

fn parse_entry(line: &str, line_no: u32) -> Result<PatchListEntry, ProtoError> {
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() < MIN_FIELDS {
        return Err(parse_error(line_no, "too few tab-separated fields"));
    }

    let length = fields[0]
        .parse::<u64>()
        .map_err(|_| parse_error(line_no, "invalid patch length"))?;
    let version_id = fields[4].to_string();

    if fields.len() == GAME_FIELDS {
        let block_size = fields[6]
            .parse::<u64>()
            .map_err(|_| parse_error(line_no, "invalid hash block size"))?;
        let hashes = parse_hashes(fields[7], line_no)?;
        Ok(PatchListEntry {
            length,
            version_id,
            url: fields[8].to_string(),
            hashes: Some(BlockHashes {
                hash_type: fields[5].to_string(),
                block_size,
                hashes,
            }),
        })
    } else {
        // Boot-style entry: no hashes, and the URL is field 5 (the same slot a game entry uses for the
        // hash type) (`PatchListParser.cs:39`).
        Ok(PatchListEntry {
            length,
            version_id,
            url: fields[5].to_string(),
            hashes: None,
        })
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
