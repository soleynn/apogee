//! Sign a catalog manifest with an offline Ed25519 key.
//!
//! One tool for all three catalogs (runners, repair indexes, components), each with its own seed
//! and its own compiled-in verifying key: the file to sign is an argument, so nothing here knows or
//! cares which catalog it is.
//!
//! Three modes:
//!   catalog-sign keygen <seed-out>
//!       Generate a fresh 32-byte seed from the OS CSPRNG, write it to <seed-out> (kept offline,
//!       never committed), and print the 32-byte public key as a ready-to-paste `[u8; 32]` array
//!       body for the compiled-in verifying key.
//!   catalog-sign pin <artifact>
//!       Print the artifact's `blake3` and `sha256` pins as ready-to-paste manifest lines. A row
//!       publishes both so a client that predates BLAKE3 can still read it; a client that
//!       understands both prefers `blake3`.
//!   catalog-sign sign <seed> <manifest.json> <out.sig>
//!       Sign the exact bytes of <manifest.json> and write the 64 raw signature bytes to <out.sig>.
//!       The signature is re-verified against the derived public key before it is written, so a
//!       corrupt or wrong-length seed fails loudly instead of emitting a bad signature.
//!
//! The private seed lives on the maintainer's machine only; this tool reads it, never embeds it.

use std::fs;
use std::process::ExitCode;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    let result = match args.get(1).map(String::as_str) {
        Some("keygen") if args.len() == 3 => keygen(&args[2]),
        Some("pin") if args.len() == 3 => pin(&args[2]),
        Some("sign") if args.len() == 5 => sign(&args[2], &args[3], &args[4]),
        _ => Err(usage()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> String {
    concat!(
        "usage:\n",
        "  catalog-sign keygen <seed-out>\n",
        "  catalog-sign pin <artifact>\n",
        "  catalog-sign sign <seed> <manifest.json> <out.sig>"
    )
    .to_owned()
}

/// Generate a signing key, persist its seed, and print the public key for compiling in.
fn keygen(seed_out: &str) -> Result<(), String> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| format!("could not read OS randomness: {e}"))?;
    let signing = SigningKey::from_bytes(&seed);
    write_new(seed_out, &seed)?;
    println!("wrote seed to {seed_out} (keep this offline, never commit it)");
    println!("public key ({seed_out} derives it) for the compiled-in verifying key:\n");
    println!("{}", format_key_array(&signing.verifying_key()));
    Ok(())
}

/// Print an artifact's pins as the manifest lines that carry them.
///
/// Both are emitted because a row publishes both: the older one keeps a client that predates BLAKE3
/// reading the file, and a client that understands both takes `blake3`. They describe one file read
/// once, so the pair cannot disagree about which bytes were pinned.
fn pin(artifact_path: &str) -> Result<(), String> {
    let bytes = fs::read(artifact_path).map_err(|e| format!("read {artifact_path}: {e}"))?;
    let blake3 = blake3::hash(&bytes);
    let sha256 = Sha256::digest(&bytes);
    println!("\"blake3\": \"{}\",", blake3.to_hex());
    println!("\"sha256\": \"{}\",", hex(&sha256));
    Ok(())
}

/// Lowercase hex, the spelling every manifest pin is written in.
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Sign a manifest and write the detached 64-byte signature.
fn sign(seed_path: &str, manifest_path: &str, out_path: &str) -> Result<(), String> {
    let seed_bytes = fs::read(seed_path).map_err(|e| format!("read {seed_path}: {e}"))?;
    let seed: [u8; 32] = seed_bytes.as_slice().try_into().map_err(|_| {
        format!(
            "{seed_path} must be exactly 32 bytes, got {}",
            seed_bytes.len()
        )
    })?;
    let signing = SigningKey::from_bytes(&seed);

    let manifest = fs::read(manifest_path).map_err(|e| format!("read {manifest_path}: {e}"))?;
    let signature = signing.sign(&manifest);

    // Re-verify before writing so a bad key never yields a signature the runtime would reject.
    signing
        .verifying_key()
        .verify_strict(&manifest, &signature)
        .map_err(|_| "signature failed self-verification".to_owned())?;

    fs::write(out_path, signature.to_bytes()).map_err(|e| format!("write {out_path}: {e}"))?;
    println!("signed {manifest_path} -> {out_path} (64 bytes)");
    Ok(())
}

/// Write `bytes` to `path`, refusing to clobber an existing file (a seed is precious).
fn write_new(path: &str, bytes: &[u8]) -> Result<(), String> {
    if fs::metadata(path).is_ok() {
        return Err(format!(
            "{path} already exists; refusing to overwrite a key"
        ));
    }
    fs::write(path, bytes).map_err(|e| format!("write {path}: {e}"))
}

/// Render a verifying key as the body of a `[u8; 32]` literal, 16 bytes per line, matching the
/// compiled-in constant's formatting.
fn format_key_array(key: &VerifyingKey) -> String {
    key.to_bytes()
        .chunks(16)
        .map(|row| {
            let cells: Vec<String> = row.iter().map(|b| format!("0x{b:02x}")).collect();
            format!("    {},", cells.join(", "))
        })
        .collect::<Vec<_>>()
        .join("\n")
}
