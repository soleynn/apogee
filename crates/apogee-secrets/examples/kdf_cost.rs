//! Measure what an Argon2id derivation costs on this machine, so the fallback store's work factor is
//! picked from numbers rather than from a guess.
//!
//! An example rather than a benchmark harness: it lives inside the package, so it reaches the
//! package's own dependencies and the library carries no timing method and no benchmark dependency.
//! Nothing gates on what this prints.
//!
//! ```text
//! cargo run -p apogee-secrets --release --example kdf_cost
//! cargo run -p apogee-secrets --release --example kdf_cost -- --target-ms 400 --reps 5
//! ```
//!
//! **Release, always.** An unoptimized build is roughly an order of magnitude slower and would pick a
//! work factor far below what the hardware can carry, which is the one way to get this wrong in the
//! direction that matters.
//!
//! The number worth having is the *worst* one the target hardware produces, so on a handheld run it
//! four ways: on a desktop session idle, in game mode idle, in game mode with a game resident, and on
//! battery. The third is usually the one that decides it.

use std::time::Instant;

use argon2::{Algorithm, Argon2, Block, Params, Version};

/// The grid. Memory in kibibytes against passes, lanes fixed at one because the derivation here is
/// sequential and a second lane costs work without buying wall clock.
const MEMORY_KIB: [u32; 6] = [19_456, 32_768, 65_536, 98_304, 131_072, 262_144];
const PASSES: [u32; 3] = [2, 3, 4];

/// What a user is willing to wait once per launcher session, at a prompt they are already at.
const DEFAULT_TARGET_MS: u128 = 500;

/// Derived key width, matching what the store asks for.
const KEY_LEN: usize = 32;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut target_ms = DEFAULT_TARGET_MS;
    let mut reps = 3usize;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--target-ms" => target_ms = args.next().ok_or("--target-ms needs a value")?.parse()?,
            "--reps" => reps = args.next().ok_or("--reps needs a value")?.parse()?,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    if reps == 0 {
        return Err("--reps must be at least one".into());
    }

    println!("memory_kib\tpasses\tlanes\tmedian_ms\tpeak_rss_mib");
    let mut best: Option<(u32, u32, u128)> = None;
    for memory_kib in MEMORY_KIB {
        for passes in PASSES {
            let median = time(memory_kib, passes, reps)?;
            println!(
                "{memory_kib}\t{passes}\t1\t{median}\t{}",
                peak_rss_mib().map_or_else(|| "?".to_owned(), |mib| mib.to_string())
            );
            if median <= target_ms {
                // The grid is walked in increasing order, so the last cell inside the budget is the
                // largest one.
                best = Some((memory_kib, passes, median));
            }
        }
    }

    match best {
        Some((memory_kib, passes, median)) => println!(
            "\nlargest cell within {target_ms} ms: {memory_kib} KiB over {passes} passes, {median} ms"
        ),
        None => println!("\nnothing on this grid fits within {target_ms} ms"),
    }
    Ok(())
}

/// Median of `reps` derivations, after one discarded run that pays for the first touch of the block
/// vector's pages.
fn time(memory_kib: u32, passes: u32, reps: usize) -> Result<u128, Box<dyn std::error::Error>> {
    let params = Params::new(memory_kib, passes, 1, Some(KEY_LEN)).map_err(|e| e.to_string())?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut blocks = vec![Block::default(); argon.params().block_count()];
    let mut key = [0u8; KEY_LEN];

    let mut once = |blocks: &mut Vec<Block>| -> Result<u128, String> {
        let start = Instant::now();
        argon
            .hash_password_into_with_memory(b"measurement", &[0u8; 16], &mut key, blocks)
            .map_err(|e| e.to_string())?;
        Ok(start.elapsed().as_millis())
    };

    once(&mut blocks)?;
    let mut times = Vec::with_capacity(reps);
    for _ in 0..reps {
        times.push(once(&mut blocks)?);
    }
    times.sort_unstable();
    times
        .get(times.len() / 2)
        .copied()
        .ok_or_else(|| "no timings were taken".into())
}

/// High-water resident memory, which is the other half of the answer: a cell that swaps on a handheld
/// costs seconds rather than the milliseconds it measured.
#[cfg(target_os = "linux")]
fn peak_rss_mib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find(|l| l.starts_with("VmHWM:"))?;
    let kib: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kib / 1024)
}

#[cfg(not(target_os = "linux"))]
fn peak_rss_mib() -> Option<u64> {
    None
}
