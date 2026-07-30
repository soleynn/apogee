//! `sqpack-tool`: the archive inspection binary. Four verbs:
//!
//! ```text
//! cargo run -p apogee-sqpack --example sqpack_tool -- stat <game-dir|sqpack-file>
//! cargo run -p apogee-sqpack --example sqpack_tool -- ls <file.index|file.index2> [limit]
//! cargo run -p apogee-sqpack --example sqpack_tool -- extract <game-dir> <game/path> <out-file>
//! cargo run -p apogee-sqpack --example sqpack_tool -- verify <game-dir> [flags]
//! ```
//!
//! `stat` reports what a game tree holds, or what one container's headers say; `ls` walks an index's
//! entries; `extract` resolves a game path and writes the file's bytes; `verify` sweeps every container
//! of an install and reports what disagrees with what it declares. All of the format knowledge lives in
//! the library, so this example stays an I/O shell that the library never has to become.
//!
//! `verify`'s flags pick how much the sweep costs. The default reads every index whole and every entry
//! header the indexes name; `--hash-data` adds a read of every declared data region, `--decode` adds
//! inflating every entry, `--headers-only` drops the entry walk, `--skip-gaps` stops it reading the
//! empty-block chain across unclaimed space, `--threads N` caps the worker count, and `--json` writes
//! the report as one object instead of lines.

use std::error::Error;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

use apogee_sqpack::integrity::{GapPolicy, Report, Scope, Severity, SweepOptions, Totals};
use apogee_sqpack::{
    ContentType, Dat, DatSource, Entry, EntryBody, GameData, Index, IndexKind, SqPackKind,
    parse_common_header,
};
use serde_json::{Value, json};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((verb, rest)) if verb == "stat" && rest.len() == 1 => stat(Path::new(&rest[0])),
        Some((verb, rest)) if verb == "ls" && (1..=2).contains(&rest.len()) => ls(rest),
        Some((verb, rest)) if verb == "extract" && rest.len() == 3 => extract(rest),
        Some((verb, rest)) if verb == "verify" && !rest.is_empty() => verify(rest),
        _ => {
            eprintln!(
                "usage:\n  sqpack_tool stat <game-dir|sqpack-file>\n  sqpack_tool ls <file.index|file.index2> [limit]\n  sqpack_tool extract <game-dir> <game/path> <out-file>\n  sqpack_tool verify <game-dir> [--hash-data] [--decode] [--headers-only] [--skip-gaps] [--threads N] [--json]"
            );
            return ExitCode::FAILURE;
        }
    };
    match result {
        Ok(clean) => {
            if clean {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Report what a game tree holds, or what one container's headers say.
fn stat(path: &Path) -> Result<bool, Box<dyn Error>> {
    if path.is_dir() {
        return stat_tree(path);
    }
    let head = read_prefix(path, 0x800)?;
    match parse_common_header(&head) {
        Ok(common) => {
            println!(
                "{}: {:?} platform={:?} header_size={} version={}",
                path.display(),
                common.kind,
                common.platform,
                common.header_size,
                common.version
            );
            match common.kind {
                SqPackKind::Index => stat_index(path),
                SqPackKind::Data => stat_dat(path),
                _ => Ok(true),
            }
        }
        // A spanned dat file may carry no magic at all; it is still readable through its data
        // header, so say so rather than stopping at the first eight bytes.
        Err(err) => {
            println!("{}: no common header ({err})", path.display());
            stat_dat(path)
        }
    }
}

fn stat_tree(root: &Path) -> Result<bool, Box<dyn Error>> {
    let game = GameData::open(root)?;
    if game.repos().is_empty() {
        // "No repositories" and "not a game tree" read the same in a summary, and one of them is a
        // typo in the argument.
        eprintln!("{}: no sqpack repositories here", root.display());
        return Ok(false);
    }
    for repo in game.repos() {
        println!(
            "{:<6} version={}",
            repo.repo.dir_name(),
            repo.version.as_deref().unwrap_or("<none>")
        );
    }
    for archive in game.archives() {
        println!(
            "{:<6} {} index={} index2={} dats={}",
            archive.repo.dir_name(),
            archive.id.stem(),
            archive.has_index1,
            archive.has_index2,
            archive.dats.len()
        );
    }
    println!(
        "{} repo(s), {} archive(s)",
        game.repos().len(),
        game.archives().len()
    );
    Ok(true)
}

fn stat_index(path: &Path) -> Result<bool, Box<dyn Error>> {
    let index = Index::open(path)?;
    let header = index.header();
    println!(
        "  kind={:?} version={} dat_files={} entries={} folders={} collisions={} sorted={}",
        header.kind,
        header.version,
        header.data_file_count,
        index.entries().len(),
        index.folders().len(),
        index.collisions().len(),
        index.is_sorted()
    );
    for (n, segment) in header.segments.iter().enumerate() {
        println!(
            "  segment {n}: offset={:<10} size={:<10} sha1={}",
            segment.offset,
            segment.size,
            hex(&segment.sha1)
        );
    }
    Ok(true)
}

fn stat_dat(path: &Path) -> Result<bool, Box<dyn Error>> {
    let dat = Dat::open(path)?;
    let header = dat.data_header();
    println!(
        "  data_size={} span_index={} max_file_size={} data_sha1={}",
        header.data_size(),
        header.span_index,
        header.max_file_size,
        hex(&header.data_sha1)
    );
    println!(
        "  file_len={} declared={}",
        dat.len(),
        header.declared_file_len()
    );
    Ok(dat.len() == header.declared_file_len())
}

/// Walk an index's entries. `args` is `index-file [limit]`.
fn ls(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let index = Index::open(Path::new(&args[0]))?;
    let limit = match args.get(1) {
        Some(n) => n.parse::<usize>()?,
        None => usize::MAX,
    };
    let short = index.kind() == IndexKind::Index2;
    for entry in index.entries().iter().take(limit) {
        match entry.location() {
            Some(at) if short => println!(
                "{:08x}  dat{} {:#012x}",
                entry.file_hash(),
                at.dat,
                at.offset
            ),
            Some(at) => println!(
                "{:08x} {:08x}  dat{} {:#012x}",
                entry.folder_hash(),
                entry.file_hash(),
                at.dat,
                at.offset
            ),
            None => println!("{:016x}  <collision>", entry.key),
        }
    }
    for record in index.collisions().iter().take(limit) {
        println!(
            "{:016x}  #{} {}",
            record.key, record.conflict_index, record.path
        );
    }
    // Both counts, because a truncated listing under a full count reads as a container that holds
    // only what was printed.
    println!(
        "showing {} of {} entry/entries, {} collision(s)",
        index.entries().len().min(limit),
        index.entries().len(),
        index.collisions().len()
    );
    Ok(true)
}

/// Resolve a game path and write its bytes. `args` is `game-dir, game/path, out-file`.
fn extract(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let game = GameData::open(Path::new(&args[0]))?;
    if game.archives().is_empty() {
        eprintln!("{}: no sqpack archives here", args[0]);
        return Ok(false);
    }
    let Some((dat, entry)) = game.entry(&args[1])? else {
        eprintln!("{}: not in this install", args[1]);
        return Ok(false);
    };
    let mut out = BufWriter::new(fs::File::create(&args[2])?);
    let written = dat.read_into(&entry, &mut out)?;
    out.flush()?;
    println!(
        "{} -> {} ({}, {} byte(s), {} block(s))",
        args[1],
        args[2],
        describe(&entry),
        written,
        entry.block_count()
    );
    // A handful of volume textures declare a length that counts padding between mip surfaces the
    // archive does not store. Extracting one is honest about the difference rather than inventing
    // bytes to close it.
    if written < entry.declared_len() {
        println!(
            "note: the entry declares {} byte(s); the archive stores {} less",
            entry.declared_len(),
            entry.declared_len() - written
        );
    }
    Ok(true)
}

fn describe(entry: &Entry) -> String {
    match (entry.content_type(), entry.body()) {
        (ContentType::Texture, EntryBody::Texture(table)) => {
            format!("texture, {} mip(s)", table.mips.len())
        }
        (ContentType::Model, EntryBody::Model(table)) => {
            format!("model, {} level(s) of detail", table.lod_count)
        }
        (kind, _) => format!("{kind:?}").to_lowercase(),
    }
}

/// What a `verify` invocation asked for.
struct Sweep {
    root: PathBuf,
    opts: SweepOptions,
    json: bool,
}

/// Sweep an install's containers and report what disagrees. `args` is `game-dir` and the cost flags.
fn verify(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let sweep = parse_sweep(args)?;
    let game = GameData::open(&sweep.root)?;
    if game.archives().is_empty() {
        eprintln!("{}: no sqpack archives here", sweep.root.display());
        return Ok(false);
    }
    // The report carries no clock, so the caller times its own sweep.
    let started = Instant::now();
    let report = game.inspect(&sweep.opts);
    let elapsed = started.elapsed();
    if sweep.json {
        println!("{}", json_report(&report, &sweep.opts, elapsed)?);
    } else {
        print_report(&report, &sweep.opts, elapsed);
    }
    Ok(report.is_clean())
}

/// The game directory, plus the flags that pick how much the sweep costs and how it is rendered.
fn parse_sweep(args: &[String]) -> Result<Sweep, Box<dyn Error>> {
    let mut opts = SweepOptions::default();
    let mut json = false;
    let mut root: Option<PathBuf> = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--hash-data" => opts.hash_data_regions = true,
            "--decode" => opts.decode_entries = true,
            "--headers-only" => opts.walk_entries = false,
            "--skip-gaps" => opts.gaps = GapPolicy::Skip,
            "--json" => json = true,
            "--threads" => {
                let count: usize = args.next().ok_or("--threads wants a count")?.parse()?;
                if count == 0 {
                    return Err("--threads wants at least one thread".into());
                }
                opts.parallelism = Some(count);
            }
            flag if flag.starts_with('-') => return Err(format!("unknown flag {flag}").into()),
            path if root.is_none() => root = Some(PathBuf::from(path)),
            extra => return Err(format!("unexpected argument {extra}").into()),
        }
    }
    Ok(Sweep {
        root: root.ok_or("verify wants a game directory")?,
        opts,
        json,
    })
}

/// Every finding, then what the sweep accounted for, then the verdict.
fn print_report(report: &Report, opts: &SweepOptions, elapsed: Duration) {
    for finding in &report.findings {
        println!("{:<8} {finding}", severity_name(finding.severity()));
    }
    for container in &report.truncated {
        println!(
            "{}: kept {} defect(s) and counted the rest",
            container.relative_path().display(),
            opts.max_defects_per_container
        );
    }
    let totals = &report.totals;
    println!(
        "{} archive(s), {} index file(s), {} data file(s), {} unreadable, {} busy",
        totals.archives,
        totals.index_files,
        totals.data_files,
        totals.containers_unreadable,
        totals.containers_busy
    );
    println!(
        "{} entry/entries, {} collision record(s), {} location(s), {} entry header(s), {} decoded",
        totals.entries,
        totals.collision_records,
        totals.locations,
        totals.entry_headers_read,
        totals.entries_decoded
    );
    // The slot map is what accounts for the data region, so these say nothing without the entry walk.
    if totals.data_region_bytes > 0 {
        println!(
            "region {} = claimed {} + unclaimed {} byte(s), slack {}",
            totals.data_region_bytes,
            totals.claimed_bytes,
            totals.unclaimed_bytes,
            totals.slack_bytes
        );
        println!(
            "{} gap(s), largest {}, {} empty-block region(s)",
            totals.gaps, totals.largest_gap, totals.unclaimed_regions
        );
    }
    println!(
        "{} index byte(s), {} hashed, {} unclaimed hash field(s), {} defect(s) suppressed",
        totals.index_bytes,
        totals.bytes_hashed,
        totals.unclaimed_hash_fields,
        totals.defects_suppressed
    );
    let swept = swept_bytes(totals);
    println!(
        "swept {} byte(s) in {:.2} s ({:.1} MB/s)",
        swept,
        elapsed.as_secs_f64(),
        rate_mb(swept, elapsed)
    );
    // Both the count and the worst arm, because a count alone does not say whether anything is worse
    // than a container a mod tool rewrote.
    match report.worst_severity() {
        None => println!("clean, no findings"),
        Some(worst) => println!(
            "{} finding(s), worst {}: {} altered, {} damaged, {} unusable",
            report.findings.len(),
            severity_name(worst),
            report.of_severity(Severity::Altered).count(),
            report.of_severity(Severity::Damaged).count(),
            report.of_severity(Severity::Unusable).count()
        ),
    }
    // A container another process held was not looked at, and saying "clean" about a sweep that
    // skipped some of the install would be the one reading a caller must not take from this.
    if !report.is_complete() {
        println!(
            "incomplete: {} container(s) were in use and not examined",
            report.totals.containers_busy
        );
    }
}

/// The same report as one object. The library publishes no `serde` (a taxonomy that grows whenever
/// something new is measured must not become a wire format), so the shape is assembled here out of what
/// it does publish: a stable slug, a severity, a scope, the rendered line, and integer totals.
fn json_report(
    report: &Report,
    opts: &SweepOptions,
    elapsed: Duration,
) -> Result<String, Box<dyn Error>> {
    let findings: Vec<Value> = report
        .findings
        .iter()
        .map(|finding| {
            json!({
                "slug": finding.slug(),
                "severity": severity_name(finding.severity()),
                "scope": scope_name(finding.scope()),
                "path": finding.site.container.relative_path().display().to_string(),
                "offset": finding.site.offset,
                // A key is 64 bits wide, which a JSON number does not carry exactly.
                "key": finding.site.key.map(|key| format!("{key:#018x}")),
                "message": finding.to_string(),
            })
        })
        .collect();
    let truncated: Vec<String> = report
        .truncated
        .iter()
        .map(|at| at.relative_path().display().to_string())
        .collect();
    let totals = &report.totals;
    let swept = swept_bytes(totals);
    let document = json!({
        "clean": report.is_clean(),
        // Alongside `clean`, never folded into it: a sweep that skipped a container another process
        // held found nothing wrong with what it read, and that is a different claim.
        "complete": report.is_complete(),
        "worst_severity": report.worst_severity().map(severity_name),
        "findings": findings,
        "truncated": truncated,
        "options": {
            "walk_entries": opts.walk_entries,
            "gaps": gap_policy_name(opts.gaps),
            "hash_data_regions": opts.hash_data_regions,
            "decode_entries": opts.decode_entries,
            "parallelism": opts.parallelism,
            "max_defects_per_container": opts.max_defects_per_container,
        },
        "timing": {
            "elapsed_seconds": elapsed.as_secs_f64(),
            "swept_bytes": swept,
            "swept_bytes_per_second": rate_mb(swept, elapsed) * 1e6,
        },
        "totals": {
            "archives": totals.archives,
            "index_files": totals.index_files,
            "data_files": totals.data_files,
            "containers_unreadable": totals.containers_unreadable,
            "containers_busy": totals.containers_busy,
            "index_bytes": totals.index_bytes,
            "entries": totals.entries,
            "collision_records": totals.collision_records,
            "locations": totals.locations,
            "entry_headers_read": totals.entry_headers_read,
            "entries_decoded": totals.entries_decoded,
            "bytes_hashed": totals.bytes_hashed,
            "data_region_bytes": totals.data_region_bytes,
            "claimed_bytes": totals.claimed_bytes,
            "slack_bytes": totals.slack_bytes,
            "unclaimed_bytes": totals.unclaimed_bytes,
            "gaps": totals.gaps,
            "largest_gap": totals.largest_gap,
            "unclaimed_regions": totals.unclaimed_regions,
            "unclaimed_hash_fields": totals.unclaimed_hash_fields,
            "defects_suppressed": totals.defects_suppressed,
        },
    });
    Ok(serde_json::to_string_pretty(&document)?)
}

/// Bytes of container the sweep put under a check: every index byte it read, plus the data region once.
/// The region is taken from whichever pass reached it, the entry walk accounting for it or the hash pass
/// reading it, with the hash pass's cover of the index headers and segments netted off so an index is not
/// counted twice.
///
/// A rate over this is how much install a pass covers per second and not a disk figure: the entry walk
/// reads twenty bytes per entry of a region it accounts for whole, and only `--hash-data` reads every
/// byte it counts.
fn swept_bytes(totals: &Totals) -> u64 {
    let region = totals
        .data_region_bytes
        .max(totals.bytes_hashed.saturating_sub(totals.index_bytes));
    totals.index_bytes + region
}

fn rate_mb(bytes: u64, elapsed: Duration) -> f64 {
    let seconds = elapsed.as_secs_f64();
    if seconds > 0.0 {
        bytes as f64 / seconds / 1e6
    } else {
        0.0
    }
}

fn severity_name(severity: Severity) -> &'static str {
    match severity {
        Severity::Altered => "altered",
        Severity::Damaged => "damaged",
        Severity::Unusable => "unusable",
    }
}

fn scope_name(scope: Scope) -> &'static str {
    match scope {
        Scope::File => "file",
        Scope::Container => "container",
        Scope::Archive => "archive",
    }
}

fn gap_policy_name(gaps: GapPolicy) -> &'static str {
    match gaps {
        GapPolicy::Skip => "skip",
        GapPolicy::Chain => "chain",
    }
}

fn read_prefix(path: &Path, len: usize) -> Result<Vec<u8>, Box<dyn Error>> {
    let source = apogee_sqpack::FileSource::open(path)?;
    let mut buf = vec![0u8; len];
    let read = source.read_at(&mut buf, 0)?;
    buf.truncate(read);
    Ok(buf)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
