//! `sqpack-tool`: the archive inspection binary. Three verbs:
//!
//! ```text
//! cargo run -p apogee-sqpack --example sqpack_tool -- stat <game-dir|sqpack-file>
//! cargo run -p apogee-sqpack --example sqpack_tool -- ls <file.index|file.index2> [limit]
//! cargo run -p apogee-sqpack --example sqpack_tool -- extract <game-dir> <game/path> <out-file>
//! ```
//!
//! `stat` reports what a game tree holds, or what one container's headers say; `ls` walks an index's
//! entries; `extract` resolves a game path and writes the file's bytes. All of the format knowledge
//! lives in the library, so this example stays an I/O shell that the library never has to become.

use std::error::Error;
use std::fs;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::process::ExitCode;

use apogee_sqpack::{
    ContentType, Dat, DatSource, Entry, EntryBody, GameData, Index, IndexKind, SqPackKind,
    parse_common_header,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.split_first() {
        Some((verb, rest)) if verb == "stat" && rest.len() == 1 => stat(Path::new(&rest[0])),
        Some((verb, rest)) if verb == "ls" && (1..=2).contains(&rest.len()) => ls(rest),
        Some((verb, rest)) if verb == "extract" && rest.len() == 3 => extract(rest),
        _ => {
            eprintln!(
                "usage:\n  sqpack_tool stat <game-dir|sqpack-file>\n  sqpack_tool ls <file.index|file.index2> [limit]\n  sqpack_tool extract <game-dir> <game/path> <out-file>"
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
    for repo in game.repos() {
        println!(
            "{:<6} version={}",
            repo.repo.dir_name(),
            repo.version.as_deref().unwrap_or("<none>")
        );
    }
    for archive in game.archives() {
        let dats = (0..u8::MAX)
            .take_while(|n| archive.dat_path(*n).is_file())
            .count();
        println!(
            "{:<6} {} index={} index2={} dats={}",
            archive.repo.dir_name(),
            archive.id.stem(),
            archive.has_index1,
            archive.has_index2,
            dats
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
    for record in index.collisions() {
        println!(
            "{:016x}  #{} {}",
            record.key, record.conflict_index, record.path
        );
    }
    println!("{} entry/entries", index.entries().len());
    Ok(true)
}

/// Resolve a game path and write its bytes. `args` is `game-dir, game/path, out-file`.
fn extract(args: &[String]) -> Result<bool, Box<dyn Error>> {
    let game = GameData::open(Path::new(&args[0]))?;
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
