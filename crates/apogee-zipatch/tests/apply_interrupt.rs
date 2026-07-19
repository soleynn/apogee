//! Interruption safety: applying a torn prefix of a patch's commands and then re-running the whole
//! patch converges to the same tree as one clean run. Every write is positioned (seek + write), so
//! re-execution is idempotent, and the patcher re-runs a whole patch after any interrupted apply
//! (the `.ver` is written only on clean completion). This pins that convergence over the at-scale
//! command mix (`A`/`D`/`E`/`H`/`F:A`) driven into the in-memory sink.

mod support;

use apogee_zipatch::{ApplyOptions, Error, PatchReader, apply};
use proptest::prelude::*;

use support::{InMemorySink, PatchBuilder, block_stored};

/// Two base-game file-targets the generated commands share, so writes interleave on the same files.
/// Their `A`/`D`/`E`/`H` path resolution and the `F:A` paths below name the same two dats.
const TARGETS: [(u16, u16, u32); 2] = [(0x0a, 0x0000, 0), (0x0a, 0x0000, 1)];
const PATHS: [&str; 2] = [
    "sqpack/ffxiv/0a0000.win32.dat0",
    "sqpack/ffxiv/0a0000.win32.dat1",
];

/// One generated command over the two shared dats. Offsets and spans are in 128-byte block units,
/// kept small so writes overlap and interleave.
#[derive(Debug, Clone)]
enum Op {
    Add {
        tgt: usize,
        off_u: u32,
        blocks: u8,
        fill: u8,
        del_u: u32,
    },
    Empty {
        tgt: usize,
        expand: bool,
        off_u: u32,
        count: u32,
    },
    Header {
        tgt: usize,
        version: bool,
        fill: u8,
    },
    AddFile {
        tgt: usize,
        off_u: u32,
        fill: u8,
        len_blocks: u8,
    },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        (0usize..2, 0u32..8, 1u8..=2, any::<u8>(), 0u32..2).prop_map(
            |(tgt, off_u, blocks, fill, del_u)| Op::Add {
                tgt,
                off_u,
                blocks,
                fill,
                del_u
            }
        ),
        (0usize..2, any::<bool>(), 0u32..8, 0u32..4).prop_map(|(tgt, expand, off_u, count)| {
            Op::Empty {
                tgt,
                expand,
                off_u,
                count,
            }
        }),
        (0usize..2, any::<bool>(), any::<u8>()).prop_map(|(tgt, version, fill)| Op::Header {
            tgt,
            version,
            fill
        }),
        (0usize..2, 0u32..8, any::<u8>(), 1u8..=2).prop_map(|(tgt, off_u, fill, len_blocks)| {
            Op::AddFile {
                tgt,
                off_u,
                fill,
                len_blocks,
            }
        }),
    ]
}

/// Render `ops` into a boot-shaped patch (`FHDR`/`T`/commands/`EOF_`).
fn build_patch(ops: &[Op]) -> Vec<u8> {
    let mut b = PatchBuilder::new();
    b.fhdr(b"DIFF", 1).target_info(0);
    for op in ops {
        match *op {
            Op::Add {
                tgt,
                off_u,
                blocks,
                fill,
                del_u,
            } => {
                let data = vec![fill; (blocks as usize) << 7];
                b.add_data(
                    TARGETS[tgt],
                    u64::from(off_u) << 7,
                    &data,
                    u64::from(del_u) << 7,
                );
            }
            Op::Empty {
                tgt,
                expand,
                off_u,
                count,
            } => {
                let cmd = if expand { b'E' } else { b'D' };
                b.empty_block(cmd, TARGETS[tgt], u64::from(off_u) << 7, count);
            }
            Op::Header { tgt, version, fill } => {
                let hk = if version { b'V' } else { b'D' };
                b.header(b'D', hk, TARGETS[tgt], &vec![fill; 1024]);
            }
            Op::AddFile {
                tgt,
                off_u,
                fill,
                len_blocks,
            } => {
                let data = vec![fill; (len_blocks as usize) << 7];
                let off = i64::from(off_u) << 7;
                b.file_op(
                    b'A',
                    off,
                    data.len() as i64,
                    PATHS[tgt],
                    &block_stored(&data),
                );
            }
        }
    }
    b.eof();
    b.bytes()
}

fn apply_all(patch: &[u8], sink: &mut InMemorySink) -> Result<(), Error> {
    let mut reader = PatchReader::open(patch)?;
    apply(&mut reader, sink, &ApplyOptions::default())
}

proptest! {
    #[test]
    fn a_torn_prefix_reapplied_converges(
        ops in prop::collection::vec(op_strategy(), 1..12),
        cut in 0usize..12,
    ) {
        let cut = cut.min(ops.len());
        let full = build_patch(&ops);
        let prefix = build_patch(&ops[..cut]);

        // One clean run.
        let mut clean = InMemorySink::default();
        apply_all(&full, &mut clean).expect("apply clean");

        // A torn run: apply the prefix, then re-run the whole patch over the partial tree.
        let mut torn = InMemorySink::default();
        apply_all(&prefix, &mut torn).expect("apply prefix");
        apply_all(&full, &mut torn).expect("re-apply full");

        prop_assert_eq!(torn.files, clean.files);
    }
}
