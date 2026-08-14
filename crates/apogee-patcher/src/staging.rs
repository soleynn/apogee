//! Handing a repair's writes to a worker that has the rights to make them.
//!
//! The division is the one an install already keeps: this process does everything but the writing.
//! It verifies the tree, plans the heal, fetches the broken ranges and checks each part's bytes
//! against the index, and only then stages those bytes into a file and names the spans to write.
//! The worker fetches nothing and decides nothing.
//!
//! What the staging file costs is a second proof. It sits in the patch store, which the unprivileged
//! user can write, so a digest travels with every span and the privileged side re-derives it from
//! what it reads. That is the same reason a patch is re-verified before it is applied, and it is why
//! the parent's own CRC check against the index is not enough on its own: the check happened here.
//!
//! Batches keep both ends bounded. A pass hands over its writes every [`FLUSH_BYTES`] or
//! [`FLUSH_WRITES`], so the staging file never grows past one batch and no request approaches the
//! frame cap. Each batch is independent and every write in it is positioned, so a run torn between
//! two batches leaves a tree the next verify simply finds still broken.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use apogee_elevate::{MAX_STAGED_SPAN, StagedOp, StagedWrite};
use apogee_zipatch::{DiskRepairSink, Error as ZipError, Op, RepairSink, RepairWrite};
use tokio::runtime::Handle;
use tokio_util::sync::CancellationToken;

use crate::elevated::WorkerLink;
use crate::{PatchError, store};

/// How many staged bytes a batch accumulates before a flush is checked for.
///
/// The check runs after a whole write lands, not during one, so a single large part can carry the
/// file past this before `send` is called; the staging file is otherwise the only disk a privileged
/// repair costs beyond the heal itself.
const FLUSH_BYTES: u64 = 32 << 20;

/// How many writes a batch carries before it is handed over.
///
/// The frame cap is the real bound; this keeps a repair of many small parts well under it without
/// having to measure the encoded size of every write.
const FLUSH_WRITES: usize = 4096;

/// A repair sink that can also report a failure the repair's own error type cannot carry.
///
/// `apogee-zipatch` unwinds a pass through its error type, which has no room for a worker that died
/// or refused. A sink that talks to one keeps the typed failure instead and hands it back here, so
/// the caller reports what actually happened rather than the placeholder it unwound on.
pub(crate) trait RepairTarget: RepairSink {
    /// The typed failure this sink stashed while unwinding, if it stashed one.
    fn fault(&mut self) -> Option<PatchError> {
        None
    }
}

/// Writing to the tree in this process cannot fail in a way the repair's error type does not already
/// carry, so it never stashes anything.
impl RepairTarget for DiskRepairSink {}

/// Stages a repair's writes and hands them to a worker in batches.
pub(crate) struct StagingSink<'a> {
    link: WorkerLink<'a>,
    handle: Handle,
    cancel: &'a CancellationToken,
    staging: PathBuf,
    file: Option<File>,
    staged: u64,
    writes: Vec<StagedWrite>,
    fault: Option<PatchError>,
}

impl<'a> StagingSink<'a> {
    /// Stage into `staging` and hand batches to `link`.
    ///
    /// `handle` is what makes a synchronous sink able to talk to an asynchronous worker: a repair
    /// pass runs on a blocking worker off the runtime (the range source already requires that), so
    /// blocking on the boundary here is the same call the range source makes to fetch.
    pub(crate) fn new(
        link: WorkerLink<'a>,
        staging: PathBuf,
        handle: Handle,
        cancel: &'a CancellationToken,
    ) -> Self {
        Self {
            link,
            handle,
            cancel,
            staging,
            file: None,
            staged: 0,
            writes: Vec::new(),
            fault: None,
        }
    }

    /// Queue a write that carries no bytes.
    fn push(&mut self, path: String, op: StagedOp) {
        self.writes.push(StagedWrite { path, op });
    }

    /// Stage one part's bytes and queue the writes that read them back.
    ///
    /// Split at [`MAX_STAGED_SPAN`], which costs nothing: the writes are positioned, so a part
    /// written in pieces lands exactly as one written whole, and the split bounds the buffer the
    /// worker holds to hash a span.
    fn stage(&mut self, path: &str, off: u64, bytes: &[u8]) -> Result<(), ZipError> {
        let span_len = MAX_STAGED_SPAN as usize;
        for (piece, span) in bytes.chunks(span_len).enumerate() {
            let staged_off = self.staged;
            self.append(span)?;
            let len = u32::try_from(span.len()).map_err(|_| ZipError::Corrupt {
                offset: off,
                detail: "a staged span is longer than the boundary accepts",
            })?;
            self.writes.push(StagedWrite {
                path: path.to_owned(),
                op: StagedOp::Bytes {
                    off: off.saturating_add((piece * span_len) as u64),
                    staged_off,
                    len,
                    digest: *blake3::hash(span).as_bytes(),
                },
            });
        }
        Ok(())
    }

    /// Append one span to the staging file, creating it on the first write of a batch.
    fn append(&mut self, span: &[u8]) -> Result<(), ZipError> {
        if self.file.is_none() {
            // The whole batch is rewritten from the start each time, so the file is created rather
            // than opened: the offsets a batch names are its own.
            if let Some(parent) = self.staging.parent() {
                std::fs::create_dir_all(parent).map_err(|e| self.stash_io(e))?;
            }
            match File::create(&self.staging) {
                Ok(file) => self.file = Some(file),
                Err(e) => return Err(self.stash_io(e)),
            }
        }
        // The offsets a batch names are counted from what actually reached the file, so a write that
        // did not happen has to fail rather than advance them: the far side would otherwise be told
        // to read a span nothing wrote. That is why the unreachable arm below is an error and not a
        // quiet success.
        let written = self.file.as_mut().map(|file| file.write_all(span));
        match written {
            Some(Ok(())) => {
                self.staged += span.len() as u64;
                Ok(())
            }
            Some(Err(e)) => Err(self.stash_io(e)),
            // Unreachable: the branch above fills the slot or returns.
            None => Err(self.stash_io(std::io::Error::other("the staging file was not opened"))),
        }
    }

    /// Hand the queued batch over, if there is one.
    fn send(&mut self) -> Result<(), ZipError> {
        if self.writes.is_empty() {
            return Ok(());
        }
        // Closed before the worker opens it: the worker takes the staging file denying other
        // writers, and an open write handle here is a sharing violation there rather than a stale
        // read.
        drop(self.file.take());
        let writes = std::mem::take(&mut self.writes);
        let staging = (self.staged > 0).then(|| self.staging.clone());
        let outcome =
            self.handle.block_on(
                self.link
                    .repair(staging.as_deref(), writes, None, self.cancel),
            );
        // The next batch starts a fresh file at offset zero, whether this one landed or not.
        self.staged = 0;
        match outcome {
            Ok(()) => Ok(()),
            Err(fault) => Err(self.stash(fault)),
        }
    }

    /// Keep a typed failure and return something to unwind the repair pass on.
    fn stash(&mut self, fault: PatchError) -> ZipError {
        let unwind = ZipError::Io {
            source: std::io::Error::other(fault.to_string()),
            target: Some(self.staging.clone()),
            during: Op::Write,
        };
        self.fault = Some(fault);
        unwind
    }

    /// The same, for a failure staging the bytes rather than handing them over.
    fn stash_io(&mut self, source: std::io::Error) -> ZipError {
        self.stash(PatchError::Io {
            path: self.staging.clone(),
            source,
        })
    }
}

impl RepairSink for StagingSink<'_> {
    fn write(&mut self, target: &Path, write: RepairWrite<'_>) -> Result<(), ZipError> {
        let path = store::slashed(target).ok_or_else(|| ZipError::PathEscape {
            raw: target.display().to_string(),
        })?;
        match write {
            RepairWrite::Create { len } => self.push(path, StagedOp::Create { len }),
            RepairWrite::Resize { len } => self.push(path, StagedOp::Resize { len }),
            RepairWrite::Zeros { off, len } => self.push(path, StagedOp::Zeros { off, len }),
            RepairWrite::Bytes { off, bytes } => self.stage(&path, off, bytes)?,
        }
        if self.staged >= FLUSH_BYTES || self.writes.len() >= FLUSH_WRITES {
            return self.send();
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), ZipError> {
        self.send()
    }
}

impl RepairTarget for StagingSink<'_> {
    fn fault(&mut self) -> Option<PatchError> {
        self.fault.take()
    }
}
