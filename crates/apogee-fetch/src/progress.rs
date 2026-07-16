//! Download progress events.

/// A snapshot of a download's progress, relayed over a channel the caller owns. A plain, clockless
/// data struct: the consumer derives rate and ETA from successive `bytes_done`, so the same event
/// serves the shell, the CLI, and tests identically.
#[derive(Debug, Clone)]
pub struct Progress {
    /// Bytes durably written and hashed so far. Monotonic within a run.
    pub bytes_done: u64,
    /// The total expected length once known (the caller's `expected_len`, else the server's
    /// advertised length), or `None` when the source declares neither.
    pub total: Option<u64>,
    /// Which stage the download has reached.
    pub phase: Phase,
}

/// The stage a download has reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    /// Opening the connection and reading response headers.
    Connecting,
    /// Streaming the body to disk.
    Downloading,
    /// Hashing the finished file for the whole-file validator.
    Verifying,
    /// The file is verified and published to its destination.
    Complete,
}
