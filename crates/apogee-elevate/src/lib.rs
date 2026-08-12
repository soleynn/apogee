#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! The privilege boundary a patch apply crosses when the install tree is not writable.
//!
//! Two sides and one message set. The unprivileged side ([`Session`]) fetches nothing here: it hands
//! a worker local files it has already downloaded and verified, and reads back typed progress and a
//! typed result. The privileged side ([`serve`]) re-proves every file from the handle it applies it
//! from, keeps every write inside the tree the session was bound to, and never ends the process it
//! is talking to. Network never crosses: this crate cannot reach an HTTP client, and the worker
//! binary built on it therefore cannot either.
//!
//! The transport is deliberately at the edge. Framing, the message set and the whole worker are
//! written against a reader and a writer, so the same code runs over a child's standard streams, an
//! in-memory pair, or the named pipe that a raised-privilege child on Windows connects back on,
//! which is the only transport that platform allows: the call that raises privileges is a shell
//! verb, and a shell verb has nowhere to put a redirected handle.
//!
//! # Layout
//!
//! - [`Session`] drives a worker: [`Session::bind`], then either [`Session::apply`] per patch and
//!   [`Session::copy_within`] (an install), or [`Session::move_within`] per stray and
//!   [`Session::repair`] per batch of writes (a repair).
//! - [`serve`] is the worker's whole main loop.
//! - [`spawn::direct`] starts a worker with this process's privileges; on Windows
//!   `spawn::elevated` raises them first.
//! - [`WorkerRequest`], [`WorkerResponse`], [`WorkerProgress`], [`Admission`] and [`StagedWrite`]
//!   are the wire.
//! - [`Error`] is what a caller sees, including [`Error::Gone`] for a worker that died mid-request.
//!
//! # Examples
//!
//! ```
//! # use std::path::Path;
//! # use apogee_elevate::{Admission, VersionWrite, Worker};
//! # use tokio_util::sync::CancellationToken;
//! # async fn demo(worker: &mut Worker, root: &Path, patch: &Path, admitted: [u8; 32])
//! #     -> apogee_elevate::Result<()> {
//! let session = worker.session();
//! session.bind(root).await?;
//! session
//!     .apply(
//!         patch,
//!         Admission::ChunkCrc { content: admitted },
//!         Some(VersionWrite {
//!             path: "ffxivboot.ver".to_owned(),
//!             contents: "2024.01.02.0000.0000".to_owned(),
//!         }),
//!         &CancellationToken::new(),
//!         |frame| tracing::debug!(?frame, "the worker made progress"),
//!     )
//!     .await?;
//! # Ok(())
//! # }
//! ```

mod client;
mod confine;
mod error;
mod proto;
pub mod spawn;
mod worker;

pub use client::Session;
pub use error::{Error, Result};
pub use proto::{
    Admission, FrameError, MAX_FRAME, MAX_STAGED_SPAN, MAX_VERSION_LEN, PROTOCOL_VERSION, StagedOp,
    StagedWrite, VersionWrite, WorkerErrorKind, WorkerProgress, WorkerRequest, WorkerResponse,
};
pub use spawn::Worker;
pub use worker::serve;
