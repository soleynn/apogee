//! One connection, from accept to close. The only file here that touches a socket.
//!
//! It holds no rules: it reads bytes, hands them to the grammar, and writes one of three constants.
//! Every decision about what a request may look like was made before this file was reached.

use std::net::IpAddr;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;
use zeroize::Zeroizing;

use super::grammar::{Digits, Feed, Refusal, RequestReader};
use super::wire::{RESPONSE_BAD_REQUEST, RESPONSE_OK, RESPONSE_TOO_MANY};

/// How long one connection may live, measured from accept and covering the read, the answer, the
/// shutdown and the drain.
///
/// Not a per-read timeout: that resets on every byte, so a peer dripping one byte at a time satisfies
/// it forever. A phone on a home network puts forty bytes on the wire in milliseconds, so three
/// seconds is three orders of margin and still turns a slow-drip peer into a three-second nuisance.
pub(crate) const CONNECTION_DEADLINE: Duration = Duration::from_secs(3);

/// How much a peer may have queued behind its request line before the drain gives up.
///
/// Its own ceiling rather than what is left of the request cap. A header block plus a body is easily
/// several hundred bytes, and a drain that stopped short would close with data still queued, which is
/// what makes the kernel send a reset.
const MAX_DRAIN: usize = 8192;

/// The scratch one read lands in before it is fed to the reader.
const SCRATCH: usize = 1024;

/// Whether this connection is read, or refused before it is read.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode {
    /// Read a request line and answer it.
    Read,
    /// The source is past its budget: answer and close without reading a byte.
    Throttled,
}

/// A code taken off the wire, on its way to the wait.
pub(crate) struct Delivery {
    pub(crate) digits: Digits,
    pub(crate) from: IpAddr,
}

/// What one connection turned out to be, handed back through the task set.
pub(crate) struct Completion {
    pub(crate) peer: IpAddr,
    /// A complete request line was read, valid or not, so this connection spends an attempt.
    ///
    /// False for a peer that never completed one, which is what keeps a garbage flood off the code
    /// budget: the flood is bounded by the concurrency caps instead, and those never produce a 429.
    pub(crate) read_a_line: bool,
    /// Whether it was turned away, for the tally.
    pub(crate) refused: bool,
}

/// Serve one connection to completion, or to `until`, whichever comes first.
///
/// The deadline wraps the whole handler rather than any single await, and the flag it reports is
/// written before the await that could expire, so a connection cut short still tells the wait what it
/// spent.
pub(crate) async fn serve_one(
    stream: TcpStream,
    peer: IpAddr,
    mode: Mode,
    until: Instant,
    deliveries: mpsc::Sender<Delivery>,
) -> Completion {
    let mut read_a_line = false;
    let refused = tokio::time::timeout_at(
        until,
        handle(stream, peer, mode, deliveries, &mut read_a_line),
    )
    .await
    .unwrap_or(true);
    Completion {
        peer,
        read_a_line,
        refused,
    }
}

/// The body. Returns whether this connection was turned away.
async fn handle(
    mut stream: TcpStream,
    peer: IpAddr,
    mode: Mode,
    deliveries: mpsc::Sender<Delivery>,
    read_a_line: &mut bool,
) -> bool {
    // One small write and nothing to coalesce it with, so waiting up to forty milliseconds for a
    // partner would be forty milliseconds of nothing.
    let _ = stream.set_nodelay(true);
    let mut scratch = Zeroizing::new([0u8; SCRATCH]);

    if matches!(mode, Mode::Throttled) {
        let _ = stream.write_all(RESPONSE_TOO_MANY).await;
        // Drained even though nothing was read, and *because* nothing was read: the peer's request is
        // still sitting in the receive queue, so closing on top of it makes the kernel send a reset,
        // and the reset discards the answer just written from the peer's own buffer. Unlike the
        // refusal below, where a complete line has usually consumed the request, here there is always
        // something left, so without this the 429 is a response no peer ever actually sees, and a
        // source being rate limited cannot tell that from the launcher having died.
        let _ = stream.shutdown().await;
        drain(&mut stream, &mut scratch).await;
        return true;
    }

    let mut reader = RequestReader::new();
    loop {
        let read = match stream.read(scratch.as_mut()).await {
            // A zero-length read is end of file and terminates the loop unconditionally. Treating it
            // as "try again" is the most common bug in a hand-rolled server: a half-closed socket
            // stays readable and answers zero every time, so the loop spins a core for as long as the
            // peer leaves it that way, and the peer pays nothing to hold it there.
            Ok(0) => {
                let _ = reader.eof();
                return true;
            }
            Ok(read) => read,
            // A peer that broke the connection has not made a request, so there is nothing to answer.
            Err(_) => return true,
        };
        let Feed::Line(line) = reader.feed(&scratch[..read]) else {
            continue;
        };
        // A line that filled the cap without a terminator is not a complete request, so it does not
        // spend the code budget. That is what keeps a flood of unterminated garbage from locking out
        // the phone that is about to push a real code.
        *read_a_line = !matches!(line, Err(Refusal::Overlong));
        let Ok(digits) = line else {
            // No shutdown and no drain: a peer already outside the contract may therefore see a reset
            // rather than its 400, which is the right trade for the cheap path.
            let _ = stream.write_all(RESPONSE_BAD_REQUEST).await;
            return true;
        };

        // Commit before answering. The response is a courtesy to the phone and never a step the login
        // waits on, so a peer that stalls reading it cannot stall the login. The channel's capacity is
        // the concurrency bound, so this cannot fail for space; a closed receiver means the wait
        // already ended, and then there is nothing to deliver to.
        let _ = deliveries.try_send(Delivery { digits, from: peer });
        let _ = stream.write_all(RESPONSE_OK).await;
        let _ = stream.shutdown().await;
        drain(&mut stream, &mut scratch).await;
        return false;
    }
}

/// Read and discard whatever the peer queued behind its request line.
///
/// Load-bearing for delivery rather than for security. Closing a socket with unread data still in the
/// receive queue makes the kernel send a reset, and the peer's stack may then discard response bytes
/// already sitting in its own buffer. A phone that sent a header block after its request line leaves
/// exactly such data, so a listener that closed immediately would be one that took a code and told the
/// phone it had failed. Bounded twice, by these bytes and by the connection deadline above, and it
/// never waits for the peer's own close.
async fn drain(stream: &mut TcpStream, scratch: &mut Zeroizing<[u8; SCRATCH]>) {
    let mut seen = 0usize;
    while seen < MAX_DRAIN {
        match stream.read(scratch.as_mut()).await {
            Ok(0) | Err(_) => return,
            Ok(read) => seen += read,
        }
    }
}
