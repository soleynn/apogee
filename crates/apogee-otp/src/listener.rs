//! The local endpoint a companion delivers a code to.
//!
//! One legal request, one response, one code. The socket is taken when a login begins waiting for a
//! phone and released when the wait ends, and the whole of the hardening is a refusal to be a general
//! server: no header is interpreted, no body is read, no connection is reused, and nothing derived
//! from a request reaches the response. What that leaves is an anchored thirty-byte comparison, a
//! fixed buffer and a deadline.
//!
//! The wire contract is the reference launcher's and cannot be strengthened without breaking the
//! phone apps it exists for: plain HTTP, no authentication, and a code from whoever reaches the port
//! first. What can be bounded is the exposure, so it is. The common launch never binds at all, because
//! a cached session skips authentication entirely.
//!
//! Origin-form targets only, which is a deliberate deviation from the HTTP grammar: this is a
//! single-endpoint appliance rather than an origin server, and accepting the absolute form means
//! parsing an authority, which means applying host normalization and default-port rules to hostile
//! input to answer a question nobody asked. Request smuggling needs a body, connection reuse, or a
//! downstream parser, and there is none of the three, so the whole family is unreachable rather than
//! filtered; that is worth knowing before anyone adds header parsing thinking it is inert. An upgrade
//! request is a valid request line under this grammar and is answered as the ordinary code delivery it
//! textually is, because there is no upgrade machinery to reach.
//!
//! Nothing here logs, and that is the mechanism rather than the discipline: this crate has no logging
//! dependency, so no request byte can reach a log from inside it. The peer address travels out on
//! [`Received::from`] and the caller says the sentence. Nothing constant-time is needed either: the
//! only comparison on this path is against a public constant, because a code is arriving rather than
//! being verified.
//!
//! Nothing here sleeps on a human. A caller passes the deadline it is willing to wait and holds its
//! own cancellation around the call, exactly as it does for the reuse guard's hold.

mod conn;
mod filter;
mod grammar;
mod limiter;
mod wire;

#[cfg(test)]
mod tests;

use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant as Monotonic};

use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::code::Code;
use crate::error::OtpError;
use conn::{Completion, Delivery, Mode, serve_one};
use limiter::{Limiter, SourceKey};

pub use filter::{Pinned, SourceFilter};

/// The port the companion app dials.
///
/// Not a preference: a listener on any other port is one that nothing will find. It is configurable
/// only because a machine may already have something else on it, and a user who moves it has to move
/// the phone too.
pub const COMPAT_PORT: u16 = 4646;

/// How many connections are served at once.
///
/// A concurrency bound, not a queue. The cost of any flood is this many buffers, tasks and
/// descriptors, whatever arrives. Past it a connection is accepted and closed immediately rather than
/// left in the backlog, because a full backlog drops the honest phone's connection attempt silently,
/// which turns a nuisance into a complete denial of delivery.
const MAX_CONCURRENT: usize = 16;

/// How many of those one source may hold.
///
/// One push is one connection, and a client retrying while its first is still draining is the only
/// legitimate second. This is what makes the overall bound mean anything: without it one scripted peer
/// holds every slot, and with it that peer needs eight working addresses.
const MAX_CONCURRENT_PER_SOURCE: usize = 2;

/// How long the wait lingers after the port is closed so the delivering peer receives its answer.
///
/// Essentially never spent: the write is about a hundred bytes into a fresh socket. It exists so that
/// a peer which stops reading cannot hold the login open, and it is the only thing the login waits on
/// once a code is in hand.
const RESPONSE_GRACE: Duration = Duration::from_millis(250);

/// How long to wait after an accept failure that is not attributable to one peer.
///
/// Not zero: the pending connection is still in the backlog, so an immediate retry spins a core.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(100);

/// Where the listener sits and who may reach it.
///
/// The bind interface is explicit rather than always the wildcard, because the wildcard is not "the
/// LAN". It is every interface this host currently answers on, which on a real machine can include a
/// tunnel reachable from anywhere on a personal overlay, a bridged virtual machine interface, a
/// container bridge, hotel wireless where every other guest is on-link, and on a machine with a public
/// address, the internet. The default is what the reference does, because that is what makes the phone
/// app work with no configuration; a multi-homed host names the interface that faces the phone.
///
/// Three fields, and each is a fact a user can be wrong about in a way nothing else can fix.
/// Everything else the listener needs is a constant with a stated reason, because a knob on the
/// hardening is a way to configure the hardening off. The deadline is not here either: how long to
/// wait is a property of this login's patience rather than of this machine's network, so it is an
/// argument to [`Listener::wait_for_code`].
///
/// The derived `Debug` is deliberate and is the only one in this module. Nothing here is a secret: it
/// is the user's own configuration, already in their settings file, and a redacted bind address would
/// make a bind failure undiagnosable.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    /// The interface to take.
    pub bind: IpAddr,
    /// The port to take. [`COMPAT_PORT`] unless a user has a conflict; zero takes an ephemeral one,
    /// which is what every test uses so that two of them never collide.
    pub port: u16,
    /// Which sources are admitted, checked at accept before anything is read or allocated.
    pub allow: SourceFilter,
}

/// Hand written rather than derived: a derived one would take port zero, which does not mean "the
/// usual port", it means "any ephemeral port", and a listener on one of those is a broken wire
/// contract that presents as the phone app not working.
impl Default for ListenerConfig {
    fn default() -> Self {
        Self {
            bind: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: COMPAT_PORT,
            allow: SourceFilter::Any,
        }
    }
}

/// The user said, in as many words, that this machine may open a port on its network while a login
/// waits.
///
/// Holds nothing, and is neither `Clone`, `Copy`, `Default`, nor deserializable, with a private field,
/// so it cannot be conjured by a struct literal or produced by parsing a config file. It is consumed
/// by the call it authorizes. What it does is confine the ability to say "the user asked for this" to
/// the layer that can actually ask, and its single constructor is greppable, so that confinement is
/// checkable rather than merely intended.
pub struct ListenerConsent(());

impl ListenerConsent {
    /// The user was shown what a listening port admits and said yes.
    #[must_use]
    pub fn granted() -> Self {
        Self(())
    }
}

/// Consent is a fact about a conversation, not a value with contents.
impl fmt::Debug for ListenerConsent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ListenerConsent")
    }
}

/// A delivered code, and what the wait saw while it waited.
///
/// Shaped like [`crate::Minted`]: the metadata is borrowed and the code is taken, so the one call that
/// submits it is the one call that names it. Implements no `Clone` (a clone is a second buffer of
/// digits with its own lifetime), no `Display`, no `PartialEq`, and has no public constructor.
pub struct Received {
    code: Code,
    from: IpAddr,
    refused: u32,
    limited: Option<IpAddr>,
}

impl Received {
    /// Take the code.
    #[must_use]
    pub fn into_code(self) -> Code {
        self.code
    }

    /// The address the code came from, canonicalized.
    ///
    /// A user who sees a code arrive from something that is not their phone learns something no other
    /// signal carries, which is the whole of what this endpoint can offer against a peer that beats
    /// the phone to it.
    #[must_use]
    pub fn from(&self) -> IpAddr {
        self.from
    }

    /// How many connections the wait turned away, over every reason: refused by the filter, refused by
    /// a budget, refused by the grammar, dropped on a deadline, or closed at the concurrency bound.
    ///
    /// One number rather than a stream. An event per refusal is itself a flood, and the unbounded
    /// channel a caller reads would carry every one of them.
    #[must_use]
    pub fn refused(&self) -> u32 {
        self.refused
    }

    /// The first source the limiter shut off, if any.
    ///
    /// Present means the limiter engaged, which is the difference between a flood that was stopped and
    /// a flood that was merely slow, and it is what a test asserts on instead of a timing.
    #[must_use]
    pub fn limited(&self) -> Option<IpAddr> {
        self.limited
    }
}

/// Everything but the code. `Code`'s own rendering would redact it anyway; this spells it out so that
/// a field added later does not quietly start printing one.
impl fmt::Debug for Received {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Received")
            .field("from", &self.from)
            .field("refused", &self.refused)
            .field("limited", &self.limited)
            .finish_non_exhaustive()
    }
}

/// The local one-time-password listener.
///
/// Bound on entering a wait and closed on leaving it, which is the improvement over the reference:
/// there is no idle listening and no port held open for the length of a launcher session.
pub struct Listener {
    socket: TcpListener,
    addr: SocketAddr,
    allow: SourceFilter,
}

impl Listener {
    /// Take the interface and port named by `cfg`.
    ///
    /// The step that can fail locally is separate from the step that sits on a human, exactly as
    /// reading the stored secret is separate from deriving a code against a clock. It is `async`
    /// because the socket has to be registered with the runtime's reactor, and an `async fn` makes
    /// that a fact the compiler checks rather than a panic a caller discovers.
    ///
    /// No fallback port and no retry: the phone app dials one port, so a listener that quietly moved
    /// is a listener nothing will find, and the honest answer is to say which port could not be taken.
    /// No socket option is set beyond what the standard library sets, and that is a decision rather
    /// than laziness. Address reuse is already the hardened setting on both platforms for opposite
    /// reasons: on Unix it permits rebinding over a lingering connection, while on Windows the same
    /// option would let a second local process bind over a live listener and take every subsequent
    /// code. Port reuse must never be set anywhere, because it invites any local process to share our
    /// codes.
    ///
    /// # Errors
    /// [`OtpError::ListenerBind`], carrying the port, for every reason the bind can fail. The port is
    /// the one fact that makes the sentence a shell renders actionable: something else already holds
    /// it, which on this port is almost always a running reference launcher.
    pub async fn bind(cfg: ListenerConfig) -> Result<Self, OtpError> {
        let wanted = cfg.port;
        let socket = TcpListener::bind(SocketAddr::new(cfg.bind, cfg.port))
            .await
            .map_err(|_| OtpError::ListenerBind { port: wanted })?;
        let addr = socket
            .local_addr()
            .map_err(|_| OtpError::ListenerBind { port: wanted })?;
        Ok(Self {
            socket,
            addr,
            allow: cfg.allow,
        })
    }

    /// The address actually taken.
    ///
    /// Read at bind time and cached, so it cannot fail and cannot change. A caller that asked for port
    /// zero learns its port here, which is how a test avoids colliding with every other test and with
    /// a launcher already running on the machine.
    #[must_use]
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Wait up to `deadline` for a well-formed code, then close.
    ///
    /// Consumes the listener, so the port is gone by the time this returns on every path there is,
    /// including the error paths, and a caller cannot hold it open by forgetting to drop it.
    /// A code that arrives afterwards is refused by the operating system, which is honest: answering
    /// success for a code that will not be used would make the phone report a login that then fails.
    ///
    /// The first well-formed code wins, including a hostile one, and the port closes before the
    /// response to it is written. A peer that beats the phone makes this login fail with a rejected
    /// code and the user starts over; that is the nuisance a contract with no authentication on it
    /// already accepts, and the address it came from rides back on [`Received::from`] so a caller can
    /// say where it came from. A user who pins their phone closes it entirely.
    ///
    /// Every other connection is answered and closed while the wait continues, so a peer sending
    /// garbage costs the wait nothing but seconds it was going to spend anyway.
    ///
    /// # Cancellation
    /// There is no token parameter. Everything this call starts, it owns, so dropping the future
    /// closes the socket and aborts every connection in flight. A caller selects this against its own
    /// token, which is where the token already lives.
    ///
    /// # Errors
    /// [`OtpError::Timeout`] if `deadline` elapses with nothing accepted, and nothing else. A failure
    /// on one connection is that connection's outcome, and an accept-level failure is backed off and
    /// retried: one bad accept may not end a wait a phone can still rescue.
    pub async fn wait_for_code(self, deadline: Duration) -> Result<Received, OtpError> {
        let Self { socket, allow, .. } = self;
        let until = Instant::now() + deadline;
        let idle = tokio::time::sleep_until(until);
        tokio::pin!(idle);

        let mut tasks: JoinSet<Completion> = JoinSet::new();
        let mut live: Vec<IpAddr> = Vec::with_capacity(MAX_CONCURRENT);
        let mut limiter = Limiter::new();
        let (tx, mut rx) = mpsc::channel::<Delivery>(MAX_CONCURRENT);
        let mut refused: u32 = 0;
        let mut limited: Option<IpAddr> = None;

        let delivered = loop {
            tokio::select! {
                // Ordered, and the order is load-bearing: the deadline first, then a code already in
                // hand, then finished work, then new work. A saturating flood can never postpone the
                // two arms that end the wait, and a code that has arrived is never delayed by a peer
                // that has just connected.
                biased;

                () = &mut idle => break None,

                Some(delivery) = rx.recv() => break Some(delivery),

                // The guard is documentation rather than a fix: an empty set is immediately ready with
                // nothing, the pattern then disables this branch for that poll, and the loop only
                // iterates when something completed. It says so out loud because this is the one
                // non-obvious line here.
                Some(joined) = tasks.join_next(), if !tasks.is_empty() => {
                    if let Ok(completion) = joined {
                        if let Some(at) = live.iter().position(|held| *held == completion.peer) {
                            live.swap_remove(at);
                        }
                        if completion.read_a_line {
                            limiter.charge(SourceKey::of(completion.peer), Monotonic::now());
                        }
                        if completion.refused {
                            refused = refused.saturating_add(1);
                        }
                    }
                    // A task that was aborted comes back with no peer on it, so its slot entry would
                    // leak. An empty set means there are no live connections, which restores the
                    // invariant at the first quiet moment; the leak is bounded by the concurrency cap
                    // until then.
                    if tasks.is_empty() {
                        live.clear();
                    }
                }

                accepted = socket.accept() => {
                    let (stream, addr) = match accepted {
                        Ok(pair) => pair,
                        Err(err) => {
                            // Nothing is fatal. The reference wraps its whole accept loop in one
                            // catch-all, so a peer that connects and resets unwinds past the loop and
                            // permanently disables delivery for the rest of the process, with nothing
                            // logged and nothing surfaced. One packet.
                            if !matches!(
                                err.kind(),
                                ErrorKind::ConnectionAborted | ErrorKind::Interrupted
                            ) {
                                // A resource failure, so retrying immediately would spin against a
                                // backlog entry that is never drained.
                                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
                            }
                            continue;
                        }
                    };
                    // Cheapest refusal first, so nothing is allocated for a peer that was never going
                    // to be served. Each of these closes the connection with no answer written.
                    let peer = addr.ip().to_canonical();
                    let held = live.iter().filter(|other| **other == peer).count();
                    if !allow.admits(peer)
                        || tasks.len() >= MAX_CONCURRENT
                        || held >= MAX_CONCURRENT_PER_SOURCE
                    {
                        refused = refused.saturating_add(1);
                        continue;
                    }
                    let mode = if limiter.spent(SourceKey::of(peer), Monotonic::now()) {
                        limited.get_or_insert(peer);
                        Mode::Throttled
                    } else {
                        Mode::Read
                    };
                    // The connection's own deadline, never past the wait's: a connection accepted a
                    // second before the end may not outlive it.
                    let ends = (Instant::now() + conn::CONNECTION_DEADLINE).min(until);
                    live.push(peer);
                    tasks.spawn(serve_one(stream, peer, mode, ends, tx.clone()));
                }
            }
        };

        // The strongest available reading of "closes on receipt": the port is gone before the response
        // to the delivering peer has necessarily even been written. On the timeout path it is gone
        // before the error is built.
        drop(socket);

        let Some(delivery) = delivered else {
            return Err(OtpError::Timeout);
        };
        // Let the delivering handler finish its write and its drain. Waiting on every task rather than
        // singling that one out needs no second channel, and a quarter second on a wait that already
        // spent tens of seconds on a human is unmeasurable. What matters is that it is bounded.
        let _ = tokio::time::timeout(RESPONSE_GRACE, async {
            while tasks.join_next().await.is_some() {}
        })
        .await;
        Ok(Received {
            code: delivery.digits.into_code(),
            from: delivery.from,
            refused,
            limited,
        })
    }
}

/// The grammar over one slice, for the crate root's fuzz entry point.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_parse_request(offered: &[u8]) {
    let _ = grammar::parse_request_line(offered);
}

/// Whether the framing reaches the same verdict at `stride` bytes a chunk as it does all at once.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_framing_agrees(offered: &[u8], stride: usize) -> bool {
    grammar::verdict(offered, stride) == grammar::verdict(offered, usize::MAX)
}

/// The bound address and whether the filter restricts anything. Never a peer, never a code.
impl fmt::Debug for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Listener")
            .field("addr", &self.addr)
            .field("pinned", &matches!(self.allow, SourceFilter::Only(_)))
            .finish_non_exhaustive()
    }
}
