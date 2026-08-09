//! The listener over real loopback sockets, driven by a raw client.
//!
//! Everything here binds port zero and reads the port back, so two of these never collide with each
//! other and none of them collides with a launcher already running on the machine.
//!
//! Nothing sleeps a fixed interval and then asserts. Paused virtual time does not work for any of it:
//! the clock only advances when every task is idle, and a task blocked on a socket read is not one, so
//! the timing cases use real short deadlines on a multi-thread runtime and everything else polls for a
//! condition. Free helpers here return `Result` and use `?`, because the unwrap exemption reaches
//! `#[test]` bodies only.

use std::error::Error;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use apogee_otp::{Listener, ListenerConfig, OtpError, Received, SourceFilter};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Any failure in a helper here, boxed: the unwrap exemption reaches `#[test]` bodies only, so a free
/// helper in this file has to propagate rather than unwrap.
type Fallible = Result<(), Box<dyn Error>>;

/// Long enough that no wait here ends by accident on a loaded machine, short enough that a hung test
/// is a failure rather than a timeout in CI.
const GENEROUS: Duration = Duration::from_secs(20);

/// The loopback address every client in this file connects from.
const HERE: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn config(port: u16, allow: SourceFilter) -> ListenerConfig {
    ListenerConfig {
        bind: HERE,
        port,
        allow,
    }
}

/// A listener on an ephemeral loopback port.
async fn bound() -> Result<Listener, OtpError> {
    Listener::bind(config(0, SourceFilter::Any)).await
}

fn request(code: &str) -> String {
    format!("GET /ffxivlauncher/{code} HTTP/1.1\r\nHost: localhost\r\n\r\n")
}

/// Push `bytes` at `addr` and read back whatever is answered before the close.
async fn push(addr: SocketAddr, bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(bytes).await?;
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await?;
    Ok(answer)
}

/// Push and ignore the answer, for the cases where only the effect matters.
async fn shove(addr: SocketAddr, bytes: &[u8]) {
    let _ = push(addr, bytes).await;
}

/// Whether anything is still accepting on `addr`.
async fn reachable(addr: SocketAddr) -> bool {
    TcpStream::connect(addr).await.is_ok()
}

/// Push until the listener actually answers success.
///
/// A refused connection closes cleanly and reads back nothing, which is indistinguishable from a
/// delivered code if a caller only checks that the call returned. Under contention a real phone would
/// be retried by its user; this retries for them.
async fn push_until_taken(addr: SocketAddr, code: &str, stop: &AtomicBool) {
    while !stop.load(Ordering::Relaxed) {
        if let Ok(answer) = push(addr, request(code).as_bytes()).await
            && answer.starts_with(b"HTTP/1.0 200")
        {
            return;
        }
        tokio::task::yield_now().await;
    }
}

/// The exact bytes the reference answers a delivered code with.
const RESPONSE_OK: &[u8] = b"HTTP/1.0 200 OK\nContent-Type: application/json; charset=UTF-8\n\n{\"app\":\"XIVLauncher\", \"version\":\"1.0.0.0\"}";

/// End to end: the code, its source, and the compatibility bytes the phone reads back.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pushed_code_comes_back_with_its_source_and_the_compat_response() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    let client = tokio::spawn(async move { push(addr, request("482913").as_bytes()).await });
    let received: Received = listener.wait_for_code(GENEROUS).await?;

    assert_eq!(received.from(), HERE);
    assert_eq!(received.limited(), None);
    let answer = client.await??;
    assert_eq!(answer, RESPONSE_OK);
    assert_eq!(received.into_code().expose(), "482913");
    Ok(())
}

/// The port is gone once a code arrives.
///
/// Invisible to every other assertion here, and it is the whole of the minimal-exposure-window claim:
/// the improvement over the reference is not that the socket is hardened but that it barely exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_port_is_closed_once_a_code_arrives() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    tokio::spawn(async move { shove(addr, request("111222").as_bytes()).await });
    let received = listener.wait_for_code(GENEROUS).await?;
    drop(received);

    assert!(!reachable(addr).await);
    Ok(())
}

/// A request split across writes is still a code.
///
/// The case that breaks legitimate clients on a flaky link, over a real socket rather than a reader in
/// isolation. The reference reads once into a fixed buffer and matches whatever landed, so this
/// request is one it silently drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_request_split_across_writes_is_still_a_code() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    tokio::spawn(async move {
        let Ok(mut stream) = TcpStream::connect(addr).await else {
            return;
        };
        for byte in request("246810").into_bytes() {
            if stream.write_all(&[byte]).await.is_err() {
                return;
            }
            let _ = stream.flush().await;
        }
        let mut sink = Vec::new();
        let _ = stream.read_to_end(&mut sink).await;
    });

    let received = listener.wait_for_code(GENEROUS).await?;
    assert_eq!(received.into_code().expose(), "246810");
    Ok(())
}

/// An ungrammatical request is answered and the wait goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_ungrammatical_request_is_answered_four_hundred_and_the_wait_goes_on() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    let probe = tokio::spawn(async move {
        let answer = push(addr, b"GET /nope HTTP/1.1\r\n\r\n").await;
        shove(addr, request("555666").as_bytes()).await;
        answer
    });

    let received = listener.wait_for_code(GENEROUS).await?;
    let answer = probe.await??;
    assert_eq!(answer, b"HTTP/1.0 400 Bad Request\nContent-Length: 0\n\n");
    assert!(received.refused() >= 1);
    assert_eq!(received.into_code().expose(), "555666");
    Ok(())
}

/// A peer that connects and says nothing does not hold the wait.
///
/// Pins that connections are handled off the accept path: if they were not, the silent peer would own
/// the listener until its own deadline expired and the real push would sit behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_sends_nothing_does_not_hold_the_wait() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    let silent = TcpStream::connect(addr).await?;
    tokio::spawn(async move { shove(addr, request("777888").as_bytes()).await });

    let received = listener.wait_for_code(GENEROUS).await?;
    assert_eq!(received.into_code().expose(), "777888");
    drop(silent);
    Ok(())
}

/// A peer that resets does not end the wait.
///
/// The reference's one-packet kill, made a regression test: there, a reset unwinds past the accept
/// loop, ends the server thread with its running flag still set, and disables delivery for the rest of
/// the process with nothing logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_peer_that_resets_does_not_end_the_wait() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    // Dropped without a graceful close and without reading, which is the shape that unwinds the
    // reference's accept loop. `SO_LINGER` would force a reset outright, but it is deprecated here
    // because it blocks the dropping thread, and what matters is that a peer vanishing mid-connection
    // is survivable however it vanishes.
    let rude = TcpStream::connect(addr).await?;
    drop(rude);

    tokio::spawn(async move { shove(addr, request("999000").as_bytes()).await });
    let received = listener.wait_for_code(GENEROUS).await?;
    assert_eq!(received.into_code().expose(), "999000");
    Ok(())
}

/// A half-closed peer is an end of file and not a spin.
///
/// A socket whose write half is shut stays readable and answers zero every time, so a loop that treats
/// zero as "try again" burns a core for as long as the peer leaves it that way. A spin shows up here as
/// a test that never finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_half_closed_peer_is_an_eof_and_not_a_spin() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    let mut partial = TcpStream::connect(addr).await?;
    partial.write_all(b"GET /ffxiv").await?;
    partial.shutdown().await?;

    tokio::spawn(async move { shove(addr, request("135791").as_bytes()).await });
    let received = listener.wait_for_code(GENEROUS).await?;
    assert_eq!(received.into_code().expose(), "135791");
    Ok(())
}

/// The deadline ends a wait nobody answered, and the port is free afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_deadline_ends_a_wait_that_nothing_pushed() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    let outcome = listener.wait_for_code(Duration::from_millis(150)).await;
    assert!(matches!(outcome, Err(OtpError::Timeout)));
    assert!(!reachable(addr).await);
    Ok(())
}

/// A slow peer is dropped at the connection deadline and the wait survives it.
///
/// One byte at a time and never a terminator, which satisfies any per-read timeout forever. The
/// connection deadline is measured from accept, so it does not reset on traffic.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_slow_peer_is_dropped_at_the_connection_deadline() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    let drip = tokio::spawn(async move {
        let Ok(mut stream) = TcpStream::connect(addr).await else {
            return;
        };
        // Runs until the listener closes the connection under it, which is the assertion.
        for _ in 0..600 {
            if stream.write_all(b"A").await.is_err() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    tokio::spawn(async move { shove(addr, request("864209").as_bytes()).await });
    let received = listener.wait_for_code(GENEROUS).await?;
    assert_eq!(received.into_code().expose(), "864209");
    drip.abort();
    Ok(())
}

/// Dropping the wait closes the port.
///
/// The cancellation contract, asserted the only way there is: there is no token parameter, so what has
/// to hold is that dropping the future releases everything it owns. Rebinding the same port is the
/// proof.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_dropped_wait_closes_the_port() -> Fallible {
    let listener = Listener::bind(config(0, SourceFilter::Any)).await?;
    let addr = listener.local_addr();

    // A peer in flight, so the drop has a task to abort and not only a socket to close.
    let holder = TcpStream::connect(addr).await?;
    // The future is passed by value, so it is dropped when the timeout that owns it resolves. Pinning
    // it and dropping the pin would drop a reference and leave the future, and its socket, alive.
    let raced =
        tokio::time::timeout(Duration::from_millis(100), listener.wait_for_code(GENEROUS)).await;
    assert!(raced.is_err(), "nothing should have been delivered");
    drop(holder);

    let again = Listener::bind(config(addr.port(), SourceFilter::Any)).await?;
    assert_eq!(again.local_addr().port(), addr.port());
    Ok(())
}

/// Six well-formed codes from one source, and the sixth is refused on the wire.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn six_well_formed_codes_from_one_source_get_a_429() -> Fallible {
    let listener = Listener::bind(config(0, SourceFilter::Any)).await?;
    let addr = listener.local_addr();

    // The wait has to keep running while the budget is spent, so the codes that spend it are the
    // wrong shape to be delivered. They are well formed, which is what charges an attempt, and then
    // the wait is ended by its own deadline rather than by a delivery.
    // Ten rather than six. Each attempt is charged when its connection is joined, which happens just
    // after the client is unblocked by the same close, so a charge can land a moment after the next
    // connect. A margin here costs nothing and keeps the assertion off that ordering.
    let flood = tokio::spawn(async move {
        let mut answers = Vec::new();
        for _ in 0..10 {
            answers.push(push(addr, b"GET /ffxivlauncher/12345 HTTP/1.1\r\n\r\n").await);
        }
        answers
    });

    let outcome = listener.wait_for_code(Duration::from_secs(5)).await;
    assert!(matches!(outcome, Err(OtpError::Timeout)));

    let answers = flood.await?;
    let answers = answers.into_iter().collect::<io::Result<Vec<_>>>()?;
    let too_many = answers
        .iter()
        .filter(|answer| answer.starts_with(b"HTTP/1.0 429"))
        .count();
    assert!(too_many >= 1, "the limiter never answered");
    Ok(())
}

/// A flood of garbage does not spend the code budget.
///
/// The constraint that forced two budgets, written as the test that fails without them: unterminated
/// writes are not complete request lines, so they are bounded by the concurrency caps and never by the
/// five-per-minute rule. If they charged, this source would be locked out long before its real code
/// arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_flood_of_garbage_does_not_spend_the_code_budget() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    // One at a time, and each carried through to the listener closing it, so the per-source
    // concurrency cap is never what is being measured here: this test is about the code budget, and a
    // version that let fifty connections pile up would fail for the other reason and read as a pass
    // for this one if the cap were ever removed.
    let flood = tokio::spawn(async move {
        for _ in 0..50 {
            if let Ok(mut stream) = TcpStream::connect(addr).await {
                let _ = stream
                    .write_all(b"not a request line, and never terminated")
                    .await;
                let _ = stream.shutdown().await;
                let mut sink = Vec::new();
                let _ = stream.read_to_end(&mut sink).await;
            }
        }
        shove(addr, request("314159").as_bytes()).await;
    });

    let received = listener.wait_for_code(GENEROUS).await?;
    assert_eq!(received.limited(), None, "the code budget was spent");
    assert_eq!(received.into_code().expose(), "314159");
    flood.await?;
    Ok(())
}

/// A source off the allowlist gets no answer at all, and the wait goes on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_source_off_the_allowlist_gets_no_answer() -> Fallible {
    let Some(elsewhere) = SourceFilter::only(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), &[]) else {
        return Err("a routable address was refused".into());
    };
    let listener = Listener::bind(config(0, elsewhere)).await?;
    let addr = listener.local_addr();

    // Concurrently with the wait, because nothing accepts until the wait runs and a client blocked on
    // an answer that will never come would otherwise hang here rather than assert.
    let probe = tokio::spawn(async move { push(addr, request("123456").as_bytes()).await });

    let outcome = listener.wait_for_code(Duration::from_millis(400)).await;
    assert!(matches!(outcome, Err(OtpError::Timeout)));

    // Either shape is the same fact: nothing was answered. A source off the list is closed before its
    // request is read, so the request is still queued and the close makes the kernel send a reset,
    // which the client sees instead of a clean end of file. Not answering at all is the point; which
    // way the operating system spells it is not ours to choose.
    match probe.await? {
        Ok(answer) => assert!(answer.is_empty(), "a refused source was answered"),
        Err(err) => assert_eq!(err.kind(), io::ErrorKind::ConnectionReset, "{err}"),
    }
    Ok(())
}

/// A pipelined second request is not a second delivery.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pipelined_second_request_is_not_a_second_delivery() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();

    let both = format!("{}{}", request("111111"), request("222222"));
    tokio::spawn(async move { shove(addr, both.as_bytes()).await });

    let received = listener.wait_for_code(GENEROUS).await?;
    assert_eq!(received.into_code().expose(), "111111");
    Ok(())
}

/// The port is named when it cannot be taken.
///
/// The one fact that makes the sentence a shell renders actionable, since on this port the cause is
/// almost always a reference launcher already running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_port_is_reported_when_it_cannot_be_taken() -> Fallible {
    let held = bound().await?;
    let port = held.local_addr().port();

    let clash = Listener::bind(config(port, SourceFilter::Any)).await;
    let Err(err) = clash else {
        return Err("a taken port was bound twice".into());
    };
    assert!(matches!(err, OtpError::ListenerBind { port: taken } if taken == port));
    assert!(err.to_string().contains(&port.to_string()), "{err}");
    Ok(())
}

/// Two waits in a row can take the same port.
///
/// The back-to-back login case: a first wait leaves connections in the operating system's lingering
/// state, and the second bind seconds later must not be refused because of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_waits_in_a_row_can_take_the_same_port() -> Fallible {
    let first = bound().await?;
    let port = first.local_addr().port();
    let addr = first.local_addr();

    tokio::spawn(async move { shove(addr, request("101010").as_bytes()).await });
    let received = first.wait_for_code(GENEROUS).await?;
    assert_eq!(received.into_code().expose(), "101010");

    let second = Listener::bind(config(port, SourceFilter::Any)).await?;
    assert_eq!(second.local_addr().port(), port);
    Ok(())
}

/// A flood never starves a second source.
///
/// The hostile-network case at crate level, and the reason the two budgets are separate. One
/// address hammers the port with garbage and with well-formed wrong codes for as long as the wait
/// lasts; the phone pushes from another address in the middle of it and its code still comes back.
///
/// The assertion is on the outcome and on which source the limiter shut off, never on a timing: a
/// version that asserted "the flood was still running" would pass whenever the machine was slow.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_never_starves_a_second_source() -> Fallible {
    let listener = bound().await?;
    let addr = listener.local_addr();
    let stop = Arc::new(AtomicBool::new(false));
    // Set the moment the flooding source reads its first refusal. The phone waits for it rather than
    // for a duration, so the ordering this test needs is a fact it observed and not a race it hopes
    // to win: by the time the code is pushed, the limiter has demonstrably engaged.
    let throttled = Arc::new(AtomicBool::new(false));

    // Loopback is a whole /8, so a second source needs no second machine: binding the client side to
    // another address in it is a genuinely different peer as far as the listener is concerned.
    let flooding = stop.clone();
    let announce = throttled.clone();
    let flood = tokio::spawn(async move {
        while !flooding.load(Ordering::Relaxed) {
            for shape in [
                // Complete request lines, so each one spends an attempt, but none of them is a
                // deliverable code. Under one-shot delivery a well-formed six-digit push from the
                // flooding source would simply win the race, which is a different property, and an
                // accepted one, from the starvation this test is about.
                b"GET /ffxivlauncher/12345 HTTP/1.1\r\n\r\n".as_slice(),
                b"GET /nope HTTP/1.1\r\n\r\n".as_slice(),
                // And one that never terminates, which must spend nothing at all.
                b"not a request line and never terminated".as_slice(),
            ] {
                let Ok(socket) = tokio::net::TcpSocket::new_v4() else {
                    return;
                };
                if socket
                    .bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0))
                    .is_err()
                {
                    return;
                }
                let Ok(mut stream) = socket.connect(addr).await else {
                    continue;
                };
                let _ = stream.write_all(shape).await;
                let mut answer = Vec::new();
                let _ = stream.read_to_end(&mut answer).await;
                if answer.starts_with(b"HTTP/1.0 429") {
                    announce.store(true, Ordering::Relaxed);
                }
            }
            tokio::task::yield_now().await;
        }
    });

    // The phone, from the ordinary loopback address, pushing once the flood is established.
    let done = stop.clone();
    let phone = tokio::spawn(async move {
        while !throttled.load(Ordering::Relaxed) {
            // The bail-out matters: if the wait ends without the limiter ever engaging, this task
            // still has to finish, or the failure it should report becomes a hang instead.
            if done.load(Ordering::Relaxed) {
                return;
            }
            tokio::task::yield_now().await;
        }
        push_until_taken(addr, "482913", &done).await;
    });

    let received = listener.wait_for_code(GENEROUS).await?;
    stop.store(true, Ordering::Relaxed);
    let _ = phone.await;
    let _ = flood.await;

    assert_eq!(received.from(), HERE, "the flood's code won the race");
    assert!(
        received.refused() > 0,
        "nothing was turned away, so the flood never reached the listener"
    );
    // The limiter engaged, and against the flooder. This is what separates a flood that was stopped
    // from a flood that was merely slow, and it is the half a timing assertion cannot pin.
    assert_eq!(
        received.limited(),
        Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))),
        "the limiter never shut the flooding source off"
    );
    assert_eq!(received.into_code().expose(), "482913");
    Ok(())
}

/// One source cannot hold more than its share of the slots at once.
///
/// The per-source cap is what makes the overall concurrency bound mean anything: without it a single
/// scripted address holds every slot and the phone's connection is never accepted at all.
///
/// Asserted on the refusal count rather than on whether the phone got in, and that choice is the
/// whole design of this test. "The phone still got in" is a race the phone usually wins anyway, so it
/// stays green with the cap deleted; the count is arithmetic. Eight connections are opened from one
/// address before the wait starts, so all eight are sitting in the backlog when it begins accepting
/// and the cap meets them as a burst: two are served and six are turned away. Delete the cap and the
/// count is zero.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_source_cannot_hold_more_than_its_share_of_the_slots() -> Fallible {
    const SQUATTERS: u32 = 8;

    let listener = bound().await?;
    let addr = listener.local_addr();

    // Established before anything accepts, so the burst is what the accept loop meets. Held for the
    // length of the test: a slot released early would let a later one through and soften the count.
    let mut held = Vec::new();
    for _ in 0..SQUATTERS {
        let socket = tokio::net::TcpSocket::new_v4()?;
        socket.bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 0))?;
        held.push(socket.connect(addr).await?);
    }

    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let phone = tokio::spawn(async move { push_until_taken(addr, "864209", &done).await });

    let received = listener.wait_for_code(GENEROUS).await?;
    stop.store(true, Ordering::Relaxed);
    let _ = phone.await;
    drop(held);

    assert_eq!(received.from(), HERE);
    assert_eq!(
        received.refused(),
        SQUATTERS - 2,
        "one address held a different number of slots than the cap permits"
    );
    assert_eq!(received.into_code().expose(), "864209");
    Ok(())
}

/// The overall concurrency bound holds however many addresses arrive.
///
/// The other half of the pair: the per-source cap stops one address taking everything, and this stops
/// many addresses doing it between them. Loopback is a whole /8, so twenty distinct sources cost
/// nothing to produce, and two connections each is exactly what the per-source cap allows, which is
/// what leaves this measuring only the overall bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn no_number_of_sources_exceeds_the_overall_bound() -> Fallible {
    const SOURCES: u32 = 20;
    const EACH: u32 = 2;
    const SLOTS: u32 = 16;

    let listener = bound().await?;
    let addr = listener.local_addr();

    let mut held = Vec::new();
    for host in 0..SOURCES {
        for _ in 0..EACH {
            let socket = tokio::net::TcpSocket::new_v4()?;
            // 127.0.0.2 upwards, leaving 127.0.0.1 to the phone.
            socket.bind(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(127, 0, 1, (host + 2) as u8)),
                0,
            ))?;
            held.push(socket.connect(addr).await?);
        }
    }

    // Retried gently rather than as fast as the loop goes round. Every slot is occupied until a
    // three-second connection deadline frees one, so a tight retry adds tens of thousands of
    // refusals of its own and drowns the number being measured.
    let stop = Arc::new(AtomicBool::new(false));
    let done = stop.clone();
    let phone = tokio::spawn(async move {
        while !done.load(Ordering::Relaxed) {
            if let Ok(answer) = push(addr, request("975310").as_bytes()).await
                && answer.starts_with(b"HTTP/1.0 200")
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let received = listener.wait_for_code(GENEROUS).await?;
    stop.store(true, Ordering::Relaxed);
    let _ = phone.await;
    drop(held);

    assert_eq!(received.from(), HERE);
    // A lower bound, not an equality: the phone's own refused attempts are counted too, and how many
    // it makes depends on when a slot frees. What the bound rules out is the shape with no cap at
    // all, where all forty are served at once and nothing is turned away.
    assert!(
        received.refused() >= SOURCES * EACH - SLOTS,
        "only {} connections were turned away, so more than {SLOTS} were served at once",
        received.refused()
    );
    assert_eq!(received.into_code().expose(), "975310");
    Ok(())
}
