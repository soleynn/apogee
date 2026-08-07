//! Per-source attempt accounting.
//!
//! Instance state on the wait that owns it, never a process global: a global limiter would carry one
//! login's flood into the next one, and a lazily initialized one is what the workspace's own audit
//! forbids in a library.
//!
//! Do the arithmetic before reading the rest of this file. The port is open for the tens of seconds a
//! login waits, so five attempts a minute is five to ten guesses out of a million, about one in
//! a hundred thousand per login. **Guessing the code is not the threat and this is not a security
//! boundary.** The threat is slot occupancy: five wrong codes in the first second spend the budget,
//! the honest phone is refused, and the login fails. The limiter that stops guessing is simultaneously
//! the denial of service, which is why every budget here is per source and why there is no global
//! counter anywhere in this crate.

use std::net::IpAddr;
use std::time::{Duration, Instant};

/// How many complete request lines one source may offer inside [`WINDOW`].
pub(crate) const ATTEMPTS: usize = 5;

/// The span the budget is measured over.
///
/// Sliding rather than a fixed bucket, which is what makes a separate backoff timer unnecessary: a
/// source that spent its budget stays refused until its oldest attempt ages out, and every other
/// source is untouched throughout. A backoff read as "stop accepting for a while" would hand an
/// attacker the whole wait for five packets.
pub(crate) const WINDOW: Duration = Duration::from_secs(60);

/// How many sources are accounted at once.
///
/// A table that grows an entry per distinct source is itself the exhaustion vector the limiter exists
/// to stop: one host with a routing prefix has more on-link source addresses than can be counted, all
/// legitimate and all free, and can insert one per connection. Sixty-four exceeds any household
/// network, and what happens past it is eviction rather than growth.
pub(crate) const TRACKED: usize = 64;

/// What a source is accounted under.
///
/// An IPv4 peer is its own key. An IPv6 peer is keyed on its /64 prefix, because a single host with a
/// routing prefix holds a /64's worth of legitimate addresses, so keying on the full address is the
/// same bug as keying on nothing. The allowlist still compares full addresses, because a pinned phone
/// is a specific device rather than a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SourceKey([u8; 16]);

impl SourceKey {
    /// The key `peer` is accounted under. `peer` is already canonical.
    pub(crate) fn of(peer: IpAddr) -> Self {
        let mut key = [0u8; 16];
        match peer {
            IpAddr::V4(v4) => key[..4].copy_from_slice(&v4.octets()),
            // The prefix only. The remaining eight bytes stay zero, which is what folds a whole
            // interface identifier range onto one row.
            IpAddr::V6(v6) => key[..8].copy_from_slice(&v6.octets()[..8]),
        }
        Self(key)
    }
}

/// One source's recent attempts.
struct Entry {
    key: SourceKey,
    /// The instants of the last [`ATTEMPTS`] attempts. A fixed ring rather than a growing list: the
    /// window only ever needs to know whether the oldest of five is still inside it.
    hits: [Option<Instant>; ATTEMPTS],
    next: usize,
    /// For eviction.
    last_seen: Instant,
}

impl Entry {
    fn fresh(key: SourceKey, now: Instant) -> Self {
        Self {
            key,
            hits: [None; ATTEMPTS],
            next: 0,
            last_seen: now,
        }
    }

    fn live(&self, now: Instant) -> usize {
        self.hits
            .iter()
            .flatten()
            .filter(|hit| now.saturating_duration_since(**hit) < WINDOW)
            .count()
    }
}

/// Per-source attempt accounting on a fixed table.
///
/// A vector with a fixed capacity and a linear scan, not a map. At sixty-four rows a scan beats a
/// hash, and it makes the eviction policy trivially auditable.
pub(crate) struct Limiter {
    entries: Vec<Entry>,
}

impl Limiter {
    pub(crate) fn new() -> Self {
        Self {
            entries: Vec::with_capacity(TRACKED),
        }
    }

    /// Whether this source is out of budget and should be answered without a read.
    ///
    /// `now` is a parameter rather than a call to the clock inside, so this whole file is testable
    /// without sleeping and so the clock is provably monotonic. Wall time is settable, and on this
    /// project it is already known to drift, so a user correcting their clock mid-login must not
    /// grant or revoke budget.
    pub(crate) fn spent(&self, key: SourceKey, now: Instant) -> bool {
        self.entries
            .iter()
            .find(|entry| entry.key == key)
            .is_some_and(|entry| entry.live(now) >= ATTEMPTS)
    }

    /// Record that this source completed a request line, valid or not.
    ///
    /// A complete line rather than one that passed the grammar. Charging only passing requests makes
    /// the number vacuous, because delivery is one-shot and so at most one passing request exists per
    /// wait; charging every complete line keeps the budget reachable, since a guess is necessarily a
    /// complete line, and costs the flood gate nothing, since unterminated garbage never charges.
    pub(crate) fn charge(&mut self, key: SourceKey, now: Instant) {
        let at = match self.entries.iter().position(|entry| entry.key == key) {
            Some(at) => at,
            None => self.admit(key, now),
        };
        let Some(entry) = self.entries.get_mut(at) else {
            return;
        };
        entry.hits[entry.next] = Some(now);
        entry.next = (entry.next + 1) % ATTEMPTS;
        entry.last_seen = now;
    }

    /// Make room for `key` and return its row.
    ///
    /// A full table evicts the least recently seen row, and the new row starts with a full budget.
    /// **Eviction can only ever grant budget, never revoke it**, and the direction is the whole
    /// argument: an honest phone can never be refused because of another address's activity, which is
    /// the failure a fail-closed table would have and which would cost the feature. Failing open costs
    /// approximately nothing, because the budget was never the security boundary; resource use is
    /// bounded by the connection caps either way.
    fn admit(&mut self, key: SourceKey, now: Instant) -> usize {
        if self.entries.len() < TRACKED {
            self.entries.push(Entry::fresh(key, now));
            return self.entries.len() - 1;
        }
        let oldest = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.last_seen)
            .map_or(0, |(at, _)| at);
        if let Some(entry) = self.entries.get_mut(oldest) {
            *entry = Entry::fresh(key, now);
        }
        oldest
    }

    /// How many sources are being accounted, for the test that pins the table never growing.
    #[cfg(test)]
    pub(crate) fn tracked(&self) -> usize {
        self.entries.len()
    }

    /// The table's allocated capacity, for the same test.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.entries.capacity()
    }
}
