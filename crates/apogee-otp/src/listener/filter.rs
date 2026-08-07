//! Which source addresses may deliver a code.

use std::net::IpAddr;

/// Which source addresses the listener admits.
///
/// An enum rather than a list whose emptiness carries meaning. An empty list has two readings, "no
/// filter configured, admit anything" and "admit nothing", the two are opposite, and a round trip
/// through a config format that drops empty collections silently converts one into the other. Here
/// the ambiguity is unrepresentable: [`SourceFilter::only`] takes its first address separately.
///
/// There is no implicit loopback exemption, and that is a decision rather than an omission. A page in
/// the user's own browser can issue this request, needs no cross-origin permission to do it, and
/// arrives from a loopback address; an implicit exemption would hand exactly that peer a way around
/// the pin the user set to stop it. Loopback is admitted when it is in the list.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum SourceFilter {
    /// Anything that can route a packet to the bound interface.
    #[default]
    Any,
    /// Only these addresses, canonicalized at construction.
    Only(Pinned),
}

/// A non-empty set of admitted addresses.
///
/// Private field and no public constructor, so the invariant cannot be forged by a struct literal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinned(Vec<IpAddr>);

impl Pinned {
    /// How many addresses are pinned. Never zero.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Always false. Present because a `len` without one is a lint, and because the invariant is
    /// worth being able to state at a call site.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl SourceFilter {
    /// Admit `first` and `rest`, and nothing else.
    ///
    /// `None` when any entry is an IPv6 link-local address. Such an address means nothing without the
    /// interface it is on, the scope identifier naming that interface is dropped by [`IpAddr`], and a
    /// pin on one would therefore be satisfied by the same address arriving over a guest bridge. A
    /// phone's link-local address is not a stable thing to pin in the first place, so refusing costs
    /// nothing, and silently dropping the scope is the option that must not be chosen by accident.
    ///
    /// Every entry is canonicalized here rather than at each comparison. A host bound to the IPv6
    /// wildcard with dual stack reports an IPv4 peer in the mapped form, and comparing that against a
    /// stored IPv4 address fails. That failure is fail-closed and silent: the user's own phone stops
    /// matching and the symptom reads as the phone app being broken.
    #[must_use]
    pub fn only(first: IpAddr, rest: &[IpAddr]) -> Option<Self> {
        let mut pinned = Vec::with_capacity(rest.len() + 1);
        for entry in std::iter::once(&first).chain(rest) {
            let canonical = entry.to_canonical();
            if is_link_local(canonical) {
                return None;
            }
            if !pinned.contains(&canonical) {
                pinned.push(canonical);
            }
        }
        Some(Self::Only(Pinned(pinned)))
    }

    /// Whether `peer` may deliver a code.
    ///
    /// Canonicalizes `peer` by the same rule the entries were, so the two sides of the comparison
    /// cannot be in different spellings of the same address.
    #[must_use]
    pub fn admits(&self, peer: IpAddr) -> bool {
        match self {
            Self::Any => true,
            Self::Only(pinned) => pinned.0.contains(&peer.to_canonical()),
        }
    }
}

/// Whether `address` is an IPv6 link-local unicast address.
///
/// Hand-rolled because the standard library's predicate is unstable, and applied after
/// canonicalization so a mapped IPv4 address cannot be mistaken for one.
fn is_link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(_) => false,
        IpAddr::V6(v6) => v6.segments()[0] & 0xffc0 == 0xfe80,
    }
}
