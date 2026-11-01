use alloc::collections::BTreeSet;
use alloc::sync::Arc;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use std::sync::Mutex;
use std::time::SystemTime;

use coqui_peer::{KeyMaterial, PeerId, TrustStore, WaitingEntry};

/// Whose key a side of the handshake admits, once the peer proved it holds that key.
///
/// The peer's id is always SHA-256, so a pin of another digest matches nothing. There is no variant
/// for admitting anyone: a session with an unknown peer exists only as a
/// [`PairingSession`](crate::PairingSession), which can do nothing but pair.
///
/// ```compile_fail
/// let _ = coqui_peer_webcrypto::Trust::AnyWithKeyProof;
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Trust {
    /// These ids, fixed when the method is built. An empty set admits nobody.
    Pinned(BTreeSet<PeerId>),
    /// The keys a store accepts, read at each handshake: a key removed or retired there is refused
    /// from the next handshake on. A responder records a proven stranger as waiting, under its
    /// [`WaitingGate`], and the proven successor of an accepted key is promoted as the store's
    /// rotation options say.
    Store(TrustStore),
}

impl Trust {
    /// [`Trust::Pinned`] from any collection of ids.
    pub fn pinned(ids: impl IntoIterator<Item = PeerId>) -> Self {
        Self::Pinned(ids.into_iter().collect())
    }
}

/// What a method's role admits: a [`Trust`], or for pairing any proved key.
#[derive(Debug, Clone)]
pub(crate) enum Admit {
    Trust(Trust),
    Any,
}

impl Admit {
    /// Whether the peer's proven `key` is admitted. A responder passes `waiting` with the
    /// connection's source so a proven stranger may be queued; an initiator queues nobody.
    pub(crate) fn admits(
        &self,
        key: &KeyMaterial,
        waiting: Option<(&Gate, Option<SocketAddr>)>,
    ) -> bool {
        let store = match self {
            Self::Any => return true,
            Self::Trust(Trust::Pinned(ids)) => return ids.contains(&key.id()),
            Self::Trust(Trust::Store(store)) => store,
        };
        let id = key.id();
        if store.accepted_key(&id).as_ref() == Some(key) {
            return true;
        }
        if store.successor_key(&id).as_ref() == Some(key) {
            return store.prove_successor(&id).is_ok()
                && !store.rotation().require_approval
                && store.promote_successor(&id).is_ok();
        }
        if let Some((gate, source)) = waiting {
            gate.record(store, key, source);
        }
        false
    }

    /// Whether a peer it admits is somebody rather than only the holder of some key.
    pub(crate) const fn identifies(&self) -> bool {
        matches!(self, Self::Trust(_))
    }
}

/// How many proved strangers a responder records as waiting. An unknown key costs a stranger
/// nothing and each record is a synced write, and behind a reverse proxy every peer has one source.
/// So a full source refuses the newcomer and leaves those waiting alone, which also keeps
/// [`TrustStore::record_waiting`] from replacing its oldest entry.
///
/// What a flood can still do is fill a source: nobody new is recorded from it until an operator
/// clears it, and a peer proves its key again at its next handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitingGate {
    /// Entries of one source to hold at most. Keep it at or below the store's
    /// [`WaitingLimits::per_source`](coqui_peer::WaitingLimits::per_source), or the store replaces
    /// the oldest.
    pub per_source: usize,
    /// The least time between two records by this method, on the store's clock.
    pub interval: Duration,
    /// The bits of an IPv6 address that name its source; 128 or more counts each address alone.
    pub ipv6_prefix: u8,
}

impl Default for WaitingGate {
    /// 16 per source, the store's own default; one record a second; IPv6 by /64.
    fn default() -> Self {
        Self {
            per_source: 16,
            interval: Duration::from_secs(1),
            ipv6_prefix: 64,
        }
    }
}

/// A [`WaitingGate`] and when it last let a record through.
#[derive(Debug, Clone)]
pub(crate) struct Gate {
    pub(crate) limits: WaitingGate,
    last: Arc<Mutex<Option<SystemTime>>>,
}

impl Gate {
    pub(crate) fn new(limits: WaitingGate) -> Self {
        Self {
            limits,
            last: Arc::new(Mutex::new(None)),
        }
    }

    fn record(&self, store: &TrustStore, key: &KeyMaterial, source: Option<SocketAddr>) {
        if store.waiting_key(&key.id()).is_some() {
            return;
        }
        let Ok(mut last) = self.last.lock() else {
            return;
        };
        let now = store.clock().now();
        let too_soon = (*last).is_some_and(|last| {
            now.duration_since(last)
                .is_ok_and(|since| since < self.limits.interval)
        });
        if too_soon {
            return;
        }
        let Ok(waiting) = store.waiting() else {
            return;
        };
        let held = waiting
            .iter()
            .filter(|entry: &&WaitingEntry| self.same_source(entry.source, source))
            .count();
        if held < self.limits.per_source {
            *last = Some(now);
            store.record_waiting(key, source);
        }
    }

    fn same_source(&self, one: Option<SocketAddr>, other: Option<SocketAddr>) -> bool {
        one.map(|source| self.bucket(source.ip())) == other.map(|source| self.bucket(source.ip()))
    }

    fn bucket(&self, address: IpAddr) -> IpAddr {
        match address {
            IpAddr::V4(_) => address,
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => {
                    let bits = u32::from(self.limits.ipv6_prefix.min(128));
                    let mask = u128::MAX.checked_shl(128 - bits).unwrap_or(0);
                    IpAddr::V6((u128::from(v6) & mask).into())
                }
            },
        }
    }
}
