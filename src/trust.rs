use alloc::collections::BTreeSet;
use core::net::SocketAddr;

use coqui_peer::{KeyMaterial, PeerId, TrustStore};

/// Whose key a side of the handshake admits, once the peer proved it holds that key.
///
/// The peer's id is always SHA-256, so a pin of another digest matches nothing.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Trust {
    /// These ids, fixed when the method is built. An empty set admits nobody.
    Pinned(BTreeSet<PeerId>),
    /// The keys a store accepts, read at each handshake: a key removed or retired there is refused
    /// from the next handshake on. A responder records a proven stranger as waiting, and the
    /// proven successor of an accepted key is promoted as the store's rotation options say.
    Store(TrustStore),
    /// Anyone who proves a key: for a connection that only runs [`coqui_peer::pair`], never one
    /// that serves anything. The session reports it
    /// ([`Session::is_trusted`](crate::Session::is_trusted)).
    AnyWithKeyProof,
}

impl Trust {
    /// [`Trust::Pinned`] from any collection of ids.
    pub fn pinned(ids: impl IntoIterator<Item = PeerId>) -> Self {
        Self::Pinned(ids.into_iter().collect())
    }

    /// Whether the peer's proven `key` is admitted. A responder passes `waiting` with the
    /// connection's source so a proven stranger is queued; an initiator queues nobody.
    pub(crate) fn admits(&self, key: &KeyMaterial, waiting: Option<Option<SocketAddr>>) -> bool {
        match self {
            Self::Pinned(ids) => ids.contains(&key.id()),
            Self::AnyWithKeyProof => true,
            Self::Store(store) => {
                let id = key.id();
                if store.accepted_key(&id).as_ref() == Some(key) {
                    return true;
                }
                if store.successor_key(&id).as_ref() == Some(key) {
                    return store.prove_successor(&id).is_ok()
                        && !store.rotation().require_approval
                        && store.promote_successor(&id).is_ok();
                }
                if let Some(source) = waiting {
                    store.record_waiting(key, source);
                }
                false
            }
        }
    }

    /// Whether a peer it admits is somebody rather than only the holder of some key.
    pub(crate) const fn identifies(&self) -> bool {
        !matches!(self, Self::AnyWithKeyProof)
    }
}
