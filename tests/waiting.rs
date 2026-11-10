//! Strangers behind one reverse proxy share one source: through this method's handshake they must
//! not be able to flush those already waiting for an operator, or write to disk as fast as they can
//! connect. The bounds are `TrustStore::record_waiting`'s; these tests hold them from the outside.

mod support;

use core::time::Duration;

use coqui_peer::{Method, TrustStoreBuilder};
use coqui_peer_webcrypto::{Identity, Trust, TrustStore, WebCrypto};
use support::exchange;

struct Server {
    identity: Identity,
    method: WebCrypto,
    store: TrustStore,
    _dir: tempfile::TempDir,
}

fn server(configure: impl FnOnce(TrustStoreBuilder) -> TrustStoreBuilder) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let store = configure(TrustStore::builder().state_dir(dir.path()))
        .build()
        .unwrap();
    let identity = Identity::generate().unwrap();
    let method = WebCrypto::builder()
        .identity(identity.clone())
        .initiators(Trust::Store(store.clone()))
        .build()
        .unwrap();
    Server {
        identity,
        method,
        store,
        _dir: dir,
    }
}

impl Server {
    fn knock(&self, peer: &Identity, source: &str) {
        let dialing = WebCrypto::builder()
            .identity(peer.clone())
            .responders(Trust::pinned([self.identity.peer_id()]))
            .build()
            .unwrap();
        let (mut near, mut far) = (
            dialing.initiate().unwrap(),
            self.method.respond(Some(source.parse().unwrap())).unwrap(),
        );
        assert!(exchange(&mut near, &mut far).is_err());
    }

    fn waiting(&self) -> usize {
        self.store.waiting().unwrap().len()
    }
}

const PROXY: &str = "192.0.2.1:443";

#[test]
fn a_flood_of_strangers_from_one_source_does_not_evict_who_is_waiting() {
    let server = server(|store| store.record_interval(Duration::ZERO));
    let legitimate = Identity::generate().unwrap();
    server.knock(&legitimate, PROXY);
    for _ in 0..40 {
        server.knock(&Identity::generate().unwrap(), PROXY);
    }
    assert!(server.store.waiting_key(&legitimate.peer_id()).is_some());
    assert_eq!(server.waiting(), 16, "the source is full, and refuses");
}

#[test]
fn one_source_records_one_new_stranger_per_interval_and_others_are_not_held_back() {
    let server = server(|store| store);
    for _ in 0..5 {
        server.knock(&Identity::generate().unwrap(), PROXY);
    }
    assert_eq!(server.waiting(), 1, "no second write inside the interval");
    server.knock(&Identity::generate().unwrap(), "198.51.100.7:443");
    assert_eq!(server.waiting(), 2);
}
