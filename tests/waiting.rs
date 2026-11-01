//! Strangers behind one reverse proxy share one source: they must not be able to flush those
//! already waiting for an operator, or write to disk as fast as they can connect.

mod support;

use core::time::Duration;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use coqui_peer::{Clock, Method};
use coqui_peer_webcrypto::{Identity, Trust, TrustStore, WaitingGate, WebCrypto};
use support::exchange;

struct Server {
    identity: Identity,
    method: WebCrypto,
    store: TrustStore,
    now: Arc<Mutex<SystemTime>>,
    _dir: tempfile::TempDir,
}

fn server(gate: WaitingGate) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let now = Arc::new(Mutex::new(UNIX_EPOCH + Duration::from_secs(1_800_000_000)));
    let reading = now.clone();
    let store = TrustStore::open(dir.path())
        .unwrap()
        .with_clock(Clock::from_fn(move || *reading.lock().unwrap()));
    let identity = Identity::generate().unwrap();
    let method = WebCrypto::new(identity.clone())
        .with_initiators(Trust::Store(store.clone()))
        .with_waiting_gate(gate);
    Server {
        identity,
        method,
        store,
        now,
        _dir: dir,
    }
}

impl Server {
    fn knock(&self, peer: &Identity, source: &str) {
        let dialing =
            WebCrypto::new(peer.clone()).with_responders(Trust::pinned([self.identity.peer_id()]));
        let (mut near, mut far) = (
            dialing.initiate().unwrap(),
            self.method.respond(Some(source.parse().unwrap())).unwrap(),
        );
        assert!(exchange(&mut near, &mut far).is_err());
    }

    fn pass(&self, time: Duration) {
        *self.now.lock().unwrap() += time;
    }

    fn waiting(&self) -> usize {
        self.store.waiting().unwrap().len()
    }
}

const PROXY: &str = "192.0.2.1:443";

#[test]
fn a_flood_of_strangers_from_one_source_does_not_evict_who_is_waiting() {
    let server = server(WaitingGate::default());
    let legitimate = Identity::generate().unwrap();
    server.knock(&legitimate, PROXY);
    for _ in 0..40 {
        server.pass(Duration::from_secs(2));
        server.knock(&Identity::generate().unwrap(), PROXY);
    }
    assert!(server.store.waiting_key(&legitimate.peer_id()).is_some());
    assert_eq!(server.waiting(), 16, "the source is full, and refuses");
}

#[test]
fn a_full_source_leaves_others_able_to_wait() {
    let server = server(WaitingGate {
        per_source: 1,
        ..WaitingGate::default()
    });
    server.knock(&Identity::generate().unwrap(), PROXY);
    server.pass(Duration::from_secs(2));
    server.knock(&Identity::generate().unwrap(), PROXY);
    assert_eq!(server.waiting(), 1);
    server.pass(Duration::from_secs(2));
    server.knock(&Identity::generate().unwrap(), "198.51.100.7:443");
    assert_eq!(server.waiting(), 2);
}

#[test]
fn records_are_rate_limited_on_the_stores_clock() {
    let server = server(WaitingGate::default());
    server.knock(&Identity::generate().unwrap(), PROXY);
    for _ in 0..5 {
        server.knock(&Identity::generate().unwrap(), PROXY);
    }
    assert_eq!(server.waiting(), 1, "no second write inside the interval");
    server.pass(Duration::from_secs(1));
    server.knock(&Identity::generate().unwrap(), PROXY);
    assert_eq!(server.waiting(), 2);
}

#[test]
fn ipv6_sources_are_grouped_by_their_prefix_and_v4_mapped_by_their_address() {
    let server = server(WaitingGate {
        per_source: 1,
        interval: Duration::ZERO,
        ipv6_prefix: 64,
    });
    server.knock(&Identity::generate().unwrap(), "[2001:db8:0:1::1]:1");
    server.knock(&Identity::generate().unwrap(), "[2001:db8:0:1::2]:1");
    assert_eq!(server.waiting(), 1);
    server.knock(&Identity::generate().unwrap(), "[2001:db8:0:2::1]:1");
    assert_eq!(server.waiting(), 2);
    server.knock(&Identity::generate().unwrap(), "192.0.2.9:1");
    server.knock(&Identity::generate().unwrap(), "[::ffff:192.0.2.9]:1");
    assert_eq!(server.waiting(), 3);
}

#[test]
fn a_looser_gate_is_listed_as_weakened() {
    let identity = Identity::generate().unwrap();
    let method = WebCrypto::new(identity).with_waiting_gate(WaitingGate {
        per_source: 1000,
        interval: Duration::ZERO,
        ipv6_prefix: 64,
    });
    let settings: Vec<_> = method.weakened().into_iter().map(|w| w.setting).collect();
    assert_eq!(
        settings,
        ["waiting_gate.per_source", "waiting_gate.interval"]
    );
}
