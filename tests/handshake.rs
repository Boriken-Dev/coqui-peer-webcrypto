//! The handshake through the coqui-peer traits: drivers, trust, the store and failure.

mod support;

use std::io;
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;

use coqui_peer::{
    DriveError, Handshake, MessageTransport, Method, RotationOptions, drive_messages, drive_stream,
};
use coqui_peer_webcrypto::{
    DEFAULT_MAX_MESSAGE, Error, Identity, METHOD, Trust, TrustStore, WebCrypto,
};
use support::{exchange, pinned_pair, run};

struct Pipe {
    out: mpsc::Sender<Vec<u8>>,
    inbox: mpsc::Receiver<Vec<u8>>,
}

impl MessageTransport for Pipe {
    fn send(&mut self, message: &[u8]) -> io::Result<()> {
        self.out
            .send(message.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        self.inbox
            .recv()
            .map_err(|_| io::ErrorKind::UnexpectedEof.into())
    }
}

fn pipes() -> (Pipe, Pipe) {
    let (to_a, a_inbox) = mpsc::channel();
    let (to_b, b_inbox) = mpsc::channel();
    (
        Pipe {
            out: to_b,
            inbox: a_inbox,
        },
        Pipe {
            out: to_a,
            inbox: b_inbox,
        },
    )
}

#[test]
fn the_method_is_named_for_its_crate_and_keys_carry_that_name() {
    let (client, _, dialing, _) = pinned_pair();
    assert_eq!(dialing.name(), "webcrypto");
    assert_eq!(client.key_material().method, METHOD);
    assert_eq!(client.key_material().label, "PUBLIC KEY");
    assert_eq!(client.key_material().id(), client.peer_id());
    assert_eq!(client.peer_id().to_string().len(), "sha256:".len() + 64);
}

#[test]
fn a_mutual_handshake_over_a_message_transport_yields_the_peers_and_one_session() {
    let (client, server, dialing, listening) = pinned_pair();
    let (mut near, mut far) = pipes();
    let served =
        thread::spawn(move || drive_messages(listening.respond(None).unwrap(), &mut far).unwrap());
    let mut at_client = drive_messages(dialing.initiate().unwrap(), &mut near).unwrap();
    let mut at_server = served.join().unwrap();
    assert_eq!(at_client.peer, server.peer_id());
    assert_eq!(at_server.peer, client.peer_id());
    assert_eq!(at_client.key.unwrap().bytes, server.spki_der().to_vec());
    let record = at_server.session.seal(b"from the responder").unwrap();
    assert_eq!(
        at_client.session.open(&record).unwrap().unwrap(),
        b"from the responder"
    );
}

#[test]
fn a_mutual_handshake_over_a_byte_stream_is_length_prefixed_by_the_driver() {
    let (_, server, dialing, listening) = pinned_pair();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let served = thread::spawn(move || {
        let (mut socket, from) = listener.accept().unwrap();
        drive_stream(listening.respond(Some(from)).unwrap(), &mut socket)
            .unwrap()
            .peer
    });
    let mut socket = TcpStream::connect(address).unwrap();
    let at_client = drive_stream(dialing.initiate().unwrap(), &mut socket).unwrap();
    assert_eq!(at_client.peer, server.peer_id());
    served.join().unwrap();
}

#[test]
fn a_session_splits_for_a_reader_and_a_writer_on_two_threads() {
    let (_, _, dialing, listening) = pinned_pair();
    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut sealer, mut opener) = at_client.session.split();
    let (mut far_sealer, mut far_opener) = at_server.session.split();
    let writer = thread::spawn(move || sealer.seal(b"up").unwrap());
    let up = writer.join().unwrap();
    assert_eq!(far_opener.open(&up).unwrap().unwrap(), b"up");
    let down = far_sealer.seal(b"").unwrap();
    assert_eq!(
        opener.open(&down).unwrap().unwrap(),
        b"",
        "an empty message is a message"
    );
}

#[test]
fn a_role_without_trust_is_unsupported() {
    let identity = Identity::generate().unwrap();
    let method = WebCrypto::builder(identity).build();
    assert!(matches!(method.initiate(), Err(Error::Unsupported)));
    assert!(matches!(method.respond(None), Err(Error::Unsupported)));
}

#[test]
fn an_empty_pin_set_admits_nobody_and_a_pin_of_another_digest_matches_nothing() {
    let (client, server, dialing, _) = pinned_pair();
    let nobody = WebCrypto::builder(server.clone())
        .initiators(Trust::pinned([]))
        .build();
    assert!(matches!(run(&dialing, &nobody), Err(Error::Untrusted)));
    let other_digest = coqui_peer::Digest::Sha384.of(client.spki_der());
    let wrong = WebCrypto::builder(server)
        .initiators(Trust::pinned([other_digest]))
        .build();
    assert!(matches!(run(&dialing, &wrong), Err(Error::Untrusted)));
}

#[test]
fn a_store_applies_acceptance_and_revocation_at_the_next_handshake() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::builder(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = WebCrypto::builder(server)
        .initiators(Trust::Store(store.clone()))
        .build();

    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
    store.accept(&client.peer_id()).unwrap();
    let (live, _) = run(&dialing, &listening).unwrap();
    assert!(store.remove(&client.peer_id()).unwrap());
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
    // A session already running is its host's to close: this stays usable.
    drop(live);
}

#[test]
fn a_proven_stranger_waits_with_its_source_and_a_failed_proof_records_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::builder(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = WebCrypto::builder(server)
        .initiators(Trust::Store(store.clone()))
        .build();
    let source = "192.0.2.7:4000".parse().unwrap();

    // A hello alone proves nothing, and a stolen public key cannot sign.
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(Some(source)).unwrap(),
    );
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    assert!(store.waiting().unwrap().is_empty());
    let challenge = b.transmit().unwrap().unwrap();
    a.receive(&challenge).unwrap();
    let forged = br#"{"profile":"dev.boriken.coqui.peer-webcrypto/v1","version":1,"type":"proof","signature":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ"}"#;
    assert!(matches!(b.receive(forged), Err(Error::BadProof)));
    assert!(store.waiting().unwrap().is_empty());

    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(Some(source)).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
    let waiting = store.waiting().unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].id, client.peer_id());
    assert_eq!(waiting[0].source, Some(source));
    assert_eq!(
        store.waiting_key(&client.peer_id()),
        Some(client.key_material())
    );
}

#[test]
fn an_initiator_trusting_a_store_queues_nobody() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::builder(client.clone())
        .responders(Trust::Store(store.clone()))
        .build();
    let listening = WebCrypto::builder(server.clone())
        .initiators(Trust::pinned([client.peer_id()]))
        .build();
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
    assert!(store.waiting().unwrap().is_empty());
    store.accept_key(&server.key_material()).unwrap();
    assert_eq!(run(&dialing, &listening).unwrap().0.peer, server.peer_id());
}

#[test]
fn a_store_refuses_another_methods_key_under_the_same_id() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let mut foreign = client.key_material();
    foreign.method = "tls".to_owned();
    store.accept_key(&foreign).unwrap();
    let dialing = WebCrypto::builder(client)
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = WebCrypto::builder(server)
        .initiators(Trust::Store(store))
        .build();
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
}

#[test]
fn a_proven_successor_is_promoted_and_the_old_key_retires() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::builder(dir.path())
        .rotation({
            let mut value = RotationOptions::default();
            value.retire_after = core::time::Duration::ZERO;
            value
        })
        .build()
        .unwrap();
    let (old, new, server) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    store.accept_key(&old.key_material()).unwrap();
    store
        .announce_successor(&old.peer_id(), &new.key_material())
        .unwrap();
    let listening = WebCrypto::builder(server.clone())
        .initiators(Trust::Store(store.clone()))
        .build();
    let with = |identity: &Identity| {
        WebCrypto::builder(identity.clone())
            .responders(Trust::pinned([server.peer_id()]))
            .build()
    };
    assert_eq!(run(&with(&new), &listening).unwrap().1.peer, new.peer_id());
    assert!(store.is_accepted(&new.peer_id()));
    assert!(!store.is_accepted(&old.peer_id()));
    assert!(matches!(
        run(&with(&old), &listening),
        Err(Error::Untrusted)
    ));
}

#[test]
fn a_successor_needing_approval_is_refused_but_recorded_as_proven() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::builder(dir.path())
        .rotation({
            let mut value = RotationOptions::default();
            value.require_approval = true;
            value
        })
        .build()
        .unwrap();
    let (old, new, server) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    store.accept_key(&old.key_material()).unwrap();
    store
        .announce_successor(&old.peer_id(), &new.key_material())
        .unwrap();
    let listening = WebCrypto::builder(server.clone())
        .initiators(Trust::Store(store.clone()))
        .build();
    let dialing = WebCrypto::builder(new.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    assert!(matches!(run(&dialing, &listening), Err(Error::Untrusted)));
    assert!(store.waiting().unwrap().is_empty());
    assert_eq!(
        store.promote_successor(&new.peer_id()).unwrap(),
        old.peer_id()
    );
    assert!(run(&dialing, &listening).is_ok());
}

#[test]
fn a_self_connection_is_refused() {
    let identity = Identity::generate().unwrap();
    let method = WebCrypto::builder(identity.clone())
        .responders(Trust::pinned([identity.peer_id()]))
        .initiators(Trust::pinned([identity.peer_id()]))
        .build();
    assert!(matches!(run(&method, &method), Err(Error::Malformed)));
}

#[test]
fn every_message_is_refused_in_the_wrong_place_and_failure_is_final() {
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let hello = a.transmit().unwrap().unwrap();
    assert!(
        matches!(a.receive(&hello), Err(Error::Malformed)),
        "a hello at the initiator"
    );
    assert!(matches!(a.transmit(), Err(Error::State)));
    assert!(matches!(a.receive(&hello), Err(Error::State)));
    assert!(!a.is_complete());
    assert!(matches!(a.finish(), Err(Error::State)));

    b.receive(&hello).unwrap();
    assert!(
        matches!(b.receive(&hello), Err(Error::Malformed)),
        "a second hello"
    );
    assert!(
        matches!(b.transmit(), Err(Error::State)),
        "a queued answer does not leave"
    );
    assert!(matches!(b.finish(), Err(Error::State)));
}

#[test]
fn finish_before_the_end_is_an_error() {
    let (_, _, dialing, listening) = pinned_pair();
    assert!(matches!(
        dialing.initiate().unwrap().finish(),
        Err(Error::State)
    ));
    assert!(matches!(
        listening.respond(None).unwrap().finish(),
        Err(Error::State)
    ));
    // Complete only once the last message has been taken.
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    a.receive(&b.transmit().unwrap().unwrap()).unwrap();
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    assert!(!b.is_complete());
    assert!(b.transmit().unwrap().is_some());
    assert!(b.is_complete());
}

#[test]
fn the_message_limit_is_a_setting_with_a_default_and_no_floor() {
    let (client, server, dialing, listening) = pinned_pair();
    assert!(matches!(
        listening
            .respond(None)
            .unwrap()
            .receive(&vec![b' '; DEFAULT_MAX_MESSAGE + 1]),
        Err(Error::TooLong)
    ));
    let tiny = WebCrypto::builder(server.clone())
        .initiators(Trust::pinned([client.peer_id()]))
        .max_message(16)
        .build();
    assert_eq!(tiny.non_defaults()[0].setting, "max_message");
    assert!(matches!(run(&dialing, &tiny), Err(Error::TooLong)));
    let large = WebCrypto::builder(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .max_message(1 << 20)
        .build();
    assert_eq!(large.non_defaults()[0].setting, "max_message");
    assert!(run(&dialing, &large).is_ok());
}

#[test]
fn a_failed_generator_is_an_error_and_not_a_panic() {
    let broken = coqui_peer_webcrypto::Random::from_fn(|_| Err(coqui_peer::Error::Random));
    let (_, _, failing, failing_listener) = support::pinned_pair_with(broken);
    assert!(matches!(failing.initiate(), Err(Error::Random)));
    let (_, _, dialing, _) = support::pinned_pair();
    let hello = dialing.initiate().unwrap().transmit().unwrap().unwrap();
    let mut handshake = failing_listener.respond(None).unwrap();
    assert!(matches!(handshake.receive(&hello), Err(Error::Random)));
}

#[test]
fn debug_and_display_show_no_key_and_no_input() {
    let (client, _, dialing, listening) = pinned_pair();
    let pem = client.to_pkcs8_pem().unwrap();
    let body = pem.lines().nth(1).unwrap().to_owned();
    assert!(!format!("{client:?}").contains(&body));
    assert!(format!("{client:?}").contains(&client.peer_id().hex()));
    assert!(!format!("{dialing:?}").contains(&body));
    let (at_client, _) = run(&dialing, &listening).unwrap();
    assert_eq!(format!("{:?}", at_client.session), "Session { .. }");
    let mut handshake = listening.respond(None).unwrap();
    let error = handshake.receive(b"attacker text").unwrap_err();
    assert!(!error.to_string().contains("attacker"));
    assert!(!format!("{error:?}").contains("attacker"));
    assert!(matches!(
        drive_failure(&dialing),
        DriveError::Handshake(Error::Malformed)
    ),);
}

fn drive_failure(dialing: &WebCrypto) -> DriveError<Error> {
    let (mut near, far) = pipes();
    far.out.send(b"not a challenge".to_vec()).unwrap();
    let error = drive_messages(dialing.initiate().unwrap(), &mut near);
    drop(far);
    error.unwrap_err()
}

#[test]
fn a_replaced_random_source_is_listed_as_a_non_default() {
    let (_, _, dialing, _) = pinned_pair();
    assert!(dialing.non_defaults().is_empty());
    let (_, _, replaced, _) = support::pinned_pair_with(coqui_peer_webcrypto::random());
    assert_eq!(replaced.non_defaults()[0].setting, "random");
}
