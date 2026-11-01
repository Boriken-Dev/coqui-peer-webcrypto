//! PIN pairing on a session: two strangers prove keys, a person types a PIN, and from then on the
//! full key is what the handshake proves. Nothing here involves TLS, so it holds behind a proxy.

mod support;

use coqui_peer::Established;
use coqui_peer::pair::{
    CodeAlphabet, PairRefusal, Pairing, PairingDesk, PairingError, PairingJoiner, PairingResponder,
    PinRole,
};
use coqui_peer_webcrypto::{Identity, Session, Trust, TrustStore, WebCrypto, random};
use support::run;

struct Run {
    joiner: PairingJoiner,
    responder: PairingResponder,
    joining: Established<Session>,
    responding: Established<Session>,
}

fn strangers(joiner: &Identity, responder: &Identity) -> (WebCrypto, WebCrypto) {
    (
        WebCrypto::new(joiner.clone()).with_responders(Trust::AnyWithKeyProof),
        WebCrypto::new(responder.clone()).with_initiators(Trust::AnyWithKeyProof),
    )
}

/// Moves the exchange's messages sealed inside the session, until both ends finish or refuse.
fn converse(run: &mut Run) -> Result<(), PairingError> {
    loop {
        let mut moved = false;
        while let Some(message) = run.joiner.transmit() {
            let record = run.joining.session.seal(&message).unwrap();
            let opened = run.responding.session.open(&record).unwrap();
            run.responder.receive(&opened)?;
            moved = true;
        }
        while let Some(message) = run.responder.transmit() {
            let record = run.responding.session.seal(&message).unwrap();
            let opened = run.joining.session.open(&record).unwrap();
            run.joiner.receive(&opened)?;
            moved = true;
        }
        if !moved {
            return Ok(());
        }
    }
}

fn start(
    joiner: &Identity,
    responder: &Identity,
    store: &TrustStore,
    desk: &PairingDesk,
    pin: &str,
) -> Run {
    let (dialing, listening) = strangers(joiner, responder);
    let (joining, responding) = run(&dialing, &listening).unwrap();
    let pin = coqui_peer::pair::Pin::parse(&CodeAlphabet::pin(), pin).unwrap();
    let joining_channel = joining
        .session
        .pair_channel(joiner, joining.key.clone().unwrap())
        .unwrap();
    let responding_channel = responding
        .session
        .pair_channel(responder, responding.key.clone().unwrap())
        .unwrap();
    assert!(
        !joining_channel.verified,
        "a key proof alone says nothing about who it is"
    );
    Run {
        joiner: Pairing::pin(pin, PinRole::Typed)
            .join(joining_channel)
            .unwrap(),
        responder: PairingResponder::new(responding_channel, store, desk, None),
        joining,
        responding,
    }
}

#[test]
fn a_typed_pin_pairs_two_strangers_and_the_full_key_is_proved_afterwards() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let desk = PairingDesk::new(random());
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = desk.show_pin().unwrap();
    let mut pairing = start(&joiner, &responder, &store, &desk, shown.pin.as_str());
    converse(&mut pairing).unwrap();
    assert!(pairing.joiner.is_complete());
    assert!(pairing.responder.is_complete());
    let paired = pairing.joiner.finish().unwrap();
    assert_eq!(paired.peer.id(), responder.peer_id());
    assert_eq!(
        pairing.responder.finish().unwrap().peer.id(),
        joiner.peer_id()
    );
    assert!(store.is_accepted(&joiner.peer_id()));

    // The next connection is the ordinary method, with no PIN and each key pinned.
    let dialing = WebCrypto::new(joiner.clone()).with_responders(Trust::pinned([paired.peer.id()]));
    let listening = WebCrypto::new(responder).with_initiators(Trust::Store(store));
    let (at_joiner, at_responder) = run(&dialing, &listening).unwrap();
    assert_eq!(at_responder.peer, joiner.peer_id());
    assert!(at_joiner.session.is_trusted());
}

#[test]
fn a_wrong_pin_is_refused_and_nobody_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let desk = PairingDesk::new(random());
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = desk.show_pin().unwrap();
    let wrong = if shown.pin.as_str() == "000000" {
        "000001"
    } else {
        "000000"
    };
    let mut pairing = start(&joiner, &responder, &store, &desk, wrong);
    assert!(matches!(
        converse(&mut pairing),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    assert!(!store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_relay_with_a_key_of_its_own_on_each_side_fails_the_pin_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let store = TrustStore::open(dir.path()).unwrap();
    let desk = PairingDesk::new(random());
    let (joiner, responder, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let shown = desk.show_pin().unwrap();
    let pin = coqui_peer::pair::Pin::parse(&CodeAlphabet::pin(), shown.pin.as_str()).unwrap();

    // Two genuine handshakes, each with the relay: joiner to relay, relay to responder.
    let (a, relay_listening) = strangers(&joiner, &relay);
    let (joining, relay_with_joiner) = run(&a, &relay_listening).unwrap();
    let (relay_dialing, b) = strangers(&relay, &responder);
    let (relay_with_responder, responding) = run(&relay_dialing, &b).unwrap();
    assert_ne!(joining.session.id(), responding.session.id());
    drop((relay_with_joiner, relay_with_responder));

    // The relay forwards the pairing's messages unchanged; each end sees the relay's key and its
    // own session's binding.
    let channel = joining
        .session
        .pair_channel(&joiner, joining.key.clone().unwrap())
        .unwrap();
    let mut joining_pair = Pairing::pin(pin, PinRole::Typed).join(channel).unwrap();
    let channel = responding
        .session
        .pair_channel(&responder, responding.key.clone().unwrap())
        .unwrap();
    let mut responding_pair = PairingResponder::new(channel, &store, &desk, None);
    let refused = (|| -> Result<(), PairingError> {
        loop {
            let mut moved = false;
            while let Some(message) = joining_pair.transmit() {
                responding_pair.receive(&message)?;
                moved = true;
            }
            while let Some(message) = responding_pair.transmit() {
                joining_pair.receive(&message)?;
                moved = true;
            }
            if !moved {
                return Ok(());
            }
        }
    })();
    assert!(
        refused.is_err(),
        "the relay's keys and two bindings cannot both confirm"
    );
    assert!(!store.is_accepted(&joiner.peer_id()));
    assert!(!store.is_accepted(&relay.peer_id()));
}
