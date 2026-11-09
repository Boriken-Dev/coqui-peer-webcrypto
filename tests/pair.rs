//! Pairing on a session: two strangers prove keys, the exchange runs sealed, and from then on the
//! full key is what the handshake proves. Nothing here involves TLS, so it holds behind a proxy.

mod support;

use std::io;
use std::sync::mpsc;
use std::thread;

use coqui_peer::pair::{
    CodeAlphabet, Mode, PairRefusal, Pairing, PairingDesk, PairingError, PairingJoiner,
    PairingResponder, Pin, PinRole, Shown,
};
use coqui_peer::{Established, Handshake, InvitationOptions, Method, ReadTimeout};
use coqui_peer_webcrypto::{
    Error, Identity, MessageTransport, PairingMethod, PairingSession, Trust, TrustStore, WebCrypto,
    random,
};
use support::{exchange, run};

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

impl ReadTimeout for Pipe {
    fn set_read_timeout(&self, _: Option<core::time::Duration>) -> io::Result<()> {
        Ok(())
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

fn pairing_run(
    joining: &PairingMethod,
    responding: &PairingMethod,
) -> Result<(Established<PairingSession>, Established<PairingSession>), Error> {
    let (mut near, mut far) = (joining.initiate()?, responding.respond(None)?);
    while !(near.is_complete() && far.is_complete()) {
        while let Some(message) = near.transmit()? {
            far.receive(&message)?;
        }
        while let Some(message) = far.transmit()? {
            near.receive(&message)?;
        }
    }
    Ok((near.finish()?, far.finish()?))
}

fn strangers(joiner: &Identity, responder: &Identity) -> (PairingSession, PairingSession) {
    let (near, far) = pairing_run(
        &PairingMethod::builder(joiner.clone()).build(),
        &PairingMethod::builder(responder.clone()).build(),
    )
    .unwrap();
    (near.session, far.session)
}

struct World {
    store: TrustStore,
    desk: PairingDesk,
    _dir: tempfile::TempDir,
}

fn world() -> World {
    let dir = tempfile::tempdir().unwrap();
    World {
        store: TrustStore::open(dir.path()).unwrap(),
        desk: PairingDesk::new(random()),
        _dir: dir,
    }
}

fn typed(pin: &str) -> Pairing {
    Pairing::pin(
        Pin::parse(&CodeAlphabet::pin(), pin).unwrap(),
        PinRole::Typed,
    )
}

fn other_pin(pin: &str) -> &'static str {
    if pin == "000000" { "000001" } else { "000000" }
}

#[test]
fn a_pairing_session_holds_a_key_and_is_nobody() {
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let (near, far) = strangers(&joiner, &responder);
    assert_eq!(near.peer_id(), responder.peer_id());
    assert_eq!(far.peer_id(), joiner.peer_id());
    assert_eq!(near.id(), far.id());
    assert!(!near.pair_channel().unwrap().verified);
    let method = PairingMethod::builder(joiner).build();
    // Admitting any proved key is what a pairing method is, so it is not a non-default setting.
    assert!(method.non_defaults().is_empty());
    // `PairingSession` has no `seal` or `open`, and `Trust` has no way to admit a stranger: the
    // doctests on both are `compile_fail`.
}

#[test]
fn a_typed_pin_pairs_two_strangers_and_the_full_key_is_proved_afterwards() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let (near, far) = strangers(&joiner, &responder);
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.respond(&store, &desk, None, &mut b))
    };
    let paired = near
        .join(typed(shown.pin.as_str()), &mut a)
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(paired.peer.id(), responder.peer_id());
    assert_eq!(paired.mode, Mode::Pin);
    assert_eq!(serving.join().unwrap().unwrap().peer.id(), joiner.peer_id());
    assert!(world.store.is_accepted(&joiner.peer_id()));

    // The next connection is the ordinary method, with no PIN and each key pinned.
    let dialing = WebCrypto::builder(joiner.clone())
        .responders(Trust::pinned([paired.peer.id()]))
        .build();
    let listening = WebCrypto::builder(responder)
        .initiators(Trust::Store(world.store.clone()))
        .build();
    let (_, at_responder) = run(&dialing, &listening).unwrap();
    assert_eq!(at_responder.peer, joiner.peer_id());
}

#[test]
fn a_wrong_pin_is_refused_at_the_confirmation_and_nobody_is_accepted() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    let (near, far) = strangers(&joiner, &responder);
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.respond(&store, &desk, None, &mut b))
    };
    let joined = near
        .join(typed(other_pin(shown.pin.as_str())), &mut a)
        .and_then(|dial| dial.finish());
    assert!(matches!(
        joined,
        Err(Error::Pairing(PairingError::Refused(
            PairRefusal::WrongCode
        )))
    ));
    drop(a);
    assert!(serving.join().unwrap().is_err());
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn an_invitation_goes_only_to_the_key_the_handshake_proved_to_be_the_inviters() {
    let world = world();
    let (joiner, inviter, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let invitation = world
        .store
        .invite(&random(), InvitationOptions::default(), "tablet")
        .unwrap();

    // A session whose real peer is someone else: the secret is never sent.
    let (to_relay, at_relay) = strangers(&joiner, &relay);
    let (mut a, b) = pipes();
    let refused = to_relay.join(
        Pairing::invitation(inviter.peer_id(), invitation.secret),
        &mut a,
    );
    assert!(matches!(
        refused,
        Err(Error::Pairing(PairingError::Unverified))
    ));
    assert!(b.inbox.try_recv().is_err(), "nothing went out");
    drop(at_relay);

    // A pin on the inviter stops such a relay at the handshake, before pairing is reached.
    let pinned = PairingMethod::builder(joiner.clone())
        .responders(Trust::pinned([inviter.peer_id()]))
        .build();
    assert!(matches!(
        pairing_run(&pinned, &PairingMethod::builder(relay).build()),
        Err(Error::Untrusted)
    ));

    // With the real inviter it pairs.
    let (near, far) =
        pairing_run(&pinned, &PairingMethod::builder(inviter.clone()).build()).unwrap();
    assert!(near.session.pair_channel().unwrap().verified);
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.session.respond(&store, &desk, None, &mut b))
    };
    let paired = near
        .session
        .join(
            Pairing::invitation(inviter.peer_id(), invitation.secret),
            &mut a,
        )
        .unwrap()
        .finish()
        .unwrap();
    assert_eq!(paired.peer.id(), inviter.peer_id());
    serving.join().unwrap().unwrap();
    assert!(world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn the_device_flow_needs_a_verified_responder_and_runs_through_the_driver() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());

    // Accepting any proved key does not verify the responder.
    let (near, _far) = strangers(&joiner, &responder);
    let (mut a, _b) = pipes();
    assert!(matches!(
        near.join(Pairing::device("kitchen"), &mut a),
        Err(Error::Pairing(PairingError::Unverified))
    ));

    let pinned = PairingMethod::builder(joiner.clone())
        .responders(Trust::pinned([responder.peer_id()]))
        .build();
    let (near, far) =
        pairing_run(&pinned, &PairingMethod::builder(responder.clone()).build()).unwrap();
    let (mut a, mut b) = pipes();
    let serving = {
        let (store, desk) = (world.store.clone(), world.desk.clone());
        thread::spawn(move || far.session.respond(&store, &desk, None, &mut b))
    };
    let dial = near
        .session
        .join(Pairing::device("kitchen"), &mut a)
        .unwrap();
    let Some(Shown::UserCode { code, .. }) = dial.shown() else {
        panic!("a user code to show");
    };
    let found = world.desk.find_device("operator", code.as_str()).unwrap();
    assert_eq!(found.peer, joiner.peer_id());
    world.desk.approve(&found).unwrap();
    assert_eq!(dial.finish().unwrap().mode, Mode::Device);
    serving.join().unwrap().unwrap();
    assert!(world.store.is_accepted(&joiner.peer_id()));
}

/// Runs a joiner and a responder that talk directly, as a relay would pass them, to their end.
fn converse(
    joiner: &mut PairingJoiner,
    responder: &mut PairingResponder,
) -> Result<(), PairingError> {
    loop {
        let mut moved = false;
        while let Some(message) = joiner.transmit() {
            responder.receive(&message)?;
            moved = true;
        }
        while let Some(message) = responder.transmit() {
            joiner.receive(&message)?;
            moved = true;
        }
        if !moved {
            return Ok(());
        }
    }
}

#[test]
fn a_relay_forwarding_unchanged_between_its_own_sessions_fails_at_the_first_message() {
    let world = world();
    let (joiner, responder, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    let shown = world.desk.show_pin().unwrap();
    let (joining, _) = strangers(&joiner, &relay);
    let (_, responding) = strangers(&relay, &responder);
    let mut near = typed(shown.pin.as_str())
        .join(joining.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        responding.pair_channel().unwrap(),
        &world.store,
        &world.desk,
        None,
    );
    // The hello names the joiner, and the responder's session proved the relay.
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Protocol)
    ));
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn a_relay_with_a_key_of_its_own_on_each_side_fails_the_pin_confirmation() {
    let world = world();
    let relay_world = self::world();
    let (joiner, responder, relay) = (
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
        Identity::generate().unwrap(),
    );
    // The person types the responder's PIN at the joiner. The relay does not know it.
    let shown = world.desk.show_pin().unwrap();

    // Toward the joiner the relay is a responder, with a PIN of its own; it must guess.
    let (joining, relay_toward_joiner) = strangers(&joiner, &relay);
    let relay_pin = relay_world.desk.show_pin().unwrap();
    assert_ne!(
        relay_pin.pin.as_str(),
        shown.pin.as_str(),
        "a one in 10^6 chance"
    );
    let mut near = typed(shown.pin.as_str())
        .join(joining.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        relay_toward_joiner.pair_channel().unwrap(),
        &relay_world.store,
        &relay_world.desk,
        None,
    );
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    assert!(!relay_world.store.is_accepted(&joiner.peer_id()));

    // Toward the responder the relay is a joiner, and its guess burns the PIN.
    let (relay_toward_responder, responding) = strangers(&relay, &responder);
    let mut near = typed(other_pin(shown.pin.as_str()))
        .join(relay_toward_responder.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        responding.pair_channel().unwrap(),
        &world.store,
        &world.desk,
        None,
    );
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    assert!(!world.store.is_accepted(&relay.peer_id()));
    assert!(world.desk.shown_pin().is_none(), "the PIN is used up");
}

#[test]
fn two_sessions_of_the_same_peers_do_not_share_a_pairing() {
    let world = world();
    let (joiner, responder) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let shown = world.desk.show_pin().unwrap();
    // The right keys and the right PIN, on two runs: only the binding differs.
    let (joining, _) = strangers(&joiner, &responder);
    let (_, responding) = strangers(&joiner, &responder);
    let mut near = typed(shown.pin.as_str())
        .join(joining.pair_channel().unwrap())
        .unwrap();
    let mut far = PairingResponder::new(
        responding.pair_channel().unwrap(),
        &world.store,
        &world.desk,
        None,
    );
    assert!(matches!(
        converse(&mut near, &mut far),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    assert!(!world.store.is_accepted(&joiner.peer_id()));
}

#[test]
fn the_methods_refuse_each_others_gaps() {
    let identity = Identity::generate().unwrap();
    let other = Identity::generate().unwrap();
    // `WebCrypto` with an empty pin set admits no stranger, whatever `PairingMethod` would do.
    let dialing = WebCrypto::builder(other.clone())
        .responders(Trust::pinned([identity.peer_id()]))
        .build();
    let listening = WebCrypto::builder(identity)
        .initiators(Trust::pinned([]))
        .build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
}
