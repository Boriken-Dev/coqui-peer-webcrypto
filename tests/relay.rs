//! What a party carrying the connection can do: a reverse proxy that ends TLS, or a relay.
//! Nothing here depends on TLS; the "transport" is whatever the relay chooses to forward.

mod support;

use coqui_peer::{Handshake, Method};
use coqui_peer_webcrypto::{Error, Identity, Trust, WebCrypto};
use serde_json::Value;
use support::{exchange, pinned_pair, run};

/// A message with one member replaced, kept canonical.
fn with_member(message: &[u8], member: &str, value: &str) -> Vec<u8> {
    let mut parsed: Value = serde_json::from_slice(message).unwrap();
    parsed[member] = Value::String(value.to_owned());
    let ordered = [
        "profile",
        "version",
        "type",
        "publicKey",
        "ephemeral",
        "nonce",
        "signature",
    ];
    let mut out = String::from("{");
    for name in ordered {
        if let Some(found) = parsed.get(name) {
            if out.len() > 1 {
                out.push(',');
            }
            out.push_str(&format!("\"{name}\":{found}"));
        }
    }
    out.push('}');
    out.into_bytes()
}

fn member(message: &[u8], name: &str) -> String {
    let parsed: Value = serde_json::from_slice(message).unwrap();
    parsed[name].as_str().unwrap().to_owned()
}

#[test]
fn a_plain_relay_connects_only_the_real_parties_and_they_agree_on_one_session() {
    let (client, server, dialing, listening) = pinned_pair();
    // The relay forwards every message unchanged, and sees all of them.
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let mut seen = Vec::new();
    while !(a.is_complete() && b.is_complete()) {
        while let Some(message) = a.transmit().unwrap() {
            seen.push(message.clone());
            b.receive(&message).unwrap();
        }
        while let Some(message) = b.transmit().unwrap() {
            seen.push(message.clone());
            a.receive(&message).unwrap();
        }
    }
    let (at_client, at_server) = (a.finish().unwrap(), b.finish().unwrap());
    assert_eq!(at_client.peer, server.peer_id());
    assert_eq!(at_server.peer, client.peer_id());
    assert_eq!(at_client.session.id(), at_server.session.id());
    assert_eq!(seen.len(), 4);
    let (mut client_session, mut server_session) = (at_client.session, at_server.session);
    let record = client_session.seal(b"secret from the relay").unwrap();
    for message in &seen {
        assert!(
            !message.windows(6).any(|window| window == b"secret"),
            "the handshake carries no application data"
        );
    }
    assert!(!record.windows(6).any(|window| window == b"secret"));
    assert_eq!(
        server_session.open(&record).unwrap().unwrap(),
        b"secret from the relay"
    );
}

#[test]
fn a_relay_cannot_inject_a_message_after_the_proof() {
    let (_, _, dialing, listening) = pinned_pair();
    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let mut server_session = at_server.session;
    let mut client_session = at_client.session;

    // In the clear, or as a record under a key of its own: neither opens.
    assert!(matches!(
        server_session.open(b"{\"jsonrpc\":\"2.0\",\"method\":\"session/prompt\"}"),
        Err(Error::Record)
    ));
    // After that the direction is over, whatever arrives.
    let genuine = client_session.seal(b"genuine").unwrap();
    assert!(matches!(server_session.open(&genuine), Err(Error::Record)));
}

#[test]
fn nothing_after_a_bad_record_is_believed_even_at_its_right_place() {
    let (_, _, dialing, listening) = pinned_pair();
    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut client, mut server) = (at_client.session, at_server.session);
    let mut first = client.seal(b"one").unwrap();
    let second = client.seal(b"two").unwrap();
    first[0] ^= 1;
    assert!(matches!(server.open(&first), Err(Error::Record)));
    assert!(matches!(server.open(&second), Err(Error::Record)));
}

#[test]
fn a_relay_cannot_swap_replay_reorder_or_reflect_a_record() {
    let (_, _, dialing, listening) = pinned_pair();
    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut client, mut server) = (at_client.session, at_server.session);
    let (first, second) = (client.seal(b"one").unwrap(), client.seal(b"two").unwrap());
    assert!(
        matches!(server.open(&second), Err(Error::Record)),
        "reordered"
    );

    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut client, mut server) = (at_client.session, at_server.session);
    let record = client.seal(b"one").unwrap();
    assert!(
        matches!(server.open(&first), Err(Error::Record)),
        "from another session"
    );

    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut client, mut server) = (at_client.session, at_server.session);
    let mine = client.seal(b"one").unwrap();
    assert!(
        matches!(client.open(&mine), Err(Error::Record)),
        "reflected"
    );
    assert_eq!(server.open(&mine).unwrap().unwrap(), b"one");
    assert!(matches!(server.open(&mine), Err(Error::Record)), "replayed");
    drop(record);

    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut client, mut server) = (at_client.session, at_server.session);
    let theirs = server.seal(b"back").unwrap();
    assert!(
        matches!(server.open(&theirs), Err(Error::Record)),
        "reflected at the responder"
    );
    assert_eq!(client.open(&theirs).unwrap().unwrap(), b"back");

    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut client, mut server) = (at_client.session, at_server.session);
    let mut altered = client.seal(b"one").unwrap();
    altered[0] ^= 1;
    assert!(
        matches!(server.open(&altered), Err(Error::Record)),
        "altered"
    );
}

#[test]
fn swapping_the_initiators_key_in_the_hello_fails_the_responders_proof() {
    let (_, server, dialing, _) = pinned_pair();
    let attacker = Identity::generate().unwrap();
    // The responder admits the attacker, so only the proof can stop this.
    let listening = WebCrypto::builder(server.clone())
        .initiators(Trust::pinned([attacker.peer_id()]))
        .build();
    let attacker_side = WebCrypto::builder(attacker)
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let attacker_hello = attacker_side
        .initiate()
        .unwrap()
        .transmit()
        .unwrap()
        .unwrap();

    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let hello = a.transmit().unwrap().unwrap();
    let swapped = with_member(&hello, "publicKey", &member(&attacker_hello, "publicKey"));
    b.receive(&swapped).unwrap();
    let challenge = b.transmit().unwrap().unwrap();
    assert!(matches!(a.receive(&challenge), Err(Error::BadProof)));
}

#[test]
fn swapping_the_responders_key_for_a_relays_own_fails_the_pin() {
    let (client, server, dialing, _) = pinned_pair();
    let relay = Identity::generate().unwrap();
    // The relay runs a real handshake of its own toward the client.
    let relaying = WebCrypto::builder(relay)
        .initiators(Trust::pinned([client.peer_id()]))
        .build();
    let (mut a, mut b) = (dialing.initiate().unwrap(), relaying.respond(None).unwrap());
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::Untrusted)));
    assert_ne!(relaying.identity().peer_id(), server.peer_id());
}

#[test]
fn swapping_an_ephemeral_key_or_a_nonce_fails_the_proof_in_each_direction() {
    let (_, _, dialing, listening) = pinned_pair();
    let other = dialing.initiate().unwrap().transmit().unwrap().unwrap();
    for name in ["ephemeral", "nonce"] {
        let replacement = member(&other, name);
        // In the hello: the responder signs what it got, which the initiator did not send.
        let (mut a, mut b) = (
            dialing.initiate().unwrap(),
            listening.respond(None).unwrap(),
        );
        let hello = a.transmit().unwrap().unwrap();
        b.receive(&with_member(&hello, name, &replacement)).unwrap();
        let challenge = b.transmit().unwrap().unwrap();
        assert!(
            matches!(a.receive(&challenge), Err(Error::BadProof)),
            "{name}"
        );

        // In the challenge: the signature covers it.
        let (mut a, mut b) = (
            dialing.initiate().unwrap(),
            listening.respond(None).unwrap(),
        );
        b.receive(&a.transmit().unwrap().unwrap()).unwrap();
        let challenge = b.transmit().unwrap().unwrap();
        let swapped = with_member(&challenge, name, &replacement);
        assert!(
            matches!(a.receive(&swapped), Err(Error::BadProof)),
            "{name}"
        );
    }
}

#[test]
fn messages_cannot_be_cross_wired_between_two_runs() {
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a1, mut b1) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    let (mut a2, mut b2) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b1.receive(&a1.transmit().unwrap().unwrap()).unwrap();
    b2.receive(&a2.transmit().unwrap().unwrap()).unwrap();
    let (challenge1, challenge2) = (
        b1.transmit().unwrap().unwrap(),
        b2.transmit().unwrap().unwrap(),
    );
    // Each initiator gets the other run's challenge.
    assert!(matches!(a1.receive(&challenge2), Err(Error::BadProof)));
    assert!(matches!(a2.receive(&challenge1), Err(Error::BadProof)));
}

#[test]
fn an_outer_binding_is_optional_and_refuses_two_different_channels() {
    let (_, _, dialing, listening) = pinned_pair();
    // Each end really ended one TLS connection, and read one exporter.
    let (mut a, mut b) = (
        dialing.initiate().unwrap().binding(b"exporter").unwrap(),
        listening
            .respond(None)
            .unwrap()
            .binding(b"exporter")
            .unwrap(),
    );
    exchange(&mut a, &mut b).unwrap();
    let (at_client, at_server) = (a.finish().unwrap(), b.finish().unwrap());
    assert_eq!(at_client.session.id(), at_server.session.id());

    // A relay ending TLS on both sides gives each end another exporter.
    let (mut a, mut b) = (
        dialing
            .initiate()
            .unwrap()
            .binding(b"exporter of leg one")
            .unwrap(),
        listening
            .respond(None)
            .unwrap()
            .binding(b"exporter of leg two")
            .unwrap(),
    );
    assert!(matches!(exchange(&mut a, &mut b), Err(Error::BadProof)));
}

#[test]
fn an_export_is_the_same_at_both_ends_and_a_relay_cannot_derive_it_from_the_id() {
    let (_, _, dialing, listening) = pinned_pair();
    let (at_client, at_server) = run(&dialing, &listening).unwrap();
    let (mut one, mut two, mut other) = ([0u8; 32], [0u8; 32], [0u8; 32]);
    at_client.session.export("label", &mut one).unwrap();
    at_server.session.export("label", &mut two).unwrap();
    at_client.session.export("another", &mut other).unwrap();
    assert_eq!(one, two);
    assert_ne!(one, other);
    assert_ne!(&one, at_client.session.id());
}

#[test]
fn a_binding_set_after_the_first_message_is_refused() {
    let (_, _, dialing, listening) = pinned_pair();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    b.receive(&a.transmit().unwrap().unwrap()).unwrap();
    assert!(matches!(b.binding(b"late"), Err(Error::State)));
    a.receive(b"").unwrap_err();
    assert!(matches!(a.binding(b"late"), Err(Error::State)));
}

#[test]
fn exports_of_one_label_and_two_lengths_are_unrelated() {
    let (_, _, dialing, listening) = pinned_pair();
    let (at_client, _) = run(&dialing, &listening).unwrap();
    let (mut short, mut long) = ([0u8; 16], [0u8; 32]);
    at_client.session.export("label", &mut short).unwrap();
    at_client.session.export("label", &mut long).unwrap();
    assert_ne!(short, long[..16]);
}
