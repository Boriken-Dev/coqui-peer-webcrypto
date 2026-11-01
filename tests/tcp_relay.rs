//! The same party as in `relay.rs` on real sockets, as a proxy between two TCP connections: a client
//! lured to it, pinning the real server, reaches that server through it. No TLS is involved, and none
//! could help: this relay would end it on both sides.

mod support;

use std::net::{TcpListener, TcpStream};
use std::thread;

use coqui_peer::{Method, drive_stream, read_frame, write_frame};
use coqui_peer_webcrypto::Error;
use support::pinned_pair;

/// One frame from `from` to `to`, unchanged.
fn forward(from: &mut TcpStream, to: &mut TcpStream) -> Vec<u8> {
    let frame = read_frame(from).unwrap();
    write_frame(to, &frame).unwrap();
    frame
}

#[test]
fn a_relay_carries_the_proof_and_a_record_and_its_own_injected_message_is_refused() {
    let (client, server, dialing, listening) = pinned_pair();
    let inner = TcpListener::bind("127.0.0.1:0").unwrap();
    let outer = TcpListener::bind("127.0.0.1:0").unwrap();
    let (inner_address, outer_address) = (inner.local_addr().unwrap(), outer.local_addr().unwrap());

    let serving = thread::spawn(move || {
        let (mut socket, from) = inner.accept().unwrap();
        let mut established =
            drive_stream(listening.respond(Some(from)).unwrap(), &mut socket).unwrap();
        let peer = established.peer;
        let session = &mut established.session;
        // What the client sent, through the relay.
        let genuine = read_frame(&mut socket).unwrap();
        let opened = session.open(&genuine).unwrap();
        write_frame(&mut socket, &session.seal(b"acknowledged").unwrap()).unwrap();
        // What the relay made up.
        let injected = read_frame(&mut socket).unwrap();
        let refused = matches!(session.open(&injected), Err(Error::Record));
        (peer, opened, refused)
    });
    let relaying = thread::spawn(move || {
        let (mut near, _) = outer.accept().unwrap();
        let mut far = TcpStream::connect(inner_address).unwrap();
        // The four handshake messages pass unchanged, and both ends succeed.
        for _ in 0..2 {
            forward(&mut near, &mut far);
            forward(&mut far, &mut near);
        }
        // The relay holds everything it saw, and its message is what a stolen channel would send.
        let record = forward(&mut near, &mut far);
        forward(&mut far, &mut near);
        write_frame(&mut far, br#"{"jsonrpc":"2.0","method":"session/prompt"}"#).unwrap();
        record
    });

    let mut socket = TcpStream::connect(outer_address).unwrap();
    let mut established = drive_stream(dialing.initiate().unwrap(), &mut socket).unwrap();
    assert_eq!(established.peer, server.peer_id());
    let record = established.session.seal(b"only for the server").unwrap();
    write_frame(&mut socket, &record).unwrap();
    let reply = read_frame(&mut socket).unwrap();
    assert_eq!(established.session.open(&reply).unwrap(), b"acknowledged");

    let (peer, opened, refused) = serving.join().unwrap();
    assert_eq!(peer, client.peer_id());
    assert_eq!(opened, b"only for the server");
    assert!(refused, "the relay's message was believed");
    let seen = relaying.join().unwrap();
    assert!(!seen.windows(4).any(|window| window == b"only"));
}
