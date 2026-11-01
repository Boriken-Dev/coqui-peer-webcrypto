//! What the integration tests share: a run of the exchange, and scripted random sources.
#![allow(dead_code, reason = "each test binary uses a part of this")]

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use coqui_peer::{Established, Handshake, Method};
use coqui_peer_webcrypto::{
    Error, Identity, Random, Session, Trust, WebCrypto, WebCryptoHandshake,
};

/// A pair of identities that pin each other, as methods.
pub fn pinned_pair() -> (Identity, Identity, WebCrypto, WebCrypto) {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::new(client.clone()).with_responders(Trust::pinned([server.peer_id()]));
    let listening =
        WebCrypto::new(server.clone()).with_initiators(Trust::pinned([client.peer_id()]));
    (client, server, dialing, listening)
}

/// Moves messages between the two sides until both finish or one fails.
pub fn exchange(a: &mut WebCryptoHandshake, b: &mut WebCryptoHandshake) -> Result<(), Error> {
    while !(a.is_complete() && b.is_complete()) {
        let mut moved = false;
        while let Some(message) = a.transmit()? {
            b.receive(&message)?;
            moved = true;
        }
        while let Some(message) = b.transmit()? {
            a.receive(&message)?;
            moved = true;
        }
        assert!(moved, "the exchange stalled");
    }
    Ok(())
}

/// A whole run between two configured methods.
pub fn run(
    dialing: &WebCrypto,
    listening: &WebCrypto,
) -> Result<(Established<Session>, Established<Session>), Error> {
    let (mut a, mut b) = (dialing.initiate()?, listening.respond(None)?);
    exchange(&mut a, &mut b)?;
    Ok((a.finish()?, b.finish()?))
}

/// A source that hands out exactly `chunks`, for a reproducible run.
pub fn scripted(chunks: &[&[u8]]) -> Random {
    let queue: VecDeque<Vec<u8>> = chunks.iter().map(|chunk| chunk.to_vec()).collect();
    let queue = Arc::new(Mutex::new(queue));
    Random::from_fn(move |out| {
        let next = queue.lock().unwrap().pop_front().expect("a scripted draw");
        out.copy_from_slice(&next);
        Ok(())
    })
}
