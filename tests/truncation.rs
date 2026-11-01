//! A relay can end a stream at any record boundary. The close record is what makes that visible:
//! a stream that ends without it is reported, wherever it was cut.

mod support;

use coqui_peer_webcrypto::{DEFAULT_SESSION_LIMIT, Error, Identity, Session, Trust, WebCrypto};
use support::{pinned_pair, run};

fn sessions() -> (Session, Session) {
    let (_, _, dialing, listening) = pinned_pair();
    let (near, far) = run(&dialing, &listening).unwrap();
    (near.session, far.session)
}

#[test]
fn a_relay_cutting_at_each_boundary_is_reported_as_truncation() {
    const MESSAGES: usize = 4;
    // A cut after `delivered` records: every message, then the close record, are the boundaries.
    for delivered in 0..=MESSAGES {
        let (mut near, mut far) = sessions();
        let mut records: Vec<Vec<u8>> = (0..MESSAGES)
            .map(|index| near.seal(&[u8::try_from(index).unwrap()]).unwrap())
            .collect();
        records.push(near.close().unwrap());
        for (index, record) in records.iter().take(delivered).enumerate() {
            assert_eq!(
                far.open(record).unwrap(),
                Some(vec![u8::try_from(index).unwrap()])
            );
        }
        assert!(
            matches!(far.verify_end(), Err(Error::Truncated)),
            "cut after {delivered} records"
        );
    }
}

#[test]
fn a_stream_ending_with_its_close_record_is_complete() {
    let (mut near, mut far) = sessions();
    assert_eq!(
        far.open(&near.seal(b"one").unwrap()).unwrap().unwrap(),
        b"one"
    );
    assert!(matches!(far.verify_end(), Err(Error::Truncated)));
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
    far.verify_end().unwrap();
}

#[test]
fn a_close_cannot_be_forged_replayed_or_followed() {
    let (mut near, mut far) = sessions();
    // A relay has no key to make a close with, so a plain guess is a bad record.
    assert!(matches!(far.open(&[2u8; 17]), Err(Error::Record)));
    assert!(matches!(far.verify_end(), Err(Error::Record)));

    let (mut near2, mut far2) = sessions();
    let close = near2.close().unwrap();
    assert_eq!(far2.open(&close).unwrap(), None);
    assert!(
        matches!(far2.open(&close), Err(Error::Record)),
        "a replayed close"
    );
    assert!(
        matches!(far2.seal(b"x"), Err(Error::Record)),
        "the session is over"
    );
    let _ = near.seal(b"unused");
}

#[test]
fn each_direction_closes_on_its_own() {
    let (mut near, mut far) = sessions();
    let close = near.close().unwrap();
    assert!(matches!(near.seal(b"late"), Err(Error::Closed)));
    assert!(matches!(near.close(), Err(Error::Closed)));
    assert_eq!(far.open(&close).unwrap(), None);
    // The other direction still works, as a half-closed stream does.
    let reply = far.seal(b"last words").unwrap();
    assert_eq!(near.open(&reply).unwrap().unwrap(), b"last words");
    assert_eq!(near.open(&far.close().unwrap()).unwrap(), None);
    near.verify_end().unwrap();
}

#[test]
fn a_split_session_reports_truncation_and_a_bad_record_stops_the_sealer() {
    let (near, far) = sessions();
    let (mut near_sealer, _near_opener) = near.split();
    let (mut far_sealer, mut far_opener) = far.split();
    let record = near_sealer.seal(b"one").unwrap();
    assert_eq!(far_opener.open(&record).unwrap().unwrap(), b"one");
    assert!(matches!(far_opener.verify_end(), Err(Error::Truncated)));
    assert!(matches!(far_opener.open(b"garbage"), Err(Error::Record)));
    assert!(matches!(far_sealer.seal(b"no more"), Err(Error::Record)));
    assert!(matches!(far_sealer.close(), Err(Error::Record)));
}

#[test]
fn a_failed_open_ends_sending_too() {
    let (_, mut far) = sessions();
    assert!(matches!(far.open(b"garbage"), Err(Error::Record)));
    assert!(matches!(far.seal(b"after"), Err(Error::Record)));
    assert!(matches!(far.close(), Err(Error::Record)));
}

fn limited(limit: u64) -> (Session, Session) {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::new(client.clone())
        .with_responders(Trust::pinned([server.peer_id()]))
        .with_session_limit(limit);
    let listening = WebCrypto::new(server)
        .with_initiators(Trust::pinned([client.peer_id()]))
        .with_session_limit(limit);
    let (near, far) = run(&dialing, &listening).unwrap();
    (near.session, far.session)
}

#[test]
fn the_session_limit_stops_a_direction_and_a_close_still_passes() {
    // One 10-byte message: 1 inner + 10 + 16 tag, and 32 overhead, is 59.
    let (mut near, mut far) = limited(59 + 59);
    for _ in 0..2 {
        let record = near.seal(&[0u8; 10]).unwrap();
        assert_eq!(far.open(&record).unwrap().unwrap(), [0u8; 10]);
    }
    assert!(matches!(near.seal(&[0u8; 10]), Err(Error::LimitReached)));
    // Nothing is lost by refusing: the sequence did not move, and the peer sees a clean end.
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
    far.verify_end().unwrap();
}

#[test]
fn a_peer_past_the_limit_is_refused_at_the_opener() {
    let (mut wide, _) = limited(1 << 20);
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::new(client.clone()).with_responders(Trust::pinned([server.peer_id()]));
    let listening = WebCrypto::new(server)
        .with_initiators(Trust::pinned([client.peer_id()]))
        .with_session_limit(0);
    let (near, far) = run(&dialing, &listening).unwrap();
    let (mut near, mut far) = (near.session, far.session);
    assert!(matches!(
        far.open(&near.seal(&[0u8; 1]).unwrap()),
        Err(Error::LimitReached)
    ));
    let _ = wide.seal(b"unused");
}

#[test]
fn a_limit_of_zero_is_allowed_and_only_a_close_passes() {
    let (mut near, mut far) = limited(0);
    assert!(matches!(near.seal(b""), Err(Error::LimitReached)));
    assert_eq!(far.open(&near.close().unwrap()).unwrap(), None);
}

#[test]
fn a_limit_above_the_default_is_listed_as_weakened() {
    let (client, _) = (Identity::generate().unwrap(), ());
    let method = WebCrypto::new(client.clone()).with_session_limit(DEFAULT_SESSION_LIMIT + 1);
    assert_eq!(method.weakened()[0].setting, "session_limit");
    assert!(
        WebCrypto::new(client)
            .with_session_limit(1)
            .weakened()
            .is_empty()
    );
}
