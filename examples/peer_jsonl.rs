//! One end of the handshake and an echo over stdin and stdout, for the JavaScript interoperability
//! tests. Not a network server: handshake messages are lines, records are lines of hex.
//!
//! `peer_jsonl responder <client id>`: prints `{"peerId":...}`, answers, echoes records.
//! `peer_jsonl initiator`: prints `{"peerId":...}`, reads the responder's id as a line, dials, sends
//! one sealed record, checks the echo.

use std::io::{self, BufRead, Write};

use coqui_peer::{Handshake, Method};
use coqui_peer_webcrypto::{Identity, PeerId, Trust, WebCrypto};
use data_encoding::HEXLOWER;

type Failure = Box<dyn std::error::Error>;

fn line(stdout: &mut impl Write, bytes: &[u8]) -> Result<(), Failure> {
    stdout.write_all(bytes)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
}

fn next(lines: &mut impl Iterator<Item = io::Result<String>>) -> Result<String, Failure> {
    Ok(lines.next().ok_or("the input ended")??)
}

fn hex(text: &str) -> Result<Vec<u8>, Failure> {
    HEXLOWER
        .decode(text.as_bytes())
        .map_err(|_| "a record is not hex".into())
}

fn main() -> Result<(), Failure> {
    let role = std::env::args().nth(1).ok_or("a role is required")?;
    let identity = Identity::generate()?;
    let mut stdout = io::stdout().lock();
    let stdin = io::stdin();
    let mut lines = stdin.lock().lines();
    line(
        &mut stdout,
        format!("{{\"peerId\":\"{}\"}}", identity.peer_id()).as_bytes(),
    )?;
    let mut handshake = if role == "responder" {
        let allowed: PeerId = std::env::args()
            .nth(2)
            .ok_or("a client id is required")?
            .parse()?;
        WebCrypto::new(identity)
            .with_initiators(Trust::pinned([allowed]))
            .respond(None)?
    } else {
        let expected: PeerId = next(&mut lines)?.parse()?;
        WebCrypto::new(identity)
            .with_responders(Trust::pinned([expected]))
            .initiate()?
    };
    let established = loop {
        while let Some(message) = handshake.transmit()? {
            line(&mut stdout, &message)?;
        }
        if handshake.is_complete() {
            break handshake.finish()?;
        }
        let message = next(&mut lines)?;
        if let Err(error) = handshake.receive(message.as_bytes()) {
            eprintln!("refused: {error:?}");
            std::process::exit(3);
        }
    };
    eprintln!("verified {}", established.peer);
    let mut session = established.session;
    line(&mut stdout, HEXLOWER.encode(session.id()).as_bytes())?;
    if role == "responder" {
        for text in lines {
            let opened = session.open(&hex(&text?)?)?;
            let reply = [b"echo:".as_slice(), &opened].concat();
            line(
                &mut stdout,
                HEXLOWER.encode(&session.seal(&reply)?).as_bytes(),
            )?;
        }
    } else {
        let record = session.seal(b"ping from rust")?;
        line(&mut stdout, HEXLOWER.encode(&record).as_bytes())?;
        let reply = session.open(&hex(&next(&mut lines)?)?)?;
        line(&mut stdout, &reply)?;
    }
    Ok(())
}
