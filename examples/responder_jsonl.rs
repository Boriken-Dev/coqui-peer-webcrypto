//! CI-only message exchange with the browser initiator; not a network server.
use coqui_peer::{Handshake, Method, PeerId};
use coqui_peer_webcrypto::WebCryptoMethod;
use serde_json::json;
use std::collections::BTreeSet;
use std::io::{self, BufRead, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let allowed: PeerId = std::env::args().nth(1).ok_or("client ID required")?.parse()?;
    let server = WebCryptoMethod::generate(BTreeSet::from([allowed]))?;
    let mut proof = server.respond(None)?;
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "{}", json!({"peerId": server.peer_id().to_string()}))?;
    stdout.flush()?;
    for line in io::stdin().lock().lines() {
        if let Err(err) = proof.receive(line?.as_bytes()) {
            eprintln!("Key proof refused: {err}");
            std::process::exit(3);
        }
        while let Some(msg) = proof.transmit()? {
            stdout.write_all(&msg)?;
            stdout.write_all(b"\n")?;
            stdout.flush()?;
        }
        if proof.is_complete() {
            eprintln!("Verified: {}", proof.finish()?.peer);
            return Ok(());
        }
    }
    Err("Incomplete authentication".into())
}
