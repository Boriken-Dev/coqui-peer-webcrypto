//! The committed vectors in `tests/vectors/` pin the wire byte for byte from a second computation of
//! the transcript and keys here, and list what every implementation must refuse. The JavaScript
//! tests read the same files.
//!
//! Regenerating them is a wire change:
//! `cargo test --all-features --test vectors -- --ignored regenerate`

mod support;

use std::fs;
use std::path::{Path, PathBuf};

use coqui_peer::{Handshake, Method};
use coqui_peer_webcrypto::{
    Error, Identity, PAIR_EXPORT_LABEL, PROFILE, Trust, WebCrypto, WebCryptoHandshake,
};
use data_encoding::{BASE64URL_NOPAD as BASE64, HEXLOWER as HEX};
use hkdf::Hkdf;
use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use p256::elliptic_curve::sec1::ToSec1Point as _;
use p256::pkcs8::EncodePrivateKey as _;
use p256::{PublicKey, SecretKey};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use support::scripted;

const INITIATOR_SCALAR: [u8; 32] = [0x11; 32];
const RESPONDER_SCALAR: [u8; 32] = [0x22; 32];
const INITIATOR_EPHEMERAL: [u8; 32] = [0x33; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x44; 32];
const INITIATOR_NONCE: [u8; 32] = [0xa1; 32];
const RESPONDER_NONCE: [u8; 32] = [0xb2; 32];
const STRANGER_SCALAR: [u8; 32] = [0x55; 32];
/// The order of P-256.
const ORDER: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

fn vectors() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

fn identity(scalar: [u8; 32]) -> Identity {
    Identity::generate_with(&scripted(&[&scalar])).unwrap()
}

fn signing(scalar: [u8; 32]) -> SigningKey {
    SigningKey::from_slice(&scalar).unwrap()
}

fn point(scalar: [u8; 32]) -> Vec<u8> {
    SecretKey::from_slice(&scalar)
        .unwrap()
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .to_vec()
}

fn initiator() -> WebCryptoHandshake {
    WebCrypto::new(identity(INITIATOR_SCALAR))
        .with_responders(Trust::pinned([identity(RESPONDER_SCALAR).peer_id()]))
        .with_random(scripted(&[&INITIATOR_NONCE, &INITIATOR_EPHEMERAL]))
        .initiate()
        .unwrap()
}

fn responder() -> WebCryptoHandshake {
    WebCrypto::new(identity(RESPONDER_SCALAR))
        .with_initiators(Trust::pinned([identity(INITIATOR_SCALAR).peer_id()]))
        .with_random(scripted(&[&RESPONDER_NONCE, &RESPONDER_EPHEMERAL]))
        .respond(None)
        .unwrap()
}

fn field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The transcript, computed apart from the crate. `None` is the session id's input.
fn transcript(role: Option<&str>) -> Vec<u8> {
    let mut out = Vec::new();
    field(&mut out, PROFILE.as_bytes());
    if let Some(role) = role {
        field(&mut out, role.as_bytes());
    }
    field(&mut out, identity(INITIATOR_SCALAR).spki_der());
    field(&mut out, identity(RESPONDER_SCALAR).spki_der());
    field(&mut out, &INITIATOR_NONCE);
    field(&mut out, &RESPONDER_NONCE);
    field(&mut out, &point(INITIATOR_EPHEMERAL));
    field(&mut out, &point(RESPONDER_EPHEMERAL));
    field(&mut out, b"");
    out
}

fn signed_by(scalar: [u8; 32], role: &str) -> String {
    let signature: Signature = signing(scalar).sign(&transcript(Some(role)));
    BASE64.encode(&signature.to_bytes())
}

fn message(members: &[(&str, &str)]) -> String {
    let mut out = format!("{{\"profile\":\"{PROFILE}\",\"version\":1");
    for (name, value) in members {
        out.push_str(&format!(",\"{name}\":\"{value}\""));
    }
    out.push('}');
    out
}

fn high_s(signature: &str) -> String {
    let bytes = BASE64.decode(signature.as_bytes()).unwrap();
    let parsed = Signature::from_slice(&bytes).unwrap();
    let (r, s) = parsed.split_scalars();
    let flipped = Signature::from_scalars(r.to_bytes(), (-*s).to_bytes()).unwrap();
    // One of the two is high; the vector carries the one the signer did not give.
    BASE64.encode(&flipped.to_bytes())
}

/// Every message a conforming implementation must refuse at this point of the exchange.
#[allow(clippy::too_many_lines, reason = "a table")]
fn refused(hello: &str, challenge: &str) -> Value {
    let spki = BASE64.encode(identity(INITIATOR_SCALAR).spki_der());
    let responder_spki = BASE64.encode(identity(RESPONDER_SCALAR).spki_der());
    let ephemeral = BASE64.encode(&point(INITIATOR_EPHEMERAL));
    let responder_ephemeral = BASE64.encode(&point(RESPONDER_EPHEMERAL));
    let nonce = BASE64.encode(&INITIATOR_NONCE);
    let responder_nonce = BASE64.encode(&RESPONDER_NONCE);
    let server_signature = signed_by(RESPONDER_SCALAR, "server");
    let client_signature = signed_by(INITIATOR_SCALAR, "client");

    let der = identity(INITIATOR_SCALAR).spki_der().to_vec();
    let enc = |bytes: &[u8]| BASE64.encode(bytes);
    let compressed = {
        let public = point(INITIATOR_SCALAR);
        let mut der = HEX
            .decode(b"3039301306072a8648ce3d020106082a8648ce3d030107032200")
            .unwrap();
        der.push(if public[64] & 1 == 1 { 3 } else { 2 });
        der.extend_from_slice(&public[1..33]);
        der
    };
    let long_form = [&[0x30, 0x81, der[1]], &der[2..]].concat();
    let trailing = [der.as_slice(), &[0]].concat();
    let mut other_curve = der.clone();
    other_curve[20] ^= 1;
    let mut off_curve = der.clone();
    off_curve[90] ^= 1;
    let zero_point = [&der[..27], &[0u8; 64]].concat();
    let p384 = [
        HEX.decode(b"3076301006072a8648ce3d020106052b8104002203620004")
            .unwrap(),
        vec![0x11; 96],
    ]
    .concat();

    let hello_with = |key: &str, eph: &str, n: &str| {
        message(&[
            ("type", "hello"),
            ("publicKey", key),
            ("ephemeral", eph),
            ("nonce", n),
        ])
    };
    let challenge_with = |key: &str, eph: &str, n: &str, s: &str| {
        message(&[
            ("type", "challenge"),
            ("publicKey", key),
            ("ephemeral", eph),
            ("nonce", n),
            ("signature", s),
        ])
    };
    let good =
        |name: &str, value: String| json!({"stage": "hello", "name": name, "message": value});
    let good_hello = hello_with(&spki, &ephemeral, &nonce);
    assert_eq!(good_hello, hello);

    let mut padded = nonce.clone();
    padded.push('=');
    let mut trailing_bits = nonce[..nonce.len() - 1].to_owned();
    trailing_bits.push('j');
    let mut other_alphabet = nonce.clone();
    other_alphabet.replace_range(0..1, "+");
    let member_order = format!(
        "{{\"version\":1,\"profile\":\"{PROFILE}\",\"type\":\"hello\",\"publicKey\":\"{spki}\",\
         \"ephemeral\":\"{ephemeral}\",\"nonce\":\"{nonce}\"}}"
    );
    let with_rest = |rest: &str| good_hello.replacen('}', &format!(",{rest}}}"), 1);
    let head = |text: &str| {
        good_hello.replacen(
            &format!("{{\"profile\":\"{PROFILE}\",\"version\":1"),
            text,
            1,
        )
    };

    let mut cases = vec![
        good("empty", String::new()),
        good("not json", "attacker text".to_owned()),
        good("an array", "[]".to_owned()),
        good(
            "deep nesting",
            format!("{}{}", "[".repeat(1400), "]".repeat(1400)),
        ),
        good("leading whitespace", format!(" {good_hello}")),
        good("trailing newline", format!("{good_hello}\n")),
        good("spaces inside", good_hello.replacen(',', ", ", 1)),
        good("members out of order", member_order),
        good("unknown member", with_rest("\"extra\":\"x\"")),
        good(
            "duplicate member",
            with_rest(&format!("\"nonce\":\"{nonce}\"")),
        ),
        good(
            "signature on a hello",
            with_rest(&format!("\"signature\":\"{server_signature}\"")),
        ),
        good(
            "another profile",
            good_hello.replace(PROFILE, "dev.boriken.coqui.peer-webcrypto/v2"),
        ),
        good(
            "version 0",
            head(&format!("{{\"profile\":\"{PROFILE}\",\"version\":0")),
        ),
        good(
            "version 2",
            head(&format!("{{\"profile\":\"{PROFILE}\",\"version\":2")),
        ),
        good(
            "version 1.0",
            head(&format!("{{\"profile\":\"{PROFILE}\",\"version\":1.0")),
        ),
        good(
            "version as text",
            head(&format!("{{\"profile\":\"{PROFILE}\",\"version\":\"1\"")),
        ),
        good("another type", good_hello.replace("\"hello\"", "\"proof\"")),
        good(
            "an escaped character",
            good_hello.replace("\"hello\"", "\"\\u0068ello\""),
        ),
        good(
            "short nonce",
            hello_with(&spki, &ephemeral, &enc(&[0xa1; 31])),
        ),
        good(
            "long nonce",
            hello_with(&spki, &ephemeral, &enc(&[0xa1; 33])),
        ),
        good("padded nonce", hello_with(&spki, &ephemeral, &padded)),
        good(
            "nonce with stray trailing bits",
            hello_with(&spki, &ephemeral, &trailing_bits),
        ),
        good(
            "nonce in the other base64 alphabet",
            hello_with(&spki, &ephemeral, &other_alphabet),
        ),
        good(
            "compressed key",
            hello_with(&enc(&compressed), &ephemeral, &nonce),
        ),
        good(
            "long-form DER key",
            hello_with(&enc(&long_form), &ephemeral, &nonce),
        ),
        good(
            "key with a trailing byte",
            hello_with(&enc(&trailing), &ephemeral, &nonce),
        ),
        good(
            "a key of the same length naming another curve",
            hello_with(&enc(&other_curve), &ephemeral, &nonce),
        ),
        good(
            "key off the curve",
            hello_with(&enc(&off_curve), &ephemeral, &nonce),
        ),
        good(
            "key at the zero point",
            hello_with(&enc(&zero_point), &ephemeral, &nonce),
        ),
        good(
            "the responder's own key",
            hello_with(&responder_spki, &ephemeral, &nonce),
        ),
        good(
            "compressed ephemeral",
            hello_with(&spki, &enc(&compressed[26..]), &nonce),
        ),
        good(
            "ephemeral off the curve",
            hello_with(&spki, &enc(&off_curve[26..]), &nonce),
        ),
        good(
            "ephemeral at the zero point",
            hello_with(&spki, &enc(&zero_point[26..]), &nonce),
        ),
        good("ephemeral an SPKI", hello_with(&spki, &spki, &nonce)),
    ];
    cases.push(good(
        "a P-384 key",
        hello_with(&enc(&p384), &ephemeral, &nonce),
    ));

    let at = |stage: &str, name: &str, value: String| json!({"stage": stage, "name": name, "message": value});
    let answer =
        |s: &str| challenge_with(&responder_spki, &responder_ephemeral, &responder_nonce, s);
    let zero = enc(&[0u8; 64]);
    let order = HEX.decode(ORDER.as_bytes()).unwrap();
    let out_of_range = enc(&[order.as_slice(), &[1u8; 32]].concat());
    let der_signature = enc(Signature::from_slice(
        &BASE64.decode(server_signature.as_bytes()).unwrap(),
    )
    .unwrap()
    .to_der()
    .as_bytes());
    let mut tampered = BASE64.decode(server_signature.as_bytes()).unwrap();
    tampered[10] ^= 1;
    let stranger = identity(STRANGER_SCALAR);
    let stranger_spki = BASE64.encode(stranger.spki_der());
    cases.extend([
        at("challenge", "altered signature", answer(&enc(&tampered))),
        at("challenge", "zero signature", answer(&zero)),
        at("challenge", "r at the group order", answer(&out_of_range)),
        at("challenge", "DER signature", answer(&der_signature)),
        at("challenge", "short signature", answer(&enc(&[1u8; 63]))),
        at(
            "challenge",
            "signed for the role client",
            answer(&signed_by(RESPONDER_SCALAR, "client")),
        ),
        at(
            "challenge",
            "signed for the role accept",
            answer(&signed_by(RESPONDER_SCALAR, "accept")),
        ),
        at(
            "challenge",
            "a key swapped for another",
            challenge_with(
                &stranger_spki,
                &responder_ephemeral,
                &responder_nonce,
                &server_signature,
            ),
        ),
        at(
            "challenge",
            "another nonce",
            challenge_with(
                &responder_spki,
                &responder_ephemeral,
                &nonce,
                &server_signature,
            ),
        ),
        at(
            "challenge",
            "another ephemeral",
            challenge_with(
                &responder_spki,
                &ephemeral,
                &responder_nonce,
                &server_signature,
            ),
        ),
        at(
            "challenge",
            "the initiator's own key",
            challenge_with(
                &spki,
                &responder_ephemeral,
                &responder_nonce,
                &server_signature,
            ),
        ),
        at("challenge", "a hello in its place", hello.to_owned()),
        at(
            "proof",
            "the challenge's signature reflected",
            message(&[("type", "proof"), ("signature", &server_signature)]),
        ),
        at(
            "proof",
            "signed for the role server",
            message(&[
                ("type", "proof"),
                ("signature", &signed_by(INITIATOR_SCALAR, "server")),
            ]),
        ),
        at(
            "proof",
            "signed for the role accept",
            message(&[
                ("type", "proof"),
                ("signature", &signed_by(INITIATOR_SCALAR, "accept")),
            ]),
        ),
        at(
            "proof",
            "signed by a stranger",
            message(&[
                ("type", "proof"),
                ("signature", &signed_by(STRANGER_SCALAR, "client")),
            ]),
        ),
        at(
            "proof",
            "with an extra key",
            message(&[
                ("type", "proof"),
                ("publicKey", &spki),
                ("signature", &client_signature),
            ]),
        ),
        at(
            "proof",
            "an accept in its place",
            message(&[("type", "accept"), ("signature", &client_signature)]),
        ),
        at(
            "accept",
            "the challenge's signature replayed",
            message(&[("type", "accept"), ("signature", &server_signature)]),
        ),
        at(
            "accept",
            "the client's proof reflected",
            message(&[("type", "accept"), ("signature", &client_signature)]),
        ),
        at(
            "accept",
            "signed by a stranger",
            message(&[
                ("type", "accept"),
                ("signature", &signed_by(STRANGER_SCALAR, "accept")),
            ]),
        ),
    ]);
    assert_eq!(challenge, answer(&server_signature));
    Value::Array(cases)
}

fn step(from: &mut WebCryptoHandshake, to: &mut WebCryptoHandshake) -> String {
    let out = from.transmit().unwrap().unwrap();
    to.receive(&out).unwrap();
    String::from_utf8(out).unwrap()
}

fn build() -> Value {
    let (mut a, mut b) = (initiator(), responder());
    let hello = step(&mut a, &mut b);
    let challenge = step(&mut b, &mut a);
    let proof = step(&mut a, &mut b);
    let accept = step(&mut b, &mut a);
    assert!(a.is_complete() && b.is_complete());
    let (at_a, at_b) = (a.finish().unwrap(), b.finish().unwrap());
    let (mut session_a, mut session_b) = (at_a.session, at_b.session);

    // The session's values, apart from the crate.
    let id: [u8; 32] = Sha256::digest(transcript(None)).into();
    assert_eq!(session_a.id(), &id);
    assert_eq!(session_b.id(), &id);
    let shared = SecretKey::from_slice(&INITIATOR_EPHEMERAL)
        .unwrap()
        .diffie_hellman(&PublicKey::from_sec1_bytes(&point(RESPONDER_EPHEMERAL)).unwrap());
    let mut keys = [0u8; 96];
    Hkdf::<Sha256>::new(Some(&id), shared.raw_secret_bytes())
        .expand(format!("{PROFILE}/keys").as_bytes(), &mut keys)
        .unwrap();
    let mut export = [0u8; 32];
    Hkdf::<Sha256>::new(None, &keys[64..])
        .expand(
            format!("{PROFILE}/export/{PAIR_EXPORT_LABEL}").as_bytes(),
            &mut export,
        )
        .unwrap();
    let mut exported = [0u8; 32];
    session_a.export(PAIR_EXPORT_LABEL, &mut exported).unwrap();
    assert_eq!(exported, export);

    let up = session_a.seal(b"from the initiator").unwrap();
    assert_eq!(session_b.open(&up).unwrap(), b"from the initiator");
    let empty = session_a.seal(b"").unwrap();
    assert_eq!(session_b.open(&empty).unwrap(), b"");
    let down = session_b.seal(b"from the responder").unwrap();
    assert_eq!(session_a.open(&down).unwrap(), b"from the responder");

    let pkcs8 = |scalar| HEX.encode(signing(scalar).to_pkcs8_der().unwrap().as_bytes());
    let signature_of = |text: &str| -> String {
        let parsed: Value = serde_json::from_str(text).unwrap();
        parsed["signature"].as_str().unwrap().to_owned()
    };
    let swapped_s = high_s(&signature_of(&challenge));
    let challenge_high_s = challenge.replace(&signature_of(&challenge), &swapped_s);
    json!({
        "profile": PROFILE,
        "initiator": {
            "pkcs8": pkcs8(INITIATOR_SCALAR),
            "spki": HEX.encode(identity(INITIATOR_SCALAR).spki_der()),
            "peerId": identity(INITIATOR_SCALAR).peer_id().to_string(),
            "nonce": HEX.encode(&INITIATOR_NONCE),
            "ephemeralScalar": HEX.encode(&INITIATOR_EPHEMERAL),
            "ephemeralPoint": HEX.encode(&point(INITIATOR_EPHEMERAL)),
        },
        "responder": {
            "pkcs8": pkcs8(RESPONDER_SCALAR),
            "spki": HEX.encode(identity(RESPONDER_SCALAR).spki_der()),
            "peerId": identity(RESPONDER_SCALAR).peer_id().to_string(),
            "nonce": HEX.encode(&RESPONDER_NONCE),
            "ephemeralScalar": HEX.encode(&RESPONDER_EPHEMERAL),
            "ephemeralPoint": HEX.encode(&point(RESPONDER_EPHEMERAL)),
        },
        "messages": {"hello": hello, "challenge": challenge, "proof": proof, "accept": accept},
        "challengeOtherS": challenge_high_s,
        "signed": {
            "server": HEX.encode(&transcript(Some("server"))),
            "client": HEX.encode(&transcript(Some("client"))),
            "accept": HEX.encode(&transcript(Some("accept"))),
        },
        "session": {
            "id": HEX.encode(&id),
            "shared": HEX.encode(shared.raw_secret_bytes()),
            "initiatorKey": HEX.encode(&keys[..32]),
            "responderKey": HEX.encode(&keys[32..64]),
            "exporter": HEX.encode(&keys[64..]),
            "pairExport": HEX.encode(&export),
        },
        "records": [
            {"from": "initiator", "message": "from the initiator", "record": HEX.encode(&up)},
            {"from": "initiator", "message": "", "record": HEX.encode(&empty)},
            {"from": "responder", "message": "from the responder", "record": HEX.encode(&down)},
        ],
        "refused": refused(&hello, &challenge),
    })
}

fn render() -> String {
    let mut text = serde_json::to_string_pretty(&build()).unwrap();
    text.push('\n');
    text
}

#[test]
fn the_committed_vectors_are_what_the_code_and_a_second_computation_give() {
    let committed = fs::read_to_string(vectors().join("handshake.json")).unwrap();
    assert_eq!(committed, render());
}

#[test]
#[ignore = "writes the vectors; a change to them is a wire change"]
fn regenerate() {
    fs::write(vectors().join("handshake.json"), render()).unwrap();
}

#[test]
fn every_listed_message_is_refused_at_its_stage_with_the_state_left_over() {
    let built = build();
    let messages = &built["messages"];
    for case in built["refused"].as_array().unwrap() {
        let (stage, name) = (
            case["stage"].as_str().unwrap(),
            case["name"].as_str().unwrap(),
        );
        let bad = case["message"].as_str().unwrap().as_bytes();
        let hello = messages["hello"].as_str().unwrap().as_bytes();
        let challenge = messages["challenge"].as_str().unwrap().as_bytes();
        let mut handshake = match stage {
            "hello" => responder(),
            "challenge" => initiator(),
            "proof" => {
                let mut side = responder();
                side.receive(hello).unwrap();
                side
            }
            "accept" => {
                let mut side = initiator();
                side.receive(challenge).unwrap();
                side
            }
            other => panic!("{other}"),
        };
        while handshake.transmit().unwrap().is_some() {}
        let refusal = handshake.receive(bad);
        assert!(refusal.is_err(), "{stage}: {name} was accepted");
        assert!(
            matches!(handshake.transmit(), Err(Error::State)),
            "{stage}: {name}"
        );
        assert!(!handshake.is_complete(), "{stage}: {name}");
    }
}

#[test]
fn a_signature_with_either_s_is_accepted_since_webcrypto_does_not_normalise_it() {
    let built = build();
    let mut side = initiator();
    side.receive(built["challengeOtherS"].as_str().unwrap().as_bytes())
        .unwrap();
    assert!(side.transmit().unwrap().is_some());
}

#[test]
fn arbitrary_bytes_are_refused_and_never_panic() {
    let hello = build()["messages"]["hello"]
        .as_str()
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    for round in 0..400 {
        let mut input = if round % 2 == 0 {
            hello.clone()
        } else {
            vec![0u8; usize::try_from(next() % 600).unwrap()]
        };
        for _ in 0..=(next() % 8) {
            if input.is_empty() {
                break;
            }
            let at = usize::try_from(next() % input.len() as u64).unwrap();
            input[at] = u8::try_from(next() & 0xff).unwrap();
        }
        // A changed nonce byte can leave a valid hello, so only garbage must be refused.
        let refused = responder().receive(&input).is_err();
        assert!(refused || round % 2 == 0);
        assert!(initiator().receive(&input).is_err());
    }
}
