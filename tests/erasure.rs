//! Forward secrecy depends on erasure. A global allocator here reads every block as it is freed and
//! counts the ones still holding a secret. It sees the heap only: copies a move leaves on the stack,
//! and what libraries keep there, are outside what this crate promises.
//!
//! One test in this binary, since the allocator counts every thread's frees.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use coqui_peer::{Method, drive_messages};
use coqui_peer_webcrypto::{Identity, MessageTransport, Random, Trust, WebCrypto};

const LONG_TERM: [u8; 32] = [0x11; 32];
const OTHER_LONG_TERM: [u8; 32] = [0x22; 32];
const INITIATOR_EPHEMERAL: [u8; 32] = [0x33; 32];
const RESPONDER_EPHEMERAL: [u8; 32] = [0x44; 32];

static SOURCE_LONG_TERM: [[u8; 32]; 1] = [LONG_TERM];
static SOURCE_OTHER_LONG_TERM: [[u8; 32]; 1] = [OTHER_LONG_TERM];
static SOURCE_INITIATOR: [[u8; 32]; 2] = [[0xa1; 32], INITIATOR_EPHEMERAL];
static SOURCE_RESPONDER: [[u8; 32]; 2] = [[0xb2; 32], RESPONDER_EPHEMERAL];

const NEEDLE_COUNT: usize = 8;
static HITS: [AtomicUsize; NEEDLE_COUNT] = [const { AtomicUsize::new(0) }; NEEDLE_COUNT];
static ARMED: AtomicBool = AtomicBool::new(false);
/// Filled before arming, and only read while armed.
static DERIVED: Mutex<[[u8; 32]; 3]> = Mutex::new([[0; 32]; 3]);

struct Scanning;

fn holds(block: &[u8], needle: &[u8]) -> bool {
    block.len() >= needle.len() && block.windows(needle.len()).any(|window| window == needle)
}

// SAFETY: every call forwards to `System` with the same arguments. `dealloc` also reads the block
// it was given, which is live and `layout.size()` bytes until the forwarded call.
unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            // Nothing here allocates: `ARMED` is off while the mutex below could be contended by a
            // thread holding it to allocate, and it is only locked to read fixed arrays.
            // SAFETY: the block is live and this long, as this function's contract says.
            let block = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
            let fixed: [&[u8]; 5] = [
                &LONG_TERM[..24],
                &OTHER_LONG_TERM[..24],
                &INITIATOR_EPHEMERAL[..24],
                &RESPONDER_EPHEMERAL[..24],
                // The base64 of a long run of 0x11, as PEM holds the long-term scalar.
                b"ERERERERERERERER",
            ];
            for (index, needle) in fixed.iter().enumerate() {
                if holds(block, needle) {
                    HITS[index].fetch_add(1, Ordering::SeqCst);
                }
            }
            if let Ok(derived) = DERIVED.try_lock() {
                for (index, key) in derived.iter().enumerate() {
                    if holds(block, key) {
                        HITS[5 + index].fetch_add(1, Ordering::SeqCst);
                    }
                }
            }
        }
        // SAFETY: forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

/// A source reading from statics, so that the test itself holds no scalar on the heap.
fn scripted(chunks: &'static [[u8; 32]]) -> Random {
    let next = AtomicUsize::new(0);
    Random::from_fn(move |out| {
        out.copy_from_slice(&chunks[next.fetch_add(1, Ordering::SeqCst)]);
        Ok(())
    })
}

struct Pipe(
    std::sync::mpsc::Sender<Vec<u8>>,
    std::sync::mpsc::Receiver<Vec<u8>>,
);

impl MessageTransport for Pipe {
    fn send(&mut self, message: &[u8]) -> std::io::Result<()> {
        self.0
            .send(message.to_vec())
            .map_err(|_| std::io::ErrorKind::BrokenPipe.into())
    }

    fn recv(&mut self) -> std::io::Result<Vec<u8>> {
        self.1
            .recv()
            .map_err(|_| std::io::ErrorKind::UnexpectedEof.into())
    }
}

fn hex32(value: &serde_json::Value) -> [u8; 32] {
    let text = value.as_str().unwrap();
    let bytes = data_encoding::HEXLOWER.decode(text.as_bytes()).unwrap();
    bytes.try_into().unwrap()
}

#[test]
fn no_freed_block_holds_a_scalar_a_traffic_key_or_the_export_secret() {
    // The vectors use these same scalars and nonces, so they name the derived keys.
    let vectors: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/handshake.json"),
        )
        .unwrap(),
    )
    .unwrap();
    *DERIVED.lock().unwrap() = [
        hex32(&vectors["session"]["initiatorKey"]),
        hex32(&vectors["session"]["responderKey"]),
        hex32(&vectors["session"]["exporter"]),
    ];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.pem");

    ARMED.store(true, Ordering::SeqCst);
    let scenario = std::thread::spawn(move || {
        let client = Identity::generate_with(&scripted(&SOURCE_LONG_TERM)).unwrap();
        let server = Identity::generate_with(&scripted(&SOURCE_OTHER_LONG_TERM)).unwrap();

        // The PEM paths, in memory and through a file.
        let pem = client.to_pkcs8_pem().unwrap();
        drop(Identity::from_pkcs8_pem(&pem).unwrap());
        drop(pem);
        client.write_new(&path).unwrap();
        drop(Identity::read(&path).unwrap().unwrap());

        let dialing = WebCrypto::new(client.clone())
            .with_responders(Trust::pinned([server.peer_id()]))
            .with_random(scripted(&SOURCE_INITIATOR));
        let listening = WebCrypto::new(server.clone())
            .with_initiators(Trust::pinned([client.peer_id()]))
            .with_random(scripted(&SOURCE_RESPONDER));
        let ((to_far, from_near), (to_near, from_far)) =
            (std::sync::mpsc::channel(), std::sync::mpsc::channel());
        let serving = std::thread::spawn(move || {
            let handshake = listening.respond(None).unwrap();
            let established = drive_messages(handshake, &mut Pipe(to_near, from_near)).unwrap();
            drop(listening);
            established
        });
        let near =
            drive_messages(dialing.initiate().unwrap(), &mut Pipe(to_far, from_far)).unwrap();
        let far = serving.join().unwrap();
        let (mut near, mut far) = (near.session, far.session);
        let record = near.seal(b"a message").unwrap();
        far.open(&record).unwrap().unwrap();
        let mut exported = [0u8; 32];
        far.export("label", &mut exported).unwrap();
        far.open(&near.close().unwrap()).unwrap();
        drop((near, far, dialing, client, server));
    });
    scenario.join().unwrap();
    ARMED.store(false, Ordering::SeqCst);

    let counts: Vec<usize> = HITS.iter().map(|hit| hit.load(Ordering::SeqCst)).collect();
    let names = [
        "long-term scalar",
        "other long-term scalar",
        "initiator ephemeral scalar",
        "responder ephemeral scalar",
        "PEM base64 of the long-term scalar",
        "initiator traffic key",
        "responder traffic key",
        "export secret",
    ];
    let found: Vec<_> = names
        .iter()
        .zip(&counts)
        .filter(|(_, count)| **count > 0)
        .collect();
    assert!(found.is_empty(), "freed blocks held: {found:?}");
}
