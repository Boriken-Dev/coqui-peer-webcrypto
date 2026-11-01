use core::fmt;
use std::io;

/// Why a handshake, a session record or an identity failed.
///
/// `Display` is one lowercase clause and never quotes the input, a key or a path.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A message is not one this protocol allows at this point: its encoding, a member, a key or
    /// its place in the exchange.
    Malformed,
    /// A message is longer than [`with_max_message`](crate::WebCrypto::with_max_message) allows,
    /// or an export is longer than HKDF can give.
    TooLong,
    /// A signature does not verify: another transcript, another key or another outer binding.
    BadProof,
    /// The peer proved its key, and [`Trust`](crate::Trust) does not admit it.
    Untrusted,
    /// This method has no [`Trust`](crate::Trust) configured for that role.
    Unsupported,
    /// The handshake is over, or [`finish`](coqui_peer::Handshake::finish) came before its end.
    State,
    /// The random source failed.
    Random,
    /// A record does not open: altered, replayed, out of order or under other keys; or the
    /// direction already failed or ran out of sequence numbers. The session is over.
    Record,
    /// The text or bytes are not a P-256 private key in PKCS#8.
    Key,
    /// Reading or writing an identity file failed.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "the message is not valid here",
            Self::TooLong => "the output or message is over its limit",
            Self::BadProof => "a signature does not verify",
            Self::Untrusted => "the peer proved its key and is not trusted",
            Self::Unsupported => "this method is not configured for that role",
            Self::State => "the handshake is over or not complete",
            Self::Random => "the random source failed",
            Self::Record => "a session record does not open, or the session is over",
            Self::Key => "not a P-256 PKCS#8 private key",
            Self::Io(_) => "an identity file could not be read or written",
        })
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}
