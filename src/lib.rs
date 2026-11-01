#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]
#![warn(
    clippy::std_instead_of_core,
    clippy::std_instead_of_alloc,
    clippy::alloc_instead_of_core
)]

extern crate alloc;

mod error;
mod handshake;
mod identity;
mod message;
mod session;
mod transcript;
mod trust;

pub use coqui_peer::pair;
pub use coqui_peer::{Established, KeyMaterial, Method, PeerId, Random, TrustStore, Weakening};
pub use error::Error;
pub use handshake::{METHOD, WebCrypto, WebCryptoHandshake, random};
pub use identity::Identity;
pub use message::{DEFAULT_MAX_MESSAGE, PROFILE};
pub use session::{Opener, PAIR_EXPORT_LABEL, Sealer, Session};
pub use trust::Trust;
