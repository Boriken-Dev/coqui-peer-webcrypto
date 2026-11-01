//! Keys: their text form, files and refusals.

use coqui_peer_webcrypto::{Error, Identity};

// `openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256`, a throwaway test key.
const OPENSSL: &str = "REMOVED-TEST-KEY
";
/// `openssl pkey -pubout -outform DER | sha256sum` of that key.
const OPENSSL_ID: &str = "sha256:a338376e7a3d9876e4f2007bcb078e50a92d5a55449a3670b89adb3d4b43a2c2";

#[test]
fn a_key_round_trips_through_pem() {
    let identity = Identity::generate().unwrap();
    let pem = identity.to_pkcs8_pem().unwrap();
    assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----\n"));
    assert_eq!(
        Identity::from_pkcs8_pem(&pem).unwrap().peer_id(),
        identity.peer_id()
    );
}

#[test]
fn a_key_openssl_wrote_is_read() {
    let identity = Identity::from_pkcs8_pem(OPENSSL).unwrap();
    assert_eq!(identity.spki_der().len(), 91);
    assert_eq!(identity.peer_id().to_string(), OPENSSL_ID);
    assert_eq!(identity.key_material().id(), identity.peer_id());
}

#[test]
fn what_is_not_a_p256_pkcs8_key_is_refused_without_quoting_it() {
    let certificate = OPENSSL.replace("PRIVATE KEY", "CERTIFICATE");
    for text in ["", "secret text", certificate.as_str()] {
        let error = Identity::from_pkcs8_pem(text).unwrap_err();
        assert!(matches!(error, Error::Key));
        assert!(!error.to_string().contains("secret"));
    }
    assert!(matches!(
        Identity::from_pkcs8_der(b"nonsense"),
        Err(Error::Key)
    ));
}

#[test]
fn a_new_file_is_written_and_never_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested/identity.pem");
    assert!(Identity::read(&path).unwrap().is_none());
    let identity = Identity::generate().unwrap();
    identity.write_new(&path).unwrap();
    assert_eq!(
        Identity::read(&path).unwrap().unwrap().peer_id(),
        identity.peer_id()
    );
    let other = Identity::generate().unwrap();
    assert!(matches!(
        other.write_new(&path),
        Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(
        Identity::open_or_create(&path).unwrap().peer_id(),
        identity.peer_id()
    );
}

#[test]
fn open_or_create_creates_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.pem");
    let created = Identity::open_or_create(&path).unwrap();
    assert_eq!(
        Identity::open_or_create(&path).unwrap().peer_id(),
        created.peer_id()
    );
}

#[cfg(unix)]
#[test]
fn the_file_is_only_its_owners() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("identity.pem");
    Identity::generate().unwrap().write_new(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600);
}
