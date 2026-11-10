//! Each builder setter reaches what it builds, a `Partial` layers under the setters, the last
//! write wins, and the settings are values a file fills.

mod support;

use coqui_builder::Partial;
use coqui_peer::Method;
use coqui_peer_webcrypto::{
    DEFAULT_MAX_MESSAGE, DEFAULT_SESSION_LIMIT, Identity, NonDefault, PairingMethod,
    PairingSettings, Trust, WebCrypto, WebCryptoSettings,
};

fn lines(found: &[NonDefault]) -> Vec<(String, String, String)> {
    found
        .iter()
        .map(|entry| {
            (
                entry.setting.clone(),
                entry.value.to_string(),
                entry.default.to_string(),
            )
        })
        .collect()
}

#[test]
fn every_setter_reaches_the_method() {
    let identity = Identity::generate().unwrap();
    let method = WebCrypto::builder()
        .identity(identity.clone())
        .max_message(4096)
        .session_limit(1000)
        .build()
        .unwrap();
    assert_eq!(method.settings().max_message, 4096);
    assert_eq!(method.settings().session_limit, 1000);
    assert_eq!(method.identity().peer_id(), identity.peer_id());
    assert_eq!(
        lines(&method.non_defaults()),
        [
            (
                "max_message".to_owned(),
                "usize(4096)".to_owned(),
                format!("usize({DEFAULT_MAX_MESSAGE})")
            ),
            (
                "session_limit".to_owned(),
                "u64(1000)".to_owned(),
                format!("u64({DEFAULT_SESSION_LIMIT})")
            ),
        ]
    );
}

#[test]
fn the_roles_are_set_by_name_and_each_side_proves_the_other() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::builder()
        .identity(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build()
        .unwrap();
    let listening = WebCrypto::builder()
        .identity(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .build()
        .unwrap();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    support::exchange(&mut a, &mut b).unwrap();
}

#[test]
fn a_method_without_an_identity_is_not_built() {
    let error = WebCrypto::builder().max_message(1).build().unwrap_err();
    assert!(error.to_string().contains("identity"), "{error}");
    assert!(PairingMethod::builder().build().is_err());
}

#[test]
fn a_partial_layers_under_the_setters_and_the_last_write_wins() {
    let mut settings = WebCryptoSettings::default();
    settings.max_message = 2048;
    let method = WebCrypto::builder()
        .identity(Identity::generate().unwrap())
        .session_limit(5)
        .fill(Partial::from(settings))
        .max_message(8192)
        .build()
        .unwrap();
    assert_eq!(method.settings().max_message, 8192);
    assert_eq!(
        method.settings().session_limit,
        DEFAULT_SESSION_LIMIT,
        "the partial replaced the earlier limit"
    );
}

#[test]
fn the_pairing_method_takes_its_own_settings() {
    let method = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .max_message(3000)
        .build()
        .unwrap();
    assert_eq!(method.settings().max_message, 3000);
    assert_eq!(method.non_defaults().len(), 1);
    let mut whole = PairingSettings::default();
    whole.max_message = 1234;
    let method = PairingMethod::builder()
        .identity(Identity::generate().unwrap())
        .max_message(1)
        .fill(Partial::from(whole))
        .build()
        .unwrap();
    assert_eq!(method.settings(), whole);
}

#[test]
fn the_defaults_report_nothing() {
    let identity = Identity::generate().unwrap();
    assert!(
        WebCrypto::builder()
            .identity(identity.clone())
            .build()
            .unwrap()
            .non_defaults()
            .is_empty()
    );
    assert!(
        PairingMethod::builder()
            .identity(identity)
            .build()
            .unwrap()
            .non_defaults()
            .is_empty()
    );
}

#[test]
fn a_replaced_random_source_is_listed() {
    let method = WebCrypto::builder()
        .identity(Identity::generate().unwrap())
        .random(coqui_peer_webcrypto::random())
        .build()
        .unwrap();
    assert_eq!(
        lines(&method.non_defaults()),
        [(
            "random".to_owned(),
            "Random(caller's)".to_owned(),
            "Random(operating system's)".to_owned()
        )]
    );
}

fn read<T: coqui_builder::Describe>(text: &str) -> T {
    toml::from_str::<Partial<T>>(text).unwrap().build().unwrap()
}

#[test]
fn settings_read_from_toml_and_json() {
    let settings: WebCryptoSettings = read("session_limit = 5\n");
    assert_eq!(settings.session_limit, 5);
    assert_eq!(settings.max_message, DEFAULT_MAX_MESSAGE);
    assert_eq!(read::<WebCryptoSettings>(""), WebCryptoSettings::default());
    let pairing = serde_json::from_str::<Partial<PairingSettings>>("{\"max_message\": 8}")
        .unwrap()
        .build()
        .unwrap();
    assert_eq!(pairing.max_message, 8);
}

#[test]
fn settings_refuse_unknown_keys() {
    let refused = |text: &str| {
        toml::from_str::<Partial<WebCryptoSettings>>(text).is_err()
            || toml::from_str::<Partial<WebCryptoSettings>>(text)
                .unwrap()
                .build()
                .is_err()
    };
    assert!(refused("maxmessage = 1"));
    assert!(refused("max_message = \"big\""));
    let pairing = toml::from_str::<Partial<PairingSettings>>("session_limit = 1");
    assert!(pairing.is_err() || pairing.unwrap().build().is_err());
}
