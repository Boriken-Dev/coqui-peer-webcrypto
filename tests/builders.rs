//! Each builder setter reaches what it builds, `settings` takes the whole, the last setter wins,
//! and the settings are values a file fills.

mod support;

use coqui_peer::{Method, NonDefault};
use coqui_peer_webcrypto::{
    DEFAULT_MAX_MESSAGE, DEFAULT_SESSION_LIMIT, Identity, PairingMethod, PairingSettings, Trust,
    WebCrypto, WebCryptoSettings,
};
use guatiao_serde::Presentation;
use guatiao_serde::text::{json, toml};

fn plain() -> Presentation {
    Presentation::new()
}

#[test]
fn every_setter_reaches_the_method() {
    let identity = Identity::generate().unwrap();
    let method = WebCrypto::builder(identity.clone())
        .max_message(4096)
        .session_limit(1000)
        .build();
    assert_eq!(method.settings().max_message, 4096);
    assert_eq!(method.settings().session_limit, 1000);
    assert_eq!(method.identity().peer_id(), identity.peer_id());
    assert_eq!(
        method.non_defaults(),
        [
            NonDefault::new("max_message", "4096", DEFAULT_MAX_MESSAGE.to_string()),
            NonDefault::new("session_limit", "1000", DEFAULT_SESSION_LIMIT.to_string()),
        ]
    );
}

#[test]
fn the_roles_are_set_by_name_and_each_side_proves_the_other() {
    let (client, server) = (Identity::generate().unwrap(), Identity::generate().unwrap());
    let dialing = WebCrypto::builder(client.clone())
        .responders(Trust::pinned([server.peer_id()]))
        .build();
    let listening = WebCrypto::builder(server)
        .initiators(Trust::pinned([client.peer_id()]))
        .build();
    let (mut a, mut b) = (
        dialing.initiate().unwrap(),
        listening.respond(None).unwrap(),
    );
    support::exchange(&mut a, &mut b).unwrap();
}

#[test]
fn settings_take_the_whole_and_the_last_setter_wins() {
    let mut settings = WebCryptoSettings::default();
    settings.max_message = 2048;
    let method = WebCrypto::builder(Identity::generate().unwrap())
        .session_limit(5)
        .settings(settings)
        .max_message(8192)
        .build();
    assert_eq!(method.settings().max_message, 8192);
    assert_eq!(
        method.settings().session_limit,
        DEFAULT_SESSION_LIMIT,
        "settings replaced the earlier limit"
    );
}

#[test]
fn the_pairing_method_takes_its_own_settings() {
    let method = PairingMethod::builder(Identity::generate().unwrap())
        .max_message(3000)
        .build();
    assert_eq!(method.settings().max_message, 3000);
    assert_eq!(method.non_defaults().len(), 1);
    let mut whole = PairingSettings::default();
    whole.max_message = 1234;
    let method = PairingMethod::builder(Identity::generate().unwrap())
        .max_message(1)
        .settings(whole)
        .build();
    assert_eq!(method.settings(), whole);
}

#[test]
fn the_defaults_report_nothing() {
    let identity = Identity::generate().unwrap();
    assert!(
        WebCrypto::builder(identity.clone())
            .build()
            .non_defaults()
            .is_empty()
    );
    assert!(
        PairingMethod::builder(identity)
            .build()
            .non_defaults()
            .is_empty()
    );
}

#[test]
fn a_replaced_random_source_is_listed() {
    let method = WebCrypto::builder(Identity::generate().unwrap())
        .random(coqui_peer_webcrypto::random())
        .build();
    assert_eq!(
        method.non_defaults(),
        [NonDefault::new("random", "caller's", "operating system's")]
    );
}

#[test]
fn settings_read_from_toml_and_json_and_round_trip() {
    let settings: WebCryptoSettings = toml::from_str_as("session_limit = 5\n", plain()).unwrap();
    assert_eq!(settings.session_limit, 5);
    assert_eq!(settings.max_message, DEFAULT_MAX_MESSAGE);
    assert_eq!(
        toml::from_str_as::<WebCryptoSettings>("", plain()).unwrap(),
        WebCryptoSettings::default()
    );
    let mut changed = WebCryptoSettings::default();
    changed.max_message = 77;
    changed.session_limit = 99;
    let text = toml::to_string_of(&changed, plain()).unwrap();
    assert_eq!(
        toml::from_str_as::<WebCryptoSettings>(&text, plain()).unwrap(),
        changed
    );
    let text = json::to_string_pretty_of(&changed, plain()).unwrap();
    assert_eq!(
        json::from_str_as::<WebCryptoSettings>(&text, plain()).unwrap(),
        changed
    );
    let pairing: PairingSettings = json::from_str_as("{\"max_message\": 8}", plain()).unwrap();
    assert_eq!(pairing.max_message, 8);
}

#[test]
fn settings_refuse_unknown_keys() {
    assert!(toml::from_str_as::<WebCryptoSettings>("maxmessage = 1", plain()).is_err());
    assert!(toml::from_str_as::<PairingSettings>("session_limit = 1", plain()).is_err());
    assert!(toml::from_str_as::<WebCryptoSettings>("max_message = \"big\"", plain()).is_err());
}
