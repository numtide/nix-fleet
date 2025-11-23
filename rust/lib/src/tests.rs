use super::*;

use anyhow::Context;
use jsonpath_rust::JsonPath;

struct TestKeyTuple {
    openssh_key: &'static str,
    openssh_pubkey: &'static str,
    pubkey: &'static str,
}

#[test]
fn parses_openssh_key() {
    // List of tuples of (Open SSH private keys, NodeId)
    const TEST_KEYS: &[TestKeyTuple] = &[
        TestKeyTuple {
            openssh_key: include_str!("../../../fixtures/coordinator.ed25519"),
            openssh_pubkey: include_str!("../../../fixtures/coordinator.ed25519.pub"),
            pubkey: "ba48d5a18a06a0348511b83ef8e8b900ea653c43086e55613344cdd8192f7f6c",
        },
        TestKeyTuple {
            openssh_key: include_str!("../../../fixtures/agent.ed25519"),
            openssh_pubkey: include_str!("../../../fixtures/agent.ed25519.pub"),
            pubkey: "976f02e6c46cd53189128d7b72ec1a2eeff05012130debefc7a5dab8d0744139",
        },
        TestKeyTuple {
            openssh_key: include_str!("../../../fixtures/admin.ed25519"),
            openssh_pubkey: include_str!("../../../fixtures/admin.ed25519.pub"),
            pubkey: "7be5463aab9b1f0446ab70dbc883e0fd2b2da0a6a2a81dc3061e5c25ce4c4e94",
        },
    ];

    for TestKeyTuple {
        openssh_key,
        openssh_pubkey,
        pubkey,
    } in TEST_KEYS
    {
        let secret = util::parse_openssh_ed25519_private(openssh_key.as_bytes()).unwrap();
        assert_eq!(&secret.public().to_string(), pubkey);

        let y_coordinate = util::parse_openssh_ed25519_public(openssh_pubkey.as_bytes()).unwrap();
        assert_eq!(*pubkey, y_coordinate.to_string());
    }
}

#[tokio::test]
#[test_log::test]
async fn facts_can_be_gathered() {
    let facts = facts::Facts::try_from_environment().await.unwrap();

    if cfg!(target_os = "linux") {
        assert_eq!(facts.os, platforms::OS::Linux);
        let facter = facts.maybe_facter.unwrap();

        let js = serde_json::from_str::<serde_json::Value>(&facter)
            .context(format!("parsing {facter}"))
            .unwrap();

        let maybe_kernel = js.query("$.kernel").unwrap().first().unwrap().as_str();
        assert_eq!(maybe_kernel, Some("Linux"), "{facter}");

        assert_eq!(
            facts.maybe_nixos_facter, None,
            "nixos-facter does not work in unit tests, hence it must be empty"
        );
    } else if cfg!(target_os = "macos") {
        assert_eq!(facts.os, platforms::OS::MacOS);
        let facter = facts.maybe_facter.unwrap();

        let js = serde_json::from_str::<serde_json::Value>(&facter)
            .context(format!("parsing {facter}"))
            .unwrap();

        let maybe_kernel = js.query("$.kernel").unwrap().first().unwrap().as_str();
        assert_eq!(maybe_kernel, Some("Darwin"), "{facter}");

        assert_eq!(
            facts.maybe_nixos_facter, None,
            "nixos-facter is not available on macos"
        );
    } else {
        tracing::warn!("unsupported target os")
    }
}
