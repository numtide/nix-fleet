pub use iroh;
pub use tokio;

pub mod util {
    use std::str::FromStr;

    use anyhow::Context;
    use iroh::SecretKey;

    pub fn parse_openssh_ed25519<R>(mut r: R) -> anyhow::Result<SecretKey>
    where
        R: std::io::Read,
    {
        let mut raw = Vec::new();
        r.read_to_end(&mut raw)?;

        let ssh_pk = ssh_key::PrivateKey::from_openssh(raw)?;
        if ssh_pk.is_encrypted() {
            anyhow::bail!("encrypted keys are currently unsupported")
        }

        let bytes = ssh_pk
            .key_data()
            .ed25519()
            .ok_or_else(|| anyhow::anyhow!("wrong key type"))?
            .private
            .to_bytes();

        let bytes = data_encoding::HEXLOWER.encode(&bytes);
        let parsed = iroh::SecretKey::from_str(&bytes)
            .context(format!("decoding {bytes} with length {}", bytes.len()))?;

        Ok(parsed)
    }
}

pub mod coordinator {
    use anyhow::Context;
    use iroh::{SecretKey, Watcher};

    pub async fn run(maybe_secret_key: Option<SecretKey>) -> anyhow::Result<()> {
        // Create an endpoint, it allows creating and accepting
        // connections in the iroh p2p world
        let endpoint = iroh::Endpoint::builder()
            .secret_key(maybe_secret_key.unwrap_or_else(|| SecretKey::generate(rand::rngs::OsRng)))
            .discovery(iroh::discovery::mdns::MdnsDiscoveryBuilder)
            // .discovery_n0()
            .bind()
            .await?;

        let mut node_addr = endpoint.node_addr();
        let node_id = node_addr.initialized().await.node_id;
        eprintln!("got node_id {node_id}");

        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => incoming,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("got ctrl-c, exiting");
                    break;
                }
            };
            let Some(incoming) = incoming else {
                break;
            };
            let Ok(connecting) = incoming.accept() else {
                break;
            };
            tokio::spawn(async move {
                if let Err(cause) = handle_endpoint_accept(connecting).await {
                    // log error at warn level
                    //
                    // we should know about it, but it's not fatal
                    eprintln!("error handling connection: {}", cause);
                }
            });
        }

        Ok(())
    }

    // Handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(connecting: iroh::endpoint::Connecting) -> anyhow::Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = &connection.remote_node_id()?;
        eprintln!("connection from {remote_node_id}");
        let (_sender, mut reader) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;

        let mut buf = vec![];
        let Some(n_bytes) = reader.read(&mut buf).await? else {
            panic!("got none");
        };

        eprintln!("read {n_bytes}");

        Ok(())
    }
}

pub mod agent {
    use iroh::SecretKey;

    pub async fn run(maybe_secret_key: Option<SecretKey>) -> anyhow::Result<()> {
        // Create an endpoint, it allows creating and accepting
        // connections in the iroh p2p world
        let endpoint = iroh::Endpoint::builder()
            .secret_key(maybe_secret_key.unwrap_or_else(|| SecretKey::generate(rand::rngs::OsRng)))
            .discovery(iroh::discovery::mdns::MdnsDiscoveryBuilder)
            // .discovery_n0()
            .bind()
            .await?;

        Ok(())
    }
}

pub mod facts {
    use std::str::FromStr;

    use anyhow::Context;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Facts {
        pub os: platforms::OS,
        pub os_info: os_info::Info,
        pub mid: mid::MidData,
        pub maybe_facter: Option<String>,
        pub maybe_nixos_facter: Option<String>,
    }

    const MID_SEED: &str = "changing this will cause the hashes to be different";

    impl Facts {
        /// Gathers various facts from the environment.
        pub async fn try_from_environment() -> anyhow::Result<Facts> {
            let os = platforms::OS::from_str(std::env::consts::OS).context("determining OS")?;

            let os_info = os_info::get();
            let mid_data = mid::data(MID_SEED).context("getting machine data")?;

            let maybe_facter = tokio::task::spawn_blocking(|| {
                better_commands::run(&mut std::process::Command::new("facter").arg("--json"))
            })
            .await
            .context("running `facter` from PATH")
            .map_err(|err| println!("{err}"))
            .map(|output| {
                output
                    .stdout()
                    .unwrap_or_default()
                    .iter()
                    .fold(String::new(), |acc, cur| {
                        let cur_string = &cur.content;
                        format!("{acc}{cur_string}\n")
                    })
            })
            .ok();

            let maybe_nixos_facter = tokio::task::spawn_blocking(|| {
                better_commands::run(&mut std::process::Command::new("nixos-facter"))
            })
            .await
            .context("running `nixos-facter` from PATH")
            .map_err(|err| println!("{err}"))
            .map(|output| {
                output
                    .stdout()
                    .unwrap_or_default()
                    .iter()
                    .fold(String::new(), |acc, cur| {
                        let cur_string = &cur.content;
                        format!("{acc}{cur_string}\n")
                    })
            })
            .ok();

            let facts = Facts {
                os,
                os_info,
                mid: mid_data,
                maybe_facter,
                maybe_nixos_facter,
            };

            Ok(facts)
        }
    }
}

pub mod admin {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::util::parse_openssh_ed25519;

    use super::*;

    use anyhow::Context;
    use jsonpath_rust::JsonPath;

    const TEST_KEYS: &[&str] = &[
        r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC6SNWhigagNIURuD746LkA6mU8QwhuVWEzRM3YGS9/bAAAAJiBEB4vgRAe
LwAAAAtzc2gtZWQyNTUxOQAAACC6SNWhigagNIURuD746LkA6mU8QwhuVWEzRM3YGS9/bA
AAAEDWgj234N5fzu7XILYAEnwYyg7TyI9hzVvQw3d7YOjKaLpI1aGKBqA0hRG4PvjouQDq
ZTxDCG5VYTNEzdgZL39sAAAAFHN0ZXZlZWpAc3RldmVlai14MTNzAQ==
-----END OPENSSH PRIVATE KEY-----"#,
        r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCXbwLmxGzVMYkSjXty7Bou7/BQEhMN6+/Hpdq40HRBOQAAAJhJO/n3STv5
9wAAAAtzc2gtZWQyNTUxOQAAACCXbwLmxGzVMYkSjXty7Bou7/BQEhMN6+/Hpdq40HRBOQ
AAAEDCosvbvoBTxMkV5G6lmxrK4zc40ugmgahvKjqMxAPjfZdvAubEbNUxiRKNe3LsGi7v
8FASEw3r78el2rjQdEE5AAAAFHN0ZXZlZWpAc3RldmVlai14MTNzAQ==
-----END OPENSSH PRIVATE KEY-----"#,
    ];

    #[test]
    fn parses_openssh_key() {
        parse_openssh_ed25519(TEST_KEYS[0].as_bytes()).unwrap();
    }

    #[tokio::test]
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
        } else {
            panic!("unsupported target os")
        }
    }

    /// Verify that the agent sends its facts to the coordinator.
    #[ignore = "WIP"]
    #[tokio::test]
    async fn agent_sends_facts_to_coordinator() {
        tokio::select! {
             _coordinator_handle = tokio::spawn(coordinator::run(Some(
                parse_openssh_ed25519(TEST_KEYS[0].as_bytes()).unwrap(),
            ))) => {
            },

           //  agent_handle = tokio::spawn(agent::run(Some(
           //     parse_openssh_ed25519(TEST_KEYS[1].as_bytes()).unwrap(),
           // ))) => {
           // },

           _ = tokio::time::sleep(Duration::from_millis(100)) => {
               panic!("timeout")
           }
        }
    }
}
