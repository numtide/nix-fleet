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

pub mod protocols {
    pub const ALPN_PING_0: &str = "nix-fleet/ping/0";
    pub const ALPN_ENROLL_AGENT_0: &str = "nix-fleet/enroll-agent/0";
}

pub mod coordinator {
    use anyhow::Context;
    use iroh::{SecretKey, Watcher};
    use tokio::io::AsyncReadExt;
    use tracing::debug;
    use tracing::info;
    use tracing::trace;
    use tracing::warn;

    pub async fn run(maybe_secret_key: Option<SecretKey>) -> anyhow::Result<()> {
        // Create an endpoint, it allows creating and accepting
        // connections in the iroh p2p world
        let endpoint = iroh::Endpoint::builder()
            .alpns(vec![crate::protocols::ALPN_PING_0.as_bytes().to_vec()])
            .secret_key(maybe_secret_key.unwrap_or_else(|| SecretKey::generate(rand::rngs::OsRng)))
            .discovery(iroh::discovery::mdns::MdnsDiscoveryBuilder)
            // .discovery_n0()
            .bind()
            .await?;

        let mut node_addr = endpoint.node_addr();
        let node_id = node_addr.initialized().await.node_id;
        debug!("got node_id {node_id}");

        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => incoming,
                _ = tokio::signal::ctrl_c() => {
                    info!("got ctrl-c, exiting");
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
                    warn!("error handling connection: {}", cause);
                }
            });
        }

        Ok(())
    }

    // Handle a new incoming connection on the endpoint
    async fn handle_endpoint_accept(connecting: iroh::endpoint::Connecting) -> anyhow::Result<()> {
        let connection = connecting.await.context("error accepting connection")?;
        let remote_node_id = &connection.remote_node_id()?;
        debug!("connection from {remote_node_id}");

        let (mut tx, mut rx) = connection
            .accept_bi()
            .await
            .context("error accepting stream")?;

        if let Some(alpn) = connection.alpn() {
            let alpn_str = str::from_utf8(&alpn)?;
            debug!("received a connection for {alpn_str} from {remote_node_id}");

            let mut receive_buf = String::new();
            if alpn_str == crate::protocols::ALPN_PING_0 {
                debug!("processing {alpn_str} request");
                let received_length = rx
                    .read_to_string(&mut receive_buf)
                    .await
                    .context("reading from stream")?;
                trace!("read {received_length} bytes: {receive_buf}",);
                receive_buf.truncate(received_length);

                tx.write_all(receive_buf.as_bytes()).await?;
                tx.finish()?;

                // Wait until the remote closes the connection, which it does once it received the response.
                connection.closed().await;
            } else {
                anyhow::bail!("unknown ALPN: {alpn_str}")
            }
        }

        Ok(())
    }
}

pub mod agent {
    use iroh::SecretKey;

    pub async fn run(maybe_secret_key: Option<SecretKey>) -> anyhow::Result<()> {
        // Create an endpoint, it allows creating and accepting
        // connections in the iroh p2p world
        let _endpoint = iroh::Endpoint::builder()
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

pub mod admin {
    use anyhow::Context;
    use iroh::SecretKey;
    use tokio::{io::AsyncReadExt, time::Instant};
    use tracing::{info, trace};

    use crate::{admin::cli::AdminArgs, protocols};

    pub mod cli {
        use clap::{Args, Subcommand};
        use iroh::PublicKey;

        #[derive(Debug, Clone, Args)]
        #[command(version, about)]
        pub struct AdminArgs {
            #[command(subcommand)]
            pub cmd: AdminCmd,
        }

        #[derive(Debug, Clone, Subcommand)]
        pub enum AdminCmd {
            /// Sends a message to the node with the PublicKey
            Ping {
                /// Number of times the message is sent and expected to come back.
                #[arg(short, long, default_value_t = 1)]
                number: usize,

                node_id: PublicKey,

                #[arg(default_value = "ping")]
                msg: String,
            },
        }
    }

    pub async fn run(
        maybe_secret_key: Option<SecretKey>,
        admin_args: AdminArgs,
    ) -> anyhow::Result<()> {
        // Create an endpoint, it allows creating and accepting
        // connections in the iroh p2p world
        let endpoint = iroh::Endpoint::builder()
            .secret_key(maybe_secret_key.unwrap_or_else(|| SecretKey::generate(rand::rngs::OsRng)))
            .discovery(iroh::discovery::mdns::MdnsDiscoveryBuilder)
            // .discovery_n0()
            .bind()
            .await?;

        match admin_args.cmd {
            cli::AdminCmd::Ping {
                node_id,
                msg,
                number,
            } => {
                for i in 0..number {
                    let t_0 = Instant::now();
                    let connection = endpoint
                        .connect(node_id, protocols::ALPN_PING_0.as_bytes())
                        .await
                        .context(format!("connecting to {node_id}"))?;
                    let (mut tx, mut rx) = connection.open_bi().await?;

                    trace!("[{i}] writing {msg} to stream");
                    tx.write_all(msg.as_bytes())
                        .await
                        .context("writing bytes to stream")?;

                    tx.finish()?;

                    let mut received_msg = String::new();

                    tokio::select! {
                        received_length = {
                            trace!("[{i}] waiting for answer on stream");
                            rx.read_to_string(&mut received_msg)
                        } => {
                            let rtt = Instant::now().duration_since(t_0);

                            let received_length = received_length?;
                            received_msg.truncate(received_length);

                            anyhow::ensure!(received_msg == msg, format!("[{i}] mismatch on ping {i}"));

                            info!("[{i}] completed within {rtt:#?}");
                        },

                        _ = tokio::time::sleep(std::time::Duration::from_millis(10000000)) => {
                            anyhow::bail!("timeout");
                        }
                    }

                    connection.close(0u32.into(), b"finished");
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use crate::util::parse_openssh_ed25519;

    use super::*;

    use anyhow::Context;
    use jsonpath_rust::JsonPath;

    struct TestKeyTuple {
        openssh_key: &'static str,
        pubkey: &'static str,
    }

    // List of tuples of (Open SSH private keys, NodeId)
    const TEST_KEYS: &[TestKeyTuple] = &[
        TestKeyTuple {
            openssh_key: r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC6SNWhigagNIURuD746LkA6mU8QwhuVWEzRM3YGS9/bAAAAJiBEB4vgRAe
LwAAAAtzc2gtZWQyNTUxOQAAACC6SNWhigagNIURuD746LkA6mU8QwhuVWEzRM3YGS9/bA
AAAEDWgj234N5fzu7XILYAEnwYyg7TyI9hzVvQw3d7YOjKaLpI1aGKBqA0hRG4PvjouQDq
ZTxDCG5VYTNEzdgZL39sAAAAFHN0ZXZlZWpAc3RldmVlai14MTNzAQ==
-----END OPENSSH PRIVATE KEY-----"#,
            pubkey: "ba48d5a18a06a0348511b83ef8e8b900ea653c43086e55613344cdd8192f7f6c",
        },
        TestKeyTuple {
            openssh_key: r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCXbwLmxGzVMYkSjXty7Bou7/BQEhMN6+/Hpdq40HRBOQAAAJhJO/n3STv5
9wAAAAtzc2gtZWQyNTUxOQAAACCXbwLmxGzVMYkSjXty7Bou7/BQEhMN6+/Hpdq40HRBOQ
AAAEDCosvbvoBTxMkV5G6lmxrK4zc40ugmgahvKjqMxAPjfZdvAubEbNUxiRKNe3LsGi7v
8FASEw3r78el2rjQdEE5AAAAFHN0ZXZlZWpAc3RldmVlai14MTNzAQ==
-----END OPENSSH PRIVATE KEY-----"#,
            pubkey: "976f02e6c46cd53189128d7b72ec1a2eeff05012130debefc7a5dab8d0744139",
        },
        TestKeyTuple {
            openssh_key: r#"-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACB75UY6q5sfBEarcNvIg+D9Ky2gpqKoHcMGHlwlzkxOlAAAAJjwfFvc8Hxb
3AAAAAtzc2gtZWQyNTUxOQAAACB75UY6q5sfBEarcNvIg+D9Ky2gpqKoHcMGHlwlzkxOlA
AAAEBQf7R1sd08u0eHCFYyw7Pd6NZKTtXjRhxG+K+FI6eeQ3vlRjqrmx8ERqtw28iD4P0r
LaCmoqgdwwYeXCXOTE6UAAAAFHN0ZXZlZWpAc3RldmVlai14MTNzAQ==
-----END OPENSSH PRIVATE KEY-----"#,
            pubkey: "7be5463aab9b1f0446ab70dbc883e0fd2b2da0a6a2a81dc3061e5c25ce4c4e94",
        },
    ];

    #[test]
    fn parses_openssh_key() {
        for TestKeyTuple {
            openssh_key,
            pubkey,
        } in TEST_KEYS
        {
            let secret = parse_openssh_ed25519(openssh_key.as_bytes()).unwrap();

            assert_eq!(&secret.public().to_string(), pubkey);
        }
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
                parse_openssh_ed25519(TEST_KEYS[0].openssh_key.as_bytes()).unwrap(),
            ))) => {
            },

           //  agent_handle = tokio::spawn(agent::run(Some(
           //     parse_openssh_ed25519(TEST_KEYS[1].0.as_bytes()).unwrap(),
           // ))) => {
           // },

           _ = tokio::time::sleep(Duration::from_millis(100)) => {
               panic!("timeout")
           }
        }
    }
}
