pub use iroh;
pub use tokio;

pub mod util {
    use std::str::FromStr;

    use anyhow::Context;
    use iroh::endpoint::Builder;
    use iroh::{discovery::ConcurrentDiscovery, PublicKey, SecretKey, Watcher};
    use tokio::time;
    use url::Url;

    pub fn parse_openssh_ed25519_private(mut r: impl std::io::Read) -> anyhow::Result<SecretKey> {
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
            .context(format!("decoding '{bytes:.3}..' ({} bytes)", bytes.len()))?;

        Ok(parsed)
    }

    pub fn parse_openssh_ed25519_public(mut r: impl std::io::Read) -> anyhow::Result<PublicKey> {
        let mut raw = String::new();
        r.read_to_string(&mut raw)?;

        let ssh_public_key: ssh_key::PublicKey = ssh_key::PublicKey::from_openssh(&raw)
            .context(format!("converting {raw} to ssh_key::PublicKey"))?;

        let ssh_public_key_ed25519 = ssh_public_key
            .key_data()
            .ed25519()
            .ok_or_else(|| anyhow::anyhow!("not a ed25519 public key"))?;

        Ok(PublicKey::from_bytes(&ssh_public_key_ed25519.0)?)
    }

    #[derive(Debug, Clone)]
    pub enum Discoveries {
        None,
        Default,
        Custom {
            secret_key: Box<SecretKey>,
            url: Box<Url>,
        },
    }

    impl Default for Discoveries {
        fn default() -> Self {
            Self::Default
        }
    }

    pub async fn get_endpoint(
        maybe_secret_key: Option<SecretKey>,
        relay_mode: Option<iroh::RelayMode>,
        discoveries: Discoveries,
    ) -> anyhow::Result<iroh::Endpoint> {
        let secret_key = maybe_secret_key.unwrap_or_else(|| SecretKey::generate(rand::rngs::OsRng));
        let public_key = secret_key.public();

        let mut builder = iroh::Endpoint::builder().secret_key(secret_key);

        if let Some(relay_mode) = &relay_mode {
            builder = builder.relay_mode(relay_mode.clone());

            // TODO: pursue a solution that works via HTTP relay in tests, which currently seems to be buggy
            // and uses HTTPS for probes against an HTTP server:
            // > 2025-10-07T19:29:17.665164Z DEBUG echo_completes:ep{me=3d4e9e47cb}:actor:reportgen.actor:run-probe{proto=Https delay=200ms relay_node=RelayNode { url: RelayUrl("http://127.0.0.1:45569/"), quic: None }}: iroh::net_report::reportgen: starting probe
            #[cfg(test)]
            fn maybe_insecure_skip_relay_cert_verify(builder: Builder) -> Builder {
                builder.insecure_skip_relay_cert_verify(true)
            }
            #[cfg(not(test))]
            fn maybe_insecure_skip_relay_cert_verify(builder: Builder) -> Builder {
                builder
            }

            builder = maybe_insecure_skip_relay_cert_verify(builder);
        } else {
            builder = builder.relay_mode(iroh::RelayMode::Disabled);
        }

        match discoveries {
            Discoveries::Custom { secret_key, url } => {
                let pkarr_url = url.join("/pkarr")?;

                builder = builder.add_discovery(
                    iroh::discovery::pkarr::PkarrPublisher::builder(pkarr_url.clone())
                        .build(*secret_key),
                );

                builder = builder.add_discovery(
                    iroh::discovery::pkarr::PkarrResolver::builder(pkarr_url.clone()).build(),
                );
            }
            Discoveries::Default => {
                let mut concurrent = ConcurrentDiscovery::empty();

                match iroh::discovery::mdns::MdnsDiscovery::new(public_key, true) {
                    Ok(mdns_discovery) => {
                        concurrent.add(mdns_discovery);
                    }
                    Err(e) => tracing::warn!("error enabling mDNS discovery: {e}"),
                };

                #[cfg(not(test))]
                concurrent.add(iroh::discovery::dns::DnsDiscovery::n0_dns().build());

                builder = builder.discovery(concurrent);
            }
            Discoveries::None => {}
        };

        let endpoint = builder.bind().await?;

        if let Some(relay_mode) = relay_mode {
            tokio::time::timeout(
                time::Duration::from_millis(500),
                endpoint.home_relay().initialized(),
            )
            .await
            .context(format!("waiting for home relay: {relay_mode:?}"))?;

            // TODO:
            // Endpoint::direct_addresses t
        }

        Ok(endpoint)
    }

    /// Spawn a server suitable for testing, while optionally enabling mainline with custom
    /// bootstrap addresses.
    #[cfg(test)]
    pub async fn iroh_dns_spawn_for_tests_with_options() -> anyhow::Result<(
        iroh_dns_server::http::HttpServer,
        url::Url,
        iroh_dns_server::dns::DnsServer,
        std::net::SocketAddr,
    )> {
        use std::net::{IpAddr, Ipv4Addr};

        let mut config = iroh_dns_server::config::Config::default();
        config.dns.port = 0;
        config.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.http.as_mut().unwrap().port = 0;
        config.http.as_mut().unwrap().bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
        config.https = None;
        config.metrics = Some(iroh_dns_server::config::MetricsConfig::disabled());

        let store = iroh_dns_server::ZoneStore::in_memory(Default::default(), Default::default())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let dns_handler =
            iroh_dns_server::dns::DnsHandler::new(store.clone(), &config.dns, Default::default())
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let state = iroh_dns_server::state::AppState {
            store,
            dns_handler,
            metrics: Default::default(),
        };

        let http_server = iroh_dns_server::http::HttpServer::spawn(
            config.http,
            config.https,
            config.pkarr_put_rate_limit,
            state.clone(),
        )
        .await
        .unwrap();

        let dns_server =
            iroh_dns_server::dns::DnsServer::spawn(config.dns, state.dns_handler.clone())
                .await
                .map_err(|e| anyhow::anyhow!(e.to_string()))?;

        let dns_addr = dns_server.local_addr();
        let http_addr = http_server.http_addr().expect("http is set");
        let http_url = format!("http://{http_addr}").parse::<url::Url>()?;
        Ok((http_server, http_url, dns_server, dns_addr))
    }
}

/// Protocol logic used on top of iroh
pub mod protocols {

    /// A simple protocol that will echo back the data to the sender.
    pub mod echo {

        use iroh::protocol::{AcceptError, ProtocolHandler};
        use tracing::debug;

        #[derive(Debug)]
        pub struct Echo;

        impl Echo {
            pub const ALPN: &[u8] = b"nix-fleet/echo/0";
        }

        impl Echo {
            pub fn send() -> anyhow::Result<()> {
                todo!("move the admin code here")
            }
        }

        impl ProtocolHandler for Echo {
            async fn accept(
                &self,
                connection: iroh::endpoint::Connection,
            ) -> Result<(), AcceptError> {
                let remote_node_id = connection.remote_node_id()?;
                debug!("accepted connection from {remote_node_id}");

                let (mut tx, mut rx) = connection.accept_bi().await?;

                let num_bytes_copied = tokio::io::copy(&mut rx, &mut tx).await?;

                debug!("copied {num_bytes_copied} bytes");

                tx.finish()?;

                connection.closed().await;

                Ok(())
            }
        }
    }

    pub mod node_admin {

        use iroh::protocol::{AcceptError, ProtocolHandler};

        #[derive(Debug)]
        pub struct NodeAdmin;

        impl NodeAdmin {
            pub const ALPN: &[u8] = b"nix-fleet/node-admin/0";
        }

        impl ProtocolHandler for NodeAdmin {
            async fn accept(
                &self,
                _connection: iroh::endpoint::Connection,
            ) -> Result<(), AcceptError> {
                Err(AcceptError::User {
                    source: "todo".into(),
                })
            }
        }
    }

    pub mod enroll_agent {

        use iroh::protocol::{AcceptError, ProtocolHandler};

        #[derive(Debug)]
        pub struct EnrollAgent;

        impl EnrollAgent {
            pub const ALPN: &[u8] = b"nix-fleet/enroll-agent/0";
        }

        impl ProtocolHandler for EnrollAgent {
            async fn accept(
                &self,
                _connection: iroh::endpoint::Connection,
            ) -> Result<(), AcceptError> {
                Err(AcceptError::User {
                    source: "todo".into(),
                })
            }
        }
    }
}

/// This module implements the Coordinator functionality.
/// It's expected to run on machines with high uptime, bandwidth, and reliability; aka servers.
pub mod coordinator {
    use iroh::{protocol::Router, Watcher};
    use tracing::info;

    use crate::protocols::{echo::Echo, enroll_agent::EnrollAgent, node_admin::NodeAdmin};

    /// Run the Coordinator.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(endpoint: iroh::Endpoint) -> anyhow::Result<()> {
        let mut node_addr = endpoint.node_addr();
        let node_id = node_addr.initialized().await.node_id;
        let bind_info = endpoint.bound_sockets();
        info!("node_id: {node_id}; listening on {bind_info:?}");

        let router = Router::builder(endpoint)
            .accept(Echo::ALPN, Echo)
            .accept(NodeAdmin::ALPN, NodeAdmin)
            .accept(EnrollAgent::ALPN, EnrollAgent)
            .spawn();

        tokio::signal::ctrl_c().await?;
        router.shutdown().await?;

        Ok(())
    }
}

pub mod agent {
    use iroh::{protocol::Router, PublicKey};

    use crate::protocols::{echo::Echo, node_admin::NodeAdmin};

    pub async fn run(
        endpoint: iroh::Endpoint,
        _coordinators: Box<[PublicKey]>,
    ) -> anyhow::Result<()> {
        let router = Router::builder(endpoint)
            .accept(Echo::ALPN, Echo)
            .accept(NodeAdmin::ALPN, NodeAdmin)
            .spawn();

        tokio::signal::ctrl_c().await?;
        router.shutdown().await?;

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
        pub mid: Option<mid::MidData>,
        pub maybe_facter: Option<String>,
        pub maybe_nixos_facter: Option<String>,
    }

    const MID_SEED: &str = "changing this will cause the hashes to be different";

    impl Facts {
        /// Gathers various facts from the environment.
        pub async fn try_from_environment() -> anyhow::Result<Facts> {
            let os = platforms::OS::from_str(std::env::consts::OS).context("determining OS")?;

            let os_info = os_info::get();
            let mid_data = mid::data(MID_SEED)
                .map_err(|e| tracing::warn!("couldn't get machine machine data: {e}"))
                .ok();

            let maybe_facter = tokio::task::spawn_blocking(|| {
                better_commands::run(std::process::Command::new("facter").arg("--json"))
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
    use std::sync::Arc;

    use anyhow::Context;
    use tokio::time::Instant;
    use tracing::{info, trace};

    use crate::{admin::cli::AdminArgs, protocols};

    pub mod cli {
        use clap::{Args, Subcommand};
        use iroh::PublicKey;

        /// Definition for the top-level Agent command
        #[derive(Debug, Clone, Args)]
        #[command(version, about)]
        pub struct AgentArgs {
            /// Pass one or multiple NodeIds that are used as coordinators
            #[arg(long)]
            pub coordinators: Vec<iroh::PublicKey>,
        }

        /// Definition for the top-level Admin command
        #[derive(Debug, Clone, Args)]
        #[command(version, about)]
        pub struct AdminArgs {
            /// Pass one or multiple NodeIds that are used as coordinators
            #[arg(long)]
            pub coordinators: Vec<String>,

            /// The admin command to call.
            #[command(subcommand)]
            pub cmd: AdminCmd,
        }

        /// All admin subcommands
        #[derive(Debug, Clone, Subcommand)]
        pub enum AdminCmd {
            /// Send a message to the node with the PublicKey
            Echo {
                /// Number of times the message is sent and expected to come back.
                #[arg(short, long, default_value_t = 1)]
                number: usize,

                /// The NodeId to send the message to.
                node_id: PublicKey,

                /// Effective message size in bytes, achieved by repeating the `msg`'s content.
                #[arg(long, default_value_t = 1024)]
                size: usize,

                /// Timeout in seconds for each echo round.
                #[arg(long, default_value_t = 0.1)]
                timeout: f64,

                /// The message that will be sent
                #[arg(default_value = "nix-fleet")]
                msg: String,
            },

            /// Retrieve a list of agents
            ListAgents {
                /// Only list unassigned agents
                only_unassigned: bool,
            },
        }
    }

    /// Run the Admin command.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(endpoint: iroh::Endpoint, admin_args: AdminArgs) -> anyhow::Result<()> {
        match admin_args.cmd {
            cli::AdminCmd::Echo {
                node_id,
                msg,
                number,
                size,
                timeout,
            } => {
                let connection = endpoint
                    .connect(node_id, protocols::echo::Echo::ALPN)
                    .await
                    .context(format!("connecting to {node_id}"))?;

                let mut msg = msg.repeat(size / msg.len() + (size % msg.len()));
                msg.truncate(size);
                let msg = msg;

                let msg_hash = blake3::Hasher::new()
                    .update(msg.as_bytes())
                    .finalize()
                    .to_string();

                let msg = std::sync::Arc::new(msg);

                let (tx, mut rx) = connection.open_bi().await?;

                let tx = std::sync::Arc::new(tokio::sync::Mutex::new(tx));

                for i in 0..number {
                    let t_0 = Instant::now();

                    trace!("[{i}] writing ({:e} bytes) to stream", msg.len());

                    // The protocol requires the sender to start receiving back immediately or else it will stall.
                    tokio::spawn({
                        let msg = std::sync::Arc::clone(&msg);

                        let tx = Arc::clone(&tx);

                        async move {
                            let mut tx_locked = tx.lock().await;

                            tx_locked
                                .write_all(msg.as_bytes())
                                .await
                                .context(format!("writing {} bytes to stream", msg.len()))?;

                            trace!("[{i}] wrote ({:e} bytes) to stream", msg.len());

                            anyhow::Ok(())
                        }
                    });

                    let mut reader_future = async || {
                        let mut len = 0;

                        let mut hasher = blake3::Hasher::new();

                        while let Some(chunk) = rx.read_chunk(1024 * 1024, true).await? {
                            len += chunk.bytes.len();
                            hasher.update(&chunk.bytes);

                            if len == msg.len() {
                                break;
                            }
                        }

                        let hash = hasher.finalize().to_string();

                        anyhow::Ok((hash, len))
                    };

                    trace!("[{i}] waiting for an answer..");
                    tokio::select! {
                        read_result = reader_future() => {
                            let (hash, len) = read_result?;

                            trace!("read {len} bytes from stream");

                            let rtt = Instant::now().duration_since(t_0);

                            anyhow::ensure!(msg_hash == hash, format!("[{i}] hash mismatch"));

                            // The data is sent once in each direction
                            let b_s =
                                2. * msg.len() as f64
                                /
                                (rtt.as_secs_f64() * 1024. * 1024.)
                                ;

                            info!("[{i}] completed within {rtt:#?} at {b_s:.4} MiB/s" );
                        },

                        _ = tokio::time::sleep(std::time::Duration::from_secs_f64(timeout)) => {
                            anyhow::bail!("timeout");
                        }
                    }
                }

                connection.close(0u32.into(), b"finished");
            }
            cli::AdminCmd::ListAgents { .. } => {
                todo!("")
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use crate::{
        admin::cli::{AdminArgs, AdminCmd},
        util::{get_endpoint, parse_openssh_ed25519_private, Discoveries},
    };

    use super::*;

    use anyhow::Context;
    use iroh::{NodeId, RelayMode, SecretKey};
    use jsonpath_rust::JsonPath;
    use rand::rngs::OsRng;
    use tracing_test::traced_test;

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
            let secret = parse_openssh_ed25519_private(openssh_key.as_bytes()).unwrap();
            assert_eq!(&secret.public().to_string(), pubkey);

            let y_coordinate =
                util::parse_openssh_ed25519_public(openssh_pubkey.as_bytes()).unwrap();
            let nodeid = NodeId::from_str(pubkey).unwrap();
            assert_eq!(nodeid, y_coordinate);
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn echo_completes() {
        // run a local relay server
        let relay_server =
            iroh_relay::server::Server::spawn(iroh_relay::server::testing::server_config())
                .await
                .unwrap();
        // TODO: switch to http and remove the insecure tls verification workaround
        let relay_url = relay_server.https_url().unwrap();
        // TODO: why doesn't relay_url.into() not work here? i.e. the test fails with that
        let relay_map: iroh::RelayMap = iroh::RelayNode {
            url: relay_url,
            quic: None,
        }
        .into();
        let relay_mode = Some(RelayMode::Custom(relay_map.clone()));

        let (_iroh_dns_http_server, iroh_dns_http_url, _iroh_dns_server, iroh_dns_url) =
            util::iroh_dns_spawn_for_tests_with_options().await.unwrap();

        tracing::info!("test servers running:\nrelay: {relay_map}\niroh_dns_http: {iroh_dns_http_url}\niroh_dns: {iroh_dns_url}");

        // coordinator
        let coordinator_key = iroh::SecretKey::generate(OsRng);
        let coordinator_pubkey = coordinator_key.public();
        let coordinator_endpoint = get_endpoint(
            Some(coordinator_key.clone()),
            relay_mode.clone(),
            util::Discoveries::Custom {
                secret_key: Box::new(coordinator_key),
                url: iroh_dns_http_url.clone().into(),
            },
        )
        .await
        .unwrap();
        let _coordinator_handle = tokio::spawn(coordinator::run(coordinator_endpoint));

        // admin
        let admin_key = iroh::SecretKey::generate(OsRng);
        let _admin_pubkey = admin_key.public();
        let admin_endpoint = get_endpoint(
            Some(admin_key.clone()),
            relay_mode.clone(),
            util::Discoveries::Custom {
                secret_key: admin_key.into(),
                url: iroh_dns_http_url.clone().into(),
            },
        )
        .await
        .unwrap();
        tokio::spawn(admin::run(
            admin_endpoint,
            AdminArgs {
                cmd: AdminCmd::Echo {
                    number: 10,
                    node_id: coordinator_pubkey,
                    msg: "hello".to_string(),
                    size: 1,
                    timeout: 0.1,
                },
                coordinators: vec![],
            },
        ))
        .await
        .unwrap()
        .unwrap();
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
        } else if cfg!(target_os = "macos") {
            assert_eq!(facts.os, platforms::OS::MacOS);
            let facter = facts.maybe_facter.unwrap();

            let js = serde_json::from_str::<serde_json::Value>(&facter)
                .context(format!("parsing {facter}"))
                .unwrap();

            let maybe_kernel = js.query("$.kernel").unwrap().first().unwrap().as_str();
            assert_eq!(maybe_kernel, Some("Darwin"), "{facter}");
        } else {
            tracing::warn!("unsupported target os")
        }
    }

    /// Verify that the agent sends its facts to the coordinator.
    #[ignore = "WIP"]
    #[tokio::test]
    async fn admin_can_list_agents_via_coordinator() {
        let coordinator_key = SecretKey::generate(OsRng);
        let coordinator_pubkey = coordinator_key.public();
        let admin_key = SecretKey::generate(OsRng);
        let _admin_pubkey = admin_key.public();
        let agent_key = SecretKey::generate(OsRng);
        let _agent_pubkey = agent_key.public();

        // Spawn the coordinator
        tokio::spawn(coordinator::run(
            get_endpoint(Some(coordinator_key), None, Discoveries::default())
                .await
                .unwrap(),
        ));

        // Spawn an agent that will talk to the coordinator
        tokio::spawn(agent::run(
            get_endpoint(Some(agent_key), None, Discoveries::default())
                .await
                .unwrap(),
            // TODO
            [coordinator_pubkey].into(),
        ));

        {
            //
            // Define all the futures in a scope and then pass them concisely to select.
            // This circumvents rustfmt not formatting code inside the select! macro.
            //

            let admin_future = admin::run(
                get_endpoint(Some(admin_key), None, Discoveries::default())
                    .await
                    .unwrap(),
                AdminArgs {
                    cmd: AdminCmd::ListAgents {
                        only_unassigned: false,
                    },
                    coordinators: Default::default(),
                },
            );

            let timeout_future = tokio::time::sleep(Duration::from_millis(100));

            tokio::select! {
               _ = admin_future => {
                   // Query coordinator for a list of agents
                   // assert the list contains the expected agent

                   todo!("")
               },
               _ = timeout_future => { panic!("timeout") },
            }
        };
    }
}
