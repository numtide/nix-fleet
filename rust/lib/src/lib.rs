pub use iroh;
pub use tokio;

pub mod util {
    use std::str::FromStr;

    use anyhow::Context;
    use iroh::endpoint::Builder;
    use iroh::{discovery::ConcurrentDiscovery, PublicKey, SecretKey};
    use url::Url;

    // Reference code in iroh-node-util showing SSH key handling: https://github.com/n0-computer/iroh-node-util/blob/3e9702ad215b9b986c6d45e4762a8fbe241163b0/src/fs.rs#L11
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

    #[derive(Debug, Clone, Default)]
    pub enum Discoveries {
        None,
        #[default]
        Default,
        Custom {
            secret_key: Box<SecretKey>,
            url: Box<Url>,
        },
    }

    pub async fn get_endpoint(
        maybe_secret_key: Option<SecretKey>,
        relay_mode: Option<iroh::RelayMode>,
        discoveries: Discoveries,
    ) -> anyhow::Result<iroh::Endpoint> {
        let secret_key = maybe_secret_key.unwrap_or_else(|| SecretKey::generate(&mut rand::rng()));
        let public_key = secret_key.public();

        let mut builder = iroh::Endpoint::builder().secret_key(secret_key);

        if let Some(relay_mode) = &relay_mode {
            builder = builder.relay_mode(relay_mode.clone());

            // TODO: Fix HTTP relay in tests (buggy HTTPS probes against HTTP server)
            #[cfg(any(test, feature = "test"))]
            fn maybe_insecure_skip_relay_cert_verify(builder: Builder) -> Builder {
                builder.insecure_skip_relay_cert_verify(true)
            }

            #[cfg(not(any(test, feature = "test")))]
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

                builder = builder.discovery(
                    iroh::discovery::pkarr::PkarrPublisher::builder(pkarr_url.clone())
                        .build(*secret_key),
                );

                builder = builder.discovery(
                    iroh::discovery::pkarr::PkarrResolver::builder(pkarr_url.clone()).build(),
                );
            }
            Discoveries::Default => {
                let concurrent = ConcurrentDiscovery::empty();

                match iroh::discovery::mdns::MdnsDiscovery::builder()
                    .advertise(true)
                    .build(public_key)
                {
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
            tokio::time::timeout(tokio::time::Duration::from_millis(500), endpoint.online())
                .await
                .context(format!("waiting for home relay: {relay_mode:?}"))?;
        }

        Ok(endpoint)
    }

    /// Spawn a server suitable for testing, while optionally enabling mainline with custom
    /// bootstrap addresses.
    #[cfg(any(test, feature = "test"))]
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

pub mod protocols;

/// This module implements the Coordinator functionality.
/// It's expected to run on machines with high uptime, bandwidth, and reliability; aka servers.
pub mod coordinator {
    use iroh::protocol::Router;
    use tracing::info;

    use crate::protocols::{
        echo::{Echo, EchoRpcApi},
        enrollment::Enrollment,
        node_admin::NodeAdmin,
    };

    /// Run the Coordinator.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(endpoint: iroh::Endpoint) -> anyhow::Result<()> {
        let node_id = endpoint.id();
        let bind_info = endpoint.bound_sockets();
        info!("node_id: {node_id}; listening on {bind_info:?}");

        let router = Router::builder(endpoint)
            .accept(Echo::ALPN, Echo)
            .accept(EchoRpcApi::ALPN, EchoRpcApi::spawn().expose()?)
            .accept(NodeAdmin::ALPN, NodeAdmin)
            .accept(Enrollment::ALPN, Enrollment)
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
    use crate::admin::cli::AdminArgs;

    pub mod cli {
        use clap::{Args, Subcommand};

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
                #[command(flatten)]
                args: crate::protocols::echo::EchoArgs,
            },

            /// Retrieve a list of agents
            ListAgents {},
        }
    }

    /// Run the Admin command.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(endpoint: iroh::Endpoint, admin_args: AdminArgs) -> anyhow::Result<()> {
        match admin_args.cmd {
            cli::AdminCmd::Echo { args } => {
                let echo = crate::protocols::echo::Echo;

                echo.send(endpoint, args).await?;
            }
            cli::AdminCmd::ListAgents { .. } => {
                todo!("")
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod tests;
