pub use iroh;
pub use serde_json;
pub use tokio;

pub mod util {
    use std::str::FromStr;

    use anyhow::Context;
    use iroh::endpoint::Builder;
    use iroh::{PublicKey, RelayMode, SecretKey};
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
    ) -> anyhow::Result<(SecretKey, iroh::Endpoint)> {
        let secret_key = maybe_secret_key.unwrap_or_else(|| SecretKey::generate(&mut rand::rng()));
        let public_key = secret_key.public();

        let mut builder = iroh::Endpoint::builder().secret_key(secret_key.clone());

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
                match iroh::discovery::mdns::MdnsDiscovery::builder()
                    .advertise(true)
                    .build(public_key)
                {
                    Ok(mdns_discovery) => {
                        builder = builder.discovery(mdns_discovery);
                    }
                    Err(e) => tracing::warn!("error enabling mDNS discovery: {e}"),
                };

                if cfg!(not(test)) {
                    builder =
                        builder.discovery(iroh::discovery::dns::DnsDiscovery::n0_dns().build());
                }
            }
            Discoveries::None => {}
        };

        let endpoint = builder.bind().await?;

        match relay_mode {
            Some(RelayMode::Disabled) | None => (),
            Some(_) => {
                tracing::debug!("waiting for network to be online..");
                tokio::time::timeout(tokio::time::Duration::from_secs_f64(5.0), endpoint.online())
                    .await
                    .context(format!("waiting for home relay: {relay_mode:?}"))?;
            }
        }

        Ok((secret_key, endpoint))
    }

    pub fn parse_relay_mode(input: &str) -> anyhow::Result<RelayMode> {
        let cleaned = input.trim().to_lowercase();
        let (variant, remainder) = cleaned.split_once(":").unwrap_or((&cleaned, ""));
        let mode = match variant {
            "disabled" => RelayMode::Disabled,
            "default" => RelayMode::Default,
            "staging" => RelayMode::Staging,
            "custom" => {
                if remainder.is_empty() {
                    anyhow::bail!("custom needs an ip:port specification for a custom relay");
                }

                RelayMode::Disabled

                // TODO: support this later
            }
            other => anyhow::bail!("unsupported relay mode string: {other}"),
        };

        Ok(mode)
    }
}

pub mod protocols;

/// Common types and functions shared between the components.
pub mod common {}

/// This module implements the Coordinator functionality.
/// It's expected to run on machines with high uptime, bandwidth, and reliability; aka servers.
pub mod coordinator {
    use iroh::{protocol::Router, SecretKey};
    use iroh_docs::engine::ProtectCallbackHandler;
    use tracing::info;

    use crate::protocols::{
        echo_hash::{docs::EchoHashDocsApi, native::EchoHashNative, rpc::EchoHashRpcApi},
        enrollment::enrollment_service::{self, EnrollmentServiceApi},
        node_admin::NodeAdmin,
    };

    /// Run the Coordinator.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(
        secret_key: SecretKey,
        endpoint: iroh::Endpoint,
    ) -> anyhow::Result<serde_json::Value> {
        let node_id = endpoint.id();
        let bind_info = endpoint.bound_sockets();
        info!("node_id: {node_id} listening on {bind_info:?}");

        // Enable iroh-docs and its dependencies
        let (protect_callback_handler, protect_callback) = ProtectCallbackHandler::new();
        let blob_store =
            iroh_blobs::store::mem::MemStore::new_with_opts(iroh_blobs::store::mem::Options {
                gc_config: Some(iroh_blobs::store::GcConfig {
                    interval: std::time::Duration::from_millis(100),
                    add_protected: Some(protect_callback),
                }),
            });
        let blobs = iroh_blobs::BlobsProtocol::new(&blob_store, None);
        let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
        let docs = iroh_docs::protocol::Docs::memory()
            .protect_handler(protect_callback_handler)
            .spawn(endpoint.clone(), (*blob_store).clone(), gossip.clone())
            .await?;

        let router_builder = Router::builder(endpoint.clone())
            .accept(EchoHashNative::ALPN, EchoHashNative)
            .accept(EchoHashRpcApi::ALPN, EchoHashRpcApi::spawn().expose()?)
            .accept(NodeAdmin::ALPN, NodeAdmin)
            .accept(
                enrollment_service::ALPN,
                EnrollmentServiceApi::spawn(secret_key.clone(), blobs.clone(), docs.clone())
                    .await?
                    .expose()?,
            );

        let router_builder = router_builder
            .accept(iroh_blobs::ALPN, blobs.clone())
            .accept(iroh_gossip::ALPN, gossip)
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(
                EchoHashDocsApi::ALPN,
                EchoHashDocsApi::spawn(endpoint.clone(), blobs.clone(), docs.clone()).expose()?,
            )
            .accept(
                enrollment_service::ALPN,
                EnrollmentServiceApi::spawn(secret_key, blobs, docs)
                    .await?
                    .expose()?,
            );

        let router = router_builder.spawn();

        tokio::signal::ctrl_c().await?;
        router.shutdown().await?;

        Ok(serde_json::to_value(())?)
    }
}

pub mod agent {
    use iroh::{protocol::Router, SecretKey};
    use iroh_docs::engine::ProtectCallbackHandler;
    use tracing::info;

    use crate::{admin::cli::AgentArgs, protocols::enrollment::enrollment_agent};

    pub async fn run(
        secret_key: SecretKey,
        endpoint: iroh::Endpoint,
        agent_args: AgentArgs,
    ) -> anyhow::Result<serde_json::Value> {
        let node_id = endpoint.id();
        let bind_info = endpoint.bound_sockets();
        info!("node_id: {node_id} listening on {bind_info:?}");

        // Enable iroh-docs and its dependencies
        let (protect_callback_handler, protect_callback) = ProtectCallbackHandler::new();
        let blob_store =
            iroh_blobs::store::mem::MemStore::new_with_opts(iroh_blobs::store::mem::Options {
                gc_config: Some(iroh_blobs::store::GcConfig {
                    interval: std::time::Duration::from_millis(100),
                    add_protected: Some(protect_callback),
                }),
            });
        let blobs = iroh_blobs::BlobsProtocol::new(&blob_store, None);
        let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
        let docs = iroh_docs::protocol::Docs::memory()
            .protect_handler(protect_callback_handler)
            .spawn(endpoint.clone(), (*blob_store).clone(), gossip.clone())
            .await?;

        let router_builder = Router::builder(endpoint.clone())
            .accept(iroh_blobs::ALPN, blobs.clone())
            .accept(iroh_gossip::ALPN, gossip)
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(
                enrollment_agent::ALPN,
                enrollment_agent::EnrollmentAgentApi::spawn(
                    secret_key, endpoint, blobs, docs, agent_args,
                )
                .await?
                .expose()?,
            );

        let router = router_builder.spawn();

        tokio::signal::ctrl_c().await?;
        router.shutdown().await?;

        Ok(serde_json::to_value(())?)
    }
}

pub mod facts {
    use std::str::FromStr;

    use anyhow::Context;
    use better_commands::CmdOutput;
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

            let filter_output_fn = |output: CmdOutput| -> Option<String> {
                match output.clone().status_code() {
                    Some(i) if i.is_negative() => return None,
                    Some(_) | None => (),
                };

                output.stdout().and_then(|lines| {
                    let non_empty_lines = lines
                        .into_iter()
                        .map(|l| l.content.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>();

                    if !non_empty_lines.is_empty() {
                        Some(non_empty_lines.join("\n"))
                    } else {
                        None
                    }
                })
            };

            let maybe_facter = tokio::task::spawn_blocking(|| {
                better_commands::run(
                    std::process::Command::new("facter")
                        .arg("--json")
                        .arg("--no-ruby")
                        .arg("--no-color"),
                )
            })
            .await
            .context("running `facter` from PATH")
            .map(filter_output_fn)
            .inspect_err(|e| tracing::error!("{e}"))
            .ok()
            .flatten();

            let maybe_nixos_facter = tokio::task::spawn_blocking(|| {
                better_commands::run(&mut std::process::Command::new("nixos-facter"))
            })
            .await
            .context("running `nixos-facter` from PATH")
            .map(filter_output_fn)
            .inspect_err(|e| tracing::error!("{e}"))
            .ok()
            .flatten();

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
    use linked_hash_map::LinkedHashMap;

    use crate::{
        admin::cli::AdminArgs,
        protocols::enrollment::enrollment_service::{
            EnrolledServiceSubscribersT, EnrollmentServiceId,
        },
    };

    pub mod cli {
        use clap::{Args, Subcommand};
        use iroh::PublicKey;

        /// Definition for the top-level Agent command
        #[derive(Debug, Clone, Args, Default)]
        #[command(version, about)]
        pub struct AgentArgs {
            /// Pass one or multiple NodeIds that are used as coordinators
            #[arg(long)]
            pub coordinators: Vec<iroh::PublicKey>,

            /// Loop interval for the loop that ensures the subscription to the enrollment service remain intact.
            #[arg(long)]
            pub maybe_subscribe_loop_interval_seconds: Option<f64>,
        }

        /// Definition for the top-level Admin command
        #[derive(Debug, Clone, Args)]
        #[command(version, about)]
        pub struct AdminArgs {
            /// Pass one or multiple NodeIds that are used as coordinators
            #[arg(long)]
            pub coordinators: Vec<PublicKey>,

            /// Timeout duration in seconds for connecting to the remote request, given in floating points.
            // TODO: create an issue on the irpc repo about connections sometimes taking 5 seconds to initiate
            #[arg(long, default_value_t = 6.0f64)]
            pub timeout: f64,

            /// The admin command to call.
            #[command(subcommand)]
            pub cmd: AdminCmd,
        }

        /// All admin subcommands
        #[derive(Debug, Clone, Subcommand)]
        pub enum AdminCmd {
            /// Send a message to the node with the PublicKey
            EchoHash {
                #[command(flatten)]
                args: crate::protocols::echo_hash::EchoHashArgs,
            },

            Ping {
                node_id: PublicKey,
            },

            GetFacts {
                node_id: PublicKey,
            },

            /// Retrieve a list of agents
            ListAgents,
        }
    }

    /// Run the Admin command.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(
        endpoint: iroh::Endpoint,
        admin_args: AdminArgs,
    ) -> anyhow::Result<serde_json::Value> {
        let AdminArgs {
            coordinators,
            timeout,
            cmd,
        } = admin_args;

        let timeout = std::time::Duration::from_secs_f64(timeout);

        let json_value = match cmd {
            cli::AdminCmd::EchoHash { args } => {
                serde_json::to_value(crate::protocols::echo_hash::send(endpoint, args).await?)?
            }

            cli::AdminCmd::Ping { node_id } => {
                let start = tokio::time::Instant::now();
                let client =
                    crate::protocols::enrollment::enrollment_agent::EnrollmentAgentClient::connect(
                        endpoint, node_id,
                    )
                    .await?;
                let time_to_connect = tokio::time::Instant::now() - start;

                let result = client.ping().await?;

                tracing::info!("time to connect: {time_to_connect:?}. ping time {result:#?}");

                serde_json::to_value(())?
            }
            cli::AdminCmd::GetFacts { node_id } => {
                let client =
                    crate::protocols::enrollment::enrollment_agent::EnrollmentAgentClient::connect(
                        endpoint, node_id,
                    )
                    .await?;

                let result = client.get_facts().await?;

                tracing::debug!("response: {result:#?}");

                serde_json::to_value(result)?
            }
            cli::AdminCmd::ListAgents => {
                let mut enrolled_agents: LinkedHashMap<
                    EnrollmentServiceId,
                    EnrolledServiceSubscribersT,
                > = Default::default();
                for coordinator in coordinators {
                    let client = crate::protocols::enrollment::enrollment_service::EnrollmentServiceClient::connect(
                            endpoint.clone(), coordinator, timeout,
                        ).await?;

                    let response = match client.list_subscribers(timeout).await {
                        Ok(response) => response,
                        Err(e) => {
                            tracing::error!("error listing subscribers from {coordinator}: {e}");
                            continue;
                        }
                    };

                    let enrolled_agents_this_coordinator =
                        enrolled_agents.entry(coordinator).or_default();
                    enrolled_agents_this_coordinator.extend(response.into_iter());
                }

                tracing::debug!("agents: {enrolled_agents:#?}");

                let result = enrolled_agents;
                serde_json::to_value(result)?
            }
        };

        Ok(json_value)
    }
}

#[cfg(test)]
pub mod tests;

#[cfg(feature = "test")]
pub mod test_utils;
