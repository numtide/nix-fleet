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

    pub fn generate_secret_key() -> SecretKey {
        SecretKey::generate(&mut rand::rng())
    }

    pub async fn get_endpoint(
        secret_key: SecretKey,
        relay_mode: Option<iroh::RelayMode>,
        discoveries: Discoveries,
    ) -> anyhow::Result<iroh::Endpoint> {
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

        builder = builder.clear_discovery();
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
                tracing::debug!("network is online!");
            }
        }

        Ok(endpoint)
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
    use anyhow::Context;
    use iroh::{
        protocol::{DynProtocolHandler, Router},
        SecretKey,
    };
    use iroh_docs::engine::ProtectCallbackHandler;
    use tokio::sync::mpsc::UnboundedReceiver;
    use tracing::info;

    use crate::{
        admin::cli::{CoordinatorArgs, PersistenceMode},
        protocols::{
            echo_hash::{docs::EchoHashDocsApi, native::EchoHashNative, rpc::EchoHashRpcApi},
            enrollment::enrollment_service::{self, EnrollmentServiceApi},
        },
    };

    /// Run the Coordinator.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(
        secret_key: SecretKey,
        endpoint: iroh::Endpoint,
        coordinator_args: CoordinatorArgs,
        maybe_shutdown_rx: Option<UnboundedReceiver<()>>,
    ) -> anyhow::Result<serde_json::Value> {
        let node_id = endpoint.id();
        let bind_info = endpoint.bound_sockets();
        info!("node_id: {node_id} listening on {bind_info:?}");

        // Enable iroh-docs and its dependencies
        let (protect_callback_handler, protect_callback) = ProtectCallbackHandler::new();
        let blob_store = {
            let gc_config = Some(iroh_blobs::store::GcConfig {
                interval: std::time::Duration::from_mins(10),
                add_protected: Some(protect_callback),
            });

            match &coordinator_args.persistence_mode {
                PersistenceMode::Memory => {
                    let memstore = iroh_blobs::store::mem::MemStore::new_with_opts(
                        iroh_blobs::store::mem::Options { gc_config },
                    );

                    iroh_blobs::api::Store::from(memstore)
                }
                PersistenceMode::Filesystem(path_buf) => {
                    let path_buf = path_buf.join("blob_store");
                    std::fs::DirBuilder::new()
                        .recursive(true)
                        .create(&path_buf)?;
                    let fsstore = iroh_blobs::store::fs::FsStore::load_with_opts(
                        path_buf.join("blob_fsstore.db"),
                        iroh_blobs::store::fs::options::Options {
                            path: iroh_blobs::store::fs::options::PathOptions::new(&path_buf),
                            gc: gc_config,
                            inline: Default::default(),
                            batch: Default::default(),
                        },
                    )
                    .await
                    .context(format!("creating FsStore at {path_buf:?}"))?;

                    iroh_blobs::api::Store::from(fsstore)
                }
            }
        };
        let blobs = iroh_blobs::BlobsProtocol::new(&blob_store, None);
        let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
        let docs = match &coordinator_args.persistence_mode {
            PersistenceMode::Memory => iroh_docs::protocol::Docs::memory(),
            PersistenceMode::Filesystem(path_buf) => {
                let path_buf = path_buf.join("docs_store");
                std::fs::DirBuilder::new()
                    .recursive(true)
                    .create(&path_buf)?;

                iroh_docs::protocol::Docs::persistent(path_buf.clone())
            }
        }
        .protect_handler(protect_callback_handler)
        .spawn(endpoint.clone(), blob_store.clone(), gossip.clone())
        .await?;
        tracing::debug!("spawned iroh-docs and dependencies.");

        let router_builder = Router::builder(endpoint.clone())
            .accept(EchoHashNative::ALPN, EchoHashNative)
            .accept(EchoHashRpcApi::ALPN, EchoHashRpcApi::spawn().expose()?)
            .accept(
                EchoHashDocsApi::ALPN,
                EchoHashDocsApi::spawn(endpoint.clone(), blobs.clone(), docs.clone()).expose()?,
            )
            .accept(
                enrollment_service::ALPN,
                EnrollmentServiceApi::spawn(secret_key.clone(), blobs.clone(), docs.clone())
                    .await?
                    .expose()?,
            );
        tracing::debug!("spawned EnrollmentServiceApi");

        let router = router_builder.spawn();

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received CTRL+C signal.");
            }

            _ = async move {
                if let Some(mut rx) = maybe_shutdown_rx {
                    rx.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                tracing::info!("received shutdown message");
            }
        }

        tracing::info!("initiating shutdown...");
        let _ = docs.shutdown().await;
        let _ = gossip.shutdown().await;
        let _ = blobs.shutdown().await;
        let _ = blob_store.shutdown().await;
        let _ = router.shutdown().await;
        tracing::info!("shutdown complete, bye!");

        Ok(().into())
    }
}

pub mod agent {
    use iroh::{
        protocol::{DynProtocolHandler, Router},
        SecretKey,
    };
    use iroh_docs::engine::ProtectCallbackHandler;
    use tokio::sync::mpsc::UnboundedReceiver;
    use tracing::info;

    use crate::{admin::cli::AgentArgs, protocols::enrollment::enrollment_agent};

    pub async fn run(
        secret_key: SecretKey,
        endpoint: iroh::Endpoint,
        agent_args: AgentArgs,
        maybe_shutdown_rx: Option<UnboundedReceiver<()>>,
    ) -> anyhow::Result<serde_json::Value> {
        let node_id = endpoint.id();
        let bind_info = endpoint.bound_sockets();
        info!("node_id: {node_id} listening on {bind_info:?}");

        // Enable iroh-docs and its dependencies
        let (protect_callback_handler, protect_callback) = ProtectCallbackHandler::new();
        let blob_store =
            iroh_blobs::store::mem::MemStore::new_with_opts(iroh_blobs::store::mem::Options {
                gc_config: Some(iroh_blobs::store::GcConfig {
                    interval: std::time::Duration::from_mins(10),
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
            .accept(iroh_gossip::ALPN, gossip.clone())
            .accept(iroh_docs::ALPN, docs.clone())
            .accept(
                enrollment_agent::ALPN,
                enrollment_agent::EnrollmentAgentApi::spawn(
                    secret_key,
                    endpoint,
                    blobs.clone(),
                    docs.clone(),
                    agent_args,
                )
                .await?
                .expose()?,
            );

        let router = router_builder.spawn();

        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received CTRL+C signal.");
            }

            _ = async move {
                if let Some(mut rx) = maybe_shutdown_rx {
                    rx.recv().await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => {
                tracing::info!("received shutdown message");
            }
        }

        tracing::info!("initiating shutdown...");
        let _ = docs.shutdown().await;
        let _ = gossip.shutdown().await;
        let _ = blobs.shutdown().await;
        let _ = blob_store.shutdown().await;
        let _ = router.shutdown().await;
        tracing::info!("shutdown complete, bye!");

        Ok(Default::default())
    }
}

pub mod facts {
    use std::str::FromStr;

    use anyhow::Context;
    use better_commands::CmdOutput;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Serialize, Deserialize, PartialEq)]
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

    use crate::admin::cli::AdminArgs;

    pub mod cli {
        use clap::{Args, Subcommand};
        use iroh::PublicKey;

        /// Definition for the top-level Admin command
        #[derive(Debug, Clone, Default, strum::EnumString, strum::Display)]
        pub enum PersistenceMode {
            #[default]
            Memory,
            Filesystem(std::path::PathBuf),
        }

        /// Definition for the top-level Admin command
        #[derive(Debug, Clone, Args, Default)]
        #[command(version, about)]
        pub struct CoordinatorArgs {
            /// Persistence for the local document storage.
            #[arg(long, default_value_t = PersistenceMode::default())]
            pub persistence_mode: PersistenceMode,
        }

        /// Definition for the top-level Agent command
        #[derive(Debug, Clone, Args, Default)]
        #[command(version, about)]
        pub struct AgentArgs {
            /// Pass one or multiple NodeIds that are used as coordinators
            #[arg(long = "coordinator")]
            pub maybe_coordinator: Option<iroh::PublicKey>,

            /// Loop interval for the loop that ensures the subscription to the enrollment service remain intact.
            #[arg(long)]
            pub maybe_subscribe_loop_interval_seconds: Option<f64>,

            #[arg(long)]
            pub maybe_update_facts_loop_interval_seconds: Option<f64>,
        }

        /// Definition for the top-level Admin command
        #[derive(Debug, Clone, Args)]
        #[command(version, about)]
        pub struct AdminArgs {
            /// Timeout duration in seconds for connecting to the remote request, given in floating points.
            // TODO: create an issue on the irpc repo about connections sometimes taking 5 seconds to initiate
            #[arg(long, default_value_t = 6.0f64)]
            pub timeout: f64,

            /// The node to connect to for the given subcommand.
            #[arg(long)]
            pub node_id: PublicKey,

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

            Ping {},

            EnrollmentAgent {
                #[command(subcommand)]
                cmd: EnrollmentAgentCmd,
            },

            EnrollmentService {
                #[command(subcommand)]
                cmd: EnrollmentServiceCmd,
            },
        }

        /// All enrollment service subcommands
        #[derive(Debug, Clone, Subcommand)]
        pub enum EnrollmentServiceCmd {
            Ping,

            /// Retrieve a list of agents
            ListAgents,

            /// Retrieve facts for an agent
            GetFacts {
                node_id: PublicKey,
            },
        }

        /// All enrollment agent subcommands
        #[derive(Debug, Clone, Subcommand)]
        pub enum EnrollmentAgentCmd {
            Ping,

            /// Get facts from an agent directly.
            GetFacts,
        }
    }

    /// Run the Admin command.
    /// The only stop condition is currently either an error or Ctrl+C.
    pub async fn run(
        endpoint: iroh::Endpoint,
        admin_args: AdminArgs,
    ) -> anyhow::Result<serde_json::Value> {
        let AdminArgs {
            timeout,
            cmd,
            node_id,
        } = admin_args;

        let timeout = std::time::Duration::from_secs_f64(timeout);

        let json_value = match cmd {
            cli::AdminCmd::EchoHash { args } => {
                serde_json::to_value(crate::protocols::echo_hash::send(endpoint, args).await?)?
            }

            cli::AdminCmd::Ping {} => {
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
            cli::AdminCmd::EnrollmentAgent { cmd } => {
                let client =
                    crate::protocols::enrollment::enrollment_agent::EnrollmentAgentClient::connect(
                        endpoint, node_id,
                    )
                    .await?;

                match cmd {
                    cli::EnrollmentAgentCmd::Ping => {
                        let duration = client.ping().await?;

                        serde_json::to_value(format!("ping to {node_id} took {duration:?}"))?
                    }
                    cli::EnrollmentAgentCmd::GetFacts => {
                        let result = client.get_facts().await?;

                        serde_json::to_value(result)?
                    }
                }
            }
            cli::AdminCmd::EnrollmentService { cmd } => {
                let client = crate::protocols::enrollment::enrollment_service::EnrollmentServiceClient::connect(
                            endpoint.clone(), node_id, timeout,
                        ).await?;

                match cmd {
                    cli::EnrollmentServiceCmd::Ping => {
                        let duration = client.ping(timeout).await?;

                        serde_json::to_value(duration)?
                    }
                    cli::EnrollmentServiceCmd::ListAgents => {
                        let response = client.list_subscribers(timeout).await?;

                        serde_json::to_value(response)?
                    }
                    cli::EnrollmentServiceCmd::GetFacts { node_id } => {
                        let response = client.get_subscriber_facts(timeout, node_id).await?;

                        serde_json::to_value(response)?
                    }
                }
            }
        };

        tracing::debug!("response: {json_value:#?}");

        Ok(json_value)
    }
}

#[cfg(test)]
pub mod tests;

#[cfg(feature = "test")]
pub mod test_utils;
