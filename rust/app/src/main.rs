use std::path::PathBuf;

use anyhow::Context;
use clap::{command, Parser, Subcommand};
use tracing::info;
use tracing_subscriber::{
    fmt::time::ChronoLocal, layer::SubscriberExt, util::SubscriberInitExt, Layer,
};

use flt_lib::{
    admin::cli::{AdminArgs, AgentArgs, CoordinatorArgs},
    iroh::RelayMode,
    util::{generate_secret_key, get_endpoint, parse_openssh_ed25519_private},
};

#[derive(Debug, Parser)]
#[command(version, about)]
struct App {
    #[arg(long)]
    maybe_secret_key: Option<PathBuf>,

    /// Choose the relay mode for incoming connections. Outgoing connections happen according to the remote node's relay mode.
    #[arg(long, value_parser = flt_lib::util::parse_relay_mode)]
    relay_mode: RelayMode,

    #[command(subcommand)]
    applet: Applet,
}

#[derive(Debug, Clone, Subcommand)]
enum Applet {
    Coordinator(CoordinatorArgs),
    Agent(AgentArgs),
    Admin(AdminArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install global subscriber configured based on RUST_LOG env-var.
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::io::stderr)
                .with_timer(ChronoLocal::rfc_3339())
                .with_filter(tracing_subscriber::EnvFilter::from_default_env()),
        )
        .try_init()
        .context("initializing tracing")?;

    info!("starting up!");

    let args = App::parse();

    let secret_key = match args.maybe_secret_key {
        None => generate_secret_key(),
        Some(path) => {
            tokio::task::spawn_blocking(move || {
                parse_openssh_ed25519_private(std::fs::File::open(&path)?)
            })
            .await??
        }
    };

    let endpoint = get_endpoint(
        secret_key.clone(),
        Some(args.relay_mode),
        flt_lib::util::Discoveries::default(),
    )
    .await?;

    let result = match args.applet {
        Applet::Coordinator(coordinator_args) => {
            flt_lib::coordinator::run(secret_key, endpoint.clone(), coordinator_args, None).await
        }
        Applet::Agent(agent_args) => {
            flt_lib::agent::run(secret_key, endpoint.clone(), agent_args, None).await
        }
        Applet::Admin(admin_args) => flt_lib::admin::run(endpoint.clone(), admin_args).await,
    };

    let result = result
        .and_then(|value| {
            flt_lib::serde_json::to_string_pretty(&value).map_err(|e| anyhow::anyhow!("{e}"))
        })
        .inspect(|json| {
            println!("{json}");
        });

    endpoint.close().await;

    result.map(|_| ())
}
