use std::path::PathBuf;

use clap::{command, Parser, Subcommand};

use flt_lib::{
    admin::cli::{AdminArgs, AgentArgs},
    util::{get_endpoint, parse_openssh_ed25519_private},
};

#[derive(Debug, Parser)]
#[command(version, about)]
struct App {
    #[arg(long)]
    maybe_secret_key: Option<PathBuf>,

    #[command(subcommand)]
    applet: Applet,
}

#[derive(Debug, Clone, Subcommand)]
enum Applet {
    Coordinator,
    Agent(AgentArgs),
    Admin(AdminArgs),
}

use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Install global subscriber configured based on RUST_LOG env-var.
    tracing_subscriber::fmt::init();

    info!("starting up!");

    let args = App::parse();

    let maybe_secret_key = match args.maybe_secret_key {
        None => None,
        Some(path) => Some(
            tokio::task::spawn_blocking(move || {
                parse_openssh_ed25519_private(std::fs::File::open(&path)?)
            })
            .await??,
        ),
    };

    let (secret_key, endpoint) = get_endpoint(
        maybe_secret_key,
        // TODO: make this configurable
        None,
        flt_lib::util::Discoveries::default(),
    )
    .await?;

    let result = match args.applet {
        Applet::Coordinator => flt_lib::coordinator::run(secret_key, endpoint.clone()).await,
        Applet::Agent(agent_args) => {
            flt_lib::agent::run(secret_key, endpoint.clone(), agent_args).await
        }
        Applet::Admin(admin_args) => flt_lib::admin::run(endpoint.clone(), admin_args).await,
    };

    endpoint.close().await;

    result.map(|_| ())
}
