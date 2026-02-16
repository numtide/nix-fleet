use std::path::PathBuf;

use clap::{Args, Subcommand};
use iroh::PublicKey;

/// Definition for the top-level Admin command
#[derive(Debug, Clone, Default, strum::EnumDiscriminants)]
#[strum_discriminants(strum(serialize_all = "lowercase"))]
#[strum_discriminants(derive(Default, strum::Display, strum::EnumString))]
pub enum PersistenceMode {
    #[default]
    #[strum_discriminants(default)]
    Memory,
    Filesystem(PathBuf),
}

/// Definition for the top-level Admin command
#[derive(Debug, Clone, Args, Default)]
#[command(version, about)]
pub struct CoordinatorArgs {
    #[command(flatten)]
    pub persistence_args: PersistenceArgs,
}

/// Definition for the top-level Admin command
#[derive(Debug, Clone, Args, Default)]
#[command(version, about)]
pub struct PersistenceArgs {
    /// Persistence for the local document storage.
    #[arg(long, default_value_t = PersistenceModeDiscriminants::default())]
    pub persistence_mode: PersistenceModeDiscriminants,

    /// Directory in which the data will be persisted.
    #[arg(long, required_if_eq("persistence_mode", "filesystem"))]
    pub persistence_dir: PathBuf,
}
impl PersistenceArgs {
    pub(crate) fn mode(&self) -> PersistenceMode {
        match self.persistence_mode {
            PersistenceModeDiscriminants::Memory => PersistenceMode::Memory,
            PersistenceModeDiscriminants::Filesystem => {
                PersistenceMode::Filesystem(self.persistence_dir.clone())
            }
        }
    }
}

/// Definition for the top-level Agent command
#[derive(Debug, Clone, Args, Default)]
#[command(version, about)]
pub struct AgentArgs {
    #[command(flatten)]
    pub persistence_args: PersistenceArgs,

    /// Pass one or multiple NodeIds that are used as coordinators
    #[arg(long = "coordinator")]
    pub maybe_coordinator: Option<iroh::PublicKey>,

    /// Loop interval for the loop that ensures the subscription to the enrollment service remain intact.
    #[arg(long)]
    pub maybe_subscribe_loop_interval_seconds: Option<f64>,

    #[arg(long)]
    pub maybe_update_facts_loop_interval_seconds: Option<f64>,
    //
    // #[arg(long)]
    // pub host_type: HostTypeDiscriminants,

    // #[arg(long)]
    // pub host_update: bool,
}

#[derive(Default, strum::EnumString, strum::Display, strum::EnumDiscriminants)]
#[strum_discriminants(derive(Default, strum::Display, strum::EnumString))]
pub enum HostType {
    #[default]
    #[strum_discriminants(default)]
    Ignore,
    Autodetect,
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

    AssignNixosClosure {
        #[arg(long)]
        node_id: PublicKey,
        #[arg(long)]
        path: PathBuf,
    },
}

/// All enrollment agent subcommands
#[derive(Debug, Clone, Subcommand)]
pub enum EnrollmentAgentCmd {
    Ping,

    /// Get facts from an agent directly.
    GetFacts,
}
