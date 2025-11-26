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
