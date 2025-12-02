//! This module implements the Coordinator functionality.
//! It's expected to run on machines with high uptime, bandwidth, and reliability; aka servers.

use iroh::{
    protocol::{DynProtocolHandler, Router},
    SecretKey,
};
use tokio::sync::mpsc::UnboundedReceiver;
use tracing::info;

use crate::{
    admin::cli::CoordinatorArgs,
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
    let (blobs, blob_store, gossip, docs) =
        crate::util::setup_iroh_docs_and_deps(&endpoint, &coordinator_args.persistence_args.mode())
            .await?;

    let router_builder = Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .accept(iroh_blobs::ALPN, blobs.clone())
        .accept(iroh_docs::ALPN, docs.clone())
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
