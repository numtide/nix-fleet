//! This module implements the Coordinator functionality.
//! It's expected to run on machines with high uptime, bandwidth, and reliability; aka servers.

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

        match &coordinator_args.persistence_mode() {
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
    let docs = match &coordinator_args.persistence_mode() {
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
