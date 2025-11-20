use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use iroh::protocol::ProtocolHandler;
use iroh::{Endpoint, PublicKey, SecretKey};
use iroh_blobs::BlobsProtocol;
use iroh_docs::api::Doc;
use iroh_docs::Author;
use irpc::{rpc_requests, Client};
use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use strum::IntoDiscriminant;
use tokio::sync::Mutex as TokioMutex;

use crate::facts::Facts;
use crate::protocols::enrollment::{ensure_node_root_doc, AgentInfo, AgentInfoDiscriminants};

pub const ALPN: &[u8] = b"nix-fleet/enrollment/service/0";

pub type EnrollmentServiceId = PublicKey;
pub type EnrollmentServiceSubscriberId = PublicKey;

pub type EnrolledServiceSubscribersT =
    LinkedHashMap<EnrollmentServiceSubscriberId, EnrollmentServiceSubscriber>;

#[rpc_requests(message = EnrollmentServiceRequestMessage)]
#[derive(Debug, Serialize, Deserialize)]
enum EnrollmentServiceRequest {
    #[rpc(tx=irpc::channel::oneshot::Sender<()>)]
    #[wrap(Ping)]
    Ping,

    /// A node announces itself for tracking.
    #[rpc(
        tx=irpc::channel::oneshot::Sender<anyhow::Result<SubscribeResponse, String>>
    )]
    #[wrap(Subscribe)]
    Subscribe {
        node_id: PublicKey,
        agent_info: AgentInfo,
    },

    /// A node announces itself for tracking.
    #[rpc(
        tx=irpc::channel::oneshot::Sender<anyhow::Result<EnrolledServiceSubscribersT, String>>
    )]
    #[wrap(ListSubscribers)]
    ListSubscribers {},
}

#[derive(Debug, Serialize, Deserialize)]
struct SubscribeResponse {}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, Default)]
pub struct EnrollmentServiceSubscriber {
    info: AgentInfoDiscriminants,
    last_subscription_confirmed: DateTime<Utc>,
}

struct EnrollmentServiceActor {
    endpoint: Endpoint,
    blobs: BlobsProtocol,
    docs: iroh_docs::protocol::Docs,
    default_author: Arc<Author>,

    /// The assumption behind this is that each node creates it with the same
    /// secret that's used for communications, tying this document to its node
    /// identity.
    node_root_doc: Arc<TokioMutex<Doc>>,
}

impl EnrollmentServiceActor {
    const DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS: &str = "enrolled-subscribers-0";

    async fn spawn(
        secret_key: SecretKey,
        endpoint: Endpoint,
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
    ) -> anyhow::Result<Client<EnrollmentServiceRequest>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        let (default_author, node_root_doc) =
            ensure_node_root_doc(&docs, &secret_key.to_bytes()).await?;

        let actor = Self {
            endpoint,
            blobs,
            docs,

            default_author: Arc::new(default_author),
            node_root_doc: Arc::new(TokioMutex::new(node_root_doc)),
        };
        tokio::task::spawn(actor.run(rx));

        Ok(Client::local(tx))
    }

    async fn run(self, mut rx: tokio::sync::mpsc::Receiver<EnrollmentServiceRequestMessage>) {
        while let Some(msg) = rx.recv().await {
            self.handle_message(msg).await
        }
    }

    async fn handle_message(&self, msg: EnrollmentServiceRequestMessage) {
        use EnrollmentServiceRequestMessage::*;

        match msg {
            Ping(irpc::WithChannels { inner, tx, .. }) => {
                tracing::debug!("{inner:?}");

                let _ = tx.send(()).await;
            }
            Subscribe(irpc::WithChannels { inner, tx, .. }) => {
                tracing::debug!("received subscribe request from: {}", inner.node_id);

                let handle_fn = async || -> anyhow::Result<SubscribeResponse> {
                    let doc = self.node_root_doc.lock().await;

                    let mut enrollment_service_subscribers: EnrolledServiceSubscribersT = match doc
                        .get_exact(
                            self.default_author.id(),
                            Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS,
                            true,
                        )
                        .await
                        .context("error getting {Self::CONNECTED_COORDINATORS}: {e}")?
                    {
                        Some(entry) => {
                            let value = self.blobs.get_bytes(entry.content_hash()).await?;

                            serde_json::from_slice(&value)?
                        }
                        None => Default::default(),
                    };

                    let current_subscriber = enrollment_service_subscribers
                        .entry(inner.node_id)
                        .or_default();

                    current_subscriber.info = inner.agent_info.discriminant();
                    current_subscriber.last_subscription_confirmed = chrono::Local::now().to_utc();

                    tracing::debug!("got subscriber {}: {current_subscriber:?}", inner.node_id);

                    doc.set_bytes(
                        self.default_author.id(),
                        Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS,
                        serde_json::to_vec_pretty(&enrollment_service_subscribers)?,
                    )
                    .await?;

                    // TODO: persist facts

                    Ok(SubscribeResponse {})
                };

                if let Err(e) = tx
                    .send(handle_fn().await.map_err(|e| {
                        tracing::error!("error while processing request: {e}");

                        e.to_string()
                    }))
                    .await
                {
                    tracing::error!("error sending response: {e}");
                };
            }
            ListSubscribers(irpc::WithChannels { inner: _, tx, .. }) => {
                let handle_fn = async || -> anyhow::Result<_> {
                    let doc = self.node_root_doc.lock().await;

                    let enrollment_service_subscribers: EnrolledServiceSubscribersT = match doc
                        .get_exact(
                            self.default_author.id(),
                            Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS,
                            true,
                        )
                        .await
                        .context("error getting {Self::CONNECTED_COORDINATORS}: {e}")?
                    {
                        Some(entry) => {
                            let value = self.blobs.get_bytes(entry.content_hash()).await?;

                            serde_json::from_slice(&value)?
                        }
                        None => Default::default(),
                    };

                    Ok(enrollment_service_subscribers)
                };

                if let Err(e) = tx
                    .send(handle_fn().await.map_err(|e| {
                        tracing::error!("error while processing request: {e}");

                        e.to_string()
                    }))
                    .await
                {
                    tracing::error!("error sending response: {e}");
                };
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnrollmentServiceApi {
    endpoint: Endpoint,
    blobs: BlobsProtocol,
    docs: iroh_docs::protocol::Docs,
    client: Client<EnrollmentServiceRequest>,
    node_root_doc: iroh_docs::api::Doc,
}

impl EnrollmentServiceApi {
    pub fn expose(&self) -> anyhow::Result<impl ProtocolHandler> {
        let local = self
            .client
            .as_local()
            .context("can not listen on remote service")?;

        let remote_handler =
            <EnrollmentServiceRequest as irpc::rpc::RemoteService>::remote_handler(local);

        Ok(irpc_iroh::IrohProtocol::new(remote_handler))
    }

    pub async fn spawn(
        secret_key: SecretKey,
        endpoint: Endpoint,
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
    ) -> anyhow::Result<Self> {
        let client = EnrollmentServiceActor::spawn(
            secret_key.clone(),
            endpoint.clone(),
            blobs.clone(),
            docs.clone(),
        )
        .await?;

        let (_, node_root_doc) = ensure_node_root_doc(&docs, &secret_key.to_bytes()).await?;

        Ok(Self {
            endpoint,
            blobs,
            docs,
            client,
            node_root_doc,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EnrollmentServiceClient {
    node_id: PublicKey,
    client: Client<EnrollmentServiceRequest>,
}

impl EnrollmentServiceClient {
    /// Connects to an EnrollmentServiceApi and returns the connected client.
    pub async fn connect(
        endpoint: iroh::Endpoint,
        addr: impl Into<iroh::EndpointAddr>,
        timeout: std::time::Duration,
    ) -> anyhow::Result<Self> {
        let conn =
            irpc_iroh::IrohLazyRemoteConnection::new(endpoint.clone(), addr.into(), ALPN.to_vec());

        let new_self = Self {
            node_id: endpoint.id(),
            client: Client::boxed(conn),
        };

        // Use a first ping to evoke the lazy connection into establishment.
        let ping = new_self.ping(timeout).await?;
        tracing::trace!("time to first ping: {ping:?}");

        Ok(new_self)
    }

    pub async fn ping(&self, timeout: std::time::Duration) -> anyhow::Result<std::time::Duration> {
        let start = tokio::time::Instant::now();
        tokio::time::timeout(timeout, self.client.rpc(Ping)).await??;
        let duration = tokio::time::Instant::now() - start;

        Ok(duration)
    }

    pub async fn subscribe(&self, timeout: std::time::Duration) -> anyhow::Result<()> {
        let request = Subscribe {
            node_id: self.node_id,
            // TODO: figure out the agent info type instead of hardcoding NixOS here
            agent_info: AgentInfo::NixOS {
                facts: Box::new(Facts::try_from_environment().await?),
            },
        };

        let response = tokio::time::timeout(timeout, self.client.rpc(request))
            .await??
            .map_err(anyhow::Error::msg)?;

        tracing::debug!("got response: {response:?}");

        Ok(())
    }

    pub async fn list_subscribers(
        &self,
        timeout: std::time::Duration,
    ) -> anyhow::Result<EnrolledServiceSubscribersT> {
        let request = ListSubscribers {};

        let response = tokio::time::timeout(timeout, self.client.rpc(request))
            .await??
            .map_err(anyhow::Error::msg)?;

        tracing::debug!("got response: {response:?}");

        Ok(response)
    }
}
