use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use iroh::protocol::ProtocolHandler;
use iroh::{PublicKey, SecretKey};
use iroh_blobs::BlobsProtocol;
use iroh_docs::api::Doc;
use iroh_docs::protocol::Docs;
use iroh_docs::store::{QueryBuilder, SingleLatestPerKeyQuery};
use iroh_docs::{Author, DocTicket};
use irpc::{rpc_requests, Client, WithChannels};
use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TokioMutex;

use crate::facts::Facts;
use crate::protocols::enrollment::{
    ensure_node_doc_with_derived_keys, DOC_KEY_DERIVE_CONTEXT_NAMESPACE_ROOT_0,
    DOC_KEY_FACTS_LATEST,
};

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
        facts_doc_ticket: Box<DocTicket>,
    },

    /// A node announces itself for tracking.
    #[rpc(
        tx=irpc::channel::oneshot::Sender<anyhow::Result<EnrolledServiceSubscribersT, String>>
    )]
    #[wrap(ListSubscribers)]
    ListSubscribers {},

    /// Retrieve facts for a given subscriber
    #[rpc(
        tx=irpc::channel::oneshot::Sender<anyhow::Result<Facts, String>>
    )]
    #[wrap(GetSubcriberFacts)]
    GetSubcriberFacts { node_id: PublicKey },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscribeResponse {}

#[derive(Debug, Serialize, Deserialize, Hash, PartialEq, Eq, Default)]
pub struct EnrollmentServiceSubscriber {
    last_subscription_confirmed: DateTime<Utc>,
    facts_latest_doc_ticket_json: String,
}

impl EnrollmentServiceSubscriber {
    /// Retrieves the latest facts and returns them if available.
    pub async fn facts_latest_doc_ticket(&self) -> anyhow::Result<DocTicket> {
        Ok(serde_json::from_str(&self.facts_latest_doc_ticket_json)?)
    }
}

/// Actor for the enrollment service.
///
/// The assumption behind the docs is that each node creates it with the same
/// secret that's used for communications, tying this document to its node
/// identity.
struct EnrollmentServiceActor {
    blobs: BlobsProtocol,
    docs: Docs,
    default_author: Arc<Author>,

    /// Local-only root node document for persistence of settings and state.
    node_doc_root: Arc<TokioMutex<Doc>>,
}

impl EnrollmentServiceActor {
    const DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS: &str = "enrolled-subscribers-0";

    async fn spawn(
        secret_key: SecretKey,
        blobs: BlobsProtocol,
        docs: Docs,
    ) -> anyhow::Result<Client<EnrollmentServiceRequest>> {
        let (tx, rx) = tokio::sync::mpsc::channel(1);

        let (default_author, node_doc_root) = ensure_node_doc_with_derived_keys(
            &docs,
            &secret_key.to_bytes(),
            DOC_KEY_DERIVE_CONTEXT_NAMESPACE_ROOT_0,
        )
        .await?;

        let actor = Self {
            blobs,
            docs,

            default_author: Arc::new(default_author),
            node_doc_root: Arc::new(TokioMutex::new(node_doc_root)),
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
                    let doc = self.node_doc_root.lock().await;

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

                    current_subscriber.last_subscription_confirmed = chrono::Local::now().to_utc();
                    current_subscriber.facts_latest_doc_ticket_json =
                        serde_json::to_string(&inner.facts_doc_ticket)
                            .context("serializing the doc ticket to JSON")?;

                    tracing::debug!("got subscriber {}: {current_subscriber:?}", inner.node_id);

                    doc.set_bytes(
                        self.default_author.id(),
                        Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS,
                        serde_json::to_vec_pretty(&enrollment_service_subscribers)?,
                    )
                    .await?;

                    // import the node's fact document which starts syncing in the background
                    self.docs
                        .import(*inner.facts_doc_ticket)
                        .await
                        .context("importing facts doc ticket")?;

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
                    let doc = self.node_doc_root.lock().await;

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
            GetSubcriberFacts(WithChannels { inner, tx, .. }) => {
                let handle_fn = async || -> anyhow::Result<_> {
                    let root_doc = self.node_doc_root.lock().await;

                    let enrollment_service_subscribers: EnrolledServiceSubscribersT = match root_doc
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

                    let subscriber = enrollment_service_subscribers
                        .get(&inner.node_id)
                        .ok_or_else(|| anyhow::anyhow!("given node is not a subscriber"))?;

                    // TODO: open the subscribers fact doc
                    let facts_doc_id = subscriber.facts_latest_doc_ticket().await?.capability.id();
                    let facts_doc = self.docs.open(facts_doc_id).await?.ok_or_else(|| {
                        anyhow::anyhow!("cannot find the facts doc with id {facts_doc_id}")
                    })?;

                    let facts_latest_entry = facts_doc
                        .get_one(QueryBuilder::<SingleLatestPerKeyQuery>::default().key_exact(DOC_KEY_FACTS_LATEST).build())
                        .await
                        .context("query for {DOC_KEY} failed")?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "cannot find entry {DOC_KEY_FACTS_LATEST} for in doc {facts_doc_id}")
                        })?;

                    let facts_latest_bytes = self
                        .blobs
                        .get_bytes(facts_latest_entry.content_hash())
                        .await
                        .context("no blobs found for {facts_latest_entry}")?;

                    let facts_latest = serde_json::from_slice(&facts_latest_bytes)
                        .context("deserializing as facts")?;

                    Ok(facts_latest)
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
    client: Client<EnrollmentServiceRequest>,
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
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
    ) -> anyhow::Result<Self> {
        let client =
            EnrollmentServiceActor::spawn(secret_key.clone(), blobs.clone(), docs.clone()).await?;

        Ok(Self { client })
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

    pub async fn subscribe(
        &self,
        timeout: std::time::Duration,
        facts_doc_ticket: DocTicket,
    ) -> anyhow::Result<SubscribeResponse> {
        let request = Subscribe {
            node_id: self.node_id,
            facts_doc_ticket: Box::new(facts_doc_ticket),
        };

        let response = tokio::time::timeout(timeout, self.client.rpc(request))
            .await??
            .map_err(anyhow::Error::msg)?;

        Ok(response)
    }

    pub async fn list_subscribers(
        &self,
        timeout: std::time::Duration,
    ) -> anyhow::Result<EnrolledServiceSubscribersT> {
        let request = ListSubscribers {};

        let response = tokio::time::timeout(timeout, self.client.rpc(request))
            .await??
            .map_err(anyhow::Error::msg)?;

        Ok(response)
    }

    pub async fn get_subscriber_facts(
        &self,
        timeout: std::time::Duration,
        node_id: PublicKey,
    ) -> anyhow::Result<Facts> {
        let request = GetSubcriberFacts { node_id };

        let response = tokio::time::timeout(timeout, self.client.rpc(request))
            .await??
            .map_err(anyhow::Error::msg)?;

        Ok(response)
    }
}
