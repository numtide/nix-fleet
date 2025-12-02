use std::future::IntoFuture;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use iroh::protocol::ProtocolHandler;
use iroh::{PublicKey, SecretKey};
use iroh_blobs::BlobsProtocol;
use iroh_docs::api::protocol::{AddrInfoOptions, ShareMode};
use iroh_docs::api::Doc;
use iroh_docs::protocol::Docs;
use iroh_docs::store::{QueryBuilder, SingleLatestPerKeyQuery};
use iroh_docs::{Author, Capability, DocTicket, NamespaceSecret};
use irpc::{rpc_requests, Client, WithChannels};
use linked_hash_map::LinkedHashMap;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex as TokioMutex;

use crate::facts::Facts;
use crate::protocols::enrollment::{
    ensure_node_doc_with_derived_keys, DocKeyNixosClosureMarker,
    DOC_KEY_DERIVE_CONTEXT_NAMESPACE_ROOT_0, DOC_KEY_FACTS_LATEST,
};

pub const ALPN: &[u8] = b"nix-fleet/enrollment/service/0";

pub type EnrollmentServiceId = PublicKey;
pub type EnrollmentServiceSubscriberId = PublicKey;

pub type EnrolledServiceSubscribersDoc<T> = LinkedHashMap<EnrollmentServiceSubscriberId, T>;

pub type EnrolledServiceSubscribersT = EnrolledServiceSubscribersDoc<EnrollmentServiceSubscriber>;

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
    #[wrap(SubscribeInner)]
    Subscribe {
        node_id: PublicKey,
        facts_doc_ticket: Box<DocTicket>,
    },

    /// A node announces itself for tracking.
    #[rpc(
        tx=irpc::channel::oneshot::Sender<anyhow::Result<EnrolledServiceSubscribersT, String>>
    )]
    #[wrap(ListSubscribersInner)]
    ListSubscribers {},

    /// Retrieve facts for a given subscriber
    #[rpc(
        tx=irpc::channel::oneshot::Sender<anyhow::Result<Facts, String>>
    )]
    #[wrap(GetSubcriberFactsInner)]
    GetSubcriberFacts { node_id: PublicKey },

    // TODO: this probably belongs into a separate protocol.
    /// Receives bytes that are assumed to be a valid NAR stream.
    /// The content is assigned as the latest available NixOS closure for the given PublicKey.
    #[rpc(tx=irpc::channel::oneshot::Sender<anyhow::Result<(), String>>, rx=irpc::channel::mpsc::Receiver<bytes::Bytes>)]
    #[wrap(UploadAndAssignNixOSClosureInner)]
    UploadAndAssignNixOSClosure { node_id: PublicKey },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubscribeResponse {
    pub nixos_closures_doc_ticket: DocTicket,
}

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
    /// Key to the doc that map SubscriberId -> EnrollmentServiceSubscriber
    const DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS: &str =
        "enrollment-service/enrolled-subscribers-0";

    /// Key to the doc that maps SubscriberId -> NamespaceSecret
    const DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBER_NIXOS_CLOSURE_SECRET: &str =
        "enrollment-service/nixos-closures-0";

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
                tracing::trace!("{inner:?}");

                let _ = tx.send(()).await;
            }
            Subscribe(irpc::WithChannels {
                inner:
                    SubscribeInner {
                        node_id,
                        facts_doc_ticket,
                    },
                tx,
                ..
            }) => {
                tracing::trace!("received subscribe request from: {}", node_id);

                let handle_fn = async || -> anyhow::Result<SubscribeResponse> {
                    let mut enrollment_service_subscribers: EnrolledServiceSubscribersT = match self
                        .node_doc_root
                        .lock()
                        .await
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

                    let current_subscriber =
                        enrollment_service_subscribers.entry(node_id).or_default();

                    current_subscriber.last_subscription_confirmed = chrono::Local::now().to_utc();
                    current_subscriber.facts_latest_doc_ticket_json =
                        serde_json::to_string(&facts_doc_ticket)
                            .context("serializing the doc ticket to JSON")?;

                    tracing::trace!("got subscriber {}: {current_subscriber:?}", node_id);

                    self.node_doc_root
                        .lock()
                        .await
                        .set_bytes(
                            self.default_author.id(),
                            Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS,
                            serde_json::to_vec_pretty(&enrollment_service_subscribers)?,
                        )
                        .await?;

                    // Import the node's fact document which starts syncing in the background
                    self.docs
                        .import(*facts_doc_ticket)
                        .await
                        .context("importing facts doc ticket")?;

                    let (_, nixos_closures_doc_read_ticket) = self
                        .get_or_create_nixos_closures_doc_for_node(node_id)
                        .await?;

                    Ok(SubscribeResponse {
                        nixos_closures_doc_ticket: nixos_closures_doc_read_ticket,
                    })
                };

                if let Err(e) = tx
                    .send(
                        handle_fn()
                            .await
                            .inspect(|response| tracing::debug!("sending response {response:?}"))
                            .map_err(|e| {
                                tracing::error!("error while processing request: {e}");

                                e.to_string()
                            }),
                    )
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
                        .context(format!(
                            "error getting {}",
                            Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBERS
                        ))? {
                        Some(entry) => {
                            let value = self.blobs.get_bytes(entry.content_hash()).await?;

                            serde_json::from_slice(&value)?
                        }
                        None => Default::default(),
                    };

                    let subscriber = enrollment_service_subscribers
                        .get(&inner.node_id)
                        .ok_or_else(|| anyhow::anyhow!("given node is not a subscriber"))?;

                    // open the subscribers fact doc
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
            UploadAndAssignNixOSClosure(WithChannels {
                inner: UploadAndAssignNixOSClosureInner { node_id },
                tx,
                rx,
                ..
            }) => {
                let handle_fn = async || -> anyhow::Result<_> {
                    tracing::debug!("starting to ingest nixos closure for {node_id}");

                    let stream = tokio_util::io::StreamReader::new(rx.into_stream());
                    let stream = tokio_util::io::ReaderStream::new(stream);
                    let blobs_tag_info = self.blobs.add_stream(stream).await.into_future().await?;

                    tracing::trace!("info: {blobs_tag_info:?}");

                    let blobs_status = self.blobs.status(blobs_tag_info.hash).await?;
                    let blobs_size = match &blobs_status {
                        iroh_blobs::api::blobs::BlobStatus::NotFound
                        | iroh_blobs::api::blobs::BlobStatus::Partial { .. } => {
                            anyhow::bail!("blob nut fully stored: {blobs_status:?}");
                        }
                        iroh_blobs::api::blobs::BlobStatus::Complete { size } => *size,
                    };

                    tracing::trace!("added closure to blobs: {blobs_tag_info:?}");

                    let (nixos_closures_doc_requested_node, _) = self
                        .get_or_create_nixos_closures_doc_for_node(node_id)
                        .await?;

                    // Referencing the hash of the imported data in a doc prevents the GC from cleaning it up
                    nixos_closures_doc_requested_node
                        .set_hash(
                            self.default_author.id(),
                            DocKeyNixosClosureMarker::Latest.to_string(),
                            blobs_tag_info.hash,
                            blobs_size,
                        )
                        .await?;

                    // Asynchronously start sync. This is a no-op if the node isn't subscribed to this doc yet.
                    // TODO: compare to synchronously notifying via irpc and let the node decide when to sync
                    let _ = nixos_closures_doc_requested_node
                        .start_sync(vec![node_id.into()])
                        .await
                        .inspect_err(|e| tracing::warn!("error starting sync with {node_id}: {e}"));

                    tracing::debug!("completed ingesting the nixos closure");

                    Ok(())
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

    const DOC_KEY_NIXOS_CLOSURE_DOC_READ_TICKET: &str = "meta/read-ticket-0";

    async fn get_or_create_nixos_closures_doc_for_node(
        &self,
        node_id: PublicKey,
    ) -> Result<(Doc, DocTicket), anyhow::Error> {
        let nixos_closures_capability = self
            .get_or_insert_doc_collection_entry::<Capability, _>(
                &node_id,
                Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIBER_NIXOS_CLOSURE_SECRET,
                Some(Box::new(|| {
                    Capability::Write(NamespaceSecret::new(&mut rand::rng()))
                })),
                false,
            )
            .await?
            .ok_or_else(|| anyhow::anyhow!("should be inserted"))?;
        let nixos_closures_doc_requested_node =
            if let Ok(Some(doc)) = self.docs.open(nixos_closures_capability.id()).await {
                doc
            } else {
                tracing::debug!("couldn't open nixos closures doc, importing it");
                let doc = self
                    .docs
                    .import_namespace(nixos_closures_capability)
                    .await
                    .context("importing nixos closures doc for node {node_id}")?;

                doc
            };

        // Use the nixos closure doc itself to store the ticket
        let ticket: DocTicket = match nixos_closures_doc_requested_node
            .get_exact(
                self.default_author.id(),
                Self::DOC_KEY_NIXOS_CLOSURE_DOC_READ_TICKET,
                false,
            )
            .await
        {
            Ok(Some(entry)) => {
                let content = self.blobs.get_bytes(entry.content_hash()).await?;
                let ticket = DocTicket::from_str(&String::from_utf8_lossy(&content))?;

                ticket
            }
            _ => {
                tracing::debug!(
                    "couldn't find ticket at {}, creating a new one",
                    Self::DOC_KEY_NIXOS_CLOSURE_DOC_READ_TICKET,
                );

                let ticket = nixos_closures_doc_requested_node
                    .share(ShareMode::Read, AddrInfoOptions::Id)
                    .await?;

                // persist the ticket
                nixos_closures_doc_requested_node
                    .set_bytes(
                        self.default_author.id(),
                        Self::DOC_KEY_NIXOS_CLOSURE_DOC_READ_TICKET,
                        ticket.to_string().into_bytes(),
                    )
                    .await?;

                ticket
            }
        };

        Ok((nixos_closures_doc_requested_node, ticket))
    }

    async fn get_or_insert_doc_collection_entry<T, K>(
        &self,
        node_id: &PublicKey,
        key_in_root_doc: K,
        maybe_insert_fn: Option<Box<dyn FnOnce() -> T + Send>>,
        overwrite: bool,
    ) -> anyhow::Result<Option<T>>
    where
        K: std::fmt::Debug + AsRef<[u8]>,
        T: Serialize + serde::de::DeserializeOwned + Clone,
    {
        let mut collection: EnrolledServiceSubscribersDoc<T> = match self
            .node_doc_root
            .lock()
            .await
            .get_exact(self.default_author.id(), &key_in_root_doc, false)
            .await
            .context(format!("error getting {key_in_root_doc:?}",))?
        {
            Some(entry) => {
                let value = self.blobs.get_bytes(entry.content_hash()).await?;

                serde_json::from_slice(&value)?
            }

            None => Default::default(),
        };

        match maybe_insert_fn {
            Some(insert_fn) if !collection.contains_key(node_id) || overwrite => {
                tracing::debug!("inserting new value at {key_in_root_doc:?}");
                collection.insert(*node_id, insert_fn());
            }

            _ => (),
        }

        self.node_doc_root
            .lock()
            .await
            .set_bytes(
                self.default_author.id(),
                bytes::Bytes::copy_from_slice(key_in_root_doc.as_ref()),
                serde_json::to_vec(&collection)?,
            )
            .await
            .context("persisting entry at key {key_in_root_doc} in the root doc")?;

        Ok(collection.get(node_id).cloned())
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
        let request = SubscribeInner {
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
        let request = ListSubscribersInner {};

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
        let request = GetSubcriberFactsInner { node_id };

        let response = tokio::time::timeout(timeout, self.client.rpc(request))
            .await??
            .map_err(anyhow::Error::msg)?;

        Ok(response)
    }

    /// This streams the recursive NAR export of the given nix path via the irpc channel.
    /// There's no optimization to detect whether the remote already has the content.
    pub(crate) async fn upload_and_assign_nixos_closure(
        &self,
        timeout: std::time::Duration,
        node_id: PublicKey,
        path: std::path::PathBuf,
    ) -> anyhow::Result<()> {
        let nix_store_paths = {
            let nix_store_cmd = tokio::process::Command::new("nix-store")
                .args(["-qR", &path.to_string_lossy()])
                .stdout(Stdio::piped())
                .spawn()
                .context("spawning nix-store")?;

            let nix_store_output = nix_store_cmd
                .wait_with_output()
                .await
                .context("completing nix-store")?;

            if !nix_store_output.status.success() {
                anyhow::bail!(
                    "error completing nix-store command: {}",
                    String::from_utf8_lossy(&nix_store_output.stderr),
                );
            }

            String::from_utf8(nix_store_output.stdout)
                .context("parsing nix-store output to utf8")?
                .lines()
                .map(|line| line.to_string())
                .collect::<Vec<_>>()
        };

        let (mut cmd_handle, mut nix_store_paths_export_stream) = {
            let mut nix_store_cmd = tokio::process::Command::new("nix-store")
                .arg("--export")
                .args(&nix_store_paths)
                .stdout(Stdio::piped())
                .spawn()
                .context("spawning nix-store")?;

            let nix_store_cmd_stdout = nix_store_cmd
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("can't get stdout from nix-store --export"))?;

            let stream = tokio_util::io::StreamReader::new(tokio_util::io::ReaderStream::new(
                nix_store_cmd_stdout,
            ));

            (nix_store_cmd, stream)
        };

        let rx = {
            // scope the streaming and rely on the implicit drop to send EOF

            let (tx, rx) = self
                .client
                .client_streaming(UploadAndAssignNixOSClosureInner { node_id }, 10)
                .await?;

            // Required adaptation from the channel sender to a viable Sink for tokio::io::copy
            let tx_copy_to_bytes = tokio_util::io::CopyToBytes::new(tx.into_sink()); // Buffers slices → Bytes for irpc
            let tx_sink_writer = tokio_util::io::SinkWriter::new(tx_copy_to_bytes);
            tokio::pin!(tx_sink_writer);

            let bytes_copied = tokio::time::timeout(
                timeout,
                tokio::io::copy(&mut nix_store_paths_export_stream, &mut tx_sink_writer),
            )
            .await??;
            tracing::debug!("copied {bytes_copied} bytes to the remote");

            tx_sink_writer.flush().await?;
            tx_sink_writer.shutdown().await?;

            rx
        };
        rx.await?.map_err(|e| anyhow::anyhow!("{e}"))?;

        // Check the process status
        if !cmd_handle.wait().await?.success() {
            if let Some(mut stderr) = cmd_handle.stderr {
                let mut stderr_string = String::new();
                stderr.read_to_string(&mut stderr_string).await?;
                tracing::warn!("process resulted in an error: {stderr_string}");
            };
        };

        Ok(())
    }
}
