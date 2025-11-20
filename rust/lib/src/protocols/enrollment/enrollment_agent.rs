use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use iroh::protocol::ProtocolHandler;
use iroh::{Endpoint, PublicKey, SecretKey};
use iroh_blobs::BlobsProtocol;
use iroh_docs::api::Doc;
use iroh_docs::Author;
use irpc::{rpc_requests, Client};
use linked_hash_set::LinkedHashSet;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TokioMutex;

use crate::admin::cli::AgentArgs;
use crate::agent;
use crate::facts::Facts;
use crate::protocols::enrollment::enrollment_service::EnrollmentServiceClient;
use crate::protocols::enrollment::ensure_node_root_doc;

pub const ALPN: &[u8] = b"nix-fleet/enrollment/agent/0";

#[rpc_requests(message = EnrollmentAgentRequestMessage)]
#[derive(Debug, Serialize, Deserialize)]
enum EnrollmentAgentRequest {
    #[rpc(tx=irpc::channel::oneshot::Sender<()>)]
    #[wrap(Ping)]
    Ping,

    /// A node announces itself for tracking.
    #[rpc(tx=irpc::channel::oneshot::Sender<Result<Facts, String>>)]
    #[wrap(GetFacts)]
    GetFacts,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EnrollmentServiceSubscription {
    last_successful_check: DateTime<Utc>,
    failed_connections: Vec<(DateTime<Utc>, String)>,
}

#[derive(Clone)]
struct EnrollmentAgentActor {
    endpoint: Endpoint,
    blobs: BlobsProtocol,
    docs: iroh_docs::protocol::Docs,
    default_author: Arc<Author>,

    /// The assumption behind this is that each node creates it with the same
    /// secret that's used for communications, tying this document to its node
    /// identity.
    node_root_doc: Arc<TokioMutex<Doc>>,

    /// Coordinators that are desired to be connected to.
    initial_enrollment_services_desired: LinkedHashSet<PublicKey>,
    enrollment_service_subscription_reconcile_interval: std::time::Duration,
}

impl EnrollmentAgentActor {
    const DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIPTIONS: &str = "SUBSCRIBED_ENROLLMENT_SERVICES";
    const DEFAULT_ENROLLMENT_SERVICE_SUBSCRIPTION_RECONCILE_INTERVAL: f64 = 10.0;
    const DEFAULT_REQUEST_TIMEOUT_SECONDS: f64 = 6.0;

    async fn spawn(
        secret_key: SecretKey,
        endpoint: Endpoint,
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
        agent_args: AgentArgs,
    ) -> anyhow::Result<Client<EnrollmentAgentRequest>> {
        let AgentArgs {
            coordinators,
            maybe_subscribe_loop_interval_seconds,
        } = agent_args;
        let enrollment_service_pubkeys = LinkedHashSet::from_iter(coordinators);

        let (tx, rx) = tokio::sync::mpsc::channel(1);

        let (default_author, node_root_doc) =
            ensure_node_root_doc(&docs, &secret_key.to_bytes()).await?;

        let actor = Self {
            endpoint,
            blobs,
            docs,

            default_author: Arc::new(default_author),
            node_root_doc: Arc::new(TokioMutex::new(node_root_doc)),

            initial_enrollment_services_desired: enrollment_service_pubkeys,
            enrollment_service_subscription_reconcile_interval: std::time::Duration::from_secs_f64(
                maybe_subscribe_loop_interval_seconds
                    .unwrap_or(Self::DEFAULT_ENROLLMENT_SERVICE_SUBSCRIPTION_RECONCILE_INTERVAL),
            ),
        };
        tokio::task::spawn(actor.run(rx));

        Ok(Client::local(tx))
    }

    async fn coordinator_connection_task_loop(self) -> Result<(), anyhow::Error> {
        let doc = self.node_root_doc.lock().await;

        let mut enrollment_service_subscriptions: BTreeMap<
            PublicKey,
            EnrollmentServiceSubscription,
        > = match doc
            .get_exact(
                self.default_author.id(),
                Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIPTIONS,
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

        tracing::trace!(
            "restored enrollment service subscriptions: {enrollment_service_subscriptions:?}",
        );

        // Ensure the subscription to all desired services is intact.
        for pubkey in &self.initial_enrollment_services_desired {
            let subscription_for_pubkey =
                enrollment_service_subscriptions.entry(*pubkey).or_default();

            let enrollment_service_client = match EnrollmentServiceClient::connect(
                self.endpoint.clone(),
                *pubkey,
                std::time::Duration::from_secs_f64(Self::DEFAULT_REQUEST_TIMEOUT_SECONDS),
            )
            .await
            {
                Ok(client) => client,
                Err(e) => {
                    tracing::error!("can't connect to remote service at {pubkey}: {e}");

                    subscription_for_pubkey
                        .failed_connections
                        .push((chrono::Local::now().to_utc(), e.to_string()));
                    continue;
                }
            };

            match enrollment_service_client
                .subscribe(std::time::Duration::from_secs_f64(
                    Self::DEFAULT_REQUEST_TIMEOUT_SECONDS,
                ))
                .await
            {
                Ok(()) => {
                    let now = chrono::Local::now().to_utc();
                    tracing::debug!("successfully confirmed subscription to {pubkey} on {now}");

                    subscription_for_pubkey.last_successful_check = now;

                    // TODO(metrics): is there any need to keep the old ones around?
                    subscription_for_pubkey.failed_connections.clear();
                }
                Err(e) => {
                    tracing::error!("{e}");
                }
            }
        }

        // TODO: unsubscribe from no longer desired services
        // enrollment_service_subscriptions
        //     .retain(|key, _| self.initial_enrollment_services_desired.contains(key));

        // persist the updated subscriptions
        doc.set_bytes(
            self.default_author.id(),
            Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIPTIONS,
            serde_json::to_vec_pretty(&enrollment_service_subscriptions)?,
        )
        .await?;

        Ok(())
    }

    async fn run(mut self, mut rx: tokio::sync::mpsc::Receiver<EnrollmentAgentRequestMessage>) {
        let enrollment_subscription_task = {
            let self_1 = self.clone();

            tokio::task::spawn(async move {
                loop {
                    tracing::debug!("starting loop iteration to maintain desired enrollment service subscriptions");

                    if let Err(e) = self_1.clone().coordinator_connection_task_loop().await {
                        tracing::error!("error in enrollment subscription task loop: {e}");
                    } else {
                        tracing::debug!("completed loop iteration to maintain desired enrollment service subscriptions");
                    }

                    tokio::time::sleep(self_1.enrollment_service_subscription_reconcile_interval)
                        .await;
                }
            })
        };

        // Message receive loop
        while let Some(msg) = rx.recv().await {
            self.handle_message(msg).await
        }

        enrollment_subscription_task.abort();
    }

    async fn handle_message(&mut self, msg: EnrollmentAgentRequestMessage) {
        use EnrollmentAgentRequestMessage::*;
        match msg {
            Ping(irpc::WithChannels { inner, tx, .. }) => {
                tracing::debug!("{inner:?}");

                let _ = tx.send(()).await;
            }
            GetFacts(irpc::WithChannels { inner, tx, .. }) => {
                let handler_fn = async move || -> anyhow::Result<()> {
                    tracing::debug!("{inner:?}");

                    let try_facts = Facts::try_from_environment()
                        .await
                        .map_err(|e| e.to_string());

                    tx.send(try_facts).await?;

                    Ok(())
                };

                if let Err(e) = handler_fn().await {
                    tracing::error!("{e}");
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnrollmentAgentApi {
    endpoint: Endpoint,
    blobs: BlobsProtocol,
    docs: iroh_docs::protocol::Docs,
    client: Client<EnrollmentAgentRequest>,
}

impl EnrollmentAgentApi {
    pub fn expose(&self) -> anyhow::Result<impl ProtocolHandler> {
        let local = self
            .client
            .as_local()
            .context("can not listen on remote Agent")?;

        let remote_handler =
            <EnrollmentAgentRequest as irpc::rpc::RemoteService>::remote_handler(local);

        Ok(irpc_iroh::IrohProtocol::new(remote_handler))
    }

    pub async fn spawn(
        secret_key: SecretKey,
        endpoint: Endpoint,
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
        agent_args: AgentArgs,
    ) -> anyhow::Result<Self> {
        let client = EnrollmentAgentActor::spawn(
            secret_key,
            endpoint.clone(),
            blobs.clone(),
            docs.clone(),
            agent_args,
        )
        .await?;

        Ok(Self {
            endpoint,
            blobs,
            docs,
            client,
        })
    }
}

pub struct EnrollmentAgentClient {
    client: Client<EnrollmentAgentRequest>,
}

impl EnrollmentAgentClient {
    /// Connects to an EnrollmentAgentApi and returns the connected client.
    pub async fn connect(
        endpoint: iroh::Endpoint,
        addr: impl Into<iroh::EndpointAddr>,
    ) -> anyhow::Result<Self> {
        let conn =
            irpc_iroh::IrohLazyRemoteConnection::new(endpoint.clone(), addr.into(), ALPN.to_vec());

        let new_self = Self {
            client: Client::boxed(conn),
        };

        // Use a first ping to evoke the lazy connection into establishment.
        let ping = new_self.ping().await?;
        tracing::trace!("time to first ping: {ping:?}");

        Ok(new_self)
    }

    pub async fn ping(&self) -> anyhow::Result<std::time::Duration> {
        let start = tokio::time::Instant::now();
        self.client.rpc(Ping).await?;
        let duration = tokio::time::Instant::now() - start;

        Ok(duration)
    }

    pub async fn get_facts(&self) -> anyhow::Result<Facts> {
        let facts = self
            .client
            .rpc(GetFacts)
            .await?
            .map_err(anyhow::Error::msg)?;

        Ok(facts)
    }
}
