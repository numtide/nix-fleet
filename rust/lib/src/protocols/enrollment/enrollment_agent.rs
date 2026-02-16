use std::collections::BTreeMap;

use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use futures_util::stream::Next;
use futures_util::{FutureExt, Stream, StreamExt, TryFutureExt};
use iroh::protocol::ProtocolHandler;
use iroh::{Endpoint, PublicKey, SecretKey};
use iroh_blobs::api::downloader::Downloader;
use iroh_blobs::BlobsProtocol;
use iroh_docs::api::Doc;
use iroh_docs::engine::LiveEvent;
use iroh_docs::{Author, DocTicket};
use irpc::{rpc_requests, Client};
use linked_hash_set::LinkedHashSet;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as TokioMutex;

use crate::admin::cli::AgentArgs;
use crate::facts::Facts;
use crate::protocols::enrollment::enrollment_service::{
    EnrollmentServiceClient, SubscribeResponse,
};
use crate::protocols::enrollment::{
    ensure_node_doc_with_derived_keys, DocKeyNixosClosureMarker,
    DOC_KEY_DERIVE_CONTEXT_NAMESPACE_FACTS_0, DOC_KEY_DERIVE_CONTEXT_NAMESPACE_ROOT_0,
    DOC_KEY_FACTS_LATEST,
};

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

/// Actor for the enrollment agent.
///
/// The assumption behind the docs is that each node creates it with the same
/// secret that's used for communications, tying this document to its node
/// identity.
#[derive(Clone)]
struct EnrollmentAgentActor {
    endpoint: Endpoint,
    blobs: BlobsProtocol,
    docs: iroh_docs::protocol::Docs,
    default_author: Arc<Author>,
    downloader: Downloader,

    /// Local-only root node document for persistence of settings and state.
    node_doc_root: Arc<TokioMutex<Doc>>,

    /// Document for sharing facts. A ticket for this is shared with the enrollment service.
    node_doc_facts: Arc<TokioMutex<Doc>>,
    facts_update_interval: std::time::Duration,

    /// Enrollment services which are desired to be connected to.
    enrollment_services_desired: LinkedHashSet<PublicKey>,
    enrollment_service_subscription_reconcile_interval: std::time::Duration,
}

impl EnrollmentAgentActor {
    const DEFAULT_REQUEST_TIMEOUT_SECONDS: f64 = 6.0;

    const DEFAULT_ENROLLMENT_SERVICE_SUBSCRIPTION_RECONCILE_INTERVAL: f64 = 10.0;
    const DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIPTIONS: &str = "enrollment-actor/subscribed-services";
    const DOC_KEY_ROOT_DOC_NIXOS_CLOSURES_READ_TICKET: &str =
        "enrollment-actor/nixos-closures-read-ticket-0";

    const DEFAULT_FACTS_UPDATE_INTERVAL: f64 = 60.0;

    async fn spawn(
        secret_key: SecretKey,
        endpoint: Endpoint,
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
        agent_args: AgentArgs,
    ) -> anyhow::Result<Client<EnrollmentAgentRequest>> {
        let AgentArgs {
            maybe_coordinator,
            maybe_subscribe_loop_interval_seconds,
            maybe_update_facts_loop_interval_seconds,
            persistence_args: _,
        } = agent_args;

        let mut enrollment_service_pubkeys: LinkedHashSet<PublicKey> = Default::default();
        if let Some(coordinator) = maybe_coordinator {
            enrollment_service_pubkeys.insert(coordinator);
        }

        let (tx, rx) = tokio::sync::mpsc::channel(1);

        let (default_author, node_doc_root) = ensure_node_doc_with_derived_keys(
            &docs,
            &secret_key.to_bytes(),
            DOC_KEY_DERIVE_CONTEXT_NAMESPACE_ROOT_0,
        )
        .await?;

        let (_, node_doc_facts) = ensure_node_doc_with_derived_keys(
            &docs,
            &secret_key.to_bytes(),
            DOC_KEY_DERIVE_CONTEXT_NAMESPACE_FACTS_0,
        )
        .await?;

        let downloader = blobs.downloader(&endpoint);
        let actor = Self {
            endpoint,
            blobs,
            docs,
            downloader,

            default_author: Arc::new(default_author),
            node_doc_root: Arc::new(TokioMutex::new(node_doc_root)),
            node_doc_facts: Arc::new(TokioMutex::new(node_doc_facts)),

            enrollment_services_desired: enrollment_service_pubkeys,
            enrollment_service_subscription_reconcile_interval: std::time::Duration::from_secs_f64(
                maybe_subscribe_loop_interval_seconds
                    .unwrap_or(Self::DEFAULT_ENROLLMENT_SERVICE_SUBSCRIPTION_RECONCILE_INTERVAL),
            ),
            facts_update_interval: std::time::Duration::from_secs_f64(
                maybe_update_facts_loop_interval_seconds
                    .unwrap_or(Self::DEFAULT_FACTS_UPDATE_INTERVAL),
            ),
        };
        tokio::task::spawn(actor.run(rx));

        Ok(Client::local(tx))
    }

    async fn facts_update_task_loop(self) -> Result<(), anyhow::Error> {
        let facts = Facts::try_from_environment().await?;
        let facts_serialized = serde_json::to_vec(&facts).context("serializing facts")?;

        self.node_doc_facts
            .lock()
            .await
            .set_bytes(
                self.default_author.id(),
                DOC_KEY_FACTS_LATEST,
                facts_serialized,
            )
            .await
            .context(format!(
                "setting bytes for latest facts doc {DOC_KEY_FACTS_LATEST}"
            ))?;

        Ok(())
    }

    async fn maybe_get_nixos_closures_read_ticket(&self) -> anyhow::Result<Option<DocTicket>> {
        self.node_doc_root
            .lock()
            .await
            .get_exact(
                self.default_author.id(),
                Self::DOC_KEY_ROOT_DOC_NIXOS_CLOSURES_READ_TICKET,
                false,
            )
            .and_then(async |maybe_entry| {
                if let Some(entry) = maybe_entry {
                    let ticket = self
                        .try_from_hash_to_doc_ticket(entry.content_hash())
                        .await?;

                    Ok(Some(ticket))
                } else {
                    Ok(None)
                }
            })
            .await
    }

    async fn coordinator_enrollment_subscription_task_loop_fn(self) -> anyhow::Result<()> {
        let mut enrollment_service_subscriptions: BTreeMap<
            PublicKey,
            EnrollmentServiceSubscription,
        > = match self
            .node_doc_root
            .lock()
            .await
            .get_exact(
                self.default_author.id(),
                Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIPTIONS,
                true,
            )
            .await
            .context(format!(
                "error getting {}",
                Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIPTIONS,
            ))? {
            Some(entry) => {
                let value = self.blobs.get_bytes(entry.content_hash()).await?;

                serde_json::from_slice(&value)?
            }
            None => Default::default(),
        };

        tracing::trace!(
            "restored enrollment service subscriptions: {enrollment_service_subscriptions:?}",
        );

        let mut failed_connection = false;

        // Ensure the subscription to all desired services is intact.
        for pubkey in &self.enrollment_services_desired {
            let subscription_for_pubkey =
                enrollment_service_subscriptions.entry(*pubkey).or_default();

            let enrollment_service_client = match EnrollmentServiceClient::connect(
                self.endpoint.clone(),
                *pubkey,
                std::time::Duration::from_secs_f64(Self::DEFAULT_REQUEST_TIMEOUT_SECONDS),
            )
            .await
            .context(format!("can't connect to remote service at {pubkey}"))
            {
                Ok(client) => client,
                Err(e) => {
                    tracing::error!("{e}");

                    failed_connection = true;

                    subscription_for_pubkey
                        .failed_connections
                        .push((chrono::Local::now().to_utc(), e.to_string()));

                    continue;
                }
            };

            match enrollment_service_client
                .subscribe(
                    std::time::Duration::from_secs_f64(Self::DEFAULT_REQUEST_TIMEOUT_SECONDS),
                    self.node_doc_facts
                        .lock()
                        .await
                        .share(
                            iroh_docs::api::protocol::ShareMode::Read,
                            iroh_docs::api::protocol::AddrInfoOptions::Id,
                        )
                        .await
                        .context("creating share link for doc facts")?,
                )
                .await
            {
                Ok(SubscribeResponse {
                    nixos_closures_doc_ticket,
                }) => {
                    let now = chrono::Local::now().to_utc();
                    tracing::debug!("successfully confirmed subscription to {pubkey} on {now}");

                    subscription_for_pubkey.last_successful_check = now;
                    // TODO(metrics): is there any need to keep the old ones around?
                    subscription_for_pubkey.failed_connections.clear();

                    let must_persist_new_ticket =
                        match self.maybe_get_nixos_closures_read_ticket().await? {
                            Some(existing_ticket) => {
                                // NOTE: DocTicket doesn't implement Eq
                                existing_ticket.to_string() != nixos_closures_doc_ticket.to_string()
                            }

                            None => true,
                        };

                    if must_persist_new_ticket {
                        tracing::trace!("persisting new ticket {nixos_closures_doc_ticket:?}");

                        // Store the ticket in the node root doc, where the actor loop looks for it.
                        self.node_doc_root
                            .lock()
                            .await
                            .set_bytes(
                                self.default_author.id(),
                                Self::DOC_KEY_ROOT_DOC_NIXOS_CLOSURES_READ_TICKET,
                                nixos_closures_doc_ticket.to_string().into_bytes(),
                            )
                            .await?;
                    }
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
        self.node_doc_root
            .lock()
            .await
            .set_bytes(
                self.default_author.id(),
                Self::DOC_KEY_ENROLLMENT_SERVICE_SUBSCRIPTIONS,
                serde_json::to_vec_pretty(&enrollment_service_subscriptions)?,
            )
            .await?;

        if failed_connection {
            anyhow::bail!("got at least one connection failure");
        }

        Ok(())
    }

    async fn run(mut self, mut rx: tokio::sync::mpsc::Receiver<EnrollmentAgentRequestMessage>) {
        let facts_update_task = {
            const TASK_NAME: &str = "facts_update_task";

            let self_1 = self.clone();

            tokio::task::spawn(async move {
                loop {
                    tracing::debug!("[{TASK_NAME}] starting loop iteration");

                    if let Err(e) = self_1.clone().facts_update_task_loop().await {
                        tracing::error!("[{TASK_NAME}] error during loop iteration: {e}");
                    } else {
                        tracing::debug!("[{TASK_NAME}] completed loop iteration");
                    }

                    tokio::time::sleep(self_1.facts_update_interval).await;
                }
            })
        };

        let enrollment_subscription_task = {
            const TASK_NAME: &str = "enrollment_subscription_task";

            let self_1 = self.clone();

            tokio::task::spawn(async move {
                let mut error_count = 0;
                loop {
                    tracing::debug!("[{TASK_NAME}] starting loop iteration");

                    if let Err(e) = self_1
                        .clone()
                        .coordinator_enrollment_subscription_task_loop_fn()
                        .await
                    {
                        error_count += 1;
                        tracing::error!("[{TASK_NAME}] error during loop iteration: {e}");
                    } else {
                        error_count = 0;
                        tracing::debug!("[{TASK_NAME}] completed loop iteration");
                    };

                    let sleep_duration = if error_count > 0 {
                        std::cmp::min(
                            std::time::Duration::from_secs(2 * error_count),
                            self_1.enrollment_service_subscription_reconcile_interval,
                        )
                    } else {
                        self_1.enrollment_service_subscription_reconcile_interval
                    };
                    tracing::debug!("[{TASK_NAME}]: sleeping for {sleep_duration:?}");
                    tokio::time::sleep(sleep_duration).await;
                }
            })
        };

        let (nixos_closure_update_ticket_sender, mut nixos_closure_update_ticket_receiver) =
            tokio::sync::mpsc::channel::<DocTicket>(10);

        let nixos_closure_update_ticket_task = {
            const TASK_NAME: &str = "nixos_closure_update_ticket_task";

            let self_1 = self.clone();

            tokio::task::spawn(async move {
                loop {
                    tracing::debug!("[{TASK_NAME}] starting loop iteration");

                    if let Err(e) = self_1
                        .clone()
                        .coordinator_nixos_closure_update_ticket_task_loop_fn(
                            &nixos_closure_update_ticket_sender,
                        )
                        .await
                    {
                        tracing::error!("[{TASK_NAME}] error during loop iteration: {e}");
                    } else {
                        tracing::debug!("[{TASK_NAME}] completed loop iteration");
                    }
                }
            })
        };

        let (nixos_closure_update_executer_sender, mut nixos_closure_update_executer_receiver) =
            tokio::sync::mpsc::channel::<iroh_docs::Entry>(10);

        // TODO: this task should also dispatch updates that were already received but haven't been applied yet
        let nixos_closure_update_dispatch_task = {
            const TASK_NAME: &str = "nixos_closure_update_dispatch_task";

            let self_1 = self.clone();

            tokio::task::spawn(async move {
                let mut update_live_stream: LiveEventStream = {
                    let fallback = Box::pin(std::future::pending().into_stream());

                    if let Ok(Some(ticket)) = self_1.maybe_get_nixos_closures_read_ticket().await {
                        if let Ok((_, stream)) = self_1.docs.import_and_subscribe(ticket).await {
                            Box::pin(stream)
                        } else {
                            fallback
                        }
                    } else {
                        fallback
                    }
                };

                loop {
                    tracing::debug!("[{TASK_NAME}] starting loop iteration");

                    match self_1
                        .clone()
                        .coordinator_nixos_closure_update_dispatch_task_loop_fn(
                            &mut nixos_closure_update_ticket_receiver,
                            update_live_stream.next(),
                            &nixos_closure_update_executer_sender,
                        )
                        .await
                    {
                        Ok(maybe_new_stream) => {
                            if let Some(new_stream) = maybe_new_stream {
                                update_live_stream = new_stream;
                            }

                            tracing::debug!("[{TASK_NAME}] completed loop iteration");
                        }

                        Err(e) => {
                            tracing::error!("[{TASK_NAME}] error during loop iteration: {e}");
                        }
                    };
                }
            })
        };

        let nixos_closure_update_executer_task = {
            const TASK_NAME: &str = "nixos_closure_update_executer_task";

            let self_1 = self.clone();

            tokio::task::spawn(async move {
                loop {
                    tracing::debug!("[{TASK_NAME}] starting loop iteration");

                    match self_1
                        .clone()
                        .coordinator_nixos_closure_update_execute_task_loop_fn(
                            &mut nixos_closure_update_executer_receiver,
                        )
                        .await
                    {
                        Ok(()) => {
                            tracing::debug!("[{TASK_NAME}] success in loop iteration");
                        }

                        Err(e) => {
                            tracing::error!("[{TASK_NAME}] error during loop iteration: {e}");
                        }
                    };
                }
            })
        };

        // Message receive loop
        while let Some(msg) = rx.recv().await {
            self.handle_message(msg).await
        }

        // TODO: send these tasks a message to shutdown
        facts_update_task.abort();
        enrollment_subscription_task.abort();
        nixos_closure_update_ticket_task.abort();
        nixos_closure_update_dispatch_task.abort();
        nixos_closure_update_executer_task.abort();
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

    async fn try_from_hash_to_doc_ticket(
        &self,
        hash: iroh_blobs::Hash,
    ) -> anyhow::Result<DocTicket> {
        let bytes = self.blobs.get_bytes(hash).await?;
        let utf8 = String::from_utf8(bytes.into())?;
        let ticket = DocTicket::from_str(&utf8)?;

        Ok(ticket)
    }

    // Watches for inserts of new nixos closure read tickets, and sends them over the given sender.
    // The receiver of this will then renew its subscription to the nixos closure
    async fn coordinator_nixos_closure_update_ticket_task_loop_fn(
        &self,
        ticket_sender: &tokio::sync::mpsc::Sender<iroh_docs::DocTicket>,
    ) -> anyhow::Result<()> {
        let mut nixos_closures_ticket_changes_subscription =
            self.node_doc_root.lock().await.subscribe().await?;

        while let Some(event) = nixos_closures_ticket_changes_subscription.next().await {
            match event {
                Ok(iroh_docs::engine::LiveEvent::InsertLocal { entry }) => {
                    if entry.key() == Self::DOC_KEY_ROOT_DOC_NIXOS_CLOSURES_READ_TICKET.as_bytes() {
                        tracing::debug!(
                            "received a nixos closure read ticket update from timestamp {}",
                            entry.timestamp()
                        );

                        let ticket = self
                            .try_from_hash_to_doc_ticket(entry.content_hash())
                            .await?;

                        ticket_sender.send(ticket).await?;
                    }
                }

                other => {
                    tracing::debug!("ignoring event update from node root doc: {other:?}");
                }
            }
        }

        Ok(())
    }

    // Renews the subscription to the latest nixos closure update entry and schedules the update.
    async fn coordinator_nixos_closure_update_dispatch_task_loop_fn(
        &self,
        ticket_receiver: &mut tokio::sync::mpsc::Receiver<DocTicket>,
        next_update_event: NextUpdateEvent<'_>,
        update_executer_sender: &tokio::sync::mpsc::Sender<iroh_docs::Entry>,
    ) -> anyhow::Result<Option<LiveEventStream>> {
        let update_event_handler_fn = |event| async {
            match event {
                iroh_docs::engine::LiveEvent::InsertRemote {
                    from,
                    entry,
                    content_status,
                } => {
                    match DocKeyNixosClosureMarker::from_str(&String::from_utf8_lossy(entry.key()))
                    {
                        Ok(DocKeyNixosClosureMarker::Latest) => {
                            tracing::debug!(
                                "remote inserted new entry for the latest nixos closure"
                            );

                            match content_status {
                                iroh_docs::ContentStatus::Complete => (),
                                iroh_docs::ContentStatus::Incomplete
                                | iroh_docs::ContentStatus::Missing => {
                                    // try to download it

                                    /*
                                     * TODO:
                                     * spawn this in the background? also think
                                     * about what happens if a newer closure is
                                     * pushed meanwhile. this should then
                                     * probably be aborted.
                                     */

                                    let downloader = self
                                        .downloader
                                        .download(vec![entry.content_hash()], vec![from]);
                                    let context_msg = format!(
                                        "downloading {} from {}",
                                        entry.content_hash(),
                                        from
                                    );
                                    tracing::debug!("[START] {context_msg}");
                                    downloader.await.context(context_msg.clone())?;
                                    tracing::debug!("[FINISH] {context_msg}");
                                }
                            }

                            // dispatch the update for execution
                            update_executer_sender.send(entry.clone()).await?;
                        }
                        // TODO: what does an error here mean?
                        Err(_) => (),
                    }
                }

                iroh_docs::engine::LiveEvent::SyncFinished(sync_event) => {
                    tracing::debug!("TODO: process SyncFinished event {sync_event:?}");
                }
                any => {
                    tracing::debug!("TODO: process event {any}");
                } // iroh_docs::engine::LiveEvent::InsertLocal { entry } => todo!(),
                  // iroh_docs::engine::LiveEvent::ContentReady { hash } => todo!(),
                  // iroh_docs::engine::LiveEvent::PendingContentReady => todo!(),
                  // iroh_docs::engine::LiveEvent::NeighborUp(public_key) => todo!(),
                  // iroh_docs::engine::LiveEvent::NeighborDown(public_key) => todo!(),
            }

            anyhow::Result::<_, anyhow::Error>::Ok(())
        };

        tokio::select! {
            maybe_ticket = ticket_receiver.recv() => {
                let ticket = if let Some(ticket) = maybe_ticket {
                    ticket
                } else {
                    return Ok(None);
                };

                // This stream has to be passed back to the loop so that it can
                // persist it and pass the next value in on the next iteration.
                let (doc, stream) = self
                    .docs
                    .import_and_subscribe(ticket.clone())
                    .await
                    .context(format!("subscribing to doc ticket {ticket:?}?"))?;

                let _ = doc.start_sync(ticket.nodes.clone()).await.inspect_err(|e| {
                    tracing::warn!("couldn't start syncing document {} with nodes {:?}: {e}", doc.id(), ticket.nodes);
                });

                Ok(Some(Box::pin(stream)))
            },

            update_event = next_update_event => {
                match update_event {
                    Some(event) => {
                        match event {
                            Ok(event) => {
                                update_event_handler_fn(event).await?;
                            },
                            Err(e) => {
                                anyhow::bail!("error processing update stream: {e}");
                            },
                        }

                    },
                    None => todo!(),
                }

                Ok(None)
            }
        }
    }

    async fn coordinator_nixos_closure_update_execute_task_loop_fn(
        &self,
        nixos_closure_update_executer_receiver: &mut tokio::sync::mpsc::Receiver<iroh_docs::Entry>,
    ) -> anyhow::Result<()> {
        while let Some(entry) = nixos_closure_update_executer_receiver.recv().await {
            tracing::debug!("processing dispatched update entry: {entry:?}");

            let content_hash = entry.content_hash();

            // export the content to the nix store
            let mut cmd = tokio::process::Command::new("sudo");
            let cmd = cmd
                .arg("nix-store")
                .args(["-vvv", "--import"])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .stdin(Stdio::piped())
                .kill_on_drop(true);
            tracing::debug!("[Command] spawning: {cmd:?}");

            let mut cmd_child = cmd.spawn().context("spawning nix-store")?;
            let mut nix_store_cmd_stdin = cmd_child
                .stdin
                .take()
                .ok_or_else(|| anyhow::anyhow!("could not take stdin from nix-store command"))?;

            let output_stream = crate::util::merged_output_stream(&mut cmd_child)?;

            let cmd_output_reader_handle = tokio::task::spawn_blocking(async move || {
                tracing::debug!("parsing output");

                // Collect everything, then sort by timestamp
                let mut events: Vec<_> = output_stream
                    .inspect(|item| {
                        tracing::debug!("{item:?}");
                    })
                    .collect()
                    .await;

                // Sort by timestamp (stable sort preserves relative order for equal times)
                events.sort_by_key(|(ts, _, _)| *ts);

                events
            });

            let cmd_child_handle = tokio::task::spawn(async move {
                let msg = "waiting for the nix-store in a spawned task";
                tracing::debug!(msg);
                cmd_child.wait().await.context(msg)
            });

            {
                let mut content_reader = self.blobs.reader(content_hash);

                let msg = format!(
                    "copying bytes from content with hash {content_hash} to nix-store's stdin"
                );

                tokio::io::copy(&mut content_reader, &mut nix_store_cmd_stdin)
                    .await
                    .inspect(|r| tracing::debug!("finished {msg}: {r}"))
                    .context(msg)?;
            };

            let cmd_exit_status = cmd_child_handle
                .await
                .inspect(|r| tracing::debug!("nix-store command finished with {r:?}"))
                .context("joining nix-store task")?;

            let mut cmd_output = cmd_output_reader_handle.await?.await;
            // the nixos closure is most likely the last item
            cmd_output.reverse();

            if cmd_exit_status.is_err() {
                tracing::error!(
                    "nix-store --import failed with status {cmd_exit_status:?} and output:\n{cmd_output:?}"
                );
            }

            // TODO: make this configurable
            const NIX_STORE_PREFIX: &str = "/nix/store";
            const STC_PATH: &str = "bin/switch-to-configuration";
            let needed_paths_in_nixos_closure = std::collections::HashSet::from([
                STC_PATH,
                // TODO: adapt the dummy closures to also provide these
                // "activate",
                // "system",
            ]);

            let (_, switch_to_configuration_path) = cmd_output
                .iter()
                .inspect(|(_, _, r)| {
                    tracing::trace!("checking for the existence of nixos closure files in {r}");
                })
                .find_map(|(_, kind, line)| {
                    if let crate::util::StreamKind::Stdout = kind {
                        let line_path: PathBuf = line.into();

                        if line_path.starts_with(NIX_STORE_PREFIX)
                            && needed_paths_in_nixos_closure
                                .iter()
                                .map(|p| line_path.join(p))
                                .all(|p| p.exists())
                        {
                            tracing::debug!("found nixos closure at {line_path:?}");
                            return Some((line_path.clone(), line_path.join(STC_PATH)));
                        }
                    }

                    None
                })
                .ok_or_else(|| anyhow::anyhow!("no nixos closure found in {cmd_output:?}"))?;

            // TODO: make the switch mode configurable
            let switch_mode = "switch";

            // TODO: call switch-to-configuration in a context outside of the agent, otherwise it could be terminated by the switch itself.
            let mut cmd = tokio::process::Command::new(&switch_to_configuration_path);
            let cmd = cmd
                .arg(switch_mode)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            tracing::debug!("[Command] spawning: {cmd:?}");

            let cmd_child = cmd
                .spawn()
                .context(format!("spawning {switch_to_configuration_path:?}"))
                .map(|cmd_child| {
                    let switch_to_configuration_path = switch_to_configuration_path.clone();
                    async move {
                        cmd_child.wait_with_output().await.context(format!(
                            "waiting for the {switch_to_configuration_path:?} command"
                        ))
                    }
                });

            match cmd_child {
                Ok(child) => match child.await {
                    Ok(output) => {
                        let exit_status = output.status;
                        if !output.status.success() {
                            Err(anyhow::anyhow!(
                                "{cmd:?} failed with status {exit_status} and output:\n{output:#?}"
                            ))
                        } else {
                            Ok(cmd_output)
                        }
                    }
                    Err(e) => Err(e),
                },
                Err(e) => Err(anyhow::anyhow!("error: {e} (kind = {e:?}")),
            }?;

            tracing::debug!("successfully processed {entry:?}");

            // TODO: persist update status / mark the update as applied
        }

        Ok(())
    }
}

type LiveEventStream =
    Pin<Box<dyn Stream<Item = Result<iroh_docs::engine::LiveEvent, anyhow::Error>> + Send>>;

type NextUpdateEvent<'a> = Next<
    'a,
    Pin<
        Box<
            dyn futures_util::Stream<Item = Result<LiveEvent, anyhow::Error>>
                + std::marker::Send
                + 'static,
        >,
    >,
>;

#[derive(Debug, Clone)]
pub struct EnrollmentAgentApi {
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

        Ok(Self { client })
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
