//! A simple protocol that will echo back the hash of the data to the sender.
//! It serves as an internal reference for evaluating Iroh's primitive.

// use arc_slice::{ArcSlice, ArcSliceMut};
// use iroh::protocol::{AcceptError, ProtocolHandler};
// use std::str::FromStr;
// use tracing::{debug, info, trace};

use std::str::FromStr;

use anyhow::Context;
use iroh::protocol::{AcceptError, ProtocolHandler, RouterBuilder};
use iroh_blobs::util::SendStream;
use tokio::io::AsyncWriteExt;
use tracing::{debug, info, trace};

use crate::protocols::echo_hash::{
    docs::EchoHashDocsApi, native::EchoHashNative, rpc::EchoHashRpcApi,
};

/// Send the data via the designated `SendMode`
pub async fn send(
    endpoint: iroh::Endpoint,
    EchoHashArgs {
        number,
        node_id,
        size,
        timeout,
        msg,
        mode,
    }: EchoHashArgs,
) -> anyhow::Result<()> {
    let generate_data_iter = std::iter::repeat(msg.bytes()).flatten().take(size);

    let msg = bytes::Bytes::from_iter(generate_data_iter);
    let msg_hash = blake3::Hasher::new().update(&msg).finalize().to_string();

    match mode {
        SendMode::Native => {
            EchoHashNative::send(endpoint, number, node_id, timeout, msg.clone(), msg_hash).await?
        }
        SendMode::Rpc | SendMode::RpcStream => {
            let api_client = EchoHashRpcApi::connect(endpoint, node_id).context(format!(
                "[{}:{}] connecting to {node_id}",
                file!(),
                line!(),
            ))?;

            for i in 0..number {
                let t_0 = tokio::time::Instant::now();

                trace!("[{i}] writing ({:e} bytes) to stream", msg.len());

                tokio::time::timeout(std::time::Duration::from_secs_f64(timeout), async {
                    api_client.send_irpc(msg.clone(), mode).await
                })
                .await??;

                let rtt = tokio::time::Instant::now().duration_since(t_0);

                let b_s = msg.len() as f64 / (rtt.as_secs_f64() * 1024. * 1024.);

                info!(
                    "[{i}] transferring {:e} bytes completed within {rtt:#?} at {b_s:.4} MiB/s",
                    msg.len()
                );
            }
        }
        SendMode::Docs => {
            // Scenario: Receiver governs writes to a replica via a custom RPC protocol
            //
            // 1. Sender stores the data in the local store
            // 2. Sender transmits the store entry via RPC to the Receiver
            // 3. Receiver creates an entry in the replica which causes the data to be pulled from the Sender
            // 4. Sender verifies the entry in the replica

            // blobs: BlobsProtocol,
            // docs: iroh_docs::protocol::Docs,
            //

            let blob_store = iroh_blobs::store::mem::MemStore::default();
            let blobs = iroh_blobs::BlobsProtocol::new(&blob_store, None);
            let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
            let docs = iroh_docs::protocol::Docs::memory()
                .spawn(endpoint.clone(), (*blob_store).clone(), gossip.clone())
                .await?;
            let router_builder = RouterBuilder::new(endpoint.clone())
                .accept(iroh_blobs::ALPN, blobs.clone())
                .accept(iroh_gossip::ALPN, gossip)
                .accept(iroh_docs::ALPN, docs.clone());

            let router = router_builder.spawn();

            let api_client = EchoHashDocsApi::connect(endpoint.clone(), node_id, blobs, docs)?;

            api_client.send(msg, mode, number, node_id, timeout).await?;

            let _ = router.shutdown().await;
        }
    };

    Ok(())
}

pub mod native {
    use anyhow::Context;
    use tokio::{io::AsyncWriteExt, time::Instant};
    use tracing::{info, trace};

    #[derive(Debug)]
    pub struct EchoHashNative;

    impl EchoHashNative {
        pub const ALPN: &[u8] = b"nix-fleet/echo-hash/0";

        pub async fn send(
            endpoint: iroh::Endpoint,
            number: usize,
            node_id: iroh::PublicKey,
            timeout: f64,
            msg: bytes::Bytes,
            msg_hash: String,
        ) -> Result<(), anyhow::Error> {
            // let msg = std::sync::Arc::new(msg);
            for i in 0..number {
                let t_0 = Instant::now();

                let connection = endpoint
                    .connect(node_id, EchoHashNative::ALPN)
                    .await
                    .context(format!(
                        "[{}:{}] connecting to {node_id} via {:?}",
                        file!(),
                        line!(),
                        endpoint.discovery()
                    ))?;
                let (mut tx, mut rx) = connection.open_bi().await?;

                trace!("[{i}] writing ({:e} bytes) to stream", msg.len());

                tx.write_all(&msg)
                    .await
                    .context(format!("writing {} bytes to stream", msg.len()))?;

                tx.flush().await?;
                tx.finish()?;

                trace!("[{i}] wrote ({:e} bytes) to stream", msg.len());

                let mut reader_future = async || {
                    let buf = rx.read_to_end(16 * 1024 * 1024).await?;

                    let hash = blake3::Hash::from_slice(&buf).context("parsing buffer as Hash")?;

                    anyhow::Ok(hash)
                };

                trace!("[{i}] waiting for an answer..");
                tokio::select! {
                    read_result = reader_future() => {
                        let hash = read_result?;

                        trace!("finished reading from stream");

                        let rtt = Instant::now().duration_since(t_0);

                        anyhow::ensure!(msg_hash == hash.to_string(), format!("[{i}] hash mismatch"));

                        let b_s =
                            msg.len() as f64
                            /
                            (rtt.as_secs_f64() * 1024. * 1024.)
                            ;

                        info!(
                            "[{i}] transferring {:e} bytes completed within {rtt:#?} at {b_s:.4} MiB/s",
                            msg.len()
                        );
                    },

                    _ = tokio::time::sleep(std::time::Duration::from_secs_f64(timeout)) => {
                        anyhow::bail!("timeout");
                    }
                }

                connection.close(0u32.into(), b"finished");
            }
            Ok(())
        }
    }
}

pub mod rpc {
    use anyhow::Context;
    use iroh::protocol::ProtocolHandler;
    use irpc::{rpc_requests, Client, WithChannels};
    use serde::{Deserialize, Serialize};

    use super::SendMode;

    #[rpc_requests(message = EchoRpcMessage)]
    #[derive(Debug, Serialize, Deserialize)]
    enum EchoHashRpc {
        // The handler receives the data via the request struct and gets a sender for the response.
        #[rpc(tx=irpc::channel::oneshot::Sender<iroh_blobs::Hash>)]
        #[wrap(Simplex)]
        Simplex { data: bytes::Bytes },
        // The handler gets a receiver for the data and a sender for the response
        #[rpc(tx=irpc::channel::mpsc::Sender<iroh_blobs::Hash>, rx=irpc::channel::mpsc::Receiver<bytes::Bytes>)]
        #[wrap(Duplex)]
        Duplex,
    }

    enum EchoRpcSender {
        Simplex,

        Duplex {
            tx: irpc::channel::mpsc::Sender<bytes::Bytes>,
            rx: irpc::channel::mpsc::Receiver<iroh_blobs::Hash>,
        },
    }

    impl EchoRpcSender {
        async fn send(
            &mut self,
            data: bytes::Bytes,
            maybe_client: Option<&Client<EchoHashRpc>>,
        ) -> anyhow::Result<blake3::Hash> {
            match (self, maybe_client) {
                (Self::Simplex, None) => {
                    anyhow::bail!("need a client for simplex sending");
                }

                (Self::Simplex, Some(client)) => Ok(client.rpc(Simplex { data }).await?.into()),
                (Self::Duplex { tx, rx }, _) => {
                    tx.send(data).await?;

                    let response = rx
                        .recv()
                        .await
                        .context("receiving data")?
                        .ok_or_else(|| anyhow::anyhow!("did not receive a value back"))?;

                    Ok(response.into())
                }
            }
        }
    }

    struct EchoRpcActor {
        recv: tokio::sync::mpsc::Receiver<EchoRpcMessage>,
    }

    impl EchoRpcActor {
        pub fn spawn() -> EchoHashRpcApi {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let actor = Self { recv: rx };
            tokio::task::spawn(actor.run());
            EchoHashRpcApi {
                inner: Client::local(tx),
            }
        }

        async fn run(mut self) {
            while let Some(msg) = self.recv.recv().await {
                self.handle(msg).await
            }
        }

        async fn handle(&self, msg: EchoRpcMessage) {
            match msg {
                EchoRpcMessage::Simplex(WithChannels {
                    tx,
                    inner: Simplex { data },
                    ..
                }) => {
                    let hash = iroh_blobs::Hash::new(&data);
                    if let Err(e) = tx.send(hash).await {
                        tracing::error!("error sending back data: {e}");
                    }
                }
                EchoRpcMessage::Duplex(WithChannels { tx, mut rx, .. }) => {
                    while let Ok(Some(data)) = rx.recv().await {
                        let hash = iroh_blobs::Hash::new(&data);

                        tracing::info!(
                            "received data with length {}. sending back hash {hash}",
                            data.len()
                        );
                        if let Err(e) = tx.send(hash).await {
                            tracing::error!("error sending back data: {e}");
                        }
                    }
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct EchoHashRpcApi {
        inner: Client<EchoHashRpc>,
    }

    impl EchoHashRpcApi {
        pub const ALPN: &[u8] = b"nix-fleet/echo-hash-irpc/0";

        // The frame header is a variable-length varint encoding the message size.
        // It ranges from 1 to 10 bytes depending on the message size. Using 10 as
        // the safe choice.
        pub const MAX_CHUNK_SIZE: usize = irpc::rpc::MAX_MESSAGE_SIZE as usize - 10;

        pub fn expose(&self) -> anyhow::Result<impl ProtocolHandler> {
            let local = self
                .inner
                .as_local()
                .context("can not listen on remote service")?;

            let remote_handler = <EchoHashRpc as irpc::rpc::RemoteService>::remote_handler(local);

            Ok(irpc_iroh::IrohProtocol::new(remote_handler))
        }

        pub fn spawn() -> Self {
            EchoRpcActor::spawn()
        }

        pub fn connect(
            endpoint: iroh::Endpoint,
            addr: impl Into<iroh::EndpointAddr>,
        ) -> anyhow::Result<EchoHashRpcApi> {
            let conn = irpc_iroh::IrohLazyRemoteConnection::new(
                endpoint,
                addr.into(),
                Self::ALPN.to_vec(),
            );

            Ok(EchoHashRpcApi {
                inner: Client::boxed(conn),
            })
        }

        /// Send the data using irpc in chunks that respect the `irpc::rpc::MAX_MESSAGE_SIZE`
        pub async fn send_irpc(&self, data: bytes::Bytes, mode: SendMode) -> anyhow::Result<()> {
            let chunks = super::chunks_from_bytes(data, Self::MAX_CHUNK_SIZE);
            let num_chunks = chunks.len();

            let mut sender = match mode {
                SendMode::Rpc => EchoRpcSender::Simplex,
                SendMode::RpcStream => {
                    let msg = Duplex;

                    let (tx, rx) = self.inner.bidi_streaming(msg, 10, 10).await?;

                    EchoRpcSender::Duplex { tx, rx }
                }

                unsupported => anyhow::bail!("mode {unsupported:?} not supported by this method"),
            };

            let mut response_hasher = blake3::Hasher::new();

            for (i, data) in chunks.into_iter().enumerate() {
                let i = i + 1;

                tracing::debug!(
                    "[{i}/{num_chunks}] sending chunk with length {}",
                    data.len(),
                );

                let hash = response_hasher.reset().update(&data).finalize();

                let reported_hash = sender.send(data, Some(&self.inner)).await?;

                anyhow::ensure!(hash == reported_hash, "hash mismatch");
            }

            Ok(())
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SendMode {
    Native,
    Rpc,
    RpcStream,
    Docs,
}

impl FromStr for SendMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();

        let new = match s.as_str() {
            "stream" => Self::Native,
            "rpc" => Self::Rpc,
            "rpcstream" => Self::RpcStream,
            "docs" => Self::Docs,
            _ => anyhow::bail!("invalid: {s}"),
        };

        Ok(new)
    }
}

#[derive(Clone, Debug, clap::Parser)]
pub struct EchoHashArgs {
    /// Number of times the message is sent and expected to come back.
    #[arg(short, long, default_value_t = 1)]
    pub(crate) number: usize,

    /// The NodeId to send the message to.
    pub(crate) node_id: iroh::PublicKey,

    /// Effective message size in bytes, achieved by repeating the `msg`'s content.
    #[arg(long, default_value_t = 1024)]
    pub(crate) size: usize,

    /// Timeout in seconds for each echo round.
    #[arg(long, default_value_t = 0.1)]
    pub(crate) timeout: f64,

    /// Whether to use the IRPC API (true) or not
    #[arg(short, long)]
    pub(crate) mode: SendMode,

    /// The message that will be sent
    #[arg(default_value = "nix-fleet")]
    pub(crate) msg: String,
}

impl ProtocolHandler for EchoHashNative {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        let remote_node_id = connection.remote_id();
        debug!("accepted connection from {remote_node_id}");

        let (mut tx, mut rx) = connection.accept_bi().await?;

        // let data = Vec::new();
        let mut hasher = blake3::Hasher::new();

        let mut buf = vec![0u8; 64 * 1024];

        while let Ok(Some(n)) = rx.read(&mut buf).await {
            tracing::debug!("received data of size {n}");

            hasher.update(&buf[..n]);
        }

        let hash = hasher.finalize();

        tx.send(hash.as_bytes()).await?;
        tx.flush().await?;
        tx.finish()?;

        tracing::debug!("wrote hash {hash} to stream, waiting for connection to be closed..");

        connection.closed().await;

        tracing::debug!("connection closed");

        Ok(())
    }
}

fn chunks_from_bytes(data: bytes::Bytes, size: usize) -> Vec<bytes::Bytes> {
    let num_chunks = data.len() / size + !data.len().is_multiple_of(size) as usize;

    tracing::debug!(
        "preparing {num_chunks} chunks for {} bytes of data",
        data.len()
    );

    let container = (0..data.len())
        .step_by(size)
        .map(move |i| {
            let end = (i + size).min(data.len());
            data.slice(i..end)
        })
        .collect();

    tracing::debug!("prepared {num_chunks} chunks");

    container
}

pub mod docs {
    use anyhow::{ensure, Context};
    use bytes::Bytes;
    use futures_util::StreamExt;
    use iroh::{protocol::ProtocolHandler, Endpoint, PublicKey};
    use iroh_blobs::{
        api::{blobs::AddProgressItem, downloader::DownloadProgressItem},
        BlobsProtocol,
    };
    use iroh_docs::{
        api::protocol::{AddrInfoOptions, ShareMode},
        engine::LiveEvent,
        store::QueryBuilder,
        NamespaceId,
    };
    use irpc::{rpc_requests, Client};
    use serde::{Deserialize, Serialize};
    use tokio::{io::AsyncReadExt, time::Instant};
    use tracing::debug;

    use super::SendMode;

    #[rpc_requests(message = Message)]
    #[derive(Debug, Serialize, Deserialize)]
    enum EchoHashDocs {
        #[rpc(tx=irpc::channel::oneshot::Sender<(iroh_docs::Entry, iroh_docs::DocTicket)>)]
        #[wrap(V0Create)]
        V0Create {
            sender_pubkey: PublicKey,
            key: String,
            hash: iroh_blobs::Hash,
            size: u64,
        },

        #[rpc(tx=irpc::channel::oneshot::Sender<anyhow::Result<(), String>>)]
        #[wrap(V0Delete)]
        V0Delete {
            hash: iroh_blobs::Hash,
            doc_id: NamespaceId,
        },
    }

    enum Sender {
        /// Use irpc for coordination and blobs for bulk data transfer
        /// 1. Local: Store the data in the blob store locally
        /// 2. Local: send the V0 request to the Remote
        /// 3. Remote: pulls the data via the blob store from the sender explicitly
        /// 4. Remote: creates the docs metadata and send it back as the request response
        /// 5. Local: Verify via the docs that the Remote indeed has the hash.
        /// 6. Local: Send a deletion request to the remote
        /// 7. Remote: Delete and send a confirmation
        /// 8. Local: Verify via the docs that the Remote has deleted the data.
        V0,
    }

    const V0_KEY: &str = "echo-v0";

    impl Sender {
        async fn send(
            &self,
            remote_id: PublicKey,
            api: &EchoHashDocsApi,
            data: Bytes,
        ) -> anyhow::Result<()> {
            let EchoHashDocsApi {
                endpoint,
                docs,
                blobs,
                client,
            } = api;

            match self {
                Sender::V0 => {
                    let hash = iroh_blobs::Hash::new(&data);

                    let size = data.len() as u64;

                    let mut progress = blobs.add_bytes(data).stream().await;
                    while let Some(next) = progress.next().await {
                        tracing::debug!("progress: {next:?}");

                        if let AddProgressItem::Done(_) = next {
                            break;
                        }
                    }

                    let doc_id = {
                        let (remote_entry, ticket) = client
                            .rpc(V0Create {
                                sender_pubkey: endpoint.id(),
                                key: V0_KEY.to_string(),
                                hash,
                                size,
                            })
                            .await
                            .context("request error")?;

                        ensure!(remote_entry.content_hash() == hash, "hash mismatch");

                        let (doc, mut stream) = docs.import_and_subscribe(ticket).await?;

                        // start syncing and wait until its completion by following the stream
                        doc.start_sync(vec![remote_id.into()]).await?;
                        while let Some(event) = stream.next().await {
                            let event = event?;

                            tracing::debug!("event: {event:?}");

                            if let LiveEvent::SyncFinished(..) = event {
                                break;
                            }
                        }

                        let query = QueryBuilder::<iroh_docs::store::FlatQuery>::default()
                            .key_exact(V0_KEY)
                            .build();

                        let entry = doc
                            .get_one(query)
                            .await?
                            .ok_or_else(|| anyhow::anyhow!("couldn't find {V0_KEY} in docs"))?;

                        ensure!(entry == remote_entry, "entry mismatch");

                        // TODO: has this been enough to prove that B actually _has_ downloaded the content?

                        doc.close().await?;

                        doc.id()
                    };

                    // drop it from the local docs instance for good practice, even though it will be dropped when the program exits.
                    docs.drop_doc(doc_id).await?;

                    client
                        .rpc(V0Delete { hash, doc_id })
                        .await
                        .context("deleting key on the remote")?
                        .map_err(|s| anyhow::anyhow!(s))?;

                    Ok(())
                }
            }
        }
    }

    struct Actor {
        recv: tokio::sync::mpsc::Receiver<Message>,
        endpoint: Endpoint,
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
    }

    impl Actor {
        fn spawn(
            endpoint: Endpoint,
            blobs: BlobsProtocol,
            docs: iroh_docs::protocol::Docs,
        ) -> Client<EchoHashDocs> {
            let (tx, rx) = tokio::sync::mpsc::channel(1);
            let actor = Self {
                recv: rx,
                endpoint,
                blobs,
                docs,
            };
            tokio::task::spawn(actor.run());

            Client::local(tx)
        }

        async fn run(mut self) {
            while let Some(msg) = self.recv.recv().await {
                self.handle(msg).await
            }
        }

        async fn handle(&self, msg: Message) {
            match msg {
                Message::V0Create(irpc::WithChannels {
                    inner:
                        V0Create {
                            sender_pubkey,
                            key,
                            hash,
                            size,
                        },
                    tx,
                    ..
                }) => {
                    let handler_fn = async move || -> anyhow::Result<u64> {
                        tokio::time::timeout(std::time::Duration::from_secs(60), async {
                                        use futures_util::StreamExt;
                                        let downloader = self.blobs.downloader(&self.endpoint);
                                        let mut download_stream = downloader
                                            .download(hash, Some(sender_pubkey))
                                            .stream()
                                            .await?;

                                        let mut downloaded_size = 0;

                                        tracing::info!("downloading {key} from {sender_pubkey}");
                                        while let Some(next) = download_stream.next().await {
                                            match next {
                                                DownloadProgressItem::PartComplete { request } => {
                                                    tracing::debug!("partcomplete: {request:?}");
                                                }
                                                DownloadProgressItem::Progress(progress) => {
                                                    tracing::debug!("progress: {progress}");

                                                    downloaded_size = std::cmp::max(downloaded_size, progress);
                                                }

                                                DownloadProgressItem::Error(error) => {
                                                    anyhow::bail!("download error: {error}");
                                                }
                                                DownloadProgressItem::TryProvider { id, request } => {
                                                    tracing::debug!("try provider: {id}, {request:?}");
                                                }
                                                DownloadProgressItem::ProviderFailed { id, request } => {
                                                    anyhow::bail!("provider failed: {id}, {request:?}");
                                                }
                                                DownloadProgressItem::DownloadError => {
                                                    anyhow::bail!("download error unspecified")
                                                }
                                            }
                                        }

                                        tracing::debug!("download finished");

                                        ensure!(downloaded_size == size, "size mismatch");

                                        let author = self.docs.author_default().await?;
                                        let doc = self.docs.create().await?;

                                        doc.set_hash(author, key.clone(), hash, downloaded_size).await?;

                                        let entry = doc
                                            .get_exact(author, key.clone(), true)
                                            .await?
                                            .ok_or_else(|| anyhow::anyhow!("entry must exist"))?;

                                        let ticket = doc.share(ShareMode::Read, AddrInfoOptions::Id).await?;

                                        debug!(
                                            "create entry {entry:?} for key {key} with hash {hash} and ticket {ticket}"
                                        );

                                        doc.close().await?;

                                        tx.send((entry, ticket)).await?;

                                        Ok(downloaded_size)
                                    })
                                    .await?
                    };

                    if let Err(e) = handler_fn().await {
                        tracing::error!("{e}");
                    }
                }
                Message::V0Delete(irpc::WithChannels {
                    inner: V0Delete { doc_id, hash },
                    tx,
                    ..
                }) => {
                    let result: anyhow::Result<()> = async {
                        self.docs.drop_doc(doc_id).await.context("dropping doc")?;

                        let now = Instant::now();

                        loop {
                            self.blobs.wait_idle().await?;

                            let mut reader = self.blobs.reader(hash);

                            if (reader.read_u8().await).is_ok() {
                                continue;
                            } else {
                                break;
                            }
                        }

                        let duration = Instant::now() - now;

                        tracing::debug!("took {duration:#?} until deletion");

                        Ok(())
                    }
                    .await;

                    if let Err(e) = tx
                        .send(result.map_err(|e| {
                            tracing::error!("{e}");

                            e.to_string()
                        }))
                        .await
                    {
                        tracing::error!("{e}");
                    };
                }
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct EchoHashDocsApi {
        endpoint: Endpoint,
        blobs: BlobsProtocol,
        docs: iroh_docs::protocol::Docs,
        client: Client<EchoHashDocs>,
    }

    impl EchoHashDocsApi {
        pub const ALPN: &[u8] = b"nix-fleet/echo-hash-docs/0";

        // The frame header is a variable-length varint encoding the message size.
        // It ranges from 1 to 10 bytes depending on the message size. Using 10 as
        // the safe choice.
        pub const MAX_CHUNK_SIZE: usize = irpc::rpc::MAX_MESSAGE_SIZE as usize - 10;

        pub fn expose(&self) -> anyhow::Result<impl ProtocolHandler> {
            let local = self
                .client
                .as_local()
                .context("can not listen on remote service")?;

            let remote_handler = <EchoHashDocs as irpc::rpc::RemoteService>::remote_handler(local);

            Ok(irpc_iroh::IrohProtocol::new(remote_handler))
        }

        pub fn spawn(
            endpoint: Endpoint,
            blobs: BlobsProtocol,
            docs: iroh_docs::protocol::Docs,
        ) -> Self {
            let client = Actor::spawn(endpoint.clone(), blobs.clone(), docs.clone());

            EchoHashDocsApi {
                endpoint,
                blobs,
                docs,
                client,
            }
        }

        pub fn connect(
            endpoint: iroh::Endpoint,
            addr: impl Into<iroh::EndpointAddr>,
            blobs: BlobsProtocol,
            docs: iroh_docs::protocol::Docs,
        ) -> anyhow::Result<EchoHashDocsApi> {
            let conn = irpc_iroh::IrohLazyRemoteConnection::new(
                endpoint.clone(),
                addr.into(),
                Self::ALPN.to_vec(),
            );

            Ok(EchoHashDocsApi {
                endpoint,
                blobs,
                docs,
                client: Client::boxed(conn),
            })
        }

        /// Send the data using irpc in chunks that respect the `irpc::rpc::MAX_MESSAGE_SIZE`
        pub async fn send(
            &self,
            data: bytes::Bytes,
            mode: SendMode,
            number: usize,
            node_id: iroh::PublicKey,
            timeout: f64,
        ) -> anyhow::Result<()> {
            let sender = match mode {
                SendMode::Docs => Sender::V0,

                unsupported => anyhow::bail!("mode {unsupported:?} not supported by this method"),
            };

            for _ in 0..number {
                tokio::time::timeout(
                    std::time::Duration::from_secs_f64(timeout),
                    sender.send(node_id, self, data.clone()),
                )
                .await??;
            }

            Ok(())
        }
    }
}

#[cfg(any(test, feature = "test"))]
pub mod tests {
    use test_case::test_case;

    use crate::{
        admin::{
            self,
            cli::{AdminArgs, AdminCmd, CoordinatorArgs},
        },
        protocols::echo_hash::{EchoHashArgs, SendMode},
        test_utils::{ComponentCallbackArgs, RelayedTestContext},
    };

    pub async fn run_echo_hash_with_context(
        ctx: &RelayedTestContext,
        mode: SendMode,
        number: usize,
        size: usize,
        timeout: f64,
        direct: bool,
    ) {
        let coordinator_assets = ctx.generate_assets().unwrap();
        ctx.spawn_component(
            |ComponentCallbackArgs {
                 secret_key,
                 shutdown_rx,
                 endpoint,
             }| {
                Box::pin(async move {
                    crate::coordinator::run(
                        secret_key,
                        endpoint,
                        CoordinatorArgs::default(),
                        Some(shutdown_rx),
                    )
                    .await?;

                    Ok(())
                })
            },
            Some(coordinator_assets.clone()),
        )
        .await
        .unwrap();

        let admin_assets = ctx.generate_assets().unwrap();
        let endpoint = ctx.get_endpoint(&admin_assets).await.unwrap();
        /*
         * TODO: ask upstream to figure out why this works nested within ctx.spawn_component as opposed to directly calling `admin::run`
         * notes:
         * using `tokio::task::spawn` around `admin::run` doesn't work either.
         */

        let admin_component_fn = move |ComponentCallbackArgs { endpoint, .. }| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = anyhow::Result<_>> + Send>,
        > {
            Box::pin(async move {
                admin::run(
                    endpoint,
                    AdminArgs {
                        node_id: coordinator_assets.pubkey,
                        cmd: AdminCmd::EchoHash {
                            args: EchoHashArgs {
                                number,
                                msg: "hello".to_string(),
                                size,
                                timeout,
                                mode,
                                node_id: coordinator_assets.pubkey,
                            },
                        },
                        timeout,
                    },
                )
                .await
            })
        };

        if direct {
            let (_shutdown_tx, shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
            admin_component_fn(ComponentCallbackArgs {
                secret_key: admin_assets.key,
                shutdown_rx,
                // won't be used anyway
                endpoint,
            })
            .await
            .unwrap();
        } else {
            ctx.spawn_component(admin_component_fn, Some(admin_assets))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    #[test_log::test]
    #[test_case(SendMode::Native, 10, 1024, 1.0, true; "Native")]
    #[test_case(SendMode::Rpc, 10, 1024, 1.0, true; "Rpc")]
    #[test_case(SendMode::RpcStream, 10, 1024, 1.0, true; "RpcStream")]
    #[test_case(SendMode::Docs, 10, 1024, 1.0, false; "Docs nested")]
    #[test_case(SendMode::Docs, 10, 1024, 1.0, true => ignore /* TODO: why does this fail? */; "Docs direct")]
    pub async fn echo_completes_admin_to_coordinator(
        mode: SendMode,
        number: usize,
        size: usize,
        timeout: f64,
        direct: bool,
    ) {
        let ctx = RelayedTestContext::new().await;

        run_echo_hash_with_context(&ctx, mode, number, size, timeout, direct).await
    }
}
