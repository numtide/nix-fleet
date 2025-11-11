//! A simple protocol that will echo back the data to the sender.rc
//! It serves as an internal reference for evaluating Iroh's primitive.

use anyhow::Context;
use arc_slice::{ArcSlice, ArcSliceMut};
use iroh::protocol::{AcceptError, ProtocolHandler};
use irpc::{rpc::MAX_MESSAGE_SIZE, rpc_requests, Client, WithChannels};
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::Arc};
use tokio::time::Instant;
use tracing::{debug, info, trace};

#[derive(Debug)]
pub struct Echo;

impl Echo {
    pub const ALPN: &[u8] = b"nix-fleet/echo/0";

    pub async fn send(
        &self,
        endpoint: iroh::Endpoint,
        EchoArgs {
            number,
            node_id,
            size,
            timeout,
            msg,
            mode,
        }: EchoArgs,
    ) -> anyhow::Result<()> {
        let generate_data_iter = std::iter::repeat(msg.into_bytes().into_iter())
            .flatten()
            .take(size);

        let mut buffer = ArcSliceMut::<[u8]>::new();
        buffer.extend(generate_data_iter);
        let msg = buffer.freeze();

        let msg_hash = blake3::Hasher::new().update(&msg).finalize().to_string();

        match mode {
            SendMode::Stream => {
                stream(&endpoint, number, node_id, timeout, msg.clone(), msg_hash).await?
            }
            SendMode::Rpc | SendMode::RpcStream => {
                let api_client = EchoRpcApi::connect(endpoint, node_id)?;

                for i in 0..number {
                    let t_0 = Instant::now();

                    trace!("[{i}] writing ({:e} bytes) to stream", msg.len());

                    tokio::time::timeout(std::time::Duration::from_secs_f64(timeout), async {
                        match mode {
                            SendMode::Rpc | SendMode::RpcStream => {
                                api_client.send_irpc(msg.clone(), mode.clone()).await
                            }
                            SendMode::Stream => unreachable!(),
                        }
                    })
                    .await??;

                    let rtt = Instant::now().duration_since(t_0);

                    // The data is sent once in each direction
                    let b_s = 2. * msg.len() as f64 / (rtt.as_secs_f64() * 1024. * 1024.);

                    info!(
                        "[{i}] transferring {:e} bytes completed within {rtt:#?} at {b_s:.4} MiB/s",
                        2 * msg.len()
                    );
                }
            }
        };

        Ok(())
    }
}

#[rpc_requests(message = EchoRpcMessage)]
#[derive(Debug, Serialize, Deserialize)]
enum EchoRpc {
    // The handler receives the data via the request struct and gets a sender for the response.
    #[rpc(tx=irpc::channel::oneshot::Sender<ArcSlice<[u8]>>)]
    #[wrap(Simplex)]
    Simplex { data: ArcSlice<[u8]> },
    // The handler gets a receiver for the data and a sender for the response
    #[rpc(tx=irpc::channel::mpsc::Sender<ArcSlice<[u8]>>, rx=irpc::channel::mpsc::Receiver<ArcSlice<[u8]>>)]
    #[wrap(Duplex)]
    Duplex,
}

enum EchoSender {
    Simplex,

    Duplex {
        tx: irpc::channel::mpsc::Sender<ArcSlice<[u8]>>,
        rx: irpc::channel::mpsc::Receiver<ArcSlice<[u8]>>,
    },
}

impl EchoSender {
    async fn send(
        &mut self,
        data: ArcSlice<[u8]>,
        maybe_client: Option<&Client<EchoRpc>>,
    ) -> anyhow::Result<ArcSlice<[u8]>> {
        match (self, maybe_client) {
            (Self::Simplex, None) => {
                anyhow::bail!("need a client for simplex sending");
            }

            (Self::Simplex, Some(client)) => Ok(client.rpc(Simplex { data }).await?),
            (Self::Duplex { tx, rx }, _) => {
                tx.send(data).await?;

                let response = rx
                    .recv()
                    .await
                    .context("receiving data")?
                    .ok_or_else(|| anyhow::anyhow!("did not receive a value back"))?;

                Ok(response)
            }
        }
    }
}

struct EchoActor {
    recv: tokio::sync::mpsc::Receiver<EchoRpcMessage>,
}

impl EchoActor {
    pub fn spawn() -> EchoRpcApi {
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let actor = Self { recv: rx };
        tokio::task::spawn(actor.run());
        EchoRpcApi {
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
                if let Err(e) = tx.send(data).await {
                    tracing::error!("error sending back data: {e}");
                }
            }
            EchoRpcMessage::Duplex(WithChannels { tx, mut rx, .. }) => {
                while let Ok(Some(data)) = rx.recv().await {
                    tracing::info!("received data with length {}. sending back..", data.len());
                    if let Err(e) = tx.send(data).await {
                        tracing::error!("error sending back data: {e}");
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct EchoRpcApi {
    inner: Client<EchoRpc>,
}

impl EchoRpcApi {
    pub const ALPN: &[u8] = b"nix-fleet/echo-irpc/0";

    // The frame header is a variable-length varint encoding the message size.
    // It ranges from 1 to 10 bytes depending on the message size. Using 10 as
    // the safe choice.
    pub const MAX_CHUNK_SIZE: usize = irpc::rpc::MAX_MESSAGE_SIZE as usize - 10;

    pub fn expose(&self) -> anyhow::Result<impl ProtocolHandler> {
        let local = self
            .inner
            .as_local()
            .context("can not listen on remote service")?;

        let remote_handler = <EchoRpc as irpc::rpc::RemoteService>::remote_handler(local);

        Ok(irpc_iroh::IrohProtocol::new(remote_handler))
    }

    pub fn spawn() -> Self {
        EchoActor::spawn()
    }

    pub fn connect(
        endpoint: iroh::Endpoint,
        addr: impl Into<iroh::EndpointAddr>,
    ) -> anyhow::Result<EchoRpcApi> {
        let conn =
            irpc_iroh::IrohLazyRemoteConnection::new(endpoint, addr.into(), Self::ALPN.to_vec());

        Ok(EchoRpcApi {
            inner: Client::boxed(conn),
        })
    }

    /// Send the data using irpc in chunks that respect the `irpc::rpc::MAX_MESSAGE_SIZE`
    pub async fn send_irpc(&self, data: ArcSlice<[u8]>, mode: SendMode) -> anyhow::Result<()> {
        let data_hash = blake3::Hasher::new().update(&data).finalize().to_string();

        let chunks = chunks_from_arc_slice(data, Self::MAX_CHUNK_SIZE);
        let num_chunks = chunks.len();

        let mut response_hasher = blake3::Hasher::new();

        let mut sender = match mode {
            SendMode::Stream => anyhow::bail!("{mode:?} not supported by this method"),
            SendMode::Rpc => EchoSender::Simplex,
            SendMode::RpcStream => {
                let msg = Duplex;

                let (tx, rx) = self.inner.bidi_streaming(msg, 10, 10).await?;

                EchoSender::Duplex { tx, rx }
            }
        };

        for (i, data) in chunks.into_iter().enumerate() {
            let i = i + 1;

            tracing::debug!(
                "[{i}/{num_chunks}] sending chunk with length {}",
                data.len(),
            );

            let response = sender.send(data, Some(&self.inner)).await?;

            tracing::debug!(
                "[{i}/{num_chunks}] received back data with length {}",
                response.len(),
            );

            response_hasher.update(&response);
        }

        let response_hash = response_hasher.finalize().to_string();

        if data_hash != response_hash {
            anyhow::bail!("mismatch in response");
        }

        Ok(())
    }
}

async fn stream(
    endpoint: &iroh::Endpoint,
    number: usize,
    node_id: iroh::PublicKey,
    timeout: f64,
    msg: ArcSlice<[u8]>,
    msg_hash: String,
) -> Result<(), anyhow::Error> {
    let connection = endpoint
        .connect(node_id, Echo::ALPN)
        .await
        .context(format!("connecting to {node_id}"))?;
    let msg = std::sync::Arc::new(msg);
    let (tx, mut rx) = connection.open_bi().await?;
    let tx = std::sync::Arc::new(tokio::sync::Mutex::new(tx));
    for i in 0..number {
        let t_0 = Instant::now();

        trace!("[{i}] writing ({:e} bytes) to stream", msg.len());

        // The protocol requires the sender to start receiving back immediately or else it will stall.
        tokio::spawn({
            let msg = std::sync::Arc::clone(&msg);

            let tx = Arc::clone(&tx);

            async move {
                let mut tx_locked = tx.lock().await;

                tx_locked
                    .write_all(&msg)
                    .await
                    .context(format!("writing {} bytes to stream", msg.len()))?;

                trace!("[{i}] wrote ({:e} bytes) to stream", msg.len());

                anyhow::Ok(())
            }
        });

        let mut reader_future = async || {
            let mut len = 0;

            let mut hasher = blake3::Hasher::new();

            while let Some(chunk) = rx.read_chunk(MAX_MESSAGE_SIZE as usize, true).await? {
                len += chunk.bytes.len();
                hasher.update(&chunk.bytes);

                if len == msg.len() {
                    break;
                }
            }

            let hash = hasher.finalize().to_string();

            anyhow::Ok((hash, len))
        };

        trace!("[{i}] waiting for an answer..");
        tokio::select! {
            read_result = reader_future() => {
                let (hash, len) = read_result?;

                trace!("read {len} bytes from stream");

                let rtt = Instant::now().duration_since(t_0);

                anyhow::ensure!(msg_hash == hash, format!("[{i}] hash mismatch"));

                // The data is sent once in each direction
                let b_s =
                    2. * msg.len() as f64
                    /
                    (rtt.as_secs_f64() * 1024. * 1024.)
                    ;

                info!(
                    "[{i}] transferring {:e} bytes completed within {rtt:#?} at {b_s:.4} MiB/s",
                    2 * msg.len()
                );
            },

            _ = tokio::time::sleep(std::time::Duration::from_secs_f64(timeout)) => {
                anyhow::bail!("timeout");
            }
        }
    }
    connection.close(0u32.into(), b"finished");
    Ok(())
}

// FIXME: investigate the performance difference between these modes. From a manual echo run on localhost:
// Stream: transferring 3.5651584e7 bytes completed within 193.131097ms at 176.0462 MiB/s
// Rpc: transferring 3.5651584e7 bytes completed within 834.675349ms at 40.7344 MiB/s
// RpcStream: transferring 3.5651584e7 bytes completed within 833.704091ms at 40.7819 MiB/s
#[derive(Debug, Clone)]
pub enum SendMode {
    Stream,
    Rpc,
    RpcStream,
}

impl FromStr for SendMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim().to_lowercase();

        let new = match s.as_str() {
            "stream" => Self::Stream,
            "rpc" => Self::Rpc,
            "rpcstream" => Self::RpcStream,
            _ => anyhow::bail!("invalid: {s}"),
        };

        Ok(new)
    }
}

#[derive(Clone, Debug, clap::Parser)]
pub struct EchoArgs {
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

impl ProtocolHandler for Echo {
    async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
        let remote_node_id = connection.remote_id();
        debug!("accepted connection from {remote_node_id}");

        let (mut tx, mut rx) = connection.accept_bi().await?;

        let num_bytes_copied = tokio::io::copy(&mut rx, &mut tx).await?;

        debug!("copied {num_bytes_copied} bytes");

        tx.finish()?;

        connection.closed().await;

        Ok(())
    }
}

fn chunks_from_arc_slice(data: ArcSlice<[u8]>, size: usize) -> Vec<ArcSlice<[u8]>> {
    let num_chunks = data.len() / size + !data.len().is_multiple_of(size) as usize;

    tracing::debug!(
        "preparing {num_chunks} chunks for {} bytes of data",
        data.len()
    );

    let mut container = Vec::<ArcSlice<[u8]>>::new();
    for i in 0..num_chunks {
        let from = i * size;
        let to = std::cmp::min(data.len(), from + size);
        let data = data.subslice(from..to);
        container.push(data);
    }

    tracing::debug!("prepared {num_chunks} chunks");

    container
}

#[cfg(any(test, feature = "test"))]
pub mod tests {
    use iroh::{Endpoint, RelayMode};
    use test_case::test_case;
    use tokio::task::JoinHandle;
    use tracing_test::traced_test;

    use crate::{
        admin::{
            self,
            cli::{AdminArgs, AdminCmd},
        },
        coordinator,
        protocols::echo::{EchoArgs, SendMode},
        util::{self, get_endpoint},
    };

    pub struct EchoCompletesFnContext {
        #[allow(unused)]
        relay_server: iroh_relay::server::Server,
        #[allow(unused)]
        iroh_dns_http_server: iroh_dns_server::http::HttpServer,
        #[allow(unused)]
        coordinator_handle: JoinHandle<Result<(), anyhow::Error>>,

        coordinator_pubkey: iroh::PublicKey,
        admin_endpoint: Endpoint,
    }

    impl EchoCompletesFnContext {
        pub async fn new() -> EchoCompletesFnContext {
            // run a local relay server
            let relay_server =
                iroh_relay::server::Server::spawn(iroh_relay::server::testing::server_config())
                    .await
                    .unwrap();
            let relay_mode = {
                // TODO: switch to http and remove the insecure TLS verification workaround
                let relay_url = relay_server.https_url().unwrap();

                let relay_map: iroh::RelayMap = iroh::RelayConfig {
                    url: relay_url,
                    quic: None,
                }
                .into();

                Some(RelayMode::Custom(relay_map.clone()))
            };

            let (iroh_dns_http_server, iroh_dns_http_url, _iroh_dns_server, iroh_dns_url) =
                util::iroh_dns_spawn_for_tests_with_options().await.unwrap();

            tracing::info!("test servers running:\nrelay: {relay_mode:?}\niroh_dns_http: {iroh_dns_http_url}\niroh_dns: {iroh_dns_url}");

            // coordinator
            let coordinator_key = iroh::SecretKey::generate(&mut rand::rng());
            let coordinator_pubkey = coordinator_key.public();
            let coordinator_endpoint = get_endpoint(
                Some(coordinator_key.clone()),
                relay_mode.clone(),
                util::Discoveries::Custom {
                    secret_key: Box::new(coordinator_key),
                    url: iroh_dns_http_url.clone().into(),
                },
            )
            .await
            .unwrap();
            let coordinator_handle = tokio::spawn(coordinator::run(coordinator_endpoint));

            // admin
            let admin_key = iroh::SecretKey::generate(&mut rand::rng());
            let _admin_pubkey = admin_key.public();
            let admin_endpoint = get_endpoint(
                Some(admin_key.clone()),
                relay_mode.clone(),
                util::Discoveries::Custom {
                    secret_key: admin_key.into(),
                    url: iroh_dns_http_url.clone().into(),
                },
            )
            .await
            .unwrap();

            EchoCompletesFnContext {
                relay_server,
                iroh_dns_http_server,
                coordinator_pubkey,
                coordinator_handle,
                admin_endpoint,
            }
        }

        pub async fn run(&self, mode: SendMode, number: usize, size: usize, timeout: f64) {
            let EchoCompletesFnContext {
                coordinator_pubkey,
                admin_endpoint,
                ..
            } = self;

            admin::run(
                admin_endpoint.clone(),
                AdminArgs {
                    cmd: AdminCmd::Echo {
                        args: EchoArgs {
                            number,
                            node_id: *coordinator_pubkey,
                            msg: "hello".to_string(),
                            size,
                            timeout,
                            mode,
                        },
                    },
                    coordinators: vec![],
                },
            )
            .await
            .unwrap();
        }
    }

    #[traced_test]
    #[tokio::test]
    #[test_case(SendMode::Stream, 10, 1024, 1.0; "Stream")]
    #[test_case(SendMode::Rpc, 10, 1024, 1.0; "Rpc")]
    #[test_case(SendMode::RpcStream, 10, 1024, 1.0; "RpcStream")]
    pub async fn echo_completes_admin_to_coordinator(
        mode: SendMode,
        number: usize,
        size: usize,
        timeout: f64,
    ) {
        let context = EchoCompletesFnContext::new().await;

        context.run(mode, number, size, timeout).await
    }
}
