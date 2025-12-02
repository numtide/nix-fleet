use std::str::FromStr;

use anyhow::Context;
use iroh::endpoint::Builder;
use iroh::{PublicKey, RelayMode, SecretKey};
use url::Url;

// Reference code in iroh-node-util showing SSH key handling: https://github.com/n0-computer/iroh-node-util/blob/3e9702ad215b9b986c6d45e4762a8fbe241163b0/src/fs.rs#L11
pub fn parse_openssh_ed25519_private(mut r: impl std::io::Read) -> anyhow::Result<SecretKey> {
    let mut raw = Vec::new();
    r.read_to_end(&mut raw)?;

    let ssh_pk = ssh_key::PrivateKey::from_openssh(raw)?;
    if ssh_pk.is_encrypted() {
        anyhow::bail!("encrypted keys are currently unsupported")
    }

    let bytes = ssh_pk
        .key_data()
        .ed25519()
        .ok_or_else(|| anyhow::anyhow!("wrong key type"))?
        .private
        .to_bytes();

    let bytes = data_encoding::HEXLOWER.encode(&bytes);
    let parsed = iroh::SecretKey::from_str(&bytes)
        .context(format!("decoding '{bytes:.3}..' ({} bytes)", bytes.len()))?;

    Ok(parsed)
}

pub fn parse_openssh_ed25519_public(mut r: impl std::io::Read) -> anyhow::Result<PublicKey> {
    let mut raw = String::new();
    r.read_to_string(&mut raw)?;

    let ssh_public_key: ssh_key::PublicKey = ssh_key::PublicKey::from_openssh(&raw)
        .context(format!("converting {raw} to ssh_key::PublicKey"))?;

    let ssh_public_key_ed25519 = ssh_public_key
        .key_data()
        .ed25519()
        .ok_or_else(|| anyhow::anyhow!("not a ed25519 public key"))?;

    Ok(PublicKey::from_bytes(&ssh_public_key_ed25519.0)?)
}

#[derive(Debug, Clone, Default)]
pub enum Discoveries {
    None,
    #[default]
    Default,
    Custom {
        secret_key: Box<SecretKey>,
        url: Box<Url>,
    },
}

pub fn generate_secret_key() -> SecretKey {
    SecretKey::generate(&mut rand::rng())
}

pub async fn get_endpoint(
    secret_key: SecretKey,
    relay_mode: Option<iroh::RelayMode>,
    discoveries: Discoveries,
) -> anyhow::Result<iroh::Endpoint> {
    let public_key = secret_key.public();

    let mut builder = iroh::Endpoint::builder().secret_key(secret_key.clone());

    if let Some(relay_mode) = &relay_mode {
        builder = builder.relay_mode(relay_mode.clone());

        // TODO: Fix HTTP relay in tests (buggy HTTPS probes against HTTP server)
        #[cfg(any(test, feature = "test"))]
        fn maybe_insecure_skip_relay_cert_verify(builder: Builder) -> Builder {
            builder.insecure_skip_relay_cert_verify(true)
        }

        #[cfg(not(any(test, feature = "test")))]
        fn maybe_insecure_skip_relay_cert_verify(builder: Builder) -> Builder {
            builder
        }

        builder = maybe_insecure_skip_relay_cert_verify(builder);
    } else {
        builder = builder.relay_mode(iroh::RelayMode::Disabled);
    }

    builder = builder.clear_discovery();
    match discoveries {
        Discoveries::Custom { secret_key, url } => {
            let pkarr_url = url.join("/pkarr")?;

            builder = builder.discovery(
                iroh::discovery::pkarr::PkarrPublisher::builder(pkarr_url.clone())
                    .build(*secret_key),
            );

            builder = builder.discovery(
                iroh::discovery::pkarr::PkarrResolver::builder(pkarr_url.clone()).build(),
            );
        }
        Discoveries::Default => {
            match iroh::discovery::mdns::MdnsDiscovery::builder()
                .advertise(true)
                .build(public_key)
            {
                Ok(mdns_discovery) => {
                    builder = builder.discovery(mdns_discovery);
                }
                Err(e) => tracing::warn!("error enabling mDNS discovery: {e}"),
            };

            if cfg!(not(test)) {
                builder = builder
                    .discovery(iroh::discovery::pkarr::PkarrPublisher::n0_dns().build(secret_key))
                    .discovery(iroh::discovery::pkarr::PkarrResolver::n0_dns().build());
            }
        }
        Discoveries::None => {}
    };

    let endpoint = builder.bind().await?;

    match relay_mode {
        Some(RelayMode::Disabled) | None => (),
        Some(_) => {
            tracing::debug!("waiting for network to be online..");
            tokio::time::timeout(tokio::time::Duration::from_secs_f64(5.0), endpoint.online())
                .await
                .context(format!("waiting for home relay: {relay_mode:?}"))?;
            tracing::debug!("network is online!");
        }
    }

    Ok(endpoint)
}

pub fn parse_relay_mode(input: &str) -> anyhow::Result<RelayMode> {
    let cleaned = input.trim().to_lowercase();
    let (variant, remainder) = cleaned.split_once(":").unwrap_or((&cleaned, ""));
    let mode = match variant {
        "disabled" => RelayMode::Disabled,
        "default" => RelayMode::Default,
        "staging" => RelayMode::Staging,
        "custom" => {
            if remainder.is_empty() {
                anyhow::bail!("custom needs an ip:port specification for a custom relay");
            }

            RelayMode::Disabled

            // TODO: support this later
        }
        other => anyhow::bail!("unsupported relay mode string: {other}"),
    };

    Ok(mode)
}

pub async fn create_blob_store(
    persistence_mode: &crate::admin::cli::PersistenceMode,
) -> anyhow::Result<(
    iroh_docs::engine::ProtectCallbackHandler,
    iroh_blobs::api::Store,
)> {
    let (protect_callback_handler, protect_callback) =
        iroh_docs::engine::ProtectCallbackHandler::new();
    let gc_config = Some(iroh_blobs::store::GcConfig {
        interval: std::time::Duration::from_mins(10),
        add_protected: Some(protect_callback),
    });

    let blob_store = match persistence_mode {
        crate::admin::cli::PersistenceMode::Memory => {
            let mem_store =
                iroh_blobs::store::mem::MemStore::new_with_opts(iroh_blobs::store::mem::Options {
                    gc_config,
                });

            iroh_blobs::api::Store::from(mem_store)
        }
        crate::admin::cli::PersistenceMode::Filesystem(ref path_buf) => {
            let path_buf = path_buf.join("blob_store");
            std::fs::DirBuilder::new()
                .recursive(true)
                .create(&path_buf)?;
            let fs_store = iroh_blobs::store::fs::FsStore::load_with_opts(
                path_buf.join("blob_fs_store.db"),
                iroh_blobs::store::fs::options::Options {
                    path: iroh_blobs::store::fs::options::PathOptions::new(&path_buf),
                    gc: gc_config,
                    inline: Default::default(),
                    batch: Default::default(),
                },
            )
            .await
            .context(format!("creating FsStore at {path_buf:?}"))?;

            iroh_blobs::api::Store::from(fs_store)
        }
    };

    Ok((protect_callback_handler, blob_store))
}

pub(crate) async fn setup_iroh_docs_and_deps(
    endpoint: &iroh::Endpoint,
    persistence_mode: &crate::admin::cli::PersistenceMode,
) -> anyhow::Result<(
    iroh_blobs::BlobsProtocol,
    iroh_blobs::api::Store,
    iroh_gossip::Gossip,
    iroh_docs::protocol::Docs,
)> {
    let (protect_callback_handler, blob_store) =
        crate::util::create_blob_store(persistence_mode).await?;
    let blobs = iroh_blobs::BlobsProtocol::new(&blob_store, None);
    let gossip = iroh_gossip::Gossip::builder().spawn(endpoint.clone());
    let docs = match persistence_mode {
        crate::admin::cli::PersistenceMode::Memory => iroh_docs::protocol::Docs::memory(),
        crate::admin::cli::PersistenceMode::Filesystem(path_buf) => {
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

    Ok((blobs, blob_store, gossip, docs))
}

#[derive(Debug)]
pub enum StreamKind {
    Stdout,
    Stderr,
}

/// Returns a stream of interleaved lines from `stdout` and `stderr` with precise timestamps.
/// The stream yields `(timestamp, kind, line)`.
/// Order is approximately preserved based on when lines are read asynchronously (close to terminal behavior).
pub fn merged_output_stream(
    child: &mut tokio::process::Child,
) -> anyhow::Result<impl futures_util::Stream<Item = (tokio::time::Instant, StreamKind, String)>> {
    use tokio::io::AsyncBufReadExt;

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("never had stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("never had stderr"))?;

    // Buffer size; adjust as needed
    let (tx, rx) = tokio::sync::mpsc::channel(128);

    // Spawn task for stdout
    let value = tx.clone();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = value
                .send((tokio::time::Instant::now(), StreamKind::Stdout, line))
                .await;
        }
    });

    // Spawn task for stderr
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let _ = tx
                .send((tokio::time::Instant::now(), StreamKind::Stderr, line))
                .await;
        }
    });

    Ok(tokio_stream::wrappers::ReceiverStream::new(rx))
}
