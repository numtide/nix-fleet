use std::{collections::HashMap, pin::Pin, sync::Arc};

use iroh::{Endpoint, PublicKey, RelayMode, SecretKey};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender},
    task::JoinHandle,
};

use crate::util::{self, get_endpoint};

/// Spawn a server suitable for testing, while optionally enabling mainline with custom
/// bootstrap addresses.
pub async fn iroh_dns_spawn_for_tests_with_options() -> anyhow::Result<(
    iroh_dns_server::http::HttpServer,
    url::Url,
    iroh_dns_server::dns::DnsServer,
    std::net::SocketAddr,
)> {
    use std::net::{IpAddr, Ipv4Addr};

    let mut config = iroh_dns_server::config::Config::default();
    config.dns.port = 0;
    config.dns.bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    config.http.as_mut().unwrap().port = 0;
    config.http.as_mut().unwrap().bind_addr = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));
    config.https = None;
    config.metrics = Some(iroh_dns_server::config::MetricsConfig::disabled());

    let store = iroh_dns_server::ZoneStore::in_memory(Default::default(), Default::default())
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let dns_handler =
        iroh_dns_server::dns::DnsHandler::new(store.clone(), &config.dns, Default::default())
            .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let state = iroh_dns_server::state::AppState {
        store,
        dns_handler,
        metrics: Default::default(),
    };

    let http_server = iroh_dns_server::http::HttpServer::spawn(
        config.http,
        config.https,
        config.pkarr_put_rate_limit,
        state.clone(),
    )
    .await
    .unwrap();

    let dns_server = iroh_dns_server::dns::DnsServer::spawn(config.dns, state.dns_handler.clone())
        .await
        .map_err(|e| anyhow::anyhow!(e.to_string()))?;

    let dns_addr = dns_server.local_addr();
    let http_addr = http_server.http_addr().expect("http is set");
    let http_url = format!("http://{http_addr}").parse::<url::Url>()?;
    Ok((http_server, http_url, dns_server, dns_addr))
}

pub struct ComponentTask {
    pub secret_key: SecretKey,
    pub handle: JoinHandle<anyhow::Result<Box<dyn erased_serde::Serialize + Send>>>,
    pub shutdown_tx: UnboundedSender<()>,
    pub endpoint: iroh::Endpoint,
}
pub type ComponentTasks = Arc<tokio::sync::Mutex<HashMap<PublicKey, ComponentTask>>>;

pub struct ComponentCallbackArgs {
    pub secret_key: SecretKey,
    pub shutdown_rx: UnboundedReceiver<()>,
    pub endpoint: iroh::Endpoint,
}

pub struct RelayedTestContext {
    pub relay_server: iroh_relay::server::Server,
    pub iroh_dns_http_server: iroh_dns_server::http::HttpServer,
    pub iroh_dns_server: iroh_dns_server::dns::DnsServer,
    pub relay_mode: Option<RelayMode>,
    pub iroh_dns_http_url: url::Url,
    pub component_tasks: ComponentTasks,
}

#[derive(Debug, Clone)]
pub struct ComponentAssets {
    pub key: SecretKey,
    pub pubkey: PublicKey,
}

impl RelayedTestContext {
    pub async fn new() -> RelayedTestContext {
        // run a local relay server
        let relay_server = iroh_relay::server::Server::spawn(iroh_relay::server::ServerConfig {
            relay: Some(iroh_relay::server::testing::relay_config()),
            quic: None,
            metrics_addr: None,
        })
        .await
        .unwrap();
        let relay_mode = Some({
            // TODO: switch to http and remove the insecure TLS verification workaround
            let relay_url = relay_server.https_url().unwrap();

            let relay_map: iroh::RelayMap = iroh::RelayConfig {
                url: relay_url,
                quic: None,
            }
            .into();

            RelayMode::Custom(relay_map.clone())
        });

        let (iroh_dns_http_server, iroh_dns_http_url, iroh_dns_server, iroh_dns_url) =
            iroh_dns_spawn_for_tests_with_options().await.unwrap();

        tracing::info!("test servers running:\nrelay: {relay_mode:?}\niroh_dns_http: {iroh_dns_http_url}\niroh_dns: {iroh_dns_url}");

        RelayedTestContext {
            relay_server,
            iroh_dns_http_server,
            iroh_dns_server,
            relay_mode,
            iroh_dns_http_url,
            component_tasks: Default::default(),
        }
    }

    pub fn generate_assets(&self) -> anyhow::Result<ComponentAssets> {
        let key = iroh::SecretKey::generate(&mut rand::rng());

        Ok(ComponentAssets {
            pubkey: key.public(),
            key,
        })
    }

    pub async fn get_endpoint(&self, assets: &ComponentAssets) -> anyhow::Result<Endpoint> {
        let endpoint = get_endpoint(
            assets.key.clone(),
            self.relay_mode.clone(),
            util::Discoveries::Custom {
                secret_key: Box::new(assets.key.clone()),
                url: self.iroh_dns_http_url.clone().into(),
            },
        )
        .await?;

        Ok(endpoint)
    }

    pub async fn spawn_component<S, F>(
        &self,
        mut component_fn: F,
        maybe_assets_override: Option<ComponentAssets>,
    ) -> anyhow::Result<ComponentAssets>
    where
        S: erased_serde::Serialize + Send + 'static,
        F: FnMut(
                ComponentCallbackArgs,
            )
                -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<S>> + Send>>
            + Send
            + 'static,
    {
        let assets = match maybe_assets_override {
            Some(assets) => assets,
            None => self.generate_assets()?,
        };

        // Ensure the previous task is aborted before spawning a new one with the same key
        if self
            .component_tasks
            .lock()
            .await
            .contains_key(&assets.pubkey)
        {
            let _ = self
                .shutdown_component(assets.pubkey)
                .await
                .map_err(|e| tracing::warn!("couldn't cleanly shutdown previous task: {e}"));
        };

        let component_task = {
            let assets = assets.clone();

            let (shutdown_tx, shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

            let endpoint = self.get_endpoint(&assets).await?;

            let callback_args = ComponentCallbackArgs {
                secret_key: assets.key.clone(),
                shutdown_rx,
                endpoint: endpoint.clone(),
            };

            let task_handle = tokio::task::spawn(async move {
                component_fn(callback_args)
                    .await
                    .map(|s| Box::new(s) as Box<dyn erased_serde::Serialize + Send>)
            });

            ComponentTask {
                secret_key: assets.key.clone(),
                handle: task_handle,
                shutdown_tx,
                endpoint,
            }
        };

        self.component_tasks
            .lock()
            .await
            .insert(assets.pubkey, component_task);

        Ok(assets)
    }

    pub async fn shutdown_component(&self, pubkey: PublicKey) -> anyhow::Result<()> {
        let ComponentTask {
            handle,
            shutdown_tx,
            ..
        }: ComponentTask = self
            .component_tasks
            .lock()
            .await
            .remove(&pubkey)
            .ok_or_else(|| anyhow::anyhow!("no task found for {pubkey}"))?;

        let _ = shutdown_tx.send(());

        let outer = handle
            .await
            .map(|inner| inner.map_err(|e| e.to_string()))
            .map_err(|e| e.to_string());

        match outer {
            Ok(Ok(_)) => (),
            Ok(Err(e)) | Err(e) => tracing::error!("{e}"),
        }

        Ok(())
    }
}
