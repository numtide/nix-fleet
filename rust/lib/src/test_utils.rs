use std::{collections::HashMap, pin::Pin, sync::Arc};

use iroh::{Endpoint, PublicKey, RelayMode, SecretKey};
use tokio::task::JoinHandle;

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

pub type ComponentTask = Arc<
    tokio::sync::Mutex<
        HashMap<
            PublicKey,
            (
                SecretKey,
                JoinHandle<anyhow::Result<Box<dyn erased_serde::Serialize + Send>>>,
            ),
        >,
    >,
>;

pub struct RelayedTestContext {
    pub(crate) relay_server: iroh_relay::server::Server,
    pub(crate) iroh_dns_http_server: iroh_dns_server::http::HttpServer,
    pub(crate) relay_mode: Option<RelayMode>,
    pub(crate) iroh_dns_http_url: url::Url,
    pub(crate) component_tasks: ComponentTask,
}

#[derive(Clone)]
pub struct ComponentAssets {
    pub pubkey: PublicKey,
    pub key: SecretKey,
    pub endpoint: Endpoint,
}

impl RelayedTestContext {
    pub async fn new() -> RelayedTestContext {
        // run a local relay server
        let relay_server =
            iroh_relay::server::Server::spawn(iroh_relay::server::testing::server_config())
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

        let (iroh_dns_http_server, iroh_dns_http_url, _iroh_dns_server, iroh_dns_url) =
            iroh_dns_spawn_for_tests_with_options().await.unwrap();

        tracing::info!("test servers running:\nrelay: {relay_mode:?}\niroh_dns_http: {iroh_dns_http_url}\niroh_dns: {iroh_dns_url}");

        // let admin_key = iroh::SecretKey::generate(&mut rand::rng());

        RelayedTestContext {
            relay_server,
            iroh_dns_http_server,
            relay_mode,
            iroh_dns_http_url,
            component_tasks: Default::default(),
        }
    }

    pub async fn spawn_component<S, F>(
        &self,
        mut component_fn: F,
        maybe_assets_override: Option<ComponentAssets>,
    ) -> anyhow::Result<ComponentAssets>
    where
        S: erased_serde::Serialize + Send + 'static,
        F: FnMut(
                ComponentAssets,
            )
                -> Pin<Box<dyn std::future::Future<Output = anyhow::Result<S>> + Send>>
            + Send
            + 'static,
    {
        let assets = match maybe_assets_override {
            Some(assets) => assets,
            None => {
                let key = iroh::SecretKey::generate(&mut rand::rng());

                let (key, endpoint) = get_endpoint(
                    Some(key.clone()),
                    self.relay_mode.clone(),
                    util::Discoveries::Custom {
                        secret_key: Box::new(key),
                        url: self.iroh_dns_http_url.clone().into(),
                    },
                )
                .await
                .unwrap();

                ComponentAssets {
                    pubkey: key.public(),
                    key,
                    endpoint,
                }
            }
        };

        let task_handle = {
            let assets = assets.clone();

            tokio::task::spawn(async move {
                component_fn(assets)
                    .await
                    .map(|s| Box::new(s) as Box<dyn erased_serde::Serialize + Send>)
            })
        };

        // Ensure the previous task is aborted before spawning a new one with the same key
        if let Some((_, task_handle)) = self.component_tasks.lock().await.remove(&assets.pubkey) {
            task_handle.abort();
            if let Err(e) = task_handle.await {
                tracing::debug!("error aborting previous task: {e}")
            };
        };

        self.component_tasks
            .lock()
            .await
            .insert(assets.pubkey, (assets.key.clone(), task_handle));

        Ok(assets)
    }
}
