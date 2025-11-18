use iroh::RelayMode;
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

pub struct RelayedTestContext {
    #[allow(unused)]
    pub(crate) relay_server: iroh_relay::server::Server,
    #[allow(unused)]
    pub(crate) iroh_dns_http_server: iroh_dns_server::http::HttpServer,
    #[allow(unused)]
    pub(crate) coordinator_handle: JoinHandle<Result<(), anyhow::Error>>,

    pub(crate) coordinator_pubkey: iroh::PublicKey,
    pub(crate) relay_mode: Option<RelayMode>,
    pub(crate) iroh_dns_http_url: url::Url,
    pub(crate) admin_key: iroh::SecretKey,
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
        let coordinator_handle = tokio::spawn(crate::coordinator::run(coordinator_endpoint));

        let admin_key = iroh::SecretKey::generate(&mut rand::rng());

        RelayedTestContext {
            relay_server,
            iroh_dns_http_server,
            coordinator_pubkey,
            coordinator_handle,
            relay_mode,
            iroh_dns_http_url,
            admin_key,
        }
    }
}
