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
