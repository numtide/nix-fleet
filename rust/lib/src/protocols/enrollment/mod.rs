use anyhow::Context;
use blake3::derive_key;
use iroh_docs::api::Doc;
use iroh_docs::{Author, Capability, NamespaceSecret};
use serde::{Deserialize, Serialize};
use strum::EnumDiscriminants;

use crate::facts::Facts;

/// Agent types inform the Service about which functionality is desired and available from this node.
#[derive(Debug, Serialize, Deserialize, Default, EnumDiscriminants)]
#[strum_discriminants(derive(Default, Hash, Serialize, Deserialize, PartialOrd))]
pub enum AgentInfo {
    #[default]
    #[strum_discriminants(default)]
    Unknown,
    NixOS {
        facts: Box<Facts>,
    },
}

enum AgentEnrollmentState<P> {
    Announced,
    Assigned(P),
}

const KEY_DERIVE_CONTEXT_AUTHOR: &str = "enrollment-default-author-0";
const KEY_DERIVE_CONTEXT_NAMESPACE: &str = "enrollment-default-namespace-0";

async fn ensure_node_root_doc(
    docs: &iroh_docs::protocol::Docs,
    key: &[u8],
) -> anyhow::Result<(Author, Doc)> {
    let author = Author::from_bytes(&derive_key(KEY_DERIVE_CONTEXT_AUTHOR, key));
    docs.author_import(author.clone())
        .await
        .context("importing author")?;
    docs.author_set_default(author.id())
        .await
        .context("setting default author")?;
    let namespace_secret =
        NamespaceSecret::from_bytes(&derive_key(KEY_DERIVE_CONTEXT_NAMESPACE, key));
    let node_root_doc = docs
        .import_namespace(Capability::Write(namespace_secret))
        .await
        .context("importing root doc")?;

    Ok((author, node_root_doc))
}

pub mod enrollment_agent;
pub mod enrollment_service;

#[cfg(test)]
mod tests {
    use anyhow::Context;
    use linked_hash_map::LinkedHashMap;

    use crate::{
        admin::{
            self,
            cli::{AdminArgs, AdminCmd, AgentArgs},
        },
        protocols::enrollment::enrollment_service::{
            EnrolledServiceSubscribersT, EnrollmentServiceId, EnrollmentServiceSubscriber,
        },
        test_utils::{ComponentAssets, RelayedTestContext},
    };

    /// Verify that the agent sends its facts to the coordinator.
    /// - [x] Launch Agent
    /// - [x] Assert Admin cannot reach Coordinator
    /// - [x] Launch Coordinator
    /// - [x] Assert Admin can reach Coordinator
    /// - [x] Assert Agent is listed in information provided to Admin by Coordinator
    #[tokio::test]
    async fn admin_can_list_agents_via_coordinator() {
        let ctx = RelayedTestContext::new().await;

        // Generate the assets for the coordinator using a no-op callback
        let coordinator_assets = {
            ctx.spawn_component(|_| Box::pin(async { Ok(()) }), None)
                .await
                .unwrap()
        };

        // spawn an agent before the coordinator is up
        let agent_assets = {
            let coordinator_pubkey = coordinator_assets.pubkey;
            ctx.spawn_component(
                move |ComponentAssets { key, endpoint, .. }| {
                    Box::pin(async move {
                        crate::agent::run(
                            key,
                            endpoint,
                            AgentArgs {
                                coordinators: vec![coordinator_pubkey],
                                ..Default::default()
                            },
                        )
                        .await
                    })
                },
                None,
            )
            .await
            .unwrap()
        };

        // Generate the assets for the admin
        let admin_assets = {
            ctx.spawn_component(|_| Box::pin(async { Ok(()) }), None)
                .await
                .unwrap()
        };

        // Ensure the admin times out calling the coordinator
        admin::run(
            admin_assets.endpoint.clone(),
            AdminArgs {
                cmd: AdminCmd::ListAgents {},
                coordinators: vec![coordinator_assets.pubkey],
                timeout: 0.5,
            },
        )
        .await
        .expect_err("coordinator isn't started yet");

        ctx.spawn_component(
            |ComponentAssets { key, endpoint, .. }| {
                Box::pin(async {
                    crate::coordinator::run(key, endpoint).await?;

                    Ok(())
                })
            },
            Some(coordinator_assets.clone()),
        )
        .await
        .unwrap();

        // Ensure the coordinator responds with a populated list now
        tokio::time::timeout(std::time::Duration::from_secs_f64(10.0), async {
            loop {
                let value = admin::run(
                    admin_assets.endpoint.clone(),
                    AdminArgs {
                        cmd: AdminCmd::ListAgents {},
                        coordinators: vec![coordinator_assets.pubkey],
                        timeout: 0.5,
                    },
                )
                .await
                .expect("coordinator is online now");

                let enrolled_agents: LinkedHashMap<
                    EnrollmentServiceId,
                    EnrolledServiceSubscribersT,
                > = serde_json::from_value(value.clone())
                    .context(format!("deserializing {value:#?})"))
                    .unwrap();

                if enrolled_agents
                    .get(&coordinator_assets.pubkey)
                    .unwrap()
                    .contains_key(&agent_assets.pubkey)
                {
                    break enrolled_agents;
                } else {
                    tracing::error!("agent should be enrolled at this point: {enrolled_agents:#?}");
                    tokio::time::sleep(std::time::Duration::from_secs_f64(0.5)).await;
                }
            }
        })
        .await
        .unwrap();
    }
}
