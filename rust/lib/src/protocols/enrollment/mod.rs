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

const DOC_KEY_DERIVE_CONTEXT_AUTHOR: &str = "enrollment-author-default-0";
const DOC_KEY_DERIVE_CONTEXT_NAMESPACE_ROOT_0: &str = "enrollment-namespace-root-0";
const DOC_KEY_DERIVE_CONTEXT_NAMESPACE_FACTS_0: &str = "enrollment-namespace-facts-0";

pub const DOC_KEY_FACTS_FIRST: &str = "enrollment-actor/facts/first";
pub const DOC_KEY_FACTS_LATEST: &str = "enrollment-actor/facts/latest";

async fn ensure_node_doc_with_derived_keys(
    docs: &iroh_docs::protocol::Docs,
    key: &[u8],
    namespace_derive_key: &str,
) -> anyhow::Result<(Author, Doc)> {
    let author = Author::from_bytes(&derive_key(DOC_KEY_DERIVE_CONTEXT_AUTHOR, key));
    docs.author_import(author.clone())
        .await
        .context("importing author")?;
    docs.author_set_default(author.id())
        .await
        .context("setting default author")?;
    let namespace_secret = NamespaceSecret::from_bytes(&derive_key(namespace_derive_key, key));
    let doc = docs
        .import_namespace(Capability::Write(namespace_secret))
        .await
        .context("importing root doc")?;

    Ok((author, doc))
}

pub mod enrollment_agent;
pub mod enrollment_service;

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use crate::{
        admin::{
            self,
            cli::{AdminArgs, AdminCmd, AgentArgs, EnrollmentServiceCmd},
        },
        facts::Facts,
        protocols::enrollment::enrollment_service::EnrolledServiceSubscribersT,
        test_utils::{ComponentAssets, RelayedTestContext},
    };

    /// Verify that the agent subscribes to a service.
    /// - [x] Launch Agent
    /// - [x] Assert Admin cannot reach Coordinator
    /// - [x] Launch Coordinator
    /// - [x] Assert Admin can reach Coordinator
    /// - [x] Assert Agent is listed in information provided to Admin by Coordinator
    #[tokio::test]
    #[test_log::test]
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
                                maybe_coordinator: Some(coordinator_pubkey),
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
                node_id: coordinator_assets.pubkey,
                timeout: 0.5,
                cmd: AdminCmd::EnrollmentService {
                    cmd: EnrollmentServiceCmd::ListAgents,
                },
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
                        node_id: coordinator_assets.pubkey,
                        timeout: 0.5,
                        cmd: AdminCmd::EnrollmentService {
                            cmd: EnrollmentServiceCmd::ListAgents,
                        },
                    },
                )
                .await
                .expect("coordinator is online now");

                let enrolled_agents: EnrolledServiceSubscribersT =
                    serde_json::from_value(value.clone())
                        .context(format!("deserializing {value:#?})"))
                        .unwrap();

                if enrolled_agents.contains_key(&agent_assets.pubkey) {
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

    /// Verify that the agent sends its facts to the coordinator.
    /// - [x] Launch Agent
    /// - [x] Launch Coordinator
    /// - [x] Assert Admin can get the facts for the Agent from the Coordinator
    #[tokio::test]
    #[test_log::test]
    async fn admin_can_get_subscriber_facts_via_coordinator() {
        let ctx = RelayedTestContext::new().await;

        let coordinator_assets = ctx
            .spawn_component(
                |ComponentAssets { key, endpoint, .. }| {
                    Box::pin(async {
                        crate::coordinator::run(key, endpoint).await?;

                        Ok(())
                    })
                },
                None,
            )
            .await
            .unwrap();

        let agent_assets = {
            let coordinator_pubkey = coordinator_assets.pubkey;
            ctx.spawn_component(
                move |ComponentAssets { key, endpoint, .. }| {
                    Box::pin(async move {
                        crate::agent::run(
                            key,
                            endpoint,
                            AgentArgs {
                                maybe_coordinator: Some(coordinator_pubkey),
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

        // Ensure the coordinator responds with a the facts within a given time
        let _facts = tokio::time::timeout(std::time::Duration::from_secs_f64(2.0), async {
            loop {
                match admin::run(
                    admin_assets.endpoint.clone(),
                    AdminArgs {
                        node_id: coordinator_assets.pubkey,
                        timeout: 0.5,
                        cmd: AdminCmd::EnrollmentService {
                            cmd: EnrollmentServiceCmd::GetFacts {
                                node_id: agent_assets.pubkey,
                            },
                        },
                    },
                )
                .await
                .map_err(|s| s.to_string())
                .and_then(|s| {
                    serde_json::from_value::<Facts>(s.clone())
                        .map_err(|e| format!("error deserializing {s}: {e}"))
                }) {
                    Ok(facts) => break facts,
                    Err(e) => {
                        tracing::error!("waiting for agent facts: {e:#?}");
                        tokio::time::sleep(std::time::Duration::from_secs_f64(0.5)).await;
                        continue;
                    }
                }
            }
        })
        .await
        .unwrap();

        // TODO(double-check): anything particular to assert in the facts?
    }
}
