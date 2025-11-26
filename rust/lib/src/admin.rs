use crate::admin::cli::AdminArgs;

pub mod cli;

/// Run the Admin command.
/// The only stop condition is currently either an error or Ctrl+C.
pub async fn run(
    endpoint: iroh::Endpoint,
    admin_args: AdminArgs,
) -> anyhow::Result<serde_json::Value> {
    let AdminArgs {
        timeout,
        cmd,
        node_id,
    } = admin_args;

    let timeout = std::time::Duration::from_secs_f64(timeout);

    let json_value = match cmd {
        cli::AdminCmd::EchoHash { args } => {
            serde_json::to_value(crate::protocols::echo_hash::send(endpoint, args).await?)?
        }

        cli::AdminCmd::Ping {} => {
            let start = tokio::time::Instant::now();
            let client =
                crate::protocols::enrollment::enrollment_agent::EnrollmentAgentClient::connect(
                    endpoint, node_id,
                )
                .await?;
            let time_to_connect = tokio::time::Instant::now() - start;

            let result = client.ping().await?;

            tracing::info!("time to connect: {time_to_connect:?}. ping time {result:#?}");

            serde_json::to_value(())?
        }
        cli::AdminCmd::EnrollmentAgent { cmd } => {
            let client =
                crate::protocols::enrollment::enrollment_agent::EnrollmentAgentClient::connect(
                    endpoint, node_id,
                )
                .await?;

            match cmd {
                cli::EnrollmentAgentCmd::Ping => {
                    let duration = client.ping().await?;

                    serde_json::to_value(format!("ping to {node_id} took {duration:?}"))?
                }
                cli::EnrollmentAgentCmd::GetFacts => {
                    let result = client.get_facts().await?;

                    serde_json::to_value(result)?
                }
            }
        }
        cli::AdminCmd::EnrollmentService { cmd } => {
            let client =
                crate::protocols::enrollment::enrollment_service::EnrollmentServiceClient::connect(
                    endpoint.clone(),
                    node_id,
                    timeout,
                )
                .await?;

            match cmd {
                cli::EnrollmentServiceCmd::Ping => {
                    let duration = client.ping(timeout).await?;

                    serde_json::to_value(duration)?
                }
                cli::EnrollmentServiceCmd::ListAgents => {
                    let response = client.list_subscribers(timeout).await?;

                    serde_json::to_value(response)?
                }
                cli::EnrollmentServiceCmd::GetFacts { node_id } => {
                    let response = client.get_subscriber_facts(timeout, node_id).await?;

                    serde_json::to_value(response)?
                }
            }
        }
    };

    tracing::debug!("response: {json_value:#?}");

    Ok(json_value)
}
