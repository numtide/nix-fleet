pub use tokio;

pub mod coordinator {
    use anyhow::Context;
    use iroh::Watcher;

    pub async fn run() -> anyhow::Result<()> {
        // Create an endpoint, it allows creating and accepting
        // connections in the iroh p2p world
        let endpoint = iroh::Endpoint::builder()
            .discovery(iroh::discovery::mdns::MdnsDiscoveryBuilder)
            // .discovery_n0()
            .bind()
            .await?;

        // handle a new incoming connection on the endpoint
        async fn handle_endpoint_accept(
            connecting: iroh::endpoint::Connecting,
        ) -> anyhow::Result<()> {
            let connection = connecting.await.context("error accepting connection")?;
            let remote_node_id = &connection.remote_node_id()?;
            eprintln!("connection from {remote_node_id}");
            let (_sender, mut reader) = connection
                .accept_bi()
                .await
                .context("error accepting stream")?;

            let mut buf = vec![];
            let Some(n_bytes) = reader.read(&mut buf).await? else {
                panic!("got none");
            };

            eprintln!("read {n_bytes}");

            Ok(())
        }

        let mut node_addr = endpoint.node_addr();
        let node_id = node_addr.initialized().await.node_id;
        eprintln!("got node_id {node_id}");

        loop {
            let incoming = tokio::select! {
                incoming = endpoint.accept() => incoming,
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("got ctrl-c, exiting");
                    break;
                }
            };
            let Some(incoming) = incoming else {
                break;
            };
            let Ok(connecting) = incoming.accept() else {
                break;
            };
            tokio::spawn(async move {
                if let Err(cause) = handle_endpoint_accept(connecting).await {
                    // log error at warn level
                    //
                    // we should know about it, but it's not fatal
                    eprintln!("error handling connection: {}", cause);
                }
            });
        }

        Ok(())
    }
}

pub mod agent {
    pub async fn run() -> anyhow::Result<()> {
        // Create an endpoint, it allows creating and accepting
        // connections in the iroh p2p world
        let endpoint = iroh::Endpoint::builder()
            .discovery(iroh::discovery::mdns::MdnsDiscoveryBuilder)
            // .discovery_n0()
            .bind()
            .await?;

        Ok(())
    }
}

pub mod admin {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
