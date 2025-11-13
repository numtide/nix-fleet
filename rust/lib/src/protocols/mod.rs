//! Protocol logic used on top of iroh

pub mod echo;

pub mod enrollment {
    use iroh::protocol::{AcceptError, ProtocolHandler};
    use tracing::info;

    #[derive(Debug)]
    pub struct Enrollment;

    impl Enrollment {
        pub const ALPN: &[u8] = b"nix-fleet/enrollment/0";
    }

    impl ProtocolHandler for Enrollment {
        async fn accept(&self, connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
            let remote_node_id = connection.remote_id();
            info!("accepted enrollment connection from {remote_node_id}");

            Err(AcceptError::User {
                source: "this is not implemented".into(),
                meta: Default::default(),
            })
        }
    }
}

pub mod node_admin {

    use iroh::protocol::{AcceptError, ProtocolHandler};

    #[derive(Debug)]
    pub struct NodeAdmin;

    impl NodeAdmin {
        pub const ALPN: &[u8] = b"nix-fleet/node-admin/0";
    }

    impl ProtocolHandler for NodeAdmin {
        async fn accept(&self, _connection: iroh::endpoint::Connection) -> Result<(), AcceptError> {
            Err(AcceptError::User {
                source: "todo".into(),
                meta: Default::default(),
            })
        }
    }
}
