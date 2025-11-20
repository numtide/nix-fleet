//! Protocol logic used on top of iroh

pub mod echo_hash;

pub mod enrollment;

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
