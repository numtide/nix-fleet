use lib::coordinator;

#[tokio::main]
async fn main() {
    coordinator::run().await.unwrap();
}
