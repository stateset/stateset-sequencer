#[tokio::main]
async fn main() -> anyhow::Result<()> {
    stateset_sequencer::server::run().await
}
