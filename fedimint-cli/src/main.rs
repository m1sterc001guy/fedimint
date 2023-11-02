use fedimint_cli::FedimintCli;
use nostrmint_client::ResolvrClientGen;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    FedimintCli::new()?
        .with_default_modules()
        .with_module(ResolvrClientGen)
        .run()
        .await;
    Ok(())
}
