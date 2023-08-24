use std::sync::Arc;

use clap::Parser;
use ln_gateway::client::GatewayLightningBuilder;
use ln_gateway::{GatewayOpts, Gatewayd};

/// Fedimint Gateway Binary
///
/// This binary runs a webserver with an API that can be used by Fedimint
/// clients to request routing of payments through the Lightning Network.
/// It uses a `GatewayLightningClient`, an rpc client to communicate with a
/// remote Lightning node accessible through a `GatewayLightningServer`.
#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let gateway_opts = GatewayOpts::parse();
    let lightning_builder = Arc::new(GatewayLightningBuilder {
        lightning_mode: gateway_opts.mode.clone(),
    });
    Gatewayd::new(lightning_builder, gateway_opts)?
        .with_default_modules()
        .run()
        .await
}
