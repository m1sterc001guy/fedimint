use std::str::FromStr;

use clap::{Parser, Subcommand};
use devimint::federation::Federation;
use devimint::version_constants::VERSION_0_3_0;
use devimint::{cmd, util};
use fedimint_core::config::FederationId;
use fedimint_testing::gateway::LightningNodeType;
use ln_gateway::rpc::FederationInfo;
use tracing::info;

#[derive(Parser)]
struct GatewayTestOpts {
    #[clap(subcommand)]
    test: GatewayTest,

    #[arg(long = "gw-type")]
    gateway_type: LightningNodeType,
}

#[derive(Debug, Clone, Subcommand)]
enum GatewayTest {
    ConfigTest,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = GatewayTestOpts::parse();
    match opts.test {
        GatewayTest::ConfigTest => config_test(opts.gateway_type).await,
    }
}

async fn config_test(gw_type: LightningNodeType) -> anyhow::Result<()> {
    devimint::run_devfed_test(|process_mgr, dev_fed| async move {
        let gw = match gw_type {
            LightningNodeType::Lnd => dev_fed.gw_lnd_registered().await?,
            LightningNodeType::Cln => dev_fed.gw_cln_registered().await?,
        };

        // Try to connect to already connected federation
        let gatewayd_version = util::Gatewayd::version_or_default().await;
        if gatewayd_version >= *VERSION_0_3_0 {
            let invite_code = dev_fed.fed().await?.invite_code()?;
            let output = cmd!(gw, "connect-fed", invite_code.clone())
                .out_json()
                .await;
            assert!(
                output.is_err(),
                "Connecting to the same federation succeeded"
            );
            info!("Verified that gateway couldn't connect to already connected federation");
        }

        info!("Creating new federation...");
        let bitcoind = dev_fed.bitcoind().await?.clone();
        let new_fed = Federation::new(&process_mgr, bitcoind, 4, true).await?;
        if gatewayd_version >= *VERSION_0_3_0 {
            let invite_code = new_fed.invite_code()?;
            let output = cmd!(gw, "connect-fed", invite_code.clone())
                .out_json()
                .await?;
            let info: FederationInfo =
                serde_json::from_value(output).expect("connect fed is serializable");
            let expected_fed_id = FederationId::from_str(&new_fed.calculate_federation_id().await)?;
            assert_eq!(
                expected_fed_id, info.federation_id,
                "Federation id of joined federation does not match"
            );
            info!("Verified that gateway can join a new federation");
        }

        // TODO: Add more configuration verification here

        // Leave federation
        let fed_id = dev_fed.fed().await?.calculate_federation_id().await;
        let fedimint_cli_version = util::FedimintCli::version_or_default().await;
        let gatewayd_version = util::Gatewayd::version_or_default().await;

        // `leave-fed` did not return any output until 0.3.0
        if fedimint_cli_version >= *VERSION_0_3_0 && gatewayd_version >= *VERSION_0_3_0 {
            let leave_fed = cmd!(gw, "leave-fed", "--federation-id", fed_id.clone())
                .out_json()
                .await
                .expect("Leaving the federation failed");

            let fed_info: FederationInfo =
                serde_json::from_value(leave_fed).expect("Could not parse FederationInfo");
            assert_eq!(fed_info.federation_id.to_string(), fed_id);
        }

        info!("Verified gateway left federation {fed_id}");

        info!("Gateway configuration test successful");
        Ok(())
    })
    .await
}
