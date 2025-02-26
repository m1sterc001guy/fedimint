use devimint::cmd;
use fedimint_core::module::serde_json;
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_client::db::RecurringPaymentCodeEntry;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    devimint::run_devfed_test(|dev_fed, process_mgr| async move {
        let client = dev_fed
            .fed()
            .await?
            .new_joined_client("recurringd-client")
            .await?;

        info!("Registering LDK Gateway...");
        let gw_ldk = dev_fed
            .gw_ldk_connected()
            .await?
            .as_ref()
            .expect("Gateways of version 0.5.0 or higher support LDK");
        for peer in 0..dev_fed.fed().await?.members.len() {
            cmd!(
                client,
                "--our-id",
                peer.to_string(),
                "--password",
                "pass",
                "module",
                "lnv2",
                "gateways",
                "add",
                gw_ldk.addr
            )
            .run()
            .await?;
        }

        info!("Registering payment code...");
        let recurring_api = format!(
            "http://127.0.0.1:{}",
            process_mgr.globals.FM_PORT_RECURRINGD
        );
        let payment_code_val = cmd!(
            client,
            "module",
            "lnv2",
            "register-recurring",
            recurring_api
        )
        .out_json()
        .await?;
        let recurring_response =
            serde_json::from_value::<RecurringPaymentCodeEntry>(payment_code_val)
                .expect("Couldn't deserialize response");
        assert_eq!(
            recurring_response.recurringd_api,
            SafeUrl::parse(&recurring_api).expect("Couldnt parse recurringd_api")
        );
        info!(?recurring_response, "Recurring Response");
        info!("recurringd tests successful");
        Ok(())
    })
    .await
}
