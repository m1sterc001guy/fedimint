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
        info!("recurringd tests successful");
        Ok(())
    })
    .await
}
