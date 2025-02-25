mod api;

use api::{RecurringdApiError, RecurringdClient};
use bitcoin::key::Keypair;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::util::SafeUrl;
use fedimint_derive_secret::ChildId;
use fedimint_lnv2_common::recurring::PaymentCodeRootKey;
use futures::StreamExt;

use crate::LightningClientModule;
use crate::db::{RecurringPaymentCodeEntry, RecurringPaymentCodePrefix};

impl LightningClientModule {
    pub async fn register_recurring_payment(
        &self,
        recurringd_api: SafeUrl,
    ) -> Result<RecurringPaymentCodeEntry, RecurringdApiError> {
        let mut module_dbtx = self.client_ctx.module_db().begin_transaction().await;
        let next_idx = module_dbtx
            .find_by_prefix_sorted_descending(&RecurringPaymentCodePrefix)
            .await
            .map(|(k, _)| k.0)
            .next()
            .await
            .unwrap_or(0);
        let payment_code_root_key = self.get_payment_code_root_key(next_idx);

        let recurringd_client = RecurringdClient::new(recurringd_api.clone());
        let register_response = recurringd_client
            .register_recurring_payment(
                self.federation_id,
                PaymentCodeRootKey(payment_code_root_key.public_key()),
            )
            .await?;

        let payment_code_entry = RecurringPaymentCodeEntry {
            code: register_response.recurring_payment_code,
            recurringd_api,
            creation_time: fedimint_core::time::now(),
        };

        module_dbtx.commit_tx().await;
        Ok(payment_code_entry)
    }

    fn get_payment_code_root_key(&self, payment_code_registration_idx: u64) -> Keypair {
        self.recurring_payment_code_secret
            .child_key(ChildId(payment_code_registration_idx))
            .to_secp_key(fedimint_core::secp256k1::SECP256K1)
    }
}
