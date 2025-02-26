use std::path::PathBuf;

use axum::response::{IntoResponse, Response};
use db::{PaymentCodeEntry, PaymentCodeKey};
use fedimint_core::Amount;
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_client::LightningClientModule;
use fedimint_lnv2_common::Bolt11InvoiceDescription;
use fedimint_lnv2_common::recurring::{
    PaymentCodeId, RecurringPaymentRegistrationRequest, RecurringPaymentRegistrationResponse,
};
use fedimint_rocksdb::RocksDb;
use lightning_invoice::Bolt11Invoice;
use lnurl::lnurl::LnUrl;
use lnurl::pay::LnURLPayInvoice;
use reqwest::StatusCode;
use thiserror::Error;
use tracing::{error, info};

mod db;

#[derive(Clone)]
pub struct RecurringInvoiceServer {
    base_url: SafeUrl,
    db: Database,
}

impl RecurringInvoiceServer {
    pub fn new(base_url: SafeUrl, data_dir: PathBuf) -> anyhow::Result<Self> {
        let db = Database::new(RocksDb::open(data_dir)?, Default::default());
        Ok(Self { base_url, db })
    }

    pub async fn register_recurring_payment_code(
        &self,
        request: RecurringPaymentRegistrationRequest,
    ) -> Result<RecurringPaymentRegistrationResponse, RecurringPaymentError> {
        let payment_code = self.create_lnurl(request.payment_code_root_key.to_payment_code_id());
        let federation_id = request.federation_id;
        let payment_code_entry = PaymentCodeEntry {
            root_key: request.payment_code_root_key,
            federation_id,
            agg_pk: request.agg_pk,
            payment_code: payment_code.clone(),
            gateway: request.gateway,
        };
        let mut dbtx = self.db.begin_transaction().await;
        if let Some(existing_code) = dbtx
            .insert_entry(
                &PaymentCodeKey(request.payment_code_root_key.to_payment_code_id()),
                &payment_code_entry,
            )
            .await
        {
            if existing_code != payment_code_entry {
                return Err(RecurringPaymentError::FailedToAddPaymentCode(
                    "Payment code already exists".to_string(),
                ));
            }

            dbtx.ignore_uncommitted();
            return Ok(RecurringPaymentRegistrationResponse {
                recurring_payment_code: payment_code,
            });
        }

        info!(
            ?federation_id,
            ?payment_code,
            "Successfully registered recurring payment code"
        );
        dbtx.commit_tx().await;

        Ok(RecurringPaymentRegistrationResponse {
            recurring_payment_code: payment_code,
        })
    }

    fn create_lnurl(&self, payment_code_id: PaymentCodeId) -> String {
        let lnurl = LnUrl::from_url(format!("{}paycodes/{}", self.base_url, payment_code_id));
        lnurl.encode()
    }

    pub async fn lnurl_invoice(
        &self,
        payment_code_id: PaymentCodeId,
        amount: Amount,
    ) -> Result<LnURLPayInvoice, RecurringPaymentError> {
        Ok(LnURLPayInvoice::new(
            self.create_bolt11_invoice(payment_code_id, amount)
                .await?
                .to_string(),
        ))
    }

    async fn create_bolt11_invoice(
        &self,
        payment_code_id: PaymentCodeId,
        amount: Amount,
    ) -> Result<Bolt11Invoice, RecurringPaymentError> {
        let payment_code_entry = self
            .db
            .begin_transaction_nc()
            .await
            .get_value(&PaymentCodeKey(payment_code_id))
            .await
            .ok_or(RecurringPaymentError::UnknownPaymentCode)?;
        let routing_info = LightningClientModule::routing_info(
            &payment_code_entry.gateway,
            &payment_code_entry.federation_id,
        )
        .await
        .map_err(|_| RecurringPaymentError::FailedToCreateInvoice)?
        .ok_or(RecurringPaymentError::FailedToCreateInvoice)?;
        let expiry = 3600;
        let description = Bolt11InvoiceDescription::Direct("".to_string());
        // TODO: Ideally we can call the federation's gateway API directly, or take a
        // Vec<SafeUrl>
        let (_, _, invoice) = LightningClientModule::create_contract_and_fetch_invoice(
            payment_code_entry.root_key.0,
            amount,
            expiry,
            description,
            payment_code_entry.gateway,
            routing_info,
            payment_code_entry.federation_id,
            payment_code_entry.agg_pk,
        )
        .await
        .map_err(|_| RecurringPaymentError::FailedToCreateInvoice)?;
        Ok(invoice)
    }
}

#[derive(Debug, Error)]
pub enum RecurringPaymentError {
    #[error("Failed to add payment code: {0}")]
    FailedToAddPaymentCode(String),
    #[error("Unknown payment code")]
    UnknownPaymentCode,
    #[error("Failed to create invoice")]
    FailedToCreateInvoice,
}

impl IntoResponse for RecurringPaymentError {
    fn into_response(self) -> axum::response::Response {
        error!("{self}");
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(self.to_string().into())
            .expect("Failed to create Response")
    }
}
