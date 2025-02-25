use std::path::PathBuf;

use axum::response::{IntoResponse, Response};
use db::{PaymentCodeEntry, PaymentCodeKey};
use fedimint_core::db::{Database, IDatabaseTransactionOpsCoreTyped};
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_common::recurring::{
    PaymentCodeId, RecurringPaymentRegistrationRequest, RecurringPaymentRegistrationResponse,
};
use fedimint_rocksdb::RocksDb;
use lnurl::lnurl::LnUrl;
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
            payment_code: payment_code.clone(),
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
}

#[derive(Debug, Error)]
pub enum RecurringPaymentError {
    #[error("Failed to add payment code: {0}")]
    FailedToAddPaymentCode(String),
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
