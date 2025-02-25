use fedimint_core::config::FederationId;
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_common::recurring::{
    PaymentCodeRootKey, RecurringPaymentRegistrationRequest, RecurringPaymentRegistrationResponse,
};
use reqwest::{Method, StatusCode};
use thiserror::Error;

pub struct RecurringdClient {
    client: reqwest::Client,
    base_url: SafeUrl,
}

impl RecurringdClient {
    pub fn new(base_url: SafeUrl) -> Self {
        Self {
            client: reqwest::Client::new(),
            base_url,
        }
    }

    pub async fn register_recurring_payment(
        &self,
        federation_id: FederationId,
        payment_code_root_key: PaymentCodeRootKey,
    ) -> Result<RecurringPaymentRegistrationResponse, RecurringdApiError> {
        let request = RecurringPaymentRegistrationRequest {
            federation_id,
            payment_code_root_key,
        };
        let url = self.base_url.join("/paycode").expect("invalid base url");
        let mut builder = self.client.request(Method::PUT, url.to_unsafe());
        builder = builder
            .json(&request)
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        let response = builder.send().await?;
        match response.status() {
            StatusCode::OK => Ok(response
                .json::<RecurringPaymentRegistrationResponse>()
                .await?),
            status => Err(RecurringdApiError::BadStatus(status)),
        }
    }
}

#[derive(Debug, Error)]
pub enum RecurringdApiError {
    #[error("Bad status returned {0}")]
    BadStatus(StatusCode),
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
}
