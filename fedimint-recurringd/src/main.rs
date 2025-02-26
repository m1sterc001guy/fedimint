use std::net::SocketAddr;
use std::path::PathBuf;

use axum::extract::{Path, Query};
use axum::response::IntoResponse;
use axum::routing::{get, put};
use axum::{Extension, Json};
use clap::Parser;
use fedimint_core::Amount;
use fedimint_core::module::serde_json::json;
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_common::recurring::{PaymentCodeId, RecurringPaymentRegistrationRequest};
use fedimint_logging::TracingSetup;
use fedimint_recurringd::{RecurringInvoiceServer, RecurringPaymentError};
use serde::Deserialize;
use tokio::net::TcpListener;
use tracing::info;

mod envs;

#[derive(Debug, Parser)]
#[command(version)]
struct CliOpts {
    #[arg(long = "listen", env = envs::FM_RECURRING_LISTEN_ADDR_ENV)]
    listen: SocketAddr,

    #[arg(long = "api-address", env = envs::FM_RECURRING_API_ADDR_ENV)]
    api_address: SafeUrl,

    #[arg(long = "data-dir", env = envs::FM_RECURRINGD_DATA_DIR_ENV)]
    data_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli_opts = CliOpts::parse();
    let listen = cli_opts.listen;
    let api_addr = cli_opts.api_address;
    let data_dir = cli_opts.data_dir;
    let recurring_invoice_server = RecurringInvoiceServer::new(api_addr.clone(), data_dir.clone())?;
    let app = axum::Router::new()
        .route("/paycodes", put(add_payment_code))
        .route("/paycodes/:payment_code_id/invoice", get(lnurl_pay_invoice))
        .layer(Extension(recurring_invoice_server));
    let listener = TcpListener::bind(&listen).await?;
    info!(?listen, ?api_addr, ?data_dir, "Starting recurringd...");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn add_payment_code(
    Extension(recurring_invoice_server): Extension<RecurringInvoiceServer>,
    Json(request): Json<RecurringPaymentRegistrationRequest>,
) -> Result<impl IntoResponse, RecurringPaymentError> {
    let payment_code = recurring_invoice_server
        .register_recurring_payment_code(request)
        .await?;
    Ok(Json(json!(payment_code)))
}

async fn lnurl_pay_invoice(
    Extension(recurring_invoice_server): Extension<RecurringInvoiceServer>,
    Path(payment_code_id): Path<PaymentCodeId>,
    Query(params): Query<GetInvoiceParams>,
) -> Result<impl IntoResponse, RecurringPaymentError> {
    let invoice = recurring_invoice_server
        .lnurl_invoice(payment_code_id, params.amount)
        .await?;
    Ok(Json(invoice))
}

#[derive(Debug, Deserialize)]
struct GetInvoiceParams {
    amount: Amount,
}
