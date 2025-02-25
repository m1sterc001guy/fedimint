use std::net::SocketAddr;
use std::path::PathBuf;

use axum::response::IntoResponse;
use axum::routing::put;
use axum::{Extension, Json};
use clap::Parser;
use fedimint_core::module::serde_json::json;
use fedimint_core::util::SafeUrl;
use fedimint_lnv2_common::recurring::RecurringPaymentRegistrationRequest;
use fedimint_logging::TracingSetup;
use fedimint_recurringd::{RecurringInvoiceServer, RecurringPaymentError};
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
        .route("/paycode", put(add_payment_code))
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
