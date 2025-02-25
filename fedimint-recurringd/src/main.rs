use std::net::SocketAddr;

use axum::response::{IntoResponse, Response};
use axum::routing::put;
use clap::Parser;
use fedimint_logging::TracingSetup;
use reqwest::StatusCode;
use thiserror::Error;
use tokio::net::TcpListener;
use tracing::{error, info};

mod envs;

#[derive(Debug, Parser)]
#[command(version)]
struct CliOpts {
    #[arg(long = "listen", env = envs::FM_RECURRING_LISTEN_ADDR_ENV)]
    listen: SocketAddr,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    TracingSetup::default().init()?;

    let cli_opts = CliOpts::parse();
    let app = axum::Router::new().route("/paycodes", put(add_payment_code));
    let listen = cli_opts.listen;
    let listener = TcpListener::bind(&listen).await?;
    info!("Starting recurringd, listening on {listen}");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn add_payment_code() -> Result<impl IntoResponse, AdminRecurringdError> {
    Ok(())
}

#[derive(Debug, Error)]
enum AdminRecurringdError {
    #[error("Failed to add payment code")]
    FailedToAddPaymentCode,
}

impl IntoResponse for AdminRecurringdError {
    fn into_response(self) -> axum::response::Response {
        error!("{self}");
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(self.to_string().into())
            .expect("Failed to create Response")
    }
}
