use std::net::SocketAddr;

use axum::response::IntoResponse;
use axum::routing::post;
use axum::{Extension, Json, Router};
use axum_macros::debug_handler;
use bitcoin_hashes::hex::ToHex;
use fedimint_core::task::TaskGroup;
use fedimint_ln_client::pay::PayInvoicePayload;
use serde_json::json;
use tower_http::cors::CorsLayer;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use tracing::{error, instrument};

use super::{
    BackupPayload, BalancePayload, ConnectFedPayload, DepositAddressPayload, InfoPayload,
    RestorePayload, WithdrawPayload,
};
use crate::{GatewayError, GatewayState, Gatewayd};

pub async fn run_webserver(
    authkey: String,
    bind_addr: SocketAddr,
    gatewayd: Gatewayd,
    task_group: &mut TaskGroup,
) -> axum::response::Result<()> {
    // Public routes on gateway webserver
    let routes = Router::new().route("/pay_invoice", post(pay_invoice));

    // Authenticated, public routes used for gateway administration
    let admin_routes = Router::new()
        .route("/info", post(info))
        .route("/balance", post(balance))
        .route("/address", post(address))
        .route("/withdraw", post(withdraw))
        .route("/connect-fed", post(connect_fed))
        .route("/backup", post(backup))
        .route("/restore", post(restore))
        .layer(ValidateRequestHeaderLayer::bearer(&authkey));

    let app = Router::new()
        .merge(routes)
        .merge(admin_routes)
        .layer(Extension(gatewayd.clone()))
        .layer(CorsLayer::permissive());

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx().await;
    let server = axum::Server::bind(&bind_addr).serve(app.into_make_service());
    task_group
        .spawn("Gateway Webserver", move |_| async move {
            let graceful = server.with_graceful_shutdown(async {
                shutdown_rx.await;
            });

            if let Err(e) = graceful.await {
                error!("Error shutting down gatewayd webserver: {:?}", e);
            }
        })
        .await;

    Ok(())
}

/// Display high-level information about the Gateway
#[debug_handler]
#[instrument(skip_all, err)]
async fn info(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<InfoPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(gateway) = gatewayd.state.read().await.clone() {
        let info = gateway.handle_get_info(payload).await?;
        return Ok(Json(json!(info)));
    }

    Err(GatewayError::Disconnected)
}

/// Display gateway ecash note balance
#[debug_handler]
#[instrument(skip_all, err)]
async fn balance(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<BalancePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(gateway) = gatewayd.state.read().await.clone() {
        let amount = gateway.handle_balance_msg(payload).await?;
        return Ok(Json(json!(amount)));
    }

    Err(GatewayError::Disconnected)
}

/// Generate deposit address
#[debug_handler]
#[instrument(skip_all, err)]
async fn address(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(gateway) = gatewayd.state.read().await.clone() {
        let address = gateway.handle_address_msg(payload).await?;
        return Ok(Json(json!(address)));
    }

    Err(GatewayError::Disconnected)
}

/// Withdraw from a gateway federation.
#[debug_handler]
#[instrument(skip_all, err)]
async fn withdraw(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(gateway) = gatewayd.state.read().await.clone() {
        let txid = gateway.handle_withdraw_msg(payload).await?;
        return Ok(Json(json!(txid)));
    }

    Err(GatewayError::Disconnected)
}

#[instrument(skip_all, err)]
async fn pay_invoice(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<PayInvoicePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(gateway) = gatewayd.state.read().await.clone() {
        let preimage = gateway.handle_pay_invoice_msg(payload).await?;
        return Ok(Json(json!(preimage.0.to_hex())));
    }

    Err(GatewayError::Disconnected)
}

/// Connect a new federation
#[instrument(skip_all, err)]
async fn connect_fed(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(mut gateway) = gatewayd.state.read().await.clone() {
        let fed = gateway.handle_connect_federation(payload).await?;
        return Ok(Json(json!(fed)));
    }

    Err(GatewayError::Disconnected)
}

/// Backup a gateway actor state
#[instrument(skip_all, err)]
async fn backup(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<BackupPayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(gateway) = gatewayd.state.read().await.clone() {
        gateway.handle_backup_msg(payload).await?;
        return Ok(());
    }

    Err(GatewayError::Disconnected)
}

// Restore a gateway actor state
#[instrument(skip_all, err)]
async fn restore(
    Extension(gatewayd): Extension<Gatewayd>,
    Json(payload): Json<RestorePayload>,
) -> Result<impl IntoResponse, GatewayError> {
    if let GatewayState::Running(gateway) = gatewayd.state.read().await.clone() {
        gateway.handle_restore_msg(payload).await?;
        return Ok(());
    }

    Err(GatewayError::Disconnected)
}
