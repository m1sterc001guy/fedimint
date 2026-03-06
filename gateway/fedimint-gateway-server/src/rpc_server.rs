use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use axum::extract::{Path, Query, Request};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use bitcoin::hashes::sha256;
use fedimint_core::config::FederationId;
use fedimint_core::task::TaskGroup;
use fedimint_core::util::FmtCompact;
use fedimint_gateway_common::{
    ADDRESS_ENDPOINT, ADDRESS_RECHECK_ENDPOINT, BACKUP_ENDPOINT, BackupPayload,
    CLOSE_CHANNELS_WITH_PEER_ENDPOINT, CONFIGURATION_ENDPOINT, CONNECT_FED_ENDPOINT,
    CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT, CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
    CloseChannelsWithPeerRequest, ConfigPayload, ConnectFedPayload,
    CreateInvoiceForOperatorPayload, CreateOfferPayload, DepositAddressPayload,
    DepositAddressRecheckPayload, GATEWAY_INFO_ENDPOINT, GET_BALANCES_ENDPOINT,
    GET_INVOICE_ENDPOINT, GET_LN_ONCHAIN_ADDRESS_ENDPOINT, GatewayRole, GetInvoiceRequest,
    INVITE_CODES_ENDPOINT, LEAVE_FED_ENDPOINT, LIST_CHANNELS_ENDPOINT, LIST_TRANSACTIONS_ENDPOINT,
    LeaveFedPayload, ListTransactionsPayload, MNEMONIC_ENDPOINT, OPEN_CHANNEL_ENDPOINT,
    OpenChannelRequest, PAY_INVOICE_FOR_OPERATOR_ENDPOINT, PAY_OFFER_FOR_OPERATOR_ENDPOINT,
    PAYMENT_LOG_ENDPOINT, PAYMENT_SUMMARY_ENDPOINT, PayInvoiceForOperatorPayload, PayOfferPayload,
    PaymentLogPayload, PaymentSummaryPayload, RECEIVE_ECASH_ENDPOINT, ReceiveEcashPayload,
    SEND_ONCHAIN_ENDPOINT, SET_FEES_ENDPOINT, SPEND_ECASH_ENDPOINT, STOP_ENDPOINT,
    SendOnchainRequest, SetFeesPayload, SetMnemonicPayload, SpendEcashPayload, V1_API_ENDPOINT,
    WITHDRAW_ENDPOINT, WithdrawPayload,
};
use fedimint_gateway_ui::IAdminGateway;
use fedimint_ln_common::gateway_endpoint_constants::{
    GET_GATEWAY_ID_ENDPOINT, PAY_INVOICE_ENDPOINT,
};
use fedimint_lnurl::LnurlResponse;
use fedimint_lnv2_common::endpoint_constants::{
    CREATE_BOLT11_INVOICE_ENDPOINT, ROUTING_INFO_ENDPOINT, SEND_PAYMENT_ENDPOINT,
};
use fedimint_lnv2_common::gateway_api::{CreateBolt11InvoicePayload, SendPaymentPayload};
use fedimint_logging::LOG_GATEWAY;
use hex::ToHex;
use serde::de::DeserializeOwned;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::cors::CorsLayer;
use tracing::{info, instrument, warn};

use crate::error::{GatewayError, LnurlError};
use crate::iroh_server::{Handlers, start_iroh_endpoint};
use crate::{Gateway, GatewayState};

/// Creates the webserver's routes and spawns the webserver in a separate task.
pub async fn run_webserver(
    gateway: Arc<Gateway>,
    mut mnemonic_receiver: tokio::sync::broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let task_group = gateway.task_group.clone();
    let mut handlers = Handlers::new();

    let routes = routes(gateway.clone(), task_group.clone(), &mut handlers);
    let ui_routes = fedimint_gateway_ui::router(gateway.clone());
    let api_v1 = Router::new()
        .nest(&format!("/{V1_API_ENDPOINT}"), routes.clone())
        // Backwards compatibility: Continue supporting gateway APIs without versioning
        .merge(routes)
        .merge(ui_routes);

    let handle = task_group.make_handle();
    let shutdown_rx = handle.make_shutdown_rx();
    let listener = TcpListener::bind(&gateway.listen).await?;
    let serve = axum::serve(listener, api_v1.into_make_service());
    task_group.spawn("Gateway Webserver", |_| async {
        let graceful = serve.with_graceful_shutdown(async {
            shutdown_rx.await;
        });

        match graceful.await {
            Err(err) => {
                warn!(target: LOG_GATEWAY, err = %err.fmt_compact(), "Error shutting down gatewayd webserver");
            }
            _ => {
                info!(target: LOG_GATEWAY, "Successfully shutdown webserver");
            }
        }
    });
    info!(target: LOG_GATEWAY, listen = %gateway.listen, "Successfully started webserver");

    // Don't start the Iroh endpoint until the mnemonic has been set via HTTP or the
    // UI
    if let GatewayState::NotConfigured { .. } = gateway.get_state().await {
        info!(target: LOG_GATEWAY, "Waiting for the mnemonic to be set before starting iroh loop.");
        let _ = mnemonic_receiver.recv().await;
    }

    start_iroh_endpoint(&gateway, task_group, Arc::new(handlers)).await?;

    Ok(())
}

/// Extracts the Bearer token from the Authorization header of the request.
fn extract_bearer_token(request: &Request) -> Result<String, StatusCode> {
    let headers = request.headers();
    let auth_header = headers.get(header::AUTHORIZATION);
    if let Some(header_value) = auth_header {
        let auth_str = header_value
            .to_str()
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        let token = auth_str.trim_start_matches("Bearer ").to_string();
        return Ok(token);
    }

    Err(StatusCode::UNAUTHORIZED)
}

async fn not_configured_middleware(
    Extension(gateway): Extension<Arc<Gateway>>,
    request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    if matches!(
        gateway.get_state().await,
        GatewayState::NotConfigured { .. }
    ) {
        let method = request.method().clone();
        let path = request.uri().path();

        // Allow the API mnemonic endpoint (for CLI usage)
        let is_mnemonic_api = method == axum::http::Method::POST
            && (path == MNEMONIC_ENDPOINT
                || path == format!("/{V1_API_ENDPOINT}/{MNEMONIC_ENDPOINT}"));

        let is_setup_route = fedimint_gateway_ui::is_allowed_setup_route(path);

        if !is_mnemonic_api && !is_setup_route {
            return Err(StatusCode::NOT_FOUND);
        }
    }

    Ok(next.run(request).await)
}

/// The authenticated user's role, attached to requests via Extension.
/// This is set by `auth_middleware` after successful authentication.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedRole(pub GatewayRole);

/// Middleware to authenticate an incoming request. Routes that are
/// authenticated with this middleware always require a Bearer token to be
/// supplied in the Authorization header.
///
/// On successful authentication, attaches an `AuthenticatedRole` extension
/// to the request indicating whether the user is an Admin or User.
async fn auth_middleware(
    Extension(gateway): Extension<Arc<Gateway>>,
    mut request: Request,
    next: Next,
) -> Result<impl IntoResponse, StatusCode> {
    let token = extract_bearer_token(&request)?;

    // Check admin password first
    if bcrypt::verify(&token, &gateway.bcrypt_password_hash.to_string())
        .expect("Bcrypt hash is valid since we just stringified it")
    {
        request
            .extensions_mut()
            .insert(AuthenticatedRole(GatewayRole::Admin));
        return Ok(next.run(request).await);
    }

    // Check user password if configured
    if let Some(ref user_hash) = gateway.bcrypt_user_password_hash {
        if bcrypt::verify(&token, &user_hash.to_string())
            .expect("Bcrypt hash is valid since we just stringified it")
        {
            request
                .extensions_mut()
                .insert(AuthenticatedRole(GatewayRole::User));
            return Ok(next.run(request).await);
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}

/// Returns an error if the authenticated role is not Admin.
/// Use this at the start of handlers that require admin access.
///
/// For HTTP requests, the role is extracted from the request extensions.
/// For Iroh requests, the role is not available via Extension (it's handled
/// separately in the Iroh server), so we pass None and assume admin access
/// since Iroh authenticated routes are admin-only.
pub fn require_admin(role: Option<&Extension<AuthenticatedRole>>) -> Result<(), GatewayError> {
    // If role is None (Iroh case), assume admin since Iroh auth = admin only
    if let Some(Extension(role)) = role {
        if role.0 != GatewayRole::Admin {
            return Err(GatewayError::Forbidden("Admin access required".to_string()));
        }
    }
    Ok(())
}

/// Registers a GET API handler for both the HTTP server and the Iroh
/// `Endpoint`.
fn register_get_handler<F, Fut>(
    handlers: &mut Handlers,
    route: &str,
    func: F,
    is_authenticated: bool,
    router: Router,
) -> Router
where
    F: Fn(Extension<Arc<Gateway>>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    handlers.add_handler(route, func.clone(), is_authenticated);
    router.route(route, get(func))
}

/// Registers a POST API handler for both the HTTP server and the Iroh
/// `Endpoint`.
fn register_post_handler<P, F, Fut>(
    handlers: &mut Handlers,
    route: &str,
    func: F,
    is_authenticated: bool,
    router: Router,
) -> Router
where
    P: DeserializeOwned + Send + 'static,
    F: Fn(Extension<Arc<Gateway>>, Json<P>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    handlers.add_handler_with_payload(route, func.clone(), is_authenticated);
    router.route(route, post(func))
}

/// Registers an HTTP-only POST handler (not for Iroh).
/// Use this for handlers that need role-based authorization.
fn register_http_post_handler<P, F, Fut>(route: &str, func: F, router: Router) -> Router
where
    P: DeserializeOwned + Send + 'static,
    F: Fn(Extension<Arc<Gateway>>, Option<Extension<AuthenticatedRole>>, Json<P>) -> Fut
        + Clone
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    router.route(route, post(func))
}

/// Registers an HTTP-only GET handler (not for Iroh).
/// Use this for handlers that need role-based authorization.
fn register_http_get_handler<F, Fut>(route: &str, func: F, router: Router) -> Router
where
    F: Fn(Extension<Arc<Gateway>>, Option<Extension<AuthenticatedRole>>) -> Fut
        + Clone
        + Send
        + Sync
        + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    router.route(route, get(func))
}

/// Registers an Iroh-only handler (admin access only).
/// This is for handlers that also have HTTP versions with role checking.
fn register_iroh_post_handler<P, F, Fut>(handlers: &mut Handlers, route: &str, func: F)
where
    P: DeserializeOwned + Send + 'static,
    F: Fn(Extension<Arc<Gateway>>, Json<P>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    handlers.add_handler_with_payload(route, func, true);
}

/// Registers an Iroh-only GET handler (admin access only).
fn register_iroh_get_handler<F, Fut>(handlers: &mut Handlers, route: &str, func: F)
where
    F: Fn(Extension<Arc<Gateway>>) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<Json<serde_json::Value>, GatewayError>> + Send + 'static,
{
    handlers.add_handler(route, func, true);
}

/// Public routes that are used in the LNv1 protocol
fn lnv1_routes(handlers: &mut Handlers) -> Router {
    let router = Router::new();
    let router = register_post_handler(handlers, PAY_INVOICE_ENDPOINT, pay_invoice, false, router);
    register_get_handler(
        handlers,
        GET_GATEWAY_ID_ENDPOINT,
        get_gateway_id,
        false,
        router,
    )
}

/// Public routes that are used in the LNv2 protocol
fn lnv2_routes(handlers: &mut Handlers) -> Router {
    let router = Router::new();
    let router = register_post_handler(
        handlers,
        ROUTING_INFO_ENDPOINT,
        routing_info_v2,
        false,
        router,
    );
    let router = register_post_handler(
        handlers,
        SEND_PAYMENT_ENDPOINT,
        pay_bolt11_invoice_v2,
        false,
        router,
    );
    let router = register_post_handler(
        handlers,
        CREATE_BOLT11_INVOICE_ENDPOINT,
        create_bolt11_invoice_v2,
        false,
        router,
    );
    // Verify endpoint does not have the same signature, it is handled separately
    router.route("/verify/{payment_hash}", get(verify_bolt11_preimage_v2_get))
}

/// Gateway Webserver Routes. The gateway supports three types of routes:
/// - Public: anyone can request these routes. Used by fedimint clients.
/// - User-level: authenticated users (User or Admin role) can access.
/// - Admin-level: only Admin role can access (destructive/config operations).
///
/// For HTTP, role-based authorization is enforced via `require_admin()`.
/// For Iroh, authenticated routes are admin-only (uses `*_iroh` wrappers).
fn routes(gateway: Arc<Gateway>, task_group: TaskGroup, handlers: &mut Handlers) -> Router {
    // =========================================================================
    // Public routes (no authentication required)
    // =========================================================================
    let mut public_routes = register_post_handler(
        handlers,
        RECEIVE_ECASH_ENDPOINT,
        receive_ecash,
        false,
        Router::new(),
    );
    public_routes = public_routes.merge(lnv1_routes(handlers));
    public_routes = public_routes.merge(lnv2_routes(handlers));

    // =========================================================================
    // User-level routes (User or Admin can access)
    // These use register_*_handler for both HTTP and Iroh
    // =========================================================================
    let is_authenticated = true;
    let mut authenticated_routes = Router::new();

    // User-level: View info, balances, channels, transactions, etc.
    authenticated_routes = register_get_handler(
        handlers,
        GATEWAY_INFO_ENDPOINT,
        info,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_post_handler(
        handlers,
        CONFIGURATION_ENDPOINT,
        configuration,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_get_handler(
        handlers,
        GET_BALANCES_ENDPOINT,
        get_balances,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_get_handler(
        handlers,
        LIST_CHANNELS_ENDPOINT,
        list_channels,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_post_handler(
        handlers,
        LIST_TRANSACTIONS_ENDPOINT,
        list_transactions,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_post_handler(
        handlers,
        PAYMENT_LOG_ENDPOINT,
        payment_log,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_post_handler(
        handlers,
        PAYMENT_SUMMARY_ENDPOINT,
        payment_summary,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_post_handler(
        handlers,
        GET_INVOICE_ENDPOINT,
        get_invoice,
        is_authenticated,
        authenticated_routes,
    );
    authenticated_routes = register_get_handler(
        handlers,
        INVITE_CODES_ENDPOINT,
        invite_codes,
        is_authenticated,
        authenticated_routes,
    );

    // =========================================================================
    // Admin-level routes (Admin only)
    // HTTP: uses handlers with role checking
    // Iroh: uses *_iroh wrappers (Iroh auth = admin only)
    // =========================================================================

    // Register Iroh handlers (admin access only)
    register_iroh_post_handler::<DepositAddressPayload, _, _>(
        handlers,
        ADDRESS_ENDPOINT,
        address_iroh,
    );
    register_iroh_post_handler::<WithdrawPayload, _, _>(handlers, WITHDRAW_ENDPOINT, withdraw_iroh);
    register_iroh_post_handler::<ConnectFedPayload, _, _>(
        handlers,
        CONNECT_FED_ENDPOINT,
        connect_fed_iroh,
    );
    register_iroh_post_handler::<LeaveFedPayload, _, _>(
        handlers,
        LEAVE_FED_ENDPOINT,
        leave_fed_iroh,
    );
    register_iroh_post_handler::<BackupPayload, _, _>(handlers, BACKUP_ENDPOINT, backup_iroh);
    register_iroh_post_handler::<CreateInvoiceForOperatorPayload, _, _>(
        handlers,
        CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT,
        create_invoice_for_operator_iroh,
    );
    register_iroh_post_handler::<CreateOfferPayload, _, _>(
        handlers,
        CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
        create_offer_for_operator_iroh,
    );
    register_iroh_post_handler::<PayInvoiceForOperatorPayload, _, _>(
        handlers,
        PAY_INVOICE_FOR_OPERATOR_ENDPOINT,
        pay_invoice_operator_iroh,
    );
    register_iroh_post_handler::<PayOfferPayload, _, _>(
        handlers,
        PAY_OFFER_FOR_OPERATOR_ENDPOINT,
        pay_offer_operator_iroh,
    );
    register_iroh_get_handler(
        handlers,
        GET_LN_ONCHAIN_ADDRESS_ENDPOINT,
        get_ln_onchain_address_iroh,
    );
    register_iroh_post_handler::<OpenChannelRequest, _, _>(
        handlers,
        OPEN_CHANNEL_ENDPOINT,
        open_channel_iroh,
    );
    register_iroh_post_handler::<CloseChannelsWithPeerRequest, _, _>(
        handlers,
        CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
        close_channels_with_peer_iroh,
    );
    register_iroh_post_handler::<SendOnchainRequest, _, _>(
        handlers,
        SEND_ONCHAIN_ENDPOINT,
        send_onchain_iroh,
    );
    register_iroh_post_handler::<DepositAddressRecheckPayload, _, _>(
        handlers,
        ADDRESS_RECHECK_ENDPOINT,
        recheck_address_iroh,
    );
    register_iroh_post_handler::<SpendEcashPayload, _, _>(
        handlers,
        SPEND_ECASH_ENDPOINT,
        spend_ecash_iroh,
    );
    register_iroh_get_handler(handlers, MNEMONIC_ENDPOINT, mnemonic_iroh);
    register_iroh_post_handler::<SetMnemonicPayload, _, _>(
        handlers,
        MNEMONIC_ENDPOINT,
        set_mnemonic_iroh,
    );
    register_iroh_post_handler::<SetFeesPayload, _, _>(handlers, SET_FEES_ENDPOINT, set_fees_iroh);

    // Register HTTP handlers (with role-based authorization)
    authenticated_routes =
        register_http_post_handler(ADDRESS_ENDPOINT, address, authenticated_routes);
    authenticated_routes =
        register_http_post_handler(WITHDRAW_ENDPOINT, withdraw, authenticated_routes);
    authenticated_routes =
        register_http_post_handler(CONNECT_FED_ENDPOINT, connect_fed, authenticated_routes);
    authenticated_routes =
        register_http_post_handler(LEAVE_FED_ENDPOINT, leave_fed, authenticated_routes);
    authenticated_routes =
        register_http_post_handler(BACKUP_ENDPOINT, backup, authenticated_routes);
    authenticated_routes = register_http_post_handler(
        CREATE_BOLT11_INVOICE_FOR_OPERATOR_ENDPOINT,
        create_invoice_for_operator,
        authenticated_routes,
    );
    authenticated_routes = register_http_post_handler(
        CREATE_BOLT12_OFFER_FOR_OPERATOR_ENDPOINT,
        create_offer_for_operator,
        authenticated_routes,
    );
    authenticated_routes = register_http_post_handler(
        PAY_INVOICE_FOR_OPERATOR_ENDPOINT,
        pay_invoice_operator,
        authenticated_routes,
    );
    authenticated_routes = register_http_post_handler(
        PAY_OFFER_FOR_OPERATOR_ENDPOINT,
        pay_offer_operator,
        authenticated_routes,
    );
    authenticated_routes = register_http_get_handler(
        GET_LN_ONCHAIN_ADDRESS_ENDPOINT,
        get_ln_onchain_address,
        authenticated_routes,
    );
    authenticated_routes =
        register_http_post_handler(OPEN_CHANNEL_ENDPOINT, open_channel, authenticated_routes);
    authenticated_routes = register_http_post_handler(
        CLOSE_CHANNELS_WITH_PEER_ENDPOINT,
        close_channels_with_peer,
        authenticated_routes,
    );
    authenticated_routes =
        register_http_post_handler(SEND_ONCHAIN_ENDPOINT, send_onchain, authenticated_routes);
    authenticated_routes = register_http_post_handler(
        ADDRESS_RECHECK_ENDPOINT,
        recheck_address,
        authenticated_routes,
    );
    authenticated_routes =
        register_http_post_handler(SPEND_ECASH_ENDPOINT, spend_ecash, authenticated_routes);
    authenticated_routes =
        register_http_get_handler(MNEMONIC_ENDPOINT, mnemonic, authenticated_routes);
    authenticated_routes =
        register_http_post_handler(MNEMONIC_ENDPOINT, set_mnemonic, authenticated_routes);
    authenticated_routes =
        register_http_post_handler(SET_FEES_ENDPOINT, set_fees, authenticated_routes);

    // Stop endpoint has a different signature (needs TaskGroup)
    authenticated_routes = authenticated_routes.route(STOP_ENDPOINT, get(stop));

    // Apply auth middleware to all authenticated routes
    let authenticated_routes = authenticated_routes.layer(middleware::from_fn(auth_middleware));

    Router::new()
        .merge(public_routes)
        .merge(authenticated_routes)
        .layer(middleware::from_fn(not_configured_middleware))
        .layer(Extension(gateway))
        .layer(Extension(task_group))
        .layer(CorsLayer::permissive())
}

/// Display high-level information about the Gateway (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn info(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let info = gateway.handle_get_info().await?;
    Ok(Json(json!(info)))
}

/// Display high-level information about the Gateway config (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn configuration(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ConfigPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let gateway_fed_config = gateway
        .handle_get_federation_config(payload.federation_id)
        .await?;
    Ok(Json(json!(gateway_fed_config)))
}

/// Generate deposit address (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn address(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let address = gateway.handle_address_msg(payload).await?;
    Ok(Json(json!(address)))
}

/// Withdraw from a gateway federation (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn withdraw(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let txid = gateway.handle_withdraw_msg(payload).await?;
    Ok(Json(json!(txid)))
}

/// Create invoice for operator (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn create_invoice_for_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<CreateInvoiceForOperatorPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let invoice = gateway
        .handle_create_invoice_for_operator_msg(payload)
        .await?;
    Ok(Json(json!(invoice)))
}

/// Pay invoice for operator (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_invoice_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<PayInvoiceForOperatorPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let preimage = gateway.handle_pay_invoice_for_operator_msg(payload).await?;
    Ok(Json(json!(preimage.0.encode_hex::<String>())))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_invoice(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<fedimint_ln_client::pay::PayInvoicePayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let preimage = gateway.handle_pay_invoice_msg(payload).await?;
    Ok(Json(json!(preimage.0.encode_hex::<String>())))
}

/// Connect a new federation (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn connect_fed(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let fed = gateway.handle_connect_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Leave a federation (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn leave_fed(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<LeaveFedPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let fed = gateway.handle_leave_federation(payload).await?;
    Ok(Json(json!(fed)))
}

/// Backup a gateway actor state (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn backup(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<BackupPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    gateway.handle_backup_msg(payload).await?;
    Ok(Json(json!(())))
}

/// Set routing fees (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn set_fees(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<SetFeesPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    gateway.handle_set_fees_msg(payload).await?;
    Ok(Json(json!(())))
}

/// Get lightning node onchain address (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_ln_onchain_address(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let address = gateway.handle_get_ln_onchain_address_msg().await?;
    Ok(Json(json!(address.to_string())))
}

/// Open a lightning channel (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn open_channel(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<OpenChannelRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let funding_txid = gateway.handle_open_channel_msg(payload).await?;
    Ok(Json(json!(funding_txid)))
}

/// Close channels with a peer (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err, fields(?payload))]
async fn close_channels_with_peer(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<CloseChannelsWithPeerRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let response = gateway.handle_close_channels_with_peer_msg(payload).await?;
    Ok(Json(json!(response)))
}

/// List lightning channels (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn list_channels(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let channels = gateway.handle_list_channels_msg().await?;
    Ok(Json(json!(channels)))
}

/// Send funds onchain from lightning node (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn send_onchain(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<SendOnchainRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let txid = gateway.handle_send_onchain_msg(payload).await?;
    Ok(Json(json!(txid)))
}

/// Recheck a deposit address (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn recheck_address(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<DepositAddressRecheckPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    gateway.handle_recheck_address_msg(payload).await?;
    Ok(Json(json!({})))
}

/// Get gateway balances (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_balances(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let balances = gateway.handle_get_balances_msg().await?;
    Ok(Json(json!(balances)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_gateway_id(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    Ok(Json(json!(gateway.http_gateway_id().await)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn routing_info_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(federation_id): Json<FederationId>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let routing_info = gateway.routing_info_v2(&federation_id).await?;
    Ok(Json(json!(routing_info)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_bolt11_invoice_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SendPaymentPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let payment_result = gateway.send_payment_v2(payload).await?;
    Ok(Json(json!(payment_result)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn create_bolt11_invoice_v2(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<CreateBolt11InvoicePayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let invoice = gateway.create_bolt11_invoice_v2(payload).await?;
    Ok(Json(json!(invoice)))
}

pub(crate) async fn verify_bolt11_preimage_v2_get(
    Extension(gateway): Extension<Arc<Gateway>>,
    Path(payment_hash): Path<sha256::Hash>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let response = gateway
        .verify_bolt11_preimage_v2(payment_hash, query.contains_key("wait"))
        .await
        .map_err(|e| LnurlError::internal(anyhow!(e)))?;

    Ok(Json(json!(LnurlResponse::Ok(response))))
}

/// Spend e-cash (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn spend_ecash(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<SpendEcashPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    Ok(Json(json!(gateway.handle_spend_ecash_msg(payload).await?)))
}

#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn receive_ecash(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ReceiveEcashPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    Ok(Json(json!(
        gateway.handle_receive_ecash_msg(payload).await?
    )))
}

/// Get gateway mnemonic (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn mnemonic(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let words = gateway.handle_mnemonic_msg().await?;
    Ok(Json(json!(words)))
}

/// Set gateway mnemonic (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn set_mnemonic(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<SetMnemonicPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    gateway.handle_set_mnemonic_msg(payload).await?;
    Ok(Json(json!(())))
}

/// Stop the gateway (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
pub(crate) async fn stop(
    Extension(task_group): Extension<TaskGroup>,
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    gateway.handle_shutdown_msg(task_group).await?;
    Ok(Json(json!(())))
}

/// Get payment log (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn payment_log(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<PaymentLogPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let payment_log = gateway.handle_payment_log_msg(payload).await?;
    Ok(Json(json!(payment_log)))
}

/// Get payment summary (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn payment_summary(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<PaymentSummaryPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let payment_summary = gateway.handle_payment_summary_msg(payload).await?;
    Ok(Json(json!(payment_summary)))
}

/// Get invoice details (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn get_invoice(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<GetInvoiceRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let invoice = gateway.handle_get_invoice_msg(payload).await?;
    Ok(Json(json!(invoice)))
}

/// List transactions (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn list_transactions(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ListTransactionsPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let transactions = gateway.handle_list_transactions_msg(payload).await?;
    Ok(Json(json!(transactions)))
}

/// Create BOLT12 offer for operator (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn create_offer_for_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<CreateOfferPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let offer = gateway
        .handle_create_offer_for_operator_msg(payload)
        .await?;
    Ok(Json(json!(offer)))
}

/// Pay BOLT12 offer for operator (Admin only)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn pay_offer_operator(
    Extension(gateway): Extension<Arc<Gateway>>,
    role: Option<Extension<AuthenticatedRole>>,
    Json(payload): Json<PayOfferPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    require_admin(role.as_ref())?;
    let response = gateway.handle_pay_offer_for_operator_msg(payload).await?;
    Ok(Json(json!(response)))
}

/// Export invite codes (User or Admin)
#[instrument(target = LOG_GATEWAY, skip_all, err)]
async fn invite_codes(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    // No require_admin - accessible by both User and Admin
    let invite_codes = gateway.handle_export_invite_codes().await;
    Ok(Json(json!(invite_codes)))
}

// =============================================================================
// Iroh-compatible wrapper functions
// =============================================================================
// These wrappers are for Iroh handlers that need admin access.
// They don't include role checking because Iroh authenticated = admin only.
// The main functions above include role checking for HTTP API.

async fn address_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<DepositAddressPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let address = gateway.handle_address_msg(payload).await?;
    Ok(Json(json!(address)))
}

async fn withdraw_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<WithdrawPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let txid = gateway.handle_withdraw_msg(payload).await?;
    Ok(Json(json!(txid)))
}

async fn connect_fed_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<ConnectFedPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let fed = gateway.handle_connect_federation(payload).await?;
    Ok(Json(json!(fed)))
}

async fn leave_fed_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<LeaveFedPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let fed = gateway.handle_leave_federation(payload).await?;
    Ok(Json(json!(fed)))
}

async fn backup_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<BackupPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    gateway.handle_backup_msg(payload).await?;
    Ok(Json(json!(())))
}

async fn create_invoice_for_operator_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<CreateInvoiceForOperatorPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let invoice = gateway
        .handle_create_invoice_for_operator_msg(payload)
        .await?;
    Ok(Json(json!(invoice)))
}

async fn create_offer_for_operator_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<CreateOfferPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let offer = gateway
        .handle_create_offer_for_operator_msg(payload)
        .await?;
    Ok(Json(json!(offer)))
}

async fn pay_invoice_operator_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<PayInvoiceForOperatorPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let preimage = gateway.handle_pay_invoice_for_operator_msg(payload).await?;
    Ok(Json(json!(preimage.0.encode_hex::<String>())))
}

async fn pay_offer_operator_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<PayOfferPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let response = gateway.handle_pay_offer_for_operator_msg(payload).await?;
    Ok(Json(json!(response)))
}

async fn get_ln_onchain_address_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let address = gateway.handle_get_ln_onchain_address_msg().await?;
    Ok(Json(json!(address.to_string())))
}

async fn open_channel_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<OpenChannelRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let funding_txid = gateway.handle_open_channel_msg(payload).await?;
    Ok(Json(json!(funding_txid)))
}

async fn close_channels_with_peer_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<CloseChannelsWithPeerRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let response = gateway.handle_close_channels_with_peer_msg(payload).await?;
    Ok(Json(json!(response)))
}

async fn send_onchain_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SendOnchainRequest>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let txid = gateway.handle_send_onchain_msg(payload).await?;
    Ok(Json(json!(txid)))
}

async fn recheck_address_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<DepositAddressRecheckPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    gateway.handle_recheck_address_msg(payload).await?;
    Ok(Json(json!({})))
}

async fn spend_ecash_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SpendEcashPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    Ok(Json(json!(gateway.handle_spend_ecash_msg(payload).await?)))
}

async fn mnemonic_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    let words = gateway.handle_mnemonic_msg().await?;
    Ok(Json(json!(words)))
}

async fn set_mnemonic_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SetMnemonicPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    gateway.handle_set_mnemonic_msg(payload).await?;
    Ok(Json(json!(())))
}

async fn set_fees_iroh(
    Extension(gateway): Extension<Arc<Gateway>>,
    Json(payload): Json<SetFeesPayload>,
) -> Result<Json<serde_json::Value>, GatewayError> {
    gateway.handle_set_fees_msg(payload).await?;
    Ok(Json(json!(())))
}
