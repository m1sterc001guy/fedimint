use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use anyhow::anyhow;
use async_trait::async_trait;
use fedimint_core::dyn_newtype_define;
use fedimint_core::task::sleep;
use futures::stream::BoxStream;
use tonic::transport::{Channel, Endpoint};
use tonic::Request;
use tracing::error;
use url::Url;

use crate::gatewaylnrpc::gateway_lightning_client::GatewayLightningClient;
use crate::gatewaylnrpc::{
    CompleteHtlcsRequest, CompleteHtlcsResponse, EmptyRequest, GetPubKeyResponse,
    GetRouteHintsResponse, PayInvoiceRequest, PayInvoiceResponse, SubscribeInterceptHtlcsRequest,
    SubscribeInterceptHtlcsResponse,
};
use crate::{GatewayError, Result};

pub type HtlcStream<'a> =
    BoxStream<'a, std::result::Result<SubscribeInterceptHtlcsResponse, tonic::Status>>;

#[async_trait]
pub trait ILnRpcClient: Debug + Send + Sync {
    /// Get the public key of the lightning node
    async fn pubkey(&self) -> Result<GetPubKeyResponse>;

    /// Get route hints to the lightning node
    async fn routehints(&self) -> Result<GetRouteHintsResponse>;

    /// Attempt to pay an invoice using the lightning node
    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse>;

    /// Subscribe to intercept htlcs that belong to a specific mint identified
    /// by `short_channel_id`
    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream<'a>>;

    /// Request completion of an intercepted htlc after processing and
    /// determining an outcome
    async fn complete_htlc(&self, outcome: CompleteHtlcsRequest) -> Result<CompleteHtlcsResponse>;

    async fn reconnect(&mut self) -> Result<()>;
}

/*
dyn_newtype_define!(
    /// Arc reference to a gateway lightning rpc client
    #[derive(Clone)]
    pub DynLnRpcClient(Arc<ILnRpcClient>)
);

impl DynLnRpcClient {
    pub fn new(client: Arc<dyn ILnRpcClient + Send + Sync>) -> Self {
        DynLnRpcClient(client)
    }
}
*/

/// An `ILnRpcClient` that wraps around `GatewayLightningClient` for
/// convenience, and makes real RPC requests over the wire to a remote lightning
/// node. The lightning node is exposed via a corresponding
/// `GatewayLightningServer`.
#[derive(Debug)]
pub struct NetworkLnRpcClient {
    client: Option<GatewayLightningClient<Channel>>,
    endpoint: Endpoint,
}

impl NetworkLnRpcClient {
    pub async fn new(url: Url) -> Result<Self> {
        let endpoint = Endpoint::from_shared(url.to_string()).map_err(|e| {
            error!("Failed to create lnrpc endpoint from url : {:?}", e);
            GatewayError::Other(anyhow!("Failed to create lnrpc endpoint from url"))
        })?;

        let mut gateway_client = NetworkLnRpcClient {
            client: None,
            endpoint,
        };
        gateway_client.reconnect().await?;

        Ok(gateway_client)
    }
}

#[async_trait]
impl ILnRpcClient for NetworkLnRpcClient {
    async fn reconnect(&mut self) -> Result<()> {
        let mut res = GatewayLightningClient::connect(self.endpoint.clone()).await;
        while res.is_err() {
            tracing::warn!("Couldn't connect to CLN extension, waiting 5 seconds and retrying...");
            sleep(Duration::from_secs(5)).await;

            res = GatewayLightningClient::connect(self.endpoint.clone()).await;
        }

        tracing::info!("Successfully connected to CLN extension");
        self.client = Some(res.unwrap());
        Ok(())
    }

    async fn pubkey(&self) -> Result<GetPubKeyResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(EmptyRequest {});
            let res = client.get_pub_key(req).await?;
            return Ok(res.into_inner());
        }

        error!("Gateway is not connected to CLN extension");
        Err(GatewayError::Other(anyhow!(
            "Gateway is not connected to CLN extension"
        )))
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(EmptyRequest {});
            let res = client.get_route_hints(req).await?;

            return Ok(res.into_inner());
        }

        error!("Gateway is not connected to CLN extension");
        Err(GatewayError::Other(anyhow!(
            "Gateway is not connected to CLN extension"
        )))
    }

    async fn pay(&self, invoice: PayInvoiceRequest) -> Result<PayInvoiceResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(invoice);
            let res = client.pay_invoice(req).await?;
            return Ok(res.into_inner());
        }

        error!("Gateway is not connected to CLN extension");
        Err(GatewayError::Other(anyhow!(
            "Gateway is not connected to CLN extension"
        )))
    }

    async fn subscribe_htlcs<'a>(
        &self,
        subscription: SubscribeInterceptHtlcsRequest,
    ) -> Result<HtlcStream<'a>> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(subscription);
            let res = client.subscribe_intercept_htlcs(req).await?;
            return Ok(Box::pin(res.into_inner()));
        }

        error!("Gateway is not connected to CLN extension");
        Err(GatewayError::Other(anyhow!(
            "Gateway is not connected to CLN extension"
        )))
    }

    async fn complete_htlc(&self, outcome: CompleteHtlcsRequest) -> Result<CompleteHtlcsResponse> {
        if let Some(mut client) = self.client.clone() {
            let req = Request::new(outcome);
            let res = client.complete_htlc(req).await?;
            return Ok(res.into_inner());
        }

        error!("Gateway is not connected to CLN extension");
        Err(GatewayError::Other(anyhow!(
            "Gateway is not connected to CLN extension"
        )))
    }
}
