use std::env;
use std::fmt::{Display, Formatter};
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use fedimint_client::module::gen::ClientModuleGenRegistry;
use fedimint_client::Client;
use fedimint_core::config::FederationId;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleDecoderRegistry;
use fedimint_core::task::TaskGroup;
use ln_gateway::client::{LightningBuilder, StandardGatewayClientBuilder};
use ln_gateway::gateway_lnrpc::{
    EmptyResponse, GetNodeInfoResponse, GetRouteHintsResponse, InterceptHtlcResponse,
    PayInvoiceRequest, PayInvoiceResponse,
};
use ln_gateway::lnrpc_client::{ILnRpcClient, LightningRpcError, RouteHtlcStream};
use ln_gateway::rpc::rpc_client::GatewayRpcClient;
use ln_gateway::rpc::rpc_server::run_webserver;
use ln_gateway::rpc::{ConnectFedPayload, FederationInfo};
use ln_gateway::{GatewayError, GatewayState, Gatewayd, DEFAULT_FEES};
use rand::rngs::OsRng;
use secp256k1::PublicKey;
use tokio::sync::RwLock;
use tracing::info;
use url::Url;

use crate::federation::FederationTest;
use crate::fixtures::{test_dir, Fixtures};
use crate::ln::mock::FakeLightningTest;
use crate::ln::real::{ClnLightningTest, LndLightningTest};
use crate::ln::LightningTest;

pub struct TestLightningBuilder {
    node_type: LightningNodeName,
}

#[async_trait]
impl LightningBuilder for TestLightningBuilder {
    async fn build(&self) -> Box<dyn ILnRpcClient> {
        if !Fixtures::is_real_test() {
            return Box::new(FakeLightningTest::new());
        }

        match &self.node_type {
            LightningNodeName::Cln => {
                let dir = env::var("FM_TEST_DIR").expect("Real tests require FM_TEST_DIR");
                Box::new(ClnLightningTest::new(dir.as_str()).await)
            }
            LightningNodeName::Lnd => Box::new(LndLightningTest::new().await),
            _ => {
                unimplemented!("Unsupported Lightning implementation");
            }
        }
    }
}

#[derive(Debug)]
struct LightningTestWrapper(Box<dyn LightningTest>);

#[async_trait]
impl ILnRpcClient for LightningTestWrapper {
    async fn info(&self) -> Result<GetNodeInfoResponse, LightningRpcError> {
        self.0.info().await
    }

    async fn routehints(&self) -> Result<GetRouteHintsResponse, LightningRpcError> {
        self.0.routehints().await
    }

    async fn pay(
        &self,
        invoice: PayInvoiceRequest,
    ) -> Result<PayInvoiceResponse, LightningRpcError> {
        self.0.pay(invoice).await
    }

    async fn route_htlcs<'a>(
        self: Box<Self>,
        task_group: &mut TaskGroup,
    ) -> Result<(RouteHtlcStream<'a>, Arc<dyn ILnRpcClient>), LightningRpcError> {
        self.0.route_htlcs(task_group).await
    }

    async fn complete_htlc(
        &self,
        htlc: InterceptHtlcResponse,
    ) -> Result<EmptyResponse, LightningRpcError> {
        self.0.complete_htlc(htlc).await
    }
}

/// Fixture for creating a gateway
pub struct GatewayTest {
    /// Password for the RPC
    pub password: String,
    /// URL for the RPC
    api: Url,
    /// Handle of the running gatewayd
    gatewayd: Gatewayd,
    // Public key of the lightning node
    pub node_pub_key: PublicKey,
    // Listening address of the lightning node
    pub listening_addr: String,
}

impl GatewayTest {
    /// RPC client for communicating with the gateway admin API
    pub async fn get_rpc(&self) -> GatewayRpcClient {
        GatewayRpcClient::new(self.api.clone(), self.password.clone())
    }

    /// Removes a client from the gateway
    pub async fn remove_client(&self, fed: &FederationTest) -> Result<Client, GatewayError> {
        if let GatewayState::Running(gateway) = self.gatewayd.state.read().await.clone() {
            return Ok(gateway.remove_client(fed.id()).await.unwrap());
        }

        Err(GatewayError::Disconnected)
    }

    pub async fn select_client(&self, federation_id: FederationId) -> Result<Client, GatewayError> {
        if let GatewayState::Running(gateway) = self.gatewayd.state.read().await.clone() {
            return Ok(gateway.select_client(federation_id).await.unwrap());
        }

        Err(GatewayError::Disconnected)
    }

    /// Connects to a new federation and stores the info
    pub async fn connect_fed(&mut self, fed: &FederationTest) -> FederationInfo {
        let invite_code = fed.invite_code().to_string();
        let rpc = self.get_rpc().await;
        rpc.connect_federation(ConnectFedPayload { invite_code })
            .await
            .unwrap()
    }

    pub fn get_gatewayd_id(&self) -> secp256k1::PublicKey {
        self.gatewayd.gatewayd_id
    }

    pub(crate) async fn new(
        base_port: u16,
        password: String,
        lightning: Box<dyn LightningTest>,
        decoders: ModuleDecoderRegistry,
        registry: ClientModuleGenRegistry,
    ) -> Self {
        let listen: SocketAddr = format!("127.0.0.1:{base_port}").parse().unwrap();
        let address: Url = format!("http://{listen}").parse().unwrap();
        let (path, _config_dir) = test_dir(&format!("gateway-{}", rand::random::<u64>()));

        // Create federation client builder for the gateway
        let client_builder: StandardGatewayClientBuilder =
            StandardGatewayClientBuilder::new(path.clone(), registry.clone(), 0);

        let listening_addr = lightning.listening_address();
        let info = lightning.info().await.unwrap();

        // Generate new gatewayd id
        let context = secp256k1::Secp256k1::new();
        let (_, public) = context.generate_keypair(&mut OsRng);

        let gatewayd = Gatewayd {
            registry,
            lightning_builder: Arc::new(TestLightningBuilder {
                node_type: lightning.lightning_node_type(),
            }),
            state: Arc::new(RwLock::new(GatewayState::Initializing)),
            gatewayd_id: public,
            gatewayd_db: Database::new(MemDatabase::new(), decoders.clone()),
        };

        let mut tg = TaskGroup::new();
        run_webserver(password.clone(), listen, gatewayd.clone(), &mut tg)
            .await
            .expect("Failed to start webserver");
        info!("Successfully started test webserver");

        gatewayd
            .clone()
            .start_gateway(&mut tg, client_builder, DEFAULT_FEES, address.clone())
            .await
            .expect("Failed to start gateway");

        // TODO: Wait for gatewayd to be `Running`

        Self {
            password,
            api: address,
            gatewayd,
            node_pub_key: PublicKey::from_slice(info.pub_key.as_slice()).unwrap(),
            listening_addr,
        }
    }
}

#[derive(Debug)]
pub enum LightningNodeName {
    Cln,
    Lnd,
    Ldk,
}

impl Display for LightningNodeName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            LightningNodeName::Cln => write!(f, "cln"),
            LightningNodeName::Lnd => write!(f, "lnd"),
            LightningNodeName::Ldk => write!(f, "ldk"),
        }
    }
}
