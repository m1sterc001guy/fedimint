use std::collections::{BTreeMap, HashSet};
use std::fmt;

use async_trait::async_trait;
use common::DummyModuleDecoder;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::config::TypedServerModuleConsensusConfig;
use fedimint_api::config::{
    ClientModuleConfig, ConfigGenParams, DkgPeerMsg, ModuleConfigGenParams, ServerModuleConfig,
    TypedServerModuleConfig,
};
use fedimint_api::core::ModuleKey;
use fedimint_api::db::DatabaseTransaction;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::__reexports::serde_json;
use fedimint_api::module::audit::Audit;
use fedimint_api::module::interconnect::ModuleInterconect;
use fedimint_api::module::{
    api_endpoint, ApiEndpoint, FederationModuleConfigGen, InputMeta, ModuleError,
    TransactionItemAmount,
};
use fedimint_api::net::peers::MuxPeerConnections;
use fedimint_api::task::TaskGroup;
use fedimint_api::{plugin_types_trait_impl, OutPoint, PeerId, ServerModulePlugin};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{DummyConfig, DummyConfigConsensus, DummyConfigPrivate};

pub mod common;
pub mod config;
pub mod db;

/// Dummy module
#[derive(Debug)]
pub struct Dummy {
    pub cfg: DummyConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DummyOutputConfirmation;

#[derive(Debug, Clone)]
pub struct DummyVerificationCache;

pub struct DummyConfigGenerator;

#[async_trait]
impl FederationModuleConfigGen for DummyConfigGenerator {
    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let _params = params
            .get::<DummyConfigGenParams>()
            .expect("Invalid mint params");

        let mint_cfg: BTreeMap<_, DummyConfig> = peers
            .iter()
            .map(|&peer| {
                let config = DummyConfig {
                    private: DummyConfigPrivate {
                        something_private: 3,
                    },
                    consensus: DummyConfigConsensus { something: 1 },
                };
                (peer, config)
            })
            .collect();

        mint_cfg
            .into_iter()
            .map(|(k, v)| (k, v.to_erased()))
            .collect()
    }

    async fn distributed_gen(
        &self,
        _connections: &MuxPeerConnections<ModuleKey, DkgPeerMsg>,
        _our_id: &PeerId,
        _peers: &[PeerId],
        params: &ConfigGenParams,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<ServerModuleConfig>> {
        let _params = params
            .get::<DummyConfigGenParams>()
            .expect("Invalid mint params");

        let server = DummyConfig {
            private: DummyConfigPrivate {
                something_private: 3,
            },
            consensus: DummyConfigConsensus { something: 2 },
        };

        Ok(Ok(server.to_erased()))
    }

    fn to_client_config(&self, config: ServerModuleConfig) -> anyhow::Result<ClientModuleConfig> {
        Ok(config
            .to_typed::<DummyConfig>()?
            .consensus
            .to_client_config())
    }

    fn to_client_config_from_consensus_value(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ClientModuleConfig> {
        Ok(serde_json::from_value::<DummyConfigConsensus>(config)?.to_client_config())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        config.to_typed::<DummyConfig>()?.validate_config(identity)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DummyConfigGenParams {
    pub important_param: u64,
}

impl ModuleConfigGenParams for DummyConfigGenParams {
    const MODULE_NAME: &'static str = "dummy";
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyInput;

impl fmt::Display for DummyInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyInput")
    }
}

#[derive(
    Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable, Default,
)]
pub struct DummyOutput;

impl fmt::Display for DummyOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutput")
    }
}
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct DummyOutputOutcome;

impl fmt::Display for DummyOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputOutcome")
    }
}

impl fmt::Display for DummyOutputConfirmation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DummyOutputConfirmation")
    }
}

#[async_trait]
impl ServerModulePlugin for Dummy {
    type Decoder = DummyModuleDecoder;
    type Input = DummyInput;
    type Output = DummyOutput;
    type OutputOutcome = DummyOutputOutcome;
    type ConsensusItem = DummyOutputConfirmation;
    type VerificationCache = DummyVerificationCache;

    fn module_key(&self) -> ModuleKey {
        MODULE_KEY_DUMMY
    }

    fn decoder(&self) -> &'static Self::Decoder {
        &DummyModuleDecoder
    }

    async fn await_consensus_proposal(&self, _dbtx: &mut DatabaseTransaction<'_>) {}

    async fn consensus_proposal(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<Self::ConsensusItem> {
        vec![]
    }

    async fn begin_consensus_epoch<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _consensus_items: Vec<(PeerId, Self::ConsensusItem)>,
    ) {
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a Self::Input> + Send,
    ) -> Self::VerificationCache {
        DummyVerificationCache
    }

    async fn validate_input<'a, 'b>(
        &self,
        _interconnect: &dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'b>,
        _verification_cache: &Self::VerificationCache,
        _input: &'a Self::Input,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn apply_input<'a, 'b, 'c>(
        &'a self,
        _interconnect: &'a dyn ModuleInterconect,
        _dbtx: &mut DatabaseTransaction<'c>,
        _input: &'b Self::Input,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        unimplemented!()
    }

    async fn validate_output(
        &self,
        _dbtx: &mut DatabaseTransaction,
        _output: &Self::Output,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn apply_output<'a, 'b>(
        &'a self,
        _dbtx: &mut DatabaseTransaction<'b>,
        _output: &'a Self::Output,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        unimplemented!()
    }

    async fn end_consensus_epoch<'a, 'b>(
        &'a self,
        _consensus_peers: &HashSet<PeerId>,
        _dbtx: &mut DatabaseTransaction<'b>,
    ) -> Vec<PeerId> {
        vec![]
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<Self::OutputOutcome> {
        None
    }

    async fn audit(&self, _dbtx: &mut DatabaseTransaction<'_>, _audit: &mut Audit) {}

    fn api_base_name(&self) -> &'static str {
        "dummy"
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            "/dummy",
            async |_module: &Dummy, _dbtx, _request: ()| -> () {
                Ok(())
            }
        }]
    }
}

impl Dummy {
    /// Create new module instance
    pub fn new(cfg: DummyConfig) -> Dummy {
        Dummy { cfg }
    }
}

// Must be unique.
// TODO: we need to provide guidence for allocating these
pub const MODULE_KEY_DUMMY: u16 = 128;
plugin_types_trait_impl!(
    MODULE_KEY_DUMMY,
    DummyInput,
    DummyOutput,
    DummyOutputOutcome,
    DummyOutputConfirmation,
    DummyVerificationCache
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error)]
pub enum DummyError {
    #[error("Something went wrong")]
    SomethingDummyWentWrong,
}
