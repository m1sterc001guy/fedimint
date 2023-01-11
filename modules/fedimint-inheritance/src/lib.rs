use std::collections::BTreeMap;

use async_trait::async_trait;
use bitcoin::Address;
use fedimint_api::cancellable::Cancellable;
use fedimint_api::config::{ClientModuleConfig, ConfigGenParams, DkgPeerMsg};
use fedimint_api::core::Decoder;
use fedimint_api::encoding::{Decodable, Encodable};
use fedimint_api::module::__reexports::serde_json;
use fedimint_api::module::registry::ModuleKey;
use fedimint_api::net::peers::MuxPeerConnections;
use fedimint_api::{
    config::ServerModuleConfig, db::Database, module::ModuleInit, server::ServerModule,
    task::TaskGroup,
};
use fedimint_api::{Amount, PeerId};

use crate::config::InheritanceConfig;

pub mod config;

#[derive(Debug)]
pub struct InheritanceModule {
    cfg: InheritanceConfig,
}

#[derive(Debug, Clone)]
pub struct InheritanceVerificationCache;

pub struct InheritanceConfigGenerator;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Copy)]
// TODO: This probably needs to be made unique so it doesn't class with other contracts
pub struct InheritanceContractId(pub u64);

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct InheritanceContractInput {
    // Which contract to change
    pub contract_id: InheritanceContractId,
    /// How sats to spend from this contract
    pub amount: Amount,
    // bitcoin address to pay out to
    pub address: Address,
    // block height when the contract will be paid out
    pub block_height: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub struct InheritanceContract {
    pub amount: Amount,
    pub address: Address,
    pub block_height: u32,
}

#[async_trait]
impl ModuleInit for InheritanceConfigGenerator {
    async fn init(
        &self,
        cfg: ServerModuleConfig,
        _db: Database,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<ServerModule> {
        //Ok(InheritanceModule::new(cfg.to_typed()?).into())
        todo!()
    }

    fn decoder(&self) -> (ModuleKey, Decoder) {
        todo!()
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        todo!()
    }

    async fn distributed_gen(
        &self,
        _connections: &MuxPeerConnections<ModuleKey, DkgPeerMsg>,
        _our_id: &PeerId,
        _peers: &[PeerId],
        params: &ConfigGenParams,
        _task_group: &mut TaskGroup,
    ) -> anyhow::Result<Cancellable<ServerModuleConfig>> {
        todo!()
    }

    fn to_client_config(&self, config: ServerModuleConfig) -> anyhow::Result<ClientModuleConfig> {
        todo!()
    }

    fn to_client_config_from_consensus_value(
        &self,
        config: serde_json::Value,
    ) -> anyhow::Result<ClientModuleConfig> {
        todo!()
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        todo!()
    }
}

impl InheritanceModule {
    /// Create new module instance
    pub fn new(cfg: InheritanceConfig) -> InheritanceModule {
        InheritanceModule { cfg }
    }
}

pub const MODULE_KEY_INHERITANCE: u16 = 55;
