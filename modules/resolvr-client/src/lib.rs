use std::collections::HashMap;

use anyhow::anyhow;
use fedimint_client::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client::module::ClientModule;
use fedimint_client::sm::{Context, DynState, State};
use fedimint_client::{Client, DynGlobalClientContext};
use fedimint_core::api::DynModuleApi;
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId};
use fedimint_core::db::ModuleDatabaseTransaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    ApiVersion, ExtendsCommonModuleInit, ModuleCommon, MultiApiVersion, TransactionItemAmount,
};
use fedimint_core::{apply, async_trait_maybe_send, PeerId};
use resolvr_common::api::ResolvrFederationApi;
use resolvr_common::{ResolvrCommonGen, ResolvrModuleTypes, UnsignedEvent, KIND};

#[apply(async_trait_maybe_send)]
pub trait ResolvrClientExt {
    async fn request_sign_event(
        &self,
        unsigned_event: nostr_sdk::UnsignedEvent,
        peer_id: PeerId,
    ) -> anyhow::Result<()>;
    async fn get_npub(&self) -> anyhow::Result<nostr_sdk::key::XOnlyPublicKey>;

    async fn list_note_requests(&self) -> anyhow::Result<HashMap<String, (UnsignedEvent, usize)>>;
}

#[apply(async_trait_maybe_send)]
impl ResolvrClientExt for Client {
    async fn request_sign_event(
        &self,
        unsigned_event: nostr_sdk::UnsignedEvent,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        let (resolvr, _instance) = self.get_first_module::<ResolvrClientModule>(&KIND);
        resolvr
            .module_api
            .request_sign_event(UnsignedEvent(unsigned_event), peer_id)
            .await?;
        Ok(())
    }

    async fn get_npub(&self) -> anyhow::Result<nostr_sdk::key::XOnlyPublicKey> {
        let (resolvr, _instance) = self.get_first_module::<ResolvrClientModule>(&KIND);
        resolvr
            .module_api
            .get_npub()
            .await
            .map_err(|e| anyhow!("get_npub error: {e:?}"))
    }

    async fn list_note_requests(&self) -> anyhow::Result<HashMap<String, (UnsignedEvent, usize)>> {
        let (resolvr, _instance) = self.get_first_module::<ResolvrClientModule>(&KIND);
        resolvr
            .module_api
            .list_note_requests()
            .await
            .map_err(|e| anyhow!("list_note_requests error: {e:?}"))
    }
}

#[derive(Debug, Clone)]
pub struct ResolvrClientGen;

#[apply(async_trait_maybe_send)]
impl ExtendsCommonModuleInit for ResolvrClientGen {
    type Common = ResolvrCommonGen;

    async fn dump_database(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        Box::new(vec![].into_iter())
    }
}

#[apply(async_trait_maybe_send)]
impl ClientModuleInit for ResolvrClientGen {
    type Module = ResolvrClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(&self, args: &ClientModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(ResolvrClientModule {
            module_api: args.module_api().clone(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ResolvrClientContext;

impl Context for ResolvrClientContext {}

#[derive(Debug)]
pub struct ResolvrClientModule {
    pub module_api: DynModuleApi,
}

impl ClientModule for ResolvrClientModule {
    type Common = ResolvrModuleTypes;
    type ModuleStateMachineContext = ResolvrClientContext;
    type States = ResolvrClientStateMachines;

    fn context(&self) -> Self::ModuleStateMachineContext {
        ResolvrClientContext {}
    }

    fn input_amount(
        &self,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> TransactionItemAmount {
        todo!()
    }

    fn output_amount(
        &self,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        todo!()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Decodable, Encodable)]
pub enum ResolvrClientStateMachines {}

impl IntoDynInstance for ResolvrClientStateMachines {
    type DynType = DynState<DynGlobalClientContext>;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}

impl State for ResolvrClientStateMachines {
    type ModuleContext = ResolvrClientContext;
    type GlobalContext = DynGlobalClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        vec![]
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        todo!()
    }
}
