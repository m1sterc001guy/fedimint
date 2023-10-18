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
use fedimint_core::{apply, async_trait_maybe_send};
use resolvr_common::api::ResolvrFederationApi;
use resolvr_common::{ResolvrCommonGen, ResolvrModuleTypes, KIND};

#[apply(async_trait_maybe_send)]
pub trait ResolvrClientExt {
    async fn request_sign_message(&self, msg: String) -> anyhow::Result<()>;
}

#[apply(async_trait_maybe_send)]
impl ResolvrClientExt for Client {
    async fn request_sign_message(&self, msg: String) -> anyhow::Result<()> {
        let (resolvr, instance) = self.get_first_module::<ResolvrClientModule>(&KIND);
        resolvr.module_api.request_sign_message(msg).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ResolvrClientGen;

#[apply(async_trait_maybe_send)]
impl ExtendsCommonModuleInit for ResolvrClientGen {
    type Common = ResolvrCommonGen;

    async fn dump_database(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        todo!()
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

    fn input_amount(&self, input: &<Self::Common as ModuleCommon>::Input) -> TransactionItemAmount {
        todo!()
    }

    fn output_amount(
        &self,
        output: &<Self::Common as ModuleCommon>::Output,
    ) -> TransactionItemAmount {
        todo!()
    }

    fn get_config(&self) -> <<Self as ClientModule>::Common as ModuleCommon>::ClientConfig {
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
        context: &Self::ModuleContext,
        global_context: &Self::GlobalContext,
    ) -> Vec<fedimint_client::sm::StateTransition<Self>> {
        vec![]
    }

    fn operation_id(&self) -> fedimint_client::sm::OperationId {
        todo!()
    }
}
