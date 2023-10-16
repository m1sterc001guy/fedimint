use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::bail;
use async_trait::async_trait;
use db::{
    ResolvrNonceKey, ResolvrNonceKeyMessagePrefix, ResolvrSignatureShareKey,
    ResolvrSignatureShareKeyPrefix,
};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, FrostShareAndPop, ServerModuleConfig,
    ServerModuleConsensusConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{Database, DatabaseVersion, MigrationMap, ModuleDatabaseTransaction};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, ConsensusProposal, CoreConsensusVersion, ExtendsCommonModuleInit,
    InputMeta, ModuleConsensusVersion, ModuleError, PeerHandle, ServerModuleInit,
    ServerModuleInitArgs, SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, PeerId, ServerModule};
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use rand::rngs::OsRng;
use resolvr_common::config::{
    ResolvrClientConfig, ResolvrConfig, ResolvrConfigConsensus, ResolvrConfigLocal,
    ResolvrConfigPrivate, ResolvrGenParams,
};
use resolvr_common::{
    ResolvrCommonGen, ResolvrConsensusItem, ResolvrInput, ResolvrModuleTypes, ResolvrNonceKeyPair,
    ResolvrOutput, ResolvrOutputOutcome, CONSENSUS_VERSION,
};
use schnorr_fun::frost::{self, Frost};
use schnorr_fun::fun::marker::{Public, Secret, Zero};
use schnorr_fun::fun::{Point, Scalar};
use schnorr_fun::musig::NonceKeyPair;
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::{Message, Signature};
use sha2::digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::digest::typenum::{UInt, UTerm, B0, B1};
use sha2::{OidSha256, Sha256, Sha256VarCore};
use tracing::info;

use crate::db::ResolvrNonceKeyPrefix;

mod db;

type ResolvrFrost = Frost<
    CoreWrapper<
        CtVariableCoreWrapper<
            Sha256VarCore,
            UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
            OidSha256,
        >,
    >,
    Synthetic<
        CoreWrapper<
            CtVariableCoreWrapper<
                Sha256VarCore,
                UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
                OidSha256,
            >,
        >,
        GlobalRng<OsRng>,
    >,
>;

#[derive(Clone)]
pub struct ResolvrGen {
    pub frost: ResolvrFrost,
}

impl std::fmt::Debug for ResolvrGen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvrGen").finish()
    }
}

#[apply(async_trait_maybe_send!)]
impl ExtendsCommonModuleInit for ResolvrGen {
    type Common = ResolvrCommonGen;

    async fn dump_database(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        todo!()
    }
}

#[async_trait]
impl ServerModuleInit for ResolvrGen {
    type Params = ResolvrGenParams;
    const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[CONSENSUS_VERSION]
    }

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(u32::MAX, 0, &[(0, 0)])
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<DynServerModule> {
        Ok(Resolvr::new(args.cfg().to_typed()?, self.frost.clone()).into())
    }

    fn get_database_migrations(&self) -> MigrationMap {
        MigrationMap::new()
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        params: &ConfigGenModuleParams,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        todo!()
    }

    async fn distributed_gen(
        &self,
        peers: &PeerHandle,
        params: &ConfigGenModuleParams,
    ) -> DkgResult<ServerModuleConfig> {
        let mut rng = rand::rngs::OsRng;

        let params = self
            .parse_params(params)
            .expect("Failed to parse ResolvrGenParams");
        let threshold = params.consensus.threshold;
        let my_secret_poly = frost::generate_scalar_poly(threshold as usize, &mut rng);
        let my_public_poly = frost::to_point_poly(&my_secret_poly);

        // Exchange public polynomials
        let peer_polynomials: BTreeMap<PeerId, Vec<Point>> = peers
            .exchange_polynomials("resolvr".to_string(), my_public_poly)
            .await?;
        let public_polys_received = peer_polynomials
            .iter()
            .map(|(peer, poly)| {
                let index = peer_id_to_scalar(peer);
                (index, poly.clone())
            })
            .collect::<BTreeMap<Scalar<Public>, Vec<Point>>>();

        info!("Public Polynomials Received: {public_polys_received:?}");

        let keygen = self
            .frost
            .new_keygen(public_polys_received)
            .expect("something went wrong with what was provided by the other parties");
        let keygen_id = self.frost.keygen_id(&keygen);
        let pop_message = Message::raw(&keygen_id);
        let (shares_i_generated, pop) =
            self.frost
                .create_shares_and_pop(&keygen, &my_secret_poly, pop_message);

        // Exchange shares and proof-of-possession
        let shares_and_pop: BTreeMap<PeerId, FrostShareAndPop> = peers
            .exchange_shares_and_pop(
                "resolvr_shares_and_pop".to_string(),
                (shares_i_generated.clone(), pop),
            )
            .await?;

        info!("Shares and Pop: {shares_and_pop:?}");

        let my_index = peer_id_to_scalar(&peers.our_id);

        let my_shares = shares_and_pop
            .iter()
            .map(|(peer, shares_from_peer)| {
                let index = peer_id_to_scalar(peer);
                (
                    index,
                    (
                        shares_from_peer.0.get(&my_index).unwrap().clone(),
                        shares_from_peer.1.clone(),
                    ),
                )
            })
            .collect::<BTreeMap<Scalar<Public>, (Scalar<Secret, Zero>, Signature)>>();

        let (my_secret_share, frost_key) = self
            .frost
            .finish_keygen(keygen.clone(), my_index, my_shares, pop_message)
            .expect("Finish keygen failed");

        info!("MyIndex: {my_index} MySecretShare: {my_secret_share} FrostKey: {frost_key:?}");

        Ok(ResolvrConfig {
            local: ResolvrConfigLocal {},
            private: ResolvrConfigPrivate { my_secret_share },
            consensus: ResolvrConfigConsensus {
                threshold,
                frost_key,
            },
        }
        .to_erased())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<ResolvrClientConfig> {
        let _config = ResolvrConfigConsensus::from_erased(config)?;
        Ok(ResolvrClientConfig {})
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        _config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

fn peer_id_to_scalar(peer_id: &PeerId) -> Scalar<Public> {
    let id = (peer_id.to_usize() + 1) as u32;
    Scalar::from_non_zero_u32(NonZeroU32::new(id).expect("NonZeroU32 returned None")).public()
}

pub struct Resolvr {
    pub cfg: ResolvrConfig,
    pub frost: Frost<
        CoreWrapper<
            CtVariableCoreWrapper<
                Sha256VarCore,
                UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
                OidSha256,
            >,
        >,
        Synthetic<
            CoreWrapper<
                CtVariableCoreWrapper<
                    Sha256VarCore,
                    UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>, B0>,
                    OidSha256,
                >,
            >,
            GlobalRng<OsRng>,
        >,
    >,
}

impl std::fmt::Debug for Resolvr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolvr").field("cfg", &self.cfg).finish()
    }
}

#[async_trait]
impl ServerModule for Resolvr {
    type Common = ResolvrModuleTypes;
    type Gen = ResolvrGen;
    type VerificationCache = ResolvrVerificationCache;

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> Vec<ResolvrConsensusItem> {
        let nonce_requests: Vec<_> = dbtx
            .find_by_prefix(&ResolvrNonceKeyPrefix)
            .await
            .collect::<Vec<_>>()
            .await;

        let consensus_items = nonce_requests
            .into_iter()
            .filter(|(_, nonce)| nonce.is_none())
            .map(|(msg, _)| {
                ResolvrConsensusItem::Nonce(
                    msg.0,
                    ResolvrNonceKeyPair(NonceKeyPair::random(&mut rand::rngs::OsRng)),
                )
            });

        let frost_key = self.cfg.consensus.frost_key.clone();

        let sig_requests: Vec<_> = dbtx
            .find_by_prefix(&ResolvrSignatureShareKeyPrefix)
            .await
            .collect::<Vec<_>>()
            .await;
        //sig_requests
        //    .into_iter()
        //    .filter(|(_, sig)| sig.is_none())
        //    .map(|(msg, sig)| {
        // TODO: Get nonces here, start sign session, and sign signature share
        //let session = frost.start_sign_session(frost_key.into_xonly_key());
        //todo!()
        //        (msg, sig)
        //    });

        consensus_items.collect()
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut ModuleDatabaseTransaction<'b>,
        consensus_item: ResolvrConsensusItem,
        peer_id: PeerId,
    ) -> anyhow::Result<()> {
        // Insert newly received nonces into the database
        match consensus_item {
            ResolvrConsensusItem::Nonce(msg, nonce) => {
                if dbtx
                    .get_value(&ResolvrNonceKey(msg.clone(), peer_id))
                    .await
                    .is_some()
                {
                    bail!("Already received a nonce for this message");
                }

                dbtx.insert_new_entry(&ResolvrNonceKey(msg.clone(), peer_id), &Some(nonce))
                    .await;

                let nonces = dbtx
                    .find_by_prefix(&ResolvrNonceKeyMessagePrefix(msg.clone()))
                    .await
                    .collect::<Vec<_>>()
                    .await;

                // Check if we have enough nonces to begin a signing session
                if nonces.len() <= self.cfg.consensus.threshold as usize {
                    return Ok(());
                }

                dbtx.insert_new_entry(&ResolvrSignatureShareKey(msg.clone(), peer_id), &None)
                    .await;
            } // TODO: Construct all signature shares here and produce a signature
        }

        // Collect all of the nonces we've received so far

        Ok(())
    }

    fn build_verification_cache<'a>(
        &'a self,
        _inputs: impl Iterator<Item = &'a ResolvrInput> + Send,
    ) -> Self::VerificationCache {
        ResolvrVerificationCache
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut ModuleDatabaseTransaction<'c>,
        _input: &'b ResolvrInput,
        _cache: &Self::VerificationCache,
    ) -> Result<InputMeta, ModuleError> {
        Ok(InputMeta {
            amount: TransactionItemAmount {
                amount: Amount::from_sats(0),
                fee: Amount::from_sats(0),
            },
            pub_keys: vec![],
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        _dbtx: &mut ModuleDatabaseTransaction<'b>,
        _output: &'a ResolvrOutput,
        _out_point: OutPoint,
    ) -> Result<TransactionItemAmount, ModuleError> {
        Ok(TransactionItemAmount {
            amount: Amount::from_sats(0),
            fee: Amount::from_sats(0),
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _out_point: OutPoint,
    ) -> Option<ResolvrOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        _dbtx: &mut ModuleDatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![api_endpoint! {
            "sign_message",
            async |module: &Resolvr, context, message: String| -> () {
                Ok(())
            }
        }]
    }
}

impl Resolvr {
    pub fn new(cfg: ResolvrConfig, frost: ResolvrFrost) -> Resolvr {
        //Self { cfg, frost: frost::new_with_synthetic_nonces::<Sha256,
        // rand::rngs::OsRng>() }
        Self { cfg, frost }
    }
}

#[derive(Debug, Clone)]
pub struct ResolvrVerificationCache;

impl fedimint_core::server::VerificationCache for ResolvrVerificationCache {}
