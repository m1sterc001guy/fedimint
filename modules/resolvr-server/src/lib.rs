use std::collections::BTreeMap;
use std::num::NonZeroU32;

use anyhow::{anyhow, bail};
use async_trait::async_trait;
use db::{
    MessageNonceRequest, MessageSignRequest, ResolvrNonceKey, ResolvrNonceKeyMessagePrefix,
    ResolvrSignatureShareKey, ResolvrSignatureShareKeyMessagePrefix,
};
use fedimint_core::config::{
    ConfigGenModuleParams, DkgResult, FrostShareAndPop, ServerModuleConfig,
    ServerModuleConsensusConfig, TypedServerModuleConfig, TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{DatabaseVersion, MigrationMap, ModuleDatabaseTransaction};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    api_endpoint, ApiEndpoint, CoreConsensusVersion, ExtendsCommonModuleInit, InputMeta,
    ModuleConsensusVersion, ModuleError, PeerHandle, ServerModuleInit, ServerModuleInitArgs,
    SupportedModuleApiVersions, TransactionItemAmount,
};
use fedimint_core::server::DynServerModule;
use fedimint_core::{apply, async_trait_maybe_send, Amount, OutPoint, PeerId, ServerModule};
use fedimint_server::check_auth;
use fedimint_server::config::distributedgen::PeerHandleOps;
use futures::StreamExt;
use nostr_sdk::{event, Client, Event, Keys, ToBech32};
use rand::rngs::OsRng;
use resolvr_common::config::{
    ResolvrClientConfig, ResolvrConfig, ResolvrConfigConsensus, ResolvrConfigLocal,
    ResolvrConfigPrivate, ResolvrGenParams,
};
use resolvr_common::{
    ResolvrCommonGen, ResolvrConsensusItem, ResolvrInput, ResolvrModuleTypes, ResolvrNonceKeyPair,
    ResolvrOutput, ResolvrOutputOutcome, ResolvrSignatureShare, UnsignedEvent, CONSENSUS_VERSION,
};
use schnorr_fun::frost::{self, Frost};
use schnorr_fun::fun::marker::{Public, Secret, Zero};
use schnorr_fun::fun::{Point, Scalar};
use schnorr_fun::musig::NonceKeyPair;
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::{Message, Signature};
use serde_json::json;
use sha2::digest::core_api::{CoreWrapper, CtVariableCoreWrapper};
use sha2::digest::typenum::{UInt, UTerm, B0, B1};
use sha2::{OidSha256, Sha256VarCore};
use tracing::info;

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
        Ok(Resolvr::new(args.cfg().to_typed()?, self.frost.clone())
            .await?
            .into())
    }

    fn get_database_migrations(&self) -> MigrationMap {
        MigrationMap::new()
    }

    fn trusted_dealer_gen(
        &self,
        _peers: &[PeerId],
        _params: &ConfigGenModuleParams,
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
            private: ResolvrConfigPrivate {
                my_secret_share,
                my_peer_id: peers.our_id,
            },
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
    // TODO: Use typedef
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
    pub nostr_client: Client,
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

    async fn consensus_proposal(
        &self,
        dbtx: &mut ModuleDatabaseTransaction<'_>,
    ) -> Vec<ResolvrConsensusItem> {
        let mut consensus_items = Vec::new();
        if let Some(event) = dbtx.get_value(&MessageNonceRequest).await {
            consensus_items.push(ResolvrConsensusItem::Nonce(
                event,
                ResolvrNonceKeyPair(NonceKeyPair::random(&mut rand::rngs::OsRng)),
            ));
        }

        if let Some(event) = dbtx.get_value(&MessageSignRequest).await {
            let frost_key = self.cfg.consensus.frost_key.clone();
            let xonly_frost_key = frost_key.into_xonly_key();
            let message_raw = Message::raw(event.0.id.as_bytes());
            let nonces = Resolvr::get_nonces(dbtx, event.clone()).await;
            let session_nonces = nonces
                .clone()
                .into_iter()
                .map(|(key, nonce)| (key, nonce.public()))
                .collect::<BTreeMap<_, _>>();
            let session =
                self.frost
                    .start_sign_session(&xonly_frost_key, session_nonces, message_raw);

            let my_secret_share = self.cfg.private.my_secret_share.clone();
            let my_index = peer_id_to_scalar(&self.cfg.private.my_peer_id);
            let my_nonce = nonces
                .get(&my_index)
                .expect("This peer did not contribute a nonce?")
                .clone();
            let my_sig_share = self.frost.sign(
                &xonly_frost_key,
                &session,
                my_index,
                &my_secret_share,
                my_nonce,
            );
            let resolvr_sig_share = ResolvrSignatureShare(my_sig_share);
            info!(
                "Submitting FrostSigShare from peer: {}",
                self.cfg.private.my_peer_id
            );
            consensus_items.push(ResolvrConsensusItem::FrostSigShare(
                event,
                resolvr_sig_share,
            ));
        }

        consensus_items
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
                    bail!("Already received a nonce for this message and peer. PeerId: {peer_id}");
                }

                let my_peer_id = self.cfg.private.my_peer_id;
                info!("Saving new Nonce Consensus Item. Nonce: {nonce:?} PeerId: {peer_id} MyPeerId: {my_peer_id}");
                dbtx.insert_new_entry(&ResolvrNonceKey(msg.clone(), peer_id), &nonce)
                    .await;

                let nonces = dbtx
                    .find_by_prefix(&ResolvrNonceKeyMessagePrefix(msg.clone()))
                    .await
                    .collect::<Vec<_>>()
                    .await;

                let threshold = self.cfg.consensus.threshold;
                if nonces.len() >= threshold as usize {
                    info!("Got enough nonces!");
                    dbtx.remove_entry(&MessageNonceRequest).await;

                    // If my nonce was included, submit a request to sign a share
                    if nonces
                        .into_iter()
                        .find(|(key, _)| key.1 == my_peer_id)
                        .is_some()
                    {
                        dbtx.insert_new_entry(&MessageSignRequest, &msg.clone())
                            .await;
                    }
                } else {
                    info!(
                        "Dont have enough nonces yet. Nonce Len: {} Threshold: {}",
                        nonces.len(),
                        threshold
                    );
                }
            }
            ResolvrConsensusItem::FrostSigShare(unsigned_event, share) => {
                if dbtx
                    .get_value(&ResolvrSignatureShareKey(unsigned_event.clone(), peer_id))
                    .await
                    .is_some()
                {
                    bail!(
                        "Already received a sig share for this message and peer. PeerId: {peer_id}"
                    );
                }

                // Verify the share is valid under the public key
                let my_peer_id = self.cfg.private.my_peer_id;
                info!("Process SigShare Consensus Item. Message: Nonce: {share:?} PeerId: {peer_id} MyPeerId: {my_peer_id}");
                let xonly_frost_key = self.cfg.consensus.frost_key.clone().into_xonly_key();
                let message_raw = Message::raw(unsigned_event.0.id.as_bytes());
                let nonces = Resolvr::get_nonces(dbtx, unsigned_event.clone()).await;
                let session_nonces = nonces
                    .clone()
                    .into_iter()
                    .map(|(key, nonce)| (key, nonce.public()))
                    .collect::<BTreeMap<_, _>>();
                let session =
                    self.frost
                        .start_sign_session(&xonly_frost_key, session_nonces, message_raw);

                let curr_index = peer_id_to_scalar(&peer_id);
                info!("Verifying received signature share...");
                if !self.frost.verify_signature_share(
                    &xonly_frost_key,
                    &session,
                    curr_index,
                    share.0,
                ) {
                    info!("RECEIVED SIGNATURE SHARE WAS INVALID");
                    return Err(anyhow!("Signature share from {peer_id} is not valid"));
                }

                info!("Saving SigShare to database. Message: Nonce: {share:?} PeerId: {peer_id} MyPeerId: {my_peer_id}");
                dbtx.insert_new_entry(
                    &ResolvrSignatureShareKey(unsigned_event.clone(), peer_id),
                    &share,
                )
                .await;

                let sig_shares = dbtx
                    .find_by_prefix(&ResolvrSignatureShareKeyMessagePrefix(
                        unsigned_event.clone(),
                    ))
                    .await
                    .collect::<Vec<_>>()
                    .await;

                let threshold = self.cfg.consensus.threshold;
                if sig_shares.len() >= threshold as usize {
                    info!("Got enough signature shares!");
                    dbtx.remove_entry(&MessageSignRequest).await;

                    let frost_shares = sig_shares
                        .into_iter()
                        .map(|(_, sig_share)| sig_share.0)
                        .collect::<Vec<_>>();

                    // Try to combine the messages into a signature
                    let combined_sig = self.frost.combine_signature_shares(
                        &xonly_frost_key,
                        &session,
                        frost_shares,
                    );

                    tracing::info!(
                        "Signature for message. Message: {unsigned_event:?} Signature: {combined_sig}"
                    );

                    let verification_outcome = self.frost.schnorr.verify(
                        &xonly_frost_key.public_key(),
                        message_raw,
                        &combined_sig,
                    );
                    tracing::info!("Signature Verification Outcome: {verification_outcome}");

                    let signature = nostr_sdk::prelude::schnorr::Signature::from_slice(
                        &combined_sig.to_bytes(),
                    )?;
                    info!("Successfully created Signature: {signature}");
                    let signed_event = unsigned_event.0.add_signature(signature);
                    info!("SignedEvent: {signed_event:?}");

                    let send_result = self.nostr_client.send_event(signed_event.unwrap()).await;
                    info!("SendResult: {send_result:?}");
                    let broadcasted_event = send_result.unwrap();

                    // TODO: Write to database as OutputOutcome
                }
            }
        }

        Ok(())
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        _dbtx: &mut ModuleDatabaseTransaction<'c>,
        _input: &'b ResolvrInput,
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
        vec![
            api_endpoint! {
                "sign_event",
                async |_module: &Resolvr, context, unsigned_event: UnsignedEvent| -> () {
                    check_auth(context)?;
                    info!("Received sign_message request. Message: {unsigned_event:?}");
                    let mut dbtx = context.dbtx();
                    dbtx.insert_new_entry(&MessageNonceRequest, &unsigned_event).await;
                    Ok(())
                }
            },
            api_endpoint! {
                "npub",
                async |module: &Resolvr, _context, _v: ()| -> nostr_sdk::key::XOnlyPublicKey {
                    let public_key = module.cfg.consensus.frost_key.public_key().to_xonly_bytes();
                    let xonly = nostr_sdk::key::XOnlyPublicKey::from_slice(&public_key).expect("Failed to create xonly public key");
                    info!("Nostr NPUB: {}", xonly.to_bech32().expect("Failed to format npub as bech32"));
                    Ok(xonly)
                }
            },
        ]
    }
}

impl Resolvr {
    pub async fn new(cfg: ResolvrConfig, frost: ResolvrFrost) -> anyhow::Result<Resolvr> {
        let public_key = cfg.consensus.frost_key.public_key().to_xonly_bytes();
        let xonly = nostr_sdk::key::XOnlyPublicKey::from_slice(&public_key)
            .expect("Failed to create xonly public key");
        let keys = Keys::from_public_key(xonly);
        let nostr_client = Client::new(&keys);
        nostr_client.add_relay("wss://relay.damus.io", None).await?;
        nostr_client
            .add_relay("wss://relay.snort.social", None)
            .await?;
        nostr_client.add_relay("wss://nostr.wine", None).await?;
        nostr_client.add_relay("wss://nos.lol", None).await?;
        nostr_client.connect().await;
        Ok(Self {
            cfg,
            frost,
            nostr_client,
        })
    }

    async fn get_nonces(
        dbtx: &mut ModuleDatabaseTransaction<'_>,
        unsigned_event: UnsignedEvent,
    ) -> BTreeMap<Scalar<Public>, NonceKeyPair> {
        let mut nonces = BTreeMap::new();
        let potential_nonces = dbtx
            .find_by_prefix(&ResolvrNonceKeyMessagePrefix(unsigned_event))
            .await
            .collect::<Vec<_>>()
            .await;
        for (key, nonce) in potential_nonces {
            nonces.insert(peer_id_to_scalar(&key.1), nonce.0);
        }

        nonces
    }
}
