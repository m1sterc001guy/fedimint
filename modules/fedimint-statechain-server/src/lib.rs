#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]

pub mod db;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, bail, ensure};
use bitcoin::{Transaction, TxOut};
use db::{
    BlockCountVoteKey, BlockCountVotePrefix, CoinKey, CoinPrefix, DbKeyPrefix,
    DkgContributionCoinPrefix, DkgContributionKey, DkgContributionPrefix, EphemeralKeyEpochPrefix,
    EphemeralKeyKey, EphemeralKeyPrefix, EphemeralSecretKey, EphemeralSecretPrefix,
    FundingOutpointKey, FundingOutpointPrefix, IncomingKey, IncomingPrefix, IncomingReceiverPrefix,
    KeyGenCoinKey, KeyGenCoinPrefix, OperatorShareKey, OperatorSharePrefix, PendingBroadcastKey,
    PendingBroadcastPrefix, SigningNonceCoinPrefix, SigningNonceKey, SigningNoncePrefix,
    StoredNonce, UnannouncedEphemeralKey, UnannouncedEphemeralKeyPrefix,
};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::envs::{
    FM_ENABLE_MODULE_STATECHAIN_ENV, is_env_var_set_opt, is_running_in_test_env,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    ApiEndpoint, ApiError, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, TransactionItemAmounts, public_api_endpoint,
};
use fedimint_core::task::{TaskGroup, sleep};
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{
    InPoint, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send, push_db_key_items,
    push_db_pair_items, util,
};
use fedimint_logging::LOG_MODULE_STATECHAIN;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::PeerHandleOps;
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
pub use fedimint_statechain_common as common;
use fedimint_statechain_common::config::{
    StatechainClientConfig, StatechainConfig, StatechainConfigConsensus, StatechainConfigPrivate,
    StatechainParams,
};
use fedimint_statechain_common::crypto::{
    DKG_CONTEXT, ROTATION_CONTEXT, SignSession, SigningKey, add_polys, add_shares,
    dkg_contribution, dkg_operator_poly, encryption_context, recover_dkg_share,
    recover_tweak_share, share_from_bytes, verify_dkg_contribution, verify_rotation_commitment,
    verify_signature,
};
use fedimint_statechain_common::endpoint_constants::{
    BLOCK_COUNT_ENDPOINT, COIN_ENDPOINT, EPHEMERAL_KEYS_ENDPOINT, INCOMING_ENDPOINT,
    NONCE_ENDPOINT, SIGN_ENDPOINT,
};
use fedimint_statechain_common::{
    BLOCK_COUNT_VOTE_DELAY, CONFIRMATION_FINALITY_DELAY, CoinId, CoinRecord, CoinStatus,
    MODULE_CONSENSUS_VERSION, NonceRequest, PublicNonce, ScalarBytes, SignRequest, SigningPurpose,
    StatechainCommonInit, StatechainConsensusItem, StatechainInput, StatechainInputError,
    StatechainInputV0, StatechainModuleTypes, StatechainOutput, StatechainOutputError,
    StatechainOutputOutcome, StatechainOutputV0, TweakDeal, txs,
};
use futures::StreamExt;
use rand::rngs::OsRng;
use schnorr_fun::binonce::SecretNonce;
use secp256k1::{PublicKey, SECP256K1, SecretKey};
use strum::IntoEnumIterator;
use tracing::{debug, info, warn};

/// Maximum number of blocks the consensus block count can advance in a single
/// consensus item to limit the work done in one `process_consensus_item` step.
const MAX_BLOCK_COUNT_INCREMENT: u64 = 5;

/// Devimint tests can mine many regtest blocks at once, so use a larger cap in
/// test environments to avoid waiting on several consensus sessions.
const TEST_MAX_BLOCK_COUNT_INCREMENT: u64 = 100;

/// How many unused signing nonces we keep per coin. A ROAST signing leaves at
/// most a couple per guardian behind and the owner can open at most
/// `n - t + 1` sessions per signature, so this leaves ample room for
/// signatures in flight while bounding what the owner can make us store.
const MAX_STORED_NONCES_PER_COIN: usize = 32;

/// Test-only: the peer id of a guardian that hands out nonces but never answers
/// signature share requests, the stall ROAST has to route around. Ignored
/// outside test environments.
pub const FM_STATECHAIN_TEST_STALL_SIGNER_ENV: &str = "FM_STATECHAIN_TEST_STALL_SIGNER";

#[derive(Debug, Clone)]
pub struct StatechainInit;

impl ModuleInit for StatechainInit {
    type Common = StatechainCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut items: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();
        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Coin => {
                    push_db_pair_items!(dbtx, CoinPrefix, CoinKey, CoinRecord, items, "Coins");
                }
                DbKeyPrefix::OperatorShare => {
                    push_db_pair_items!(
                        dbtx,
                        OperatorSharePrefix,
                        OperatorShareKey,
                        ScalarBytes,
                        items,
                        "Operator Shares"
                    );
                }
                DbKeyPrefix::EphemeralSecret => {
                    push_db_pair_items!(
                        dbtx,
                        EphemeralSecretPrefix,
                        EphemeralSecretKey,
                        SecretKey,
                        items,
                        "Ephemeral Secrets"
                    );
                }
                DbKeyPrefix::EphemeralKey => {
                    push_db_pair_items!(
                        dbtx,
                        EphemeralKeyPrefix,
                        EphemeralKeyKey,
                        PublicKey,
                        items,
                        "Ephemeral Keys"
                    );
                }
                DbKeyPrefix::DkgContribution => {
                    push_db_pair_items!(
                        dbtx,
                        DkgContributionPrefix,
                        DkgContributionKey,
                        fedimint_statechain_common::DkgContribution,
                        items,
                        "DKG Contributions"
                    );
                }
                DbKeyPrefix::KeyGenCoin => {
                    push_db_key_items!(
                        dbtx,
                        KeyGenCoinPrefix,
                        KeyGenCoinKey,
                        items,
                        "KeyGen Coins"
                    );
                }
                DbKeyPrefix::FundingOutpoint => {
                    push_db_pair_items!(
                        dbtx,
                        FundingOutpointPrefix,
                        FundingOutpointKey,
                        CoinId,
                        items,
                        "Funding Outpoints"
                    );
                }
                DbKeyPrefix::Incoming => {
                    push_db_key_items!(dbtx, IncomingPrefix, IncomingKey, items, "Incoming");
                }
                DbKeyPrefix::SigningNonce => {
                    push_db_pair_items!(
                        dbtx,
                        SigningNoncePrefix,
                        SigningNonceKey,
                        StoredNonce,
                        items,
                        "Signing Nonces"
                    );
                }
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u64,
                        items,
                        "Block Count Votes"
                    );
                }
                DbKeyPrefix::PendingBroadcast => {
                    push_db_pair_items!(
                        dbtx,
                        PendingBroadcastPrefix,
                        PendingBroadcastKey,
                        Transaction,
                        items,
                        "Pending Broadcasts"
                    );
                }
                DbKeyPrefix::UnannouncedEphemeralKey => {
                    push_db_key_items!(
                        dbtx,
                        UnannouncedEphemeralKeyPrefix,
                        UnannouncedEphemeralKey,
                        items,
                        "Unannounced Ephemeral Keys"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for StatechainInit {
    type Module = Statechain;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn is_enabled_by_default(&self) -> bool {
        // Experimental: guardians have to opt in.
        is_env_var_set_opt(FM_ENABLE_MODULE_STATECHAIN_ENV).unwrap_or(false)
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![EnvVarDoc {
            name: FM_ENABLE_MODULE_STATECHAIN_ENV,
            description: "Set to 1/true to enable the experimental statechain module. Disabled by default.",
        }]
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Statechain::new(
            args.cfg().to_typed()?,
            args.db().clone(),
            args.task_group(),
            args.server_bitcoin_rpc_monitor(),
            args.our_peer_id(),
            args.num_peers().peer_ids().collect(),
        ))
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        peers
            .iter()
            .map(|peer| {
                let config = StatechainConfig {
                    private: StatechainConfigPrivate,
                    consensus: StatechainConfigConsensus {
                        params: StatechainParams::new(args.network),
                    },
                };

                (*peer, config.to_erased())
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        _peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        // Operator keys are generated per coin, so the setup has no secrets to
        // agree on.
        let config = StatechainConfig {
            private: StatechainConfigPrivate,
            consensus: StatechainConfigConsensus {
                params: StatechainParams::new(args.network),
            },
        };

        Ok(config.to_erased())
    }

    fn validate_config(
        &self,
        _identity: &PeerId,
        config: ServerModuleConfig,
    ) -> anyhow::Result<()> {
        config.to_typed::<StatechainConfig>()?;

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<StatechainClientConfig> {
        let config = StatechainConfigConsensus::from_erased(config)?;

        Ok(StatechainClientConfig {
            params: config.params,
        })
    }

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Statechain>> {
        BTreeMap::new()
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}

#[derive(Debug)]
pub struct Statechain {
    cfg: StatechainConfig,
    db: Database,
    btc_rpc: ServerBitcoinRpcMonitor,
    our_peer_id: PeerId,
    peers: BTreeSet<PeerId>,
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Statechain {
    type Common = StatechainModuleTypes;
    type Init = StatechainInit;

    async fn consensus_proposal(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<StatechainConsensusItem> {
        let mut items = Vec::new();

        if let Some(status) = self.btc_rpc.status() {
            assert_eq!(status.network, self.params().network);

            let block_count_vote = status.block_count.saturating_sub(BLOCK_COUNT_VOTE_DELAY);

            let consensus_block_count = self.consensus_block_count(dbtx).await;

            let max_block_count_increment = if is_running_in_test_env() {
                TEST_MAX_BLOCK_COUNT_INCREMENT
            } else {
                MAX_BLOCK_COUNT_INCREMENT
            };

            let block_count_vote = match consensus_block_count {
                0 => block_count_vote,
                _ => block_count_vote.min(consensus_block_count + max_block_count_increment),
            };

            items.push(StatechainConsensusItem::BlockCount(block_count_vote));
        }

        let unannounced = dbtx
            .find_by_prefix(&UnannouncedEphemeralKeyPrefix)
            .await
            .map(|(key, ())| (key.0, key.1))
            .collect::<Vec<(CoinId, u64)>>()
            .await;

        for (coin, epoch) in unannounced {
            if let Some(secret) = dbtx.get_value(&EphemeralSecretKey(coin, epoch)).await {
                items.push(StatechainConsensusItem::EphemeralKey {
                    coin,
                    epoch,
                    key: secret.public_key(SECP256K1),
                });
            }
        }

        let keygen_coins = dbtx
            .find_by_prefix(&KeyGenCoinPrefix)
            .await
            .map(|(key, ())| key.0)
            .collect::<Vec<CoinId>>()
            .await;

        for coin in keygen_coins {
            if dbtx
                .get_value(&DkgContributionKey(coin, self.our_peer_id))
                .await
                .is_some()
            {
                continue;
            }

            let ephemeral_keys = self.ephemeral_keys(dbtx, coin, 0).await;

            // Every guardian receives a share, so every guardian's key is needed.
            if ephemeral_keys.len() != self.peers.len() {
                continue;
            }

            let contribution = dkg_contribution(
                self.our_peer_id,
                self.threshold(),
                &ephemeral_keys,
                &encryption_context(coin, 0, DKG_CONTEXT),
                &mut OsRng,
            );

            items.push(StatechainConsensusItem::DkgContribution { coin, contribution });
        }

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: StatechainConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        match consensus_item {
            StatechainConsensusItem::BlockCount(vote) => {
                self.process_block_count(dbtx, vote, peer).await
            }
            StatechainConsensusItem::EphemeralKey { coin, epoch, key } => {
                let record = dbtx
                    .get_value(&CoinKey(coin))
                    .await
                    .context("Unknown coin")?;

                ensure!(epoch == record.epoch, "Ephemeral key for a past epoch");

                ensure!(
                    record.signers.contains(&peer),
                    "Peer does not hold a share of this coin"
                );

                ensure!(
                    !matches!(
                        record.status,
                        CoinStatus::Exiting | CoinStatus::Closed { .. } | CoinStatus::Invalid
                    ),
                    "The coin can no longer rotate"
                );

                ensure!(
                    dbtx.insert_entry(&EphemeralKeyKey(coin, epoch, peer), &key)
                        .await
                        .is_none(),
                    "Ephemeral key is already announced"
                );

                if peer == self.our_peer_id {
                    dbtx.remove_entry(&UnannouncedEphemeralKey(coin, epoch))
                        .await;
                }

                Ok(())
            }
            StatechainConsensusItem::DkgContribution { coin, contribution } => {
                let record = dbtx
                    .get_value(&CoinKey(coin))
                    .await
                    .context("Unknown coin")?;

                ensure!(
                    record.status == CoinStatus::KeyGen,
                    "Key generation is not running for this coin"
                );

                ensure!(
                    self.ephemeral_keys(dbtx, coin, 0).await.len() == self.peers.len(),
                    "Not every guardian has announced its ephemeral key yet"
                );

                ensure!(
                    verify_dkg_contribution(peer, &self.peers, self.threshold(), &contribution),
                    "Invalid DKG contribution"
                );

                ensure!(
                    dbtx.insert_entry(&DkgContributionKey(coin, peer), &contribution)
                        .await
                        .is_none(),
                    "DKG contribution is already recorded"
                );

                self.finish_dkg_if_complete(dbtx, coin, record).await;

                Ok(())
            }
            StatechainConsensusItem::Default { variant, .. } => {
                bail!("Received statechain consensus item with unknown variant {variant}")
            }
        }
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b StatechainInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, StatechainInputError> {
        let input = input.ensure_v0_ref()?;
        let coin = input.coin();

        let mut record = dbtx
            .get_value(&CoinKey(coin))
            .await
            .ok_or(StatechainInputError::UnknownCoin)?;

        let pub_key = match input {
            StatechainInputV0::RegisterFunding {
                funding,
                exit_script,
                ..
            } => {
                ensure_status(record.status == CoinStatus::AwaitingFunding)?;

                if funding.amount < self.params().min_deposit {
                    return Err(StatechainInputError::DepositTooSmall);
                }

                record.funding = Some(*funding);
                record.exit_script = Some(exit_script.clone());
                record.level = 0;
                record.status = CoinStatus::Unconfirmed;

                // The depositor's exit has to be constructible with the deposit.
                record
                    .signing_tx(self.params(), SigningPurpose::Exit { level: 0 })
                    .map_err(|_| StatechainInputError::InsufficientValue)?;

                if dbtx
                    .insert_entry(&FundingOutpointKey(funding.outpoint), &coin)
                    .await
                    .is_some()
                {
                    return Err(StatechainInputError::FundingAlreadyRegistered);
                }

                record.user_pk
            }
            StatechainInputV0::Send { receiver, .. } => {
                ensure_status(record.status == CoinStatus::Active)?;

                if receiver.pubkey == record.user_pk {
                    return Err(StatechainInputError::UnchangedUserKey);
                }

                let user_pk = record.user_pk;

                record.status = CoinStatus::SendPending {
                    receiver: receiver.clone(),
                };

                let next_level = record
                    .level
                    .checked_add(1)
                    .ok_or(StatechainInputError::TimelockExhausted)?;

                // Fails if the receiver's exit would have no timelock left or no
                // value above the dust limit.
                record
                    .signing_tx(self.params(), SigningPurpose::Exit { level: next_level })
                    .map_err(|err| match err {
                        fedimint_statechain_common::SigningTxError::TimelockExhausted => {
                            StatechainInputError::TimelockExhausted
                        }
                        _ => StatechainInputError::InsufficientValue,
                    })?;

                user_pk
            }
            StatechainInputV0::CompleteSend {
                node_signature,
                exit_signature,
                intermediate_pk,
                tweak,
                encrypted_secret,
                ..
            } => {
                let CoinStatus::SendPending { receiver } = record.status.clone() else {
                    return Err(StatechainInputError::InvalidCoinState);
                };

                let aggregate_pk = record
                    .aggregate_pk()
                    .ok_or(StatechainInputError::InvalidCoinState)?;

                let next_level = record.level + 1;

                for (purpose, signature) in [
                    (SigningPurpose::Node, node_signature),
                    (SigningPurpose::Exit { level: next_level }, exit_signature),
                ] {
                    let message = record
                        .signing_tx(self.params(), purpose)
                        .map_err(|_| StatechainInputError::InvalidCoinState)?
                        .sighash();

                    if !verify_signature(&aggregate_pk, &message, signature) {
                        return Err(StatechainInputError::InvalidSignature);
                    }
                }

                let sender_pk = record.user_pk;

                self.rotate(dbtx, coin, &mut record, tweak, intermediate_pk)
                    .await?;

                record.level = next_level;
                record.exit_script = Some(receiver.exit_script.clone());
                record.node_signature = Some(*node_signature);
                record.exit_signature = Some(*exit_signature);

                dbtx.insert_entry(&IncomingKey(receiver.pubkey, coin), &())
                    .await;

                record.status = CoinStatus::AwaitingClaim {
                    receiver,
                    encrypted_secret: *encrypted_secret,
                };

                sender_pk
            }
            StatechainInputV0::Claim { tweak, .. } => {
                let CoinStatus::AwaitingClaim { receiver, .. } = record.status.clone() else {
                    return Err(StatechainInputError::InvalidCoinState);
                };

                self.rotate(dbtx, coin, &mut record, tweak, &receiver.pubkey)
                    .await?;

                dbtx.remove_entry(&IncomingKey(receiver.pubkey, coin)).await;

                record.status = CoinStatus::Active;

                receiver.pubkey
            }
            StatechainInputV0::PegOut {
                destination, fee, ..
            } => {
                ensure_status(record.status == CoinStatus::Active)?;

                record.status = CoinStatus::PegOutPending {
                    destination: destination.clone(),
                    fee: *fee,
                };

                record
                    .signing_tx(self.params(), SigningPurpose::PegOut)
                    .map_err(|_| StatechainInputError::InsufficientValue)?;

                record.user_pk
            }
            StatechainInputV0::CompletePegOut { signature, .. } => {
                ensure_status(matches!(record.status, CoinStatus::PegOutPending { .. }))?;

                let aggregate_pk = record
                    .aggregate_pk()
                    .ok_or(StatechainInputError::InvalidCoinState)?;

                let signing_tx = record
                    .signing_tx(self.params(), SigningPurpose::PegOut)
                    .map_err(|_| StatechainInputError::InvalidCoinState)?;

                if !verify_signature(&aggregate_pk, &signing_tx.sighash(), signature) {
                    return Err(StatechainInputError::InvalidSignature);
                }

                let tx = txs::with_signature(signing_tx.tx, signature);

                dbtx.insert_entry(&PendingBroadcastKey(tx.compute_txid()), &tx)
                    .await;

                record.status = CoinStatus::PegOutBroadcast { tx };

                record.user_pk
            }
        };

        dbtx.insert_entry(&CoinKey(coin), &record).await;

        Ok(InputMeta {
            amount: TransactionItemAmounts::ZERO,
            pub_key,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a StatechainOutput,
        outpoint: OutPoint,
    ) -> Result<TransactionItemAmounts, StatechainOutputError> {
        let StatechainOutputV0::Deposit { user_pk } = output.ensure_v0_ref()?;

        let coin = CoinId(outpoint);

        dbtx.insert_new_entry(
            &CoinKey(coin),
            &CoinRecord {
                user_pk: *user_pk,
                epoch: 0,
                operator_poly: Vec::new(),
                signers: self.peers.clone(),
                funding: None,
                exit_script: None,
                level: 0,
                node_signature: None,
                exit_signature: None,
                status: CoinStatus::KeyGen,
            },
        )
        .await;

        dbtx.insert_new_entry(&KeyGenCoinKey(coin), &()).await;

        // Announced by our next consensus proposal; the other guardians encrypt
        // our shares of the coin's operator key to it.
        new_ephemeral_secret(dbtx, coin, 0).await;

        Ok(TransactionItemAmounts::ZERO)
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _outpoint: OutPoint,
    ) -> Option<StatechainOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _audit: &mut Audit,
        _module_instance_id: ModuleInstanceId,
    ) {
        // Statecoins are UTXOs owned jointly with their users, not liabilities
        // of the federation's e-cash.
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Statechain, context, _params: ()| -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_block_count(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                COIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Statechain, context, coin: CoinId| -> Option<CoinRecord> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx.get_value(&CoinKey(coin)).await)
                }
            },
            public_api_endpoint! {
                EPHEMERAL_KEYS_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Statechain, context, coin: CoinId| -> BTreeMap<PeerId, PublicKey> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    let record = dbtx
                        .get_value(&CoinKey(coin))
                        .await
                        .ok_or_else(|| ApiError::bad_request("Unknown coin".to_string()))?;
                    Ok(module.ephemeral_keys(&mut dbtx, coin, record.epoch).await)
                }
            },
            public_api_endpoint! {
                INCOMING_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Statechain, context, receiver: PublicKey| -> Vec<CoinId> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx
                        .find_by_prefix(&IncomingReceiverPrefix(receiver))
                        .await
                        .map(|(key, ())| key.1)
                        .collect()
                        .await)
                }
            },
            public_api_endpoint! {
                NONCE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Statechain, context, request: NonceRequest| -> PublicNonce {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;
                    let nonce = module
                        .nonce(&mut dbtx.to_ref_nc(), request)
                        .await
                        .map_err(|err| ApiError::bad_request(err.to_string()))?;
                    dbtx.commit_tx_result().await?;
                    Ok(nonce)
                }
            },
            public_api_endpoint! {
                SIGN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Statechain, context, request: SignRequest| -> ScalarBytes {
                    if module.stalls_signing() {
                        std::future::pending::<()>().await;
                    }

                    let db = context.db();
                    let mut dbtx = db.begin_transaction().await;
                    let share = module
                        .sign(&mut dbtx.to_ref_nc(), request)
                        .await
                        .map_err(|err| ApiError::bad_request(err.to_string()))?;
                    // The share must not leave before the removal of its nonce
                    // is committed, or a retry could reuse the nonce.
                    dbtx.commit_tx_result().await?;
                    Ok(share)
                }
            },
        ]
    }
}

/// Generates our ephemeral key for a coin's epoch, to be announced by our next
/// consensus proposal.
async fn new_ephemeral_secret(dbtx: &mut DatabaseTransaction<'_>, coin: CoinId, epoch: u64) {
    dbtx.insert_new_entry(
        &EphemeralSecretKey(coin, epoch),
        &SecretKey::new(&mut OsRng),
    )
    .await;

    dbtx.insert_new_entry(&UnannouncedEphemeralKey(coin, epoch), &())
        .await;
}

/// Removes our ephemeral key for a coin's epoch. Once it is gone the shares
/// encrypted to it in the consensus history can no longer be decrypted.
async fn take_ephemeral_secret(
    dbtx: &mut DatabaseTransaction<'_>,
    coin: CoinId,
    epoch: u64,
) -> Option<SecretKey> {
    dbtx.remove_entry(&UnannouncedEphemeralKey(coin, epoch))
        .await;

    dbtx.remove_entry(&EphemeralSecretKey(coin, epoch)).await
}

fn ensure_status(allowed: bool) -> Result<(), StatechainInputError> {
    if allowed {
        Ok(())
    } else {
        Err(StatechainInputError::InvalidCoinState)
    }
}

impl Statechain {
    fn new(
        cfg: StatechainConfig,
        db: Database,
        task_group: &TaskGroup,
        btc_rpc: ServerBitcoinRpcMonitor,
        our_peer_id: PeerId,
        peers: BTreeSet<PeerId>,
    ) -> Self {
        Self::spawn_broadcast_task(btc_rpc.clone(), db.clone(), task_group);

        Self {
            cfg,
            db,
            btc_rpc,
            our_peer_id,
            peers,
        }
    }

    /// Test hook, see [`FM_STATECHAIN_TEST_STALL_SIGNER_ENV`].
    fn stalls_signing(&self) -> bool {
        is_running_in_test_env()
            && std::env::var(FM_STATECHAIN_TEST_STALL_SIGNER_ENV)
                .ok()
                .and_then(|peer| peer.parse::<u16>().ok())
                .is_some_and(|peer| PeerId::from(peer) == self.our_peer_id)
    }

    fn params(&self) -> &StatechainParams {
        &self.cfg.consensus.params
    }

    fn threshold(&self) -> usize {
        self.peers.to_num_peers().threshold()
    }

    /// Rebroadcasts signed peg-out transactions until block scanning sees
    /// their coin's funding output spent.
    fn spawn_broadcast_task(
        btc_rpc: ServerBitcoinRpcMonitor,
        db: Database,
        task_group: &TaskGroup,
    ) {
        task_group.spawn_cancellable("statechain_broadcast_pegouts", async move {
            loop {
                let pending = db
                    .begin_transaction_nc()
                    .await
                    .find_by_prefix(&PendingBroadcastPrefix)
                    .await
                    .map(|entry| entry.1)
                    .collect::<Vec<Transaction>>()
                    .await;

                for tx in pending {
                    if let Err(err) = btc_rpc.submit_transaction(tx).await {
                        debug!(
                            target: LOG_MODULE_STATECHAIN,
                            err = %err.fmt_compact(),
                            "Error broadcasting peg-out transaction"
                        );
                    }
                }

                sleep(if is_running_in_test_env() {
                    std::time::Duration::from_secs(1)
                } else {
                    std::time::Duration::from_mins(1)
                })
                .await;
            }
        });
    }

    async fn ephemeral_keys(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        coin: CoinId,
        epoch: u64,
    ) -> BTreeMap<PeerId, PublicKey> {
        dbtx.find_by_prefix(&EphemeralKeyEpochPrefix(coin, epoch))
            .await
            .map(|(key, pk)| (key.2, pk))
            .collect()
            .await
    }

    /// Completes a coin's key generation once every guardian contributed:
    /// records the operator polynomial, recovers our share and deletes the
    /// ephemeral key it was encrypted to.
    async fn finish_dkg_if_complete(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        coin: CoinId,
        mut record: CoinRecord,
    ) {
        let contributions = dbtx
            .find_by_prefix(&DkgContributionCoinPrefix(coin))
            .await
            .map(|(key, contribution)| (key.1, contribution))
            .collect::<BTreeMap<PeerId, fedimint_statechain_common::DkgContribution>>()
            .await;

        if contributions.len() != self.peers.len() {
            return;
        }

        let operator_poly = dkg_operator_poly(&contributions)
            .expect("Contributions were checked to have the threshold's degree");

        let ephemeral_sk = take_ephemeral_secret(dbtx, coin, 0).await;

        let share = ephemeral_sk.and_then(|sk| {
            recover_dkg_share(
                self.our_peer_id,
                &sk,
                &contributions,
                &operator_poly,
                &encryption_context(coin, 0, DKG_CONTEXT),
            )
        });

        if let Some(share) = share {
            dbtx.insert_new_entry(&OperatorShareKey(coin), &ScalarBytes::from_scalar(&share))
                .await;

            new_ephemeral_secret(dbtx, coin, 1).await;
        } else {
            warn!(
                target: LOG_MODULE_STATECHAIN,
                %coin,
                "Could not recover a valid operator key share; we will not sign for this coin"
            );
        }

        dbtx.remove_by_prefix(&DkgContributionCoinPrefix(coin))
            .await;
        dbtx.remove_by_prefix(&EphemeralKeyEpochPrefix(coin, 0))
            .await;
        dbtx.remove_entry(&KeyGenCoinKey(coin)).await;

        record.operator_poly = operator_poly;
        record.epoch = 1;
        record.status = CoinStatus::AwaitingFunding;

        dbtx.insert_entry(&CoinKey(coin), &record).await;

        info!(target: LOG_MODULE_STATECHAIN, %coin, "Generated statecoin operator key");
    }

    /// Hands the user half of a coin's key to `new_user_pk` by applying the
    /// tweak deal: every recipient guardian adds its share of the tweak to its
    /// operator share and deletes the old share together with the ephemeral key
    /// the tweak share was encrypted to.
    async fn rotate(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        coin: CoinId,
        record: &mut CoinRecord,
        deal: &TweakDeal,
        new_user_pk: &PublicKey,
    ) -> Result<(), StatechainInputError> {
        if *new_user_pk == record.user_pk {
            return Err(StatechainInputError::UnchangedUserKey);
        }

        if !verify_rotation_commitment(deal, self.threshold(), &record.user_pk, new_user_pk) {
            return Err(StatechainInputError::InvalidTweak);
        }

        // The deal must reach exactly the guardians that announced an ephemeral
        // key for this epoch, and enough of them to keep the coin signable.
        let announced = self.ephemeral_keys(dbtx, coin, record.epoch).await;
        let recipients = deal
            .shares
            .ciphertexts
            .keys()
            .copied()
            .collect::<BTreeSet<PeerId>>();

        if !recipients.iter().eq(announced.keys())
            || recipients.len() < self.threshold()
            || !recipients.is_subset(&record.signers)
        {
            return Err(StatechainInputError::EphemeralKeyMismatch);
        }

        let operator_poly = add_polys(&record.operator_poly, &deal.commitments)
            .ok_or(StatechainInputError::InvalidTweak)?;

        let context = encryption_context(coin, record.epoch, ROTATION_CONTEXT);

        let ephemeral_sk = take_ephemeral_secret(dbtx, coin, record.epoch).await;

        // Removing the old share is what makes the previous user key useless.
        let old_share = dbtx.remove_entry(&OperatorShareKey(coin)).await;

        let new_share = match (ephemeral_sk, old_share.as_ref().and_then(share_from_bytes)) {
            (Some(sk), Some(old_share)) if recipients.contains(&self.our_peer_id) => {
                recover_tweak_share(self.our_peer_id, &sk, deal, &context)
                    .map(|tweak_share| add_shares(&old_share, &tweak_share))
            }
            _ => None,
        };

        if let Some(share) = new_share {
            dbtx.insert_new_entry(&OperatorShareKey(coin), &ScalarBytes::from_scalar(&share))
                .await;

            new_ephemeral_secret(dbtx, coin, record.epoch + 1).await;
        } else if old_share.is_some() {
            warn!(
                target: LOG_MODULE_STATECHAIN,
                %coin,
                "Rotation did not give us a valid operator key share; we will not sign for this coin"
            );
        }

        // Unused nonces belong to sessions over the old key split.
        dbtx.remove_by_prefix(&SigningNonceCoinPrefix(coin)).await;

        dbtx.remove_by_prefix(&EphemeralKeyEpochPrefix(coin, record.epoch))
            .await;

        record.user_pk = *new_user_pk;
        record.operator_poly = operator_poly;
        record.signers = recipients;
        record.epoch += 1;

        Ok(())
    }

    /// Hands out a fresh nonce for a signing session the coin's state allows.
    async fn nonce(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: NonceRequest,
    ) -> anyhow::Result<PublicNonce> {
        let record = dbtx
            .get_value(&CoinKey(request.coin))
            .await
            .context("Unknown coin")?;

        ensure!(
            request.verify(&record.user_pk),
            "The request is not signed by the coin's user key"
        );

        ensure!(
            dbtx.get_value(&OperatorShareKey(request.coin))
                .await
                .is_some(),
            "We do not hold a share of this coin's operator key"
        );

        record.signing_tx(self.params(), request.purpose)?;

        // ROAST leaves a few unused nonces behind per signature, so the oldest
        // nonce is evicted instead of refusing the owner once the cap is hit.
        // An evicted nonce only fails the session it was meant for.
        let mut stored_nonces = dbtx
            .find_by_prefix(&SigningNonceCoinPrefix(request.coin))
            .await
            .map(|(key, stored)| (stored.created, key))
            .collect::<Vec<(u64, SigningNonceKey)>>()
            .await;

        stored_nonces.sort_unstable_by_key(|(created, _)| *created);

        for (_, key) in stored_nonces
            .iter()
            .take((stored_nonces.len() + 1).saturating_sub(MAX_STORED_NONCES_PER_COIN))
        {
            dbtx.remove_entry(key).await;
        }

        let (secret, public) = fedimint_statechain_common::crypto::generate_nonce(&mut OsRng);
        let [hiding, binding] = secret.0;

        let created = fedimint_core::time::duration_since_epoch()
            .as_micros()
            .try_into()
            .unwrap_or(u64::MAX);

        ensure!(
            dbtx.insert_entry(
                &SigningNonceKey(request.coin, request.nonce_id),
                &StoredNonce {
                    purpose: request.purpose,
                    hiding: hiding.to_bytes(),
                    binding: binding.to_bytes(),
                    created,
                },
            )
            .await
            .is_none(),
            "The nonce id was already used"
        );

        Ok(public)
    }

    /// Produces our signature share for a session, consuming its nonce.
    async fn sign(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        request: SignRequest,
    ) -> anyhow::Result<ScalarBytes> {
        let stored = dbtx
            .remove_entry(&SigningNonceKey(request.coin, request.nonce_id))
            .await
            .context("Unknown signing session")?;

        ensure!(
            stored.purpose == request.purpose,
            "The session was opened for another purpose"
        );

        let mut nonce_bytes = [0; 64];
        nonce_bytes[..32].copy_from_slice(&stored.hiding);
        nonce_bytes[32..].copy_from_slice(&stored.binding);
        let secret_nonce = SecretNonce::from_bytes(nonce_bytes).context("Corrupt stored nonce")?;

        let record = dbtx
            .get_value(&CoinKey(request.coin))
            .await
            .context("Unknown coin")?;

        ensure!(
            request.guardian_nonces.len() == self.threshold(),
            "A signing session needs exactly a threshold of guardians"
        );

        ensure!(
            request
                .guardian_nonces
                .keys()
                .all(|peer| record.signers.contains(peer)),
            "A signer does not hold a share of this coin's operator key"
        );

        ensure!(
            request.guardian_nonces.get(&self.our_peer_id)
                == Some(&schnorr_nonce_public(&secret_nonce)),
            "The session does not include our nonce"
        );

        let share = dbtx
            .get_value(&OperatorShareKey(request.coin))
            .await
            .as_ref()
            .and_then(share_from_bytes)
            .context("We do not hold a share of this coin's operator key")?;

        let aggregate_pk = record.aggregate_pk().context("No operator key yet")?;

        let message = record.signing_tx(self.params(), request.purpose)?.sighash();

        let session = SignSession::new(
            SigningKey::new(&aggregate_pk),
            message,
            &request.guardian_nonces,
            request.user_nonce,
        );

        Ok(session.guardian_sign(self.our_peer_id, share, &secret_nonce))
    }

    async fn process_block_count(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        block_count_vote: u64,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let old_consensus_block_count = self.consensus_block_count(dbtx).await;

        let current_vote = dbtx
            .insert_entry(&BlockCountVoteKey(peer), &block_count_vote)
            .await
            .unwrap_or(0);

        ensure!(
            current_vote < block_count_vote,
            "Block count vote is redundant"
        );

        let new_consensus_block_count = self.consensus_block_count(dbtx).await;

        assert!(old_consensus_block_count <= new_consensus_block_count);

        // Coins can only be funded after the federation exists, so outside
        // regtest we do not scan the blocks that predate it. Regtest scans from
        // genesis to avoid racing the first block count transition in tests.
        let scan_from_genesis = self.params().network == bitcoin::Network::Regtest;
        if old_consensus_block_count == 0 && !scan_from_genesis {
            return Ok(());
        }

        // Our bitcoin backend needs to be synced for the following calls to the
        // get_block rpc to be safe for consensus.
        self.await_local_sync_to_block_count(
            new_consensus_block_count + CONFIRMATION_FINALITY_DELAY,
        )
        .await;

        for height in old_consensus_block_count..new_consensus_block_count {
            let block_hash = util::retry(
                "get_block_hash",
                util::backoff_util::background_backoff(),
                || self.btc_rpc.get_block_hash(height),
            )
            .await
            .expect("Bitcoind rpc to get_block_hash failed");

            let block = util::retry(
                "get_block",
                util::backoff_util::background_backoff(),
                || self.btc_rpc.get_block(&block_hash),
            )
            .await
            .expect("Bitcoind rpc to get_block failed");

            assert_eq!(block.block_hash(), block_hash, "Block hash mismatch");

            for tx in &block.txdata {
                let txid = tx.compute_txid();

                for (vout, tx_out) in tx.output.iter().enumerate() {
                    let outpoint = bitcoin::OutPoint {
                        txid,
                        vout: u32::try_from(vout).expect("Bitcoin limits the output count"),
                    };

                    if let Some(coin) = dbtx.get_value(&FundingOutpointKey(outpoint)).await {
                        self.process_funding_confirmation(dbtx, coin, tx_out).await;
                    }
                }

                for input in &tx.input {
                    if let Some(coin) = dbtx
                        .remove_entry(&FundingOutpointKey(input.previous_output))
                        .await
                    {
                        self.process_funding_spend(dbtx, coin, tx).await;
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_funding_confirmation(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        coin: CoinId,
        tx_out: &TxOut,
    ) {
        let mut record = dbtx
            .get_value(&CoinKey(coin))
            .await
            .expect("Funding outpoints are indexed for existing coins");

        if record.status != CoinStatus::Unconfirmed {
            return;
        }

        let funding = record.funding.expect("Unconfirmed coins are funded");

        record.status = if Some(&tx_out.script_pubkey) == record.coin_script().as_ref()
            && tx_out.value == funding.amount
        {
            info!(target: LOG_MODULE_STATECHAIN, %coin, "Statecoin deposit confirmed");
            CoinStatus::Active
        } else {
            warn!(
                target: LOG_MODULE_STATECHAIN,
                %coin,
                "Statecoin funding output does not match its registration"
            );
            CoinStatus::Invalid
        };

        dbtx.insert_entry(&CoinKey(coin), &record).await;
    }

    async fn process_funding_spend(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        coin: CoinId,
        tx: &Transaction,
    ) {
        let mut record = dbtx
            .get_value(&CoinKey(coin))
            .await
            .expect("Funding outpoints are indexed for existing coins");

        let txid = tx.compute_txid();

        let node_txid = record
            .signing_tx(self.params(), SigningPurpose::Node)
            .map(|signing_tx| signing_tx.tx.compute_txid());

        if let CoinStatus::AwaitingClaim { receiver, .. } = &record.status {
            dbtx.remove_entry(&IncomingKey(receiver.pubkey, coin)).await;
        }

        record.status = if node_txid == Ok(txid) {
            info!(target: LOG_MODULE_STATECHAIN, %coin, "Statecoin unilateral exit started");
            CoinStatus::Exiting
        } else {
            info!(target: LOG_MODULE_STATECHAIN, %coin, %txid, "Statecoin funding output spent");
            CoinStatus::Closed { txid }
        };

        dbtx.remove_entry(&PendingBroadcastKey(txid)).await;
        dbtx.remove_by_prefix(&SigningNonceCoinPrefix(coin)).await;
        dbtx.remove_by_prefix(&EphemeralKeyEpochPrefix(coin, record.epoch))
            .await;
        take_ephemeral_secret(dbtx, coin, record.epoch).await;

        dbtx.insert_entry(&CoinKey(coin), &record).await;
    }

    async fn await_local_sync_to_block_count(&self, block_count: u64) {
        loop {
            if self
                .btc_rpc
                .status()
                .is_some_and(|status| status.block_count >= block_count)
            {
                break;
            }

            info!(
                target: LOG_MODULE_STATECHAIN,
                block_count,
                "Waiting for local bitcoin backend to sync"
            );

            sleep(std::time::Duration::from_secs(1)).await;
        }
    }

    pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.peers.to_num_peers();

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        assert!(counts.len() <= num_peers.total());

        counts.sort_unstable();

        counts.reverse();

        // The block count we select guarantees that any threshold of correct peers can
        // increase the consensus block count and any consensus block count has been
        // confirmed by a threshold of peers.
        counts.get(num_peers.threshold() - 1).copied().unwrap_or(0)
    }

    pub fn db(&self) -> &Database {
        &self.db
    }
}

fn schnorr_nonce_public(secret: &SecretNonce) -> PublicNonce {
    let public = secret.clone().into_keypair().public();
    let [hiding, binding] = public.0;

    PublicNonce {
        hiding: PublicKey::from(hiding),
        binding: PublicKey::from(binding),
    }
}
