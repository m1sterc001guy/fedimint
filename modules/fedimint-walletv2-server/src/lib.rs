#![deny(clippy::pedantic)]
#![allow(clippy::similar_names)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::default_trait_access)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::single_match_else)]
#![allow(clippy::too_many_lines)]

pub mod db;

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, Sequence, Transaction, TxIn, TxOut, Txid};
use common::config::WalletConfigConsensus;
use common::{
    OutputInfo, StandardScript, WalletCommonInit, WalletConsensusItem, WalletInput,
    WalletModuleTypes, WalletOutput, WalletOutputOutcome,
};
use db::{
    DbKeyPrefix, FederationWalletKey, FederationWalletPrefix, Output, OutputKey, OutputPrefix,
    SignaturesKey, SignaturesPrefix, SignaturesTxidPrefix, SpentOutputKey, SpentOutputPrefix,
    TxInfoIndexKey, TxInfoIndexPrefix,
};
use fedimint_core::config::{
    ServerModuleConfig, ServerModuleConsensusConfig, TypedServerModuleConfig,
    TypedServerModuleConsensusConfig,
};
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::envs::{
    FM_ENABLE_MODULE_WALLETV2_ENV, is_env_var_set_opt, is_running_in_test_env,
};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CoreConsensusVersion, InputMeta, ModuleConsensusVersion,
    ModuleInit, MultiApiVersion, TransactionItemAmounts, public_api_endpoint,
};
#[cfg(not(target_family = "wasm"))]
use fedimint_core::task::TaskGroup;
use fedimint_core::task::sleep;
use fedimint_core::util::FmtCompactAnyhow as _;
use fedimint_core::{
    InPoint, NumPeersExt, OutPoint, PeerId, apply, async_trait_maybe_send, push_db_pair_items, util,
};
use fedimint_logging::LOG_MODULE_WALLETV2;
use fedimint_server_core::bitcoin_rpc::ServerBitcoinRpcMonitor;
use fedimint_server_core::config::{PeerHandleOps, PeerHandleOpsExt};
use fedimint_server_core::migration::ServerModuleDbMigrationFn;
use fedimint_server_core::{
    ConfigGenModuleArgs, EnvVarDoc, ServerModule, ServerModuleInit, ServerModuleInitArgs,
};
pub use fedimint_walletv2_common as common;
use fedimint_walletv2_common::config::{
    FeeConsensus, WalletClientConfig, WalletConfig, WalletConfigPrivate,
};
use fedimint_walletv2_common::endpoint_constants::{
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CONSENSUS_FEERATE_ENDPOINT, FEDERATION_WALLET_ENDPOINT,
    OUTPUT_INFO_SLICE_ENDPOINT, PENDING_TRANSACTION_CHAIN_ENDPOINT, RECEIVE_FEE_ENDPOINT,
    SEND_FEE_ENDPOINT, TRANSACTION_CHAIN_ENDPOINT, TRANSACTION_ID_ENDPOINT,
};
use fedimint_walletv2_common::{
    FederationWallet, MODULE_CONSENSUS_VERSION, TxInfo, WalletInputError, WalletOutputError,
    descriptor, is_potential_receive, tweak_public_key,
};
use futures::StreamExt;
use miniscript::descriptor::Wsh;
use rand::rngs::OsRng;
use secp256k1::ecdsa::Signature;
use secp256k1::{PublicKey, Scalar, SecretKey};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tracing::{debug, info};

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, FeeRateVoteKey, FeeRateVotePrefix, PendingBatchKey,
    PendingBatchPrefix, PendingReceiveKey, PendingReceivePrefix, PendingSendIndexKey,
    PendingSendIndexPrefix, PendingSendKey, PendingSendPrefix, QueuedBalanceKey,
    QueuedBalancePrefix, TxInfoKey, TxInfoPrefix, UnconfirmedTxKey, UnconfirmedTxPrefix,
    UnsignedTxKey, UnsignedTxPrefix,
};

/// Number of confirmations required for a transaction to be considered as
/// final by the federation. The block that mines the transaction does
/// not count towards the number of confirmations.
pub const CONFIRMATION_FINALITY_DELAY: u64 = 6;

/// Maximum number of blocks the consensus block count can advance in a single
/// consensus item to limit the work done in one `process_consensus_item` step.
const MAX_BLOCK_COUNT_INCREMENT: u64 = 5;

/// Devimint tests can mine many regtest blocks at once, so use a larger cap in
/// test environments to avoid waiting on several consensus sessions.
const TEST_MAX_BLOCK_COUNT_INCREMENT: u64 = 100;

/// Minimum fee rate vote of 1 sat/vB to ensure we never propose a fee rate
/// below what Bitcoin Core will relay.
const MIN_FEERATE_VOTE_SATS_PER_KVB: u64 = 1000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct FederationTx {
    pub tx: Transaction,
    pub spent_tx_outs: Vec<SpentTxOut>,
    pub vbytes: u64,
    pub fee: Amount,
}

/// A transaction input that the federation has to sign.
///
/// These correspond to `tx.input` positionally, and the inputs requiring a
/// signature are always a *prefix* of the transaction's inputs. A batch child
/// spends its parent's ephemeral anchor, which is anyone-can-spend and takes an
/// empty witness, so it has one more input than it has entries here.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpentTxOut {
    pub value: Amount,
    pub tweak: sha256::Hash,
}

/// Maximum vbytes of a batch transaction.
///
/// TRUC (BIP 431) caps a version 3 parent at 10,000 vB. Batches are not version
/// 3 yet, but adopting the limit now means switching them over is a pure
/// transaction-shape change rather than one that also cuts throughput.
const MAX_BATCH_VBYTES: u64 = 10_000;

/// Output index of the federation's change in a batch parent.
const PARENT_CHANGE_VOUT: u32 = 0;

/// Output index of the ephemeral anchor in a batch parent.
///
/// Fixed rather than trailing the destinations so the settlement path can
/// construct the outpoint without recounting what was in the batch.
const PARENT_ANCHOR_VOUT: u32 = 1;

/// Blocks to let requests accumulate before a batch is built.
///
/// Only one batch is outstanding at a time and the next cannot be built until
/// the previous has been observed confirmed, which costs roughly seven blocks.
/// The penalty for just missing a batch is therefore far larger than the cost
/// of waiting a block for stragglers to join one.
const BATCH_ACCUMULATION_BLOCKS: u64 = 1;

/// A peg-out accepted by consensus and waiting to be included in a batch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct PendingSend {
    pub destination: StandardScript,
    pub value: Amount,
    pub fee: Amount,
    /// Outpoint of the funding transaction output. Used to answer the
    /// transaction id endpoint once the batch carrying this peg-out is built.
    pub outpoint: OutPoint,
    /// Consensus block count when this peg-out was accepted, used to let a
    /// batch accumulate for a block before it is built.
    pub created: u64,
    /// Set to the batch parent's txid when this peg-out is included in one. The
    /// record is only deleted once that batch settles, so a batch that never
    /// confirms can be rebuilt from the queue rather than reconstructed.
    pub batch: Option<Txid>,
}

/// A deposit claimed by its owner and waiting to be consolidated into a batch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct PendingReceive {
    pub output_index: u64,
    pub outpoint: bitcoin::OutPoint,
    pub value: Amount,
    pub tweak: PublicKey,
    pub fee: Amount,
    /// Consensus block count when this deposit was claimed.
    pub created: u64,
    pub batch: Option<Txid>,
}

/// The batch currently in flight, as a parent and a child.
///
/// Which wallet the federation advances to is decided by whatever spends the
/// parent's anchor. Ephemeral dust policy forces every child of the parent to
/// spend it, so that single outpoint is a complete discriminator.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct PendingBatch {
    pub parent_txid: Txid,
    pub child_txid: Txid,
    /// The parent's ephemeral anchor.
    pub anchor: bitcoin::OutPoint,
    /// Wallet to advance to when our own child confirms.
    pub child_wallet: FederationWallet,
    /// Wallet to advance to when anything else spends the anchor, which makes
    /// our child permanently invalid. The parent's change becomes the wallet
    /// and the child's fee is never paid, so the federation keeps it.
    pub parent_wallet: FederationWallet,
}

/// Value that consensus has committed to but the chain has not yet settled.
///
/// The federation wallet tracks only mined funds, so peg-outs are validated
/// against the wallet adjusted by these totals. Without it, several peg-outs
/// could each individually pass the balance check and collectively exceed the
/// federation's funds, leaving users debited against a batch that cannot be
/// constructed.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Encodable, Decodable)]
pub struct QueuedBalance {
    /// Sum of queued deposit values, net of their fees.
    pub inflow: Amount,
    /// Sum of queued peg-out values, including their fees.
    pub outflow: Amount,
}

impl Default for QueuedBalance {
    fn default() -> Self {
        Self {
            inflow: Amount::ZERO,
            outflow: Amount::ZERO,
        }
    }
}

/// Subtraction that floors at zero instead of overflowing.
fn saturating_sub(minuend: Amount, subtrahend: Amount) -> Amount {
    Amount::from_sat(minuend.to_sat().saturating_sub(subtrahend.to_sat()))
}

/// Broadcasts the batch currently in flight.
///
/// The parent pays no fee, so it can only ever reach the network as a package
/// with its child, and must never be submitted on its own. Once the parent has
/// confirmed the child is an ordinary transaction spending confirmed outputs
/// and goes out by itself.
async fn broadcast_pending_batch(
    btc_rpc: &ServerBitcoinRpcMonitor,
    dbtx: &mut DatabaseTransaction<'_>,
) {
    let Some(batch) = dbtx.get_value(&PendingBatchKey).await else {
        return;
    };

    let parent = dbtx.get_value(&UnconfirmedTxKey(batch.parent_txid)).await;
    let child = dbtx.get_value(&UnconfirmedTxKey(batch.child_txid)).await;

    let result = match (parent, child) {
        (Some(parent), Some(child)) => btc_rpc.submit_package(vec![parent.tx, child.tx]).await,
        (None, Some(child)) => btc_rpc.submit_transaction(child.tx).await,
        // Either nothing is signed yet, or the child is gone and the parent
        // alone can never be relayed.
        _ => return,
    };

    if let Err(err) = result {
        debug!(
            target: LOG_MODULE_WALLETV2,
            err = %err.fmt_compact_anyhow(),
            "Error broadcasting walletv2 batch"
        );
    }
}

async fn queued_balance(dbtx: &mut DatabaseTransaction<'_>) -> QueuedBalance {
    dbtx.get_value(&QueuedBalanceKey).await.unwrap_or_default()
}

/// Funds the federation may commit to: what has been mined, plus everything
/// already queued against it.
async fn available_balance(
    dbtx: &mut DatabaseTransaction<'_>,
    wallet: &FederationWallet,
) -> Option<Amount> {
    let queued = queued_balance(dbtx).await;

    wallet
        .value
        .checked_add(queued.inflow)?
        .checked_sub(queued.outflow)
}

async fn next_pending_send_index(dbtx: &mut DatabaseTransaction<'_>) -> u64 {
    dbtx.find_by_prefix_sorted_descending(&PendingSendPrefix)
        .await
        .next()
        .await
        .map_or(0, |entry| entry.0.0 + 1)
}

async fn next_pending_receive_index(dbtx: &mut DatabaseTransaction<'_>) -> u64 {
    dbtx.find_by_prefix_sorted_descending(&PendingReceivePrefix)
        .await
        .next()
        .await
        .map_or(0, |entry| entry.0.0 + 1)
}

#[derive(Debug, Clone)]
pub struct WalletInit;

impl ModuleInit for WalletInit {
    type Common = WalletCommonInit;

    async fn dump_database(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        prefix_names: Vec<String>,
    ) -> Box<dyn Iterator<Item = (String, Box<dyn erased_serde::Serialize + Send>)> + '_> {
        let mut wallet: BTreeMap<String, Box<dyn erased_serde::Serialize + Send>> = BTreeMap::new();

        let filtered_prefixes = DbKeyPrefix::iter().filter(|f| {
            prefix_names.is_empty() || prefix_names.contains(&f.to_string().to_lowercase())
        });

        for table in filtered_prefixes {
            match table {
                DbKeyPrefix::Output => {
                    push_db_pair_items!(
                        dbtx,
                        OutputPrefix,
                        OutputKey,
                        Output,
                        wallet,
                        "Wallet Outputs"
                    );
                }
                DbKeyPrefix::SpentOutput => {
                    push_db_pair_items!(
                        dbtx,
                        SpentOutputPrefix,
                        SpentOutputKey,
                        (),
                        wallet,
                        "Wallet Spent Outputs"
                    );
                }
                DbKeyPrefix::PendingSend => {
                    push_db_pair_items!(
                        dbtx,
                        PendingSendPrefix,
                        PendingSendKey,
                        PendingSend,
                        wallet,
                        "Wallet Pending Sends"
                    );
                }
                DbKeyPrefix::PendingSendIndex => {
                    push_db_pair_items!(
                        dbtx,
                        PendingSendIndexPrefix,
                        PendingSendIndexKey,
                        u64,
                        wallet,
                        "Wallet Pending Send Index"
                    );
                }
                DbKeyPrefix::PendingReceive => {
                    push_db_pair_items!(
                        dbtx,
                        PendingReceivePrefix,
                        PendingReceiveKey,
                        PendingReceive,
                        wallet,
                        "Wallet Pending Receives"
                    );
                }
                DbKeyPrefix::PendingBatch => {
                    push_db_pair_items!(
                        dbtx,
                        PendingBatchPrefix,
                        PendingBatchKey,
                        PendingBatch,
                        wallet,
                        "Wallet Pending Batch"
                    );
                }
                DbKeyPrefix::QueuedBalance => {
                    push_db_pair_items!(
                        dbtx,
                        QueuedBalancePrefix,
                        QueuedBalanceKey,
                        QueuedBalance,
                        wallet,
                        "Wallet Queued Balance"
                    );
                }
                DbKeyPrefix::BlockCountVote => {
                    push_db_pair_items!(
                        dbtx,
                        BlockCountVotePrefix,
                        BlockCountVoteKey,
                        u64,
                        wallet,
                        "Wallet Block Count Votes"
                    );
                }
                DbKeyPrefix::FeeRateVote => {
                    push_db_pair_items!(
                        dbtx,
                        FeeRateVotePrefix,
                        FeeRateVoteKey,
                        Option<u64>,
                        wallet,
                        "Wallet Fee Rate Votes"
                    );
                }
                DbKeyPrefix::TxLog => {
                    push_db_pair_items!(
                        dbtx,
                        TxInfoPrefix,
                        TxInfoKey,
                        TxInfo,
                        wallet,
                        "Wallet Tx Log"
                    );
                }
                DbKeyPrefix::TxInfoIndex => {
                    push_db_pair_items!(
                        dbtx,
                        TxInfoIndexPrefix,
                        TxInfoIndexKey,
                        u64,
                        wallet,
                        "Wallet Tx Info Index"
                    );
                }
                DbKeyPrefix::UnsignedTx => {
                    push_db_pair_items!(
                        dbtx,
                        UnsignedTxPrefix,
                        UnsignedTxKey,
                        FederationTx,
                        wallet,
                        "Wallet Unsigned Transactions"
                    );
                }
                DbKeyPrefix::Signatures => {
                    push_db_pair_items!(
                        dbtx,
                        SignaturesPrefix,
                        SignaturesKey,
                        Vec<Signature>,
                        wallet,
                        "Wallet Signatures"
                    );
                }
                DbKeyPrefix::UnconfirmedTx => {
                    push_db_pair_items!(
                        dbtx,
                        UnconfirmedTxPrefix,
                        UnconfirmedTxKey,
                        FederationTx,
                        wallet,
                        "Wallet Unconfirmed Transactions"
                    );
                }
                DbKeyPrefix::FederationWallet => {
                    push_db_pair_items!(
                        dbtx,
                        FederationWalletPrefix,
                        FederationWalletKey,
                        FederationWallet,
                        wallet,
                        "Federation Wallet"
                    );
                }
            }
        }

        Box::new(wallet.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModuleInit for WalletInit {
    type Module = Wallet;

    fn versions(&self, _core: CoreConsensusVersion) -> &[ModuleConsensusVersion] {
        &[MODULE_CONSENSUS_VERSION]
    }

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_WALLETV2_ENV).unwrap_or(true)
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![EnvVarDoc {
            name: FM_ENABLE_MODULE_WALLETV2_ENV,
            description: "Set to 0/false to disable the WalletV2 module. Enabled by default.",
        }]
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Wallet::new(
            args.cfg().to_typed()?,
            args.db(),
            args.task_group(),
            args.server_bitcoin_rpc_monitor(),
        ))
    }

    fn trusted_dealer_gen(
        &self,
        peers: &[PeerId],
        args: &ConfigGenModuleArgs,
    ) -> BTreeMap<PeerId, ServerModuleConfig> {
        let fee_consensus = FeeConsensus::new(0).expect("Relative fee is within range");

        let bitcoin_sks = peers
            .iter()
            .map(|peer| (*peer, SecretKey::new(&mut secp256k1::rand::thread_rng())))
            .collect::<BTreeMap<PeerId, SecretKey>>();

        let bitcoin_pks = bitcoin_sks
            .iter()
            .map(|(peer, sk)| (*peer, sk.public_key(secp256k1::SECP256K1)))
            .collect::<BTreeMap<PeerId, PublicKey>>();

        bitcoin_sks
            .into_iter()
            .map(|(peer, bitcoin_sk)| {
                let config = WalletConfig {
                    private: WalletConfigPrivate { bitcoin_sk },
                    consensus: WalletConfigConsensus::new(
                        bitcoin_pks.clone(),
                        fee_consensus.clone(),
                        args.network,
                    ),
                };

                (peer, config.to_erased())
            })
            .collect()
    }

    async fn distributed_gen(
        &self,
        peers: &(dyn PeerHandleOps + Send + Sync),
        args: &ConfigGenModuleArgs,
    ) -> anyhow::Result<ServerModuleConfig> {
        let fee_consensus = FeeConsensus::new(0).expect("Relative fee is within range");

        let (bitcoin_sk, bitcoin_pk) = secp256k1::generate_keypair(&mut OsRng);

        let bitcoin_pks: BTreeMap<PeerId, PublicKey> = peers
            .exchange_encodable(bitcoin_pk)
            .await?
            .into_iter()
            .collect();

        let config = WalletConfig {
            private: WalletConfigPrivate { bitcoin_sk },
            consensus: WalletConfigConsensus::new(bitcoin_pks, fee_consensus, args.network),
        };

        Ok(config.to_erased())
    }

    fn validate_config(&self, identity: &PeerId, config: ServerModuleConfig) -> anyhow::Result<()> {
        let config = config.to_typed::<WalletConfig>()?;

        ensure!(
            config
                .consensus
                .bitcoin_pks
                .get(identity)
                .ok_or(anyhow::anyhow!("No public key for our identity"))?
                == &config.private.bitcoin_sk.public_key(secp256k1::SECP256K1),
            "Bitcoin wallet private key doesn't match multisig pubkey"
        );

        Ok(())
    }

    fn get_client_config(
        &self,
        config: &ServerModuleConsensusConfig,
    ) -> anyhow::Result<WalletClientConfig> {
        let config = WalletConfigConsensus::from_erased(config)?;

        Ok(WalletClientConfig {
            bitcoin_pks: config.bitcoin_pks,
            descriptor: config.descriptor,
            send_tx_vbytes: config.send_tx_vbytes,
            receive_tx_vbytes: config.receive_tx_vbytes,
            feerate_base: config.feerate_base,
            dust_limit: config.dust_limit,
            fee_consensus: config.fee_consensus,
            network: config.network,
        })
    }

    fn get_database_migrations(
        &self,
    ) -> BTreeMap<DatabaseVersion, ServerModuleDbMigrationFn<Wallet>> {
        BTreeMap::new()
    }

    fn used_db_prefixes(&self) -> Option<BTreeSet<u8>> {
        Some(DbKeyPrefix::iter().map(|p| p as u8).collect())
    }
}

#[apply(async_trait_maybe_send!)]
impl ServerModule for Wallet {
    type Common = WalletModuleTypes;
    type Init = WalletInit;

    async fn consensus_proposal<'a>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> Vec<WalletConsensusItem> {
        let mut items = dbtx
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(key, unsigned_tx)| {
                let signatures = self.sign_tx(&unsigned_tx);

                self.verify_signatures(
                    &unsigned_tx,
                    &signatures,
                    self.cfg.private.bitcoin_sk.public_key(secp256k1::SECP256K1),
                )
                .expect("Our signatures failed verification against our private key");

                WalletConsensusItem::Signatures(key.0, signatures)
            })
            .collect::<Vec<WalletConsensusItem>>()
            .await;

        if let Some(status) = self.btc_rpc.status() {
            assert_eq!(status.network, self.cfg.consensus.network);

            let block_count_vote = status
                .block_count
                .saturating_sub(CONFIRMATION_FINALITY_DELAY);

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

            items.push(WalletConsensusItem::BlockCount(block_count_vote));

            let feerate_vote = status
                .fee_rate
                .sats_per_kvb
                .max(MIN_FEERATE_VOTE_SATS_PER_KVB);

            items.push(WalletConsensusItem::Feerate(Some(feerate_vote)));
        } else {
            // Bitcoin backend not connected, retract fee rate vote
            items.push(WalletConsensusItem::Feerate(None));
        }

        items
    }

    async fn process_consensus_item<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        consensus_item: WalletConsensusItem,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        match consensus_item {
            WalletConsensusItem::BlockCount(block_count_vote) => {
                self.process_block_count(dbtx, block_count_vote, peer).await
            }
            WalletConsensusItem::Feerate(feerate) => {
                if Some(feerate) == dbtx.insert_entry(&FeeRateVoteKey(peer), &feerate).await {
                    return Err(anyhow!("Fee rate vote is redundant"));
                }

                Ok(())
            }
            WalletConsensusItem::Signatures(txid, signatures) => {
                self.process_signatures(dbtx, txid, signatures, peer).await
            }
            WalletConsensusItem::Default { variant, .. } => Err(anyhow!(
                "Received wallet consensus item with unknown variant {variant}"
            )),
        }
    }

    async fn process_input<'a, 'b, 'c>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'c>,
        input: &'b WalletInput,
        _in_point: InPoint,
    ) -> Result<InputMeta, WalletInputError> {
        let input = input.ensure_v0_ref()?;

        if dbtx
            .insert_entry(&SpentOutputKey(input.output_index), &())
            .await
            .is_some()
        {
            return Err(WalletInputError::OutputAlreadySpent);
        }

        let Output(tracked_outpoint, tracked_output) = dbtx
            .get_value(&OutputKey(input.output_index))
            .await
            .ok_or(WalletInputError::UnknownOutputIndex)?;

        let tweaked_pubkey = self
            .descriptor(&input.tweak.consensus_hash())
            .script_pubkey();

        if tracked_output.script_pubkey != tweaked_pubkey {
            return Err(WalletInputError::WrongTweak);
        }

        let consensus_receive_fee = self
            .receive_fee(dbtx)
            .await
            .ok_or(WalletInputError::NoConsensusFeerateAvailable)?;

        // We allow for a higher fee such that a guardian could construct a CPFP
        // transaction. This is the last line of defense should the federations
        // transactions ever get stuck due to a critical failure of the feerate
        // estimation.
        if input.fee < consensus_receive_fee {
            return Err(WalletInputError::InsufficientTotalFee);
        }

        let output_value = tracked_output
            .value
            .checked_sub(input.fee)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        match dbtx.get_value(&FederationWalletKey).await {
            None => {
                // The federation holds no UTXO yet, so this deposit becomes it
                // directly and no bitcoin transaction is needed. Assuming the
                // first receive is made through a standard transaction its
                // value is over the P2WSH dust limit, and by induction so is
                // every change value derived from it.
                dbtx.insert_new_entry(
                    &FederationWalletKey,
                    &FederationWallet {
                        value: tracked_output.value,
                        outpoint: tracked_outpoint,
                        tweak: input.tweak.consensus_hash(),
                    },
                )
                .await;
            }
            Some(_) => {
                let created = self.consensus_block_count(dbtx).await;

                let mut queued = queued_balance(dbtx).await;

                queued.inflow = queued
                    .inflow
                    .checked_add(output_value)
                    .ok_or(WalletInputError::ArithmeticOverflow)?;

                dbtx.insert_entry(&QueuedBalanceKey, &queued).await;

                let index = next_pending_receive_index(dbtx).await;

                dbtx.insert_new_entry(
                    &PendingReceiveKey(index),
                    &PendingReceive {
                        output_index: input.output_index,
                        outpoint: tracked_outpoint,
                        value: tracked_output.value,
                        tweak: input.tweak,
                        fee: input.fee,
                        created,
                        batch: None,
                    },
                )
                .await;
            }
        }

        let amount = output_value
            .to_sat()
            .checked_mul(1000)
            .map(fedimint_core::Amount::from_msats)
            .ok_or(WalletInputError::ArithmeticOverflow)?;

        Ok(InputMeta {
            amount: TransactionItemAmounts {
                amounts: Amounts::new_bitcoin(amount),
                fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.fee(amount)),
            },
            pub_key: input.tweak,
        })
    }

    async fn process_output<'a, 'b>(
        &'a self,
        dbtx: &mut DatabaseTransaction<'b>,
        output: &'a WalletOutput,
        outpoint: OutPoint,
    ) -> Result<TransactionItemAmounts, WalletOutputError> {
        let output = output.ensure_v0_ref()?;

        if output.value < self.cfg.consensus.dust_limit {
            return Err(WalletOutputError::UnderDustLimit);
        }

        // Rejected here rather than at batch construction, where there would be
        // no user left to return an error to.
        if output.destination.script_pubkey().is_none() {
            return Err(WalletOutputError::UnknownScriptVariant);
        }

        let wallet = dbtx
            .get_value(&FederationWalletKey)
            .await
            .ok_or(WalletOutputError::NoFederationUTXO)?;

        let consensus_send_fee = self
            .send_fee(dbtx)
            .await
            .ok_or(WalletOutputError::NoConsensusFeerateAvailable)?;

        // We allow for a higher fee such that a guardian could construct a CPFP
        // transaction. This is the last line of defense should the federations
        // transactions ever get stuck due to a critical failure of the feerate
        // estimation.
        if output.fee < consensus_send_fee {
            return Err(WalletOutputError::InsufficientTotalFee);
        }

        let output_value = output
            .value
            .checked_add(output.fee)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        // The federation wallet only tracks mined funds, so the balance this
        // peg-out has to fit into is the wallet adjusted by everything already
        // queued against it. Validating against the wallet alone would let
        // several peg-outs each pass individually while collectively exceeding
        // the federation's funds.
        let change_value = available_balance(dbtx, &wallet)
            .await
            .ok_or(WalletOutputError::ArithmeticOverflow)?
            .checked_sub(output_value)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        if change_value < self.cfg.consensus.dust_limit {
            return Err(WalletOutputError::ChangeUnderDustLimit);
        }

        let mut queued = queued_balance(dbtx).await;

        queued.outflow = queued
            .outflow
            .checked_add(output_value)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        dbtx.insert_entry(&QueuedBalanceKey, &queued).await;

        let created = self.consensus_block_count(dbtx).await;

        let index = next_pending_send_index(dbtx).await;

        dbtx.insert_new_entry(
            &PendingSendKey(index),
            &PendingSend {
                destination: output.destination.clone(),
                value: output.value,
                fee: output.fee,
                outpoint,
                created,
                batch: None,
            },
        )
        .await;

        dbtx.insert_new_entry(&PendingSendIndexKey(outpoint), &index)
            .await;

        let amount = output_value
            .to_sat()
            .checked_mul(1000)
            .map(fedimint_core::Amount::from_msats)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        Ok(TransactionItemAmounts {
            amounts: Amounts::new_bitcoin(amount),
            fees: Amounts::new_bitcoin(self.cfg.consensus.fee_consensus.fee(amount)),
        })
    }

    async fn output_status(
        &self,
        _dbtx: &mut DatabaseTransaction<'_>,
        _outpoint: OutPoint,
    ) -> Option<WalletOutputOutcome> {
        None
    }

    async fn audit(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        audit: &mut Audit,
        module_instance_id: ModuleInstanceId,
    ) {
        audit
            .add_items(
                dbtx,
                module_instance_id,
                &FederationWalletPrefix,
                |_, wallet| 1000 * wallet.value.to_sat() as i64,
            )
            .await;
    }

    fn api_endpoints(&self) -> Vec<ApiEndpoint<Self>> {
        vec![
            public_api_endpoint! {
                CONSENSUS_BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_block_count(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                CONSENSUS_FEERATE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<u64> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_feerate(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                FEDERATION_WALLET_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Wallet, context, _params: ()| -> Option<FederationWallet> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx.get_value(&FederationWalletKey).await)
                }
            },
            public_api_endpoint! {
                SEND_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.send_fee(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                RECEIVE_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.receive_fee(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                TRANSACTION_ID_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, _context, params: OutPoint| -> Option<Txid> {
                    Ok(module.await_tx_id(params).await)
                }
            },
            public_api_endpoint! {
                OUTPUT_INFO_SLICE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: (u64, u64)| -> Vec<OutputInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.get_outputs(&mut dbtx, params.0, params.1).await)
                }
            },
            public_api_endpoint! {
                PENDING_TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Vec<TxInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.pending_tx_chain(&mut dbtx).await)
                }
            },
            public_api_endpoint! {
                TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Vec<TxInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.tx_chain(&mut dbtx).await)
                }
            },
        ]
    }

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion::new(0, 1)])
            .expect("walletv2 declares one API version per major version")
    }
}

#[derive(Debug)]
pub struct Wallet {
    cfg: WalletConfig,
    db: Database,
    btc_rpc: ServerBitcoinRpcMonitor,
}

impl Wallet {
    fn new(
        cfg: WalletConfig,
        db: &Database,
        task_group: &TaskGroup,
        btc_rpc: ServerBitcoinRpcMonitor,
    ) -> Wallet {
        Self::spawn_broadcast_unconfirmed_txs_task(btc_rpc.clone(), db.clone(), task_group);

        Wallet {
            cfg,
            btc_rpc,
            db: db.clone(),
        }
    }

    fn spawn_broadcast_unconfirmed_txs_task(
        btc_rpc: ServerBitcoinRpcMonitor,
        db: Database,
        task_group: &TaskGroup,
    ) {
        task_group.spawn_cancellable("broadcast_unconfirmed_transactions", async move {
            loop {
                let mut dbtx = db.begin_transaction_nc().await;

                broadcast_pending_batch(&btc_rpc, &mut dbtx).await;

                drop(dbtx);

                sleep(common::sleep_duration()).await;
            }
        });
    }

    /// Constructs the next batch from the queue, as a TRUC parent and child.
    ///
    /// Runs from `process_block_count`, so the only clock it depends on is the
    /// consensus block count. Calls are idempotent: once a batch is in flight
    /// every further call is a no-op until that batch settles, which is what
    /// keeps exactly one batch outstanding — and what TRUC requires, since the
    /// parent and its child already fill a two transaction cluster.
    async fn construct_batch(&self, dbtx: &mut DatabaseTransaction<'_>) {
        if dbtx.get_value(&PendingBatchKey).await.is_some() {
            return;
        }

        let Some(wallet) = dbtx.get_value(&FederationWalletKey).await else {
            return;
        };

        let receives = dbtx
            .find_by_prefix(&PendingReceivePrefix)
            .await
            .map(|entry| (entry.0.0, entry.1))
            .collect::<Vec<(u64, PendingReceive)>>()
            .await;

        let sends = dbtx
            .find_by_prefix(&PendingSendPrefix)
            .await
            .map(|entry| (entry.0.0, entry.1))
            .collect::<Vec<(u64, PendingSend)>>()
            .await;

        // Let requests accumulate for a block before building. Missing a batch
        // costs roughly seven blocks of waiting, so it is worth a block of
        // latency to let stragglers join this one.
        let Some(oldest) = receives
            .iter()
            .map(|(_, receive)| receive.created)
            .chain(sends.iter().map(|(_, send)| send.created))
            .min()
        else {
            return;
        };

        if self.consensus_block_count(dbtx).await < oldest.saturating_add(BATCH_ACCUMULATION_BLOCKS)
        {
            return;
        }

        // The parent pays no fee at all, which is what lets its anchor be a
        // zero value output under ephemeral dust policy. Every fee collected
        // is carried by the child instead, so the parent's change is tracked
        // gross and the fee separately.
        let mut parent_change = wallet.value;
        let mut fee = Amount::ZERO;
        let mut batched_receives: Vec<(u64, PendingReceive)> = Vec::new();
        let mut batched_sends: Vec<(u64, PendingSend)> = Vec::new();

        // Deposits are consolidated before peg-outs are paid. They only add
        // value, so taking them first means a peg-out is never included while
        // the inflow funding it is left behind for a later batch.
        for (index, receive) in receives {
            let inputs = batched_receives.len() as u64 + 2;

            if self.cfg.consensus.parent_vbytes(inputs, 0) > MAX_BATCH_VBYTES {
                break;
            }

            let (Some(next_change), Some(next_fee)) = (
                parent_change.checked_add(receive.value),
                fee.checked_add(receive.fee),
            ) else {
                break;
            };

            if saturating_sub(next_change, next_fee) < self.cfg.consensus.dust_limit {
                break;
            }

            parent_change = next_change;
            fee = next_fee;

            batched_receives.push((index, receive));
        }

        // Peg-outs are taken in queue order, and we stop at the first one that
        // does not fit rather than skipping over it, so that a large peg-out
        // cannot be starved by smaller ones queued behind it.
        for (index, send) in sends {
            let inputs = batched_receives.len() as u64 + 1;
            let destinations = batched_sends.len() as u64 + 1;

            if self.cfg.consensus.parent_vbytes(inputs, destinations) > MAX_BATCH_VBYTES {
                break;
            }

            let (Some(next_change), Some(next_fee)) = (
                parent_change.checked_sub(send.value),
                fee.checked_add(send.fee),
            ) else {
                break;
            };

            // The dust limit applies to the child's output, since that is what
            // becomes the next federation wallet.
            if saturating_sub(next_change, next_fee) < self.cfg.consensus.dust_limit {
                break;
            }

            parent_change = next_change;
            fee = next_fee;

            batched_sends.push((index, send));
        }

        if batched_receives.is_empty() && batched_sends.is_empty() {
            return;
        }

        let Some(child_value) = parent_change.checked_sub(fee) else {
            return;
        };

        // Each hop derives the next tweak from the wallet state it replaces, so
        // the parent's change and the child's output land on distinct scripts.
        let parent_tweak = wallet.consensus_hash();

        let mut parent_inputs = vec![TxIn {
            previous_output: wallet.outpoint,
            script_sig: Default::default(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: bitcoin::Witness::new(),
        }];

        let mut parent_spent_tx_outs = vec![SpentTxOut {
            value: wallet.value,
            tweak: wallet.tweak,
        }];

        for (_, receive) in &batched_receives {
            parent_inputs.push(TxIn {
                previous_output: receive.outpoint,
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            });

            parent_spent_tx_outs.push(SpentTxOut {
                value: receive.value,
                tweak: receive.tweak.consensus_hash(),
            });
        }

        let mut parent_outputs = vec![
            TxOut {
                value: parent_change,
                script_pubkey: self.descriptor(&parent_tweak).script_pubkey(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::new_p2a(),
            },
        ];

        for (_, send) in &batched_sends {
            parent_outputs.push(TxOut {
                value: send.value,
                script_pubkey: send
                    .destination
                    .script_pubkey()
                    .expect("Destination was validated when the peg-out was accepted"),
            });
        }

        let parent = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: parent_inputs,
            output: parent_outputs,
        };

        let parent_txid = parent.compute_txid();

        let parent_wallet = FederationWallet {
            value: parent_change,
            outpoint: bitcoin::OutPoint {
                txid: parent_txid,
                vout: PARENT_CHANGE_VOUT,
            },
            tweak: parent_tweak,
        };

        let anchor = bitcoin::OutPoint {
            txid: parent_txid,
            vout: PARENT_ANCHOR_VOUT,
        };

        let child_tweak = parent_wallet.consensus_hash();

        // The signed input comes first and the anchor second, keeping the
        // signed inputs a prefix as `SpentTxOut` documents.
        let child = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: parent_wallet.outpoint,
                    script_sig: Default::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::new(),
                },
                TxIn {
                    previous_output: anchor,
                    script_sig: Default::default(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: child_value,
                script_pubkey: self.descriptor(&child_tweak).script_pubkey(),
            }],
        };

        let child_txid = child.compute_txid();

        let parent_vbytes = self.cfg.consensus.parent_vbytes(
            batched_receives.len() as u64 + 1,
            batched_sends.len() as u64,
        );

        let child_vbytes = self.cfg.consensus.child_vbytes();

        let tx_index = self.total_txs(dbtx).await;

        let created = self.consensus_block_count(dbtx).await;

        // The parent is the transaction users care about, since it carries the
        // peg-out destinations. The fee and vbytes cover both, so `feerate()`
        // reports the package feerate that actually gets the batch mined.
        dbtx.insert_new_entry(
            &TxInfoKey(tx_index),
            &TxInfo {
                index: tx_index,
                txid: parent_txid,
                input: wallet.value,
                output: child_value,
                vbytes: parent_vbytes + child_vbytes,
                fee,
                created,
            },
        )
        .await;

        // Queue entries are marked rather than deleted. They are only removed
        // once the batch settles, so a batch that never confirms leaves the
        // queue intact to rebuild from.
        for (index, send) in &batched_sends {
            dbtx.insert_new_entry(&TxInfoIndexKey(send.outpoint), &tx_index)
                .await;

            dbtx.insert_entry(
                &PendingSendKey(*index),
                &PendingSend {
                    batch: Some(parent_txid),
                    ..send.clone()
                },
            )
            .await;
        }

        for (index, receive) in &batched_receives {
            dbtx.insert_entry(
                &PendingReceiveKey(*index),
                &PendingReceive {
                    batch: Some(parent_txid),
                    ..receive.clone()
                },
            )
            .await;
        }

        dbtx.insert_new_entry(
            &UnsignedTxKey(parent_txid),
            &FederationTx {
                tx: parent,
                spent_tx_outs: parent_spent_tx_outs,
                vbytes: parent_vbytes,
                fee: Amount::ZERO,
            },
        )
        .await;

        dbtx.insert_new_entry(
            &UnsignedTxKey(child_txid),
            &FederationTx {
                tx: child,
                spent_tx_outs: vec![SpentTxOut {
                    value: parent_change,
                    tweak: parent_tweak,
                }],
                vbytes: child_vbytes,
                fee,
            },
        )
        .await;

        dbtx.insert_new_entry(
            &PendingBatchKey,
            &PendingBatch {
                parent_txid,
                child_txid,
                anchor,
                child_wallet: FederationWallet {
                    value: child_value,
                    outpoint: bitcoin::OutPoint {
                        txid: child_txid,
                        vout: 0,
                    },
                    tweak: child_tweak,
                },
                parent_wallet,
            },
        )
        .await;

        debug!(
            target: LOG_MODULE_WALLETV2,
            %parent_txid,
            %child_txid,
            receives = batched_receives.len(),
            sends = batched_sends.len(),
            vbytes = parent_vbytes + child_vbytes,
            fee_sat = fee.to_sat(),
            "Constructed walletv2 batch"
        );
    }

    /// Settles the batch in flight once its outcome is visible on chain, and
    /// clears the queue entries it carried.
    ///
    /// The discriminator is the parent's anchor. Ephemeral dust policy rejects
    /// any child of the parent that fails to spend it, so whatever spends that
    /// outpoint is *the* child, and there is never any other way for the batch
    /// to resolve. If it is our own child the federation advances onto it; if
    /// it is anyone else's, our child is permanently invalid and the parent's
    /// change becomes the wallet instead — with the child's fee never paid,
    /// because the third party paid for the confirmation themselves.
    ///
    /// A parent mined without any child spending the anchor settles nothing.
    /// Our child is still valid and still broadcastable, and advancing onto the
    /// parent's change would be wrong the moment it confirmed.
    async fn settle_batch(&self, dbtx: &mut DatabaseTransaction<'_>, tx: &Transaction, txid: Txid) {
        let Some(batch) = dbtx.get_value(&PendingBatchKey).await else {
            return;
        };

        if !tx
            .input
            .iter()
            .any(|input| input.previous_output == batch.anchor)
        {
            return;
        }

        let (wallet, settled_by_us) = if txid == batch.child_txid {
            (batch.child_wallet, true)
        } else {
            (batch.parent_wallet, false)
        };

        dbtx.remove_entry(&PendingBatchKey).await;

        // Whichever child lost is now permanently invalid, so stop
        // rebroadcasting it.
        dbtx.remove_entry(&UnsignedTxKey(batch.parent_txid)).await;
        dbtx.remove_entry(&UnsignedTxKey(batch.child_txid)).await;
        dbtx.remove_entry(&UnconfirmedTxKey(batch.parent_txid))
            .await;
        dbtx.remove_entry(&UnconfirmedTxKey(batch.child_txid)).await;

        dbtx.insert_entry(&FederationWalletKey, &wallet).await;

        let mut queued = queued_balance(dbtx).await;

        let settled_receives = dbtx
            .find_by_prefix(&PendingReceivePrefix)
            .await
            .filter(|entry| std::future::ready(entry.1.batch == Some(batch.parent_txid)))
            .map(|entry| (entry.0.0, entry.1))
            .collect::<Vec<(u64, PendingReceive)>>()
            .await;

        for (index, receive) in settled_receives {
            dbtx.remove_entry(&PendingReceiveKey(index)).await;

            queued.inflow =
                saturating_sub(queued.inflow, saturating_sub(receive.value, receive.fee));
        }

        let settled_sends = dbtx
            .find_by_prefix(&PendingSendPrefix)
            .await
            .filter(|entry| std::future::ready(entry.1.batch == Some(batch.parent_txid)))
            .map(|entry| (entry.0.0, entry.1))
            .collect::<Vec<(u64, PendingSend)>>()
            .await;

        for (index, send) in settled_sends {
            dbtx.remove_entry(&PendingSendKey(index)).await;
            dbtx.remove_entry(&PendingSendIndexKey(send.outpoint)).await;

            queued.outflow = saturating_sub(
                queued.outflow,
                send.value
                    .checked_add(send.fee)
                    .unwrap_or(Amount::MAX_MONEY),
            );
        }

        dbtx.insert_entry(&QueuedBalanceKey, &queued).await;

        debug!(
            target: LOG_MODULE_WALLETV2,
            parent_txid = %batch.parent_txid,
            settled_by_us,
            wallet_sat = wallet.value.to_sat(),
            "Settled walletv2 batch"
        );
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

        debug!(
            target: LOG_MODULE_WALLETV2,
            %peer,
            vote = block_count_vote,
            old_consensus = old_consensus_block_count,
            new_consensus = new_consensus_block_count,
            advanced = new_consensus_block_count - old_consensus_block_count,
            "Processed block count vote"
        );

        // Outside regtest, do not sync blocks that predate the federation itself.
        // Regtest starts from scratch, so scan from genesis to avoid races where
        // test deposits are mined before the first walletv2 block count
        // transition is processed.
        let scan_from_genesis = self.cfg.consensus.network == bitcoin::Network::Regtest;
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
            // Verify network matches (status should be available after sync)
            if let Some(status) = self.btc_rpc.status() {
                assert_eq!(status.network, self.cfg.consensus.network);
            }

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

            let pks_hash = self.cfg.consensus.bitcoin_pks.consensus_hash();

            let txs_num = block.txdata.len();
            let mut potential_receives_num: usize = 0;

            for tx in block.txdata {
                let txid = tx.compute_txid();

                dbtx.remove_entry(&UnconfirmedTxKey(txid)).await;

                self.settle_batch(dbtx, &tx, txid).await;

                // We maintain an append-only log of transaction outputs that pass
                // the probabilistic receive filter created since the federation was
                // established. This is downloaded by clients to detect pegins and
                // claim them by index.

                for (vout, tx_out) in tx.output.iter().enumerate() {
                    if is_potential_receive(&tx_out.script_pubkey, &pks_hash) {
                        let outpoint = bitcoin::OutPoint {
                            txid,
                            vout: u32::try_from(vout)
                                .expect("Bitcoin transaction has more than u32::MAX outputs"),
                        };

                        let index = dbtx
                            .find_by_prefix_sorted_descending(&OutputPrefix)
                            .await
                            .next()
                            .await
                            .map_or(0, |entry| entry.0.0 + 1);

                        dbtx.insert_new_entry(&OutputKey(index), &Output(outpoint, tx_out.clone()))
                            .await;

                        debug!(
                            target: LOG_MODULE_WALLETV2,
                            output_index = index,
                            %outpoint,
                            value_sat = tx_out.value.to_sat(),
                            height,
                            "Recorded potential walletv2 receive"
                        );

                        potential_receives_num += 1;
                    }
                }
            }

            debug!(
                target: LOG_MODULE_WALLETV2,
                height,
                txs_num,
                potential_receives_num,
                "Scanned block"
            );
        }

        // Now that the scan has settled which of our transactions confirmed,
        // build the next batch if the queue has anything in it.
        self.construct_batch(dbtx).await;

        Ok(())
    }

    async fn process_signatures(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        txid: bitcoin::Txid,
        signatures: Vec<Signature>,
        peer: PeerId,
    ) -> anyhow::Result<()> {
        let mut unsigned = dbtx
            .get_value(&UnsignedTxKey(txid))
            .await
            .context("Unsigned transaction does not exist")?;

        let pk = self
            .cfg
            .consensus
            .bitcoin_pks
            .get(&peer)
            .expect("Failed to get public key of peer from config");

        self.verify_signatures(&unsigned, &signatures, *pk)?;

        if dbtx
            .insert_entry(&SignaturesKey(txid, peer), &signatures)
            .await
            .is_some()
        {
            bail!("Already received valid signatures from this peer")
        }

        let signatures = dbtx
            .find_by_prefix(&SignaturesTxidPrefix(txid))
            .await
            .map(|(key, signatures)| (key.1, signatures))
            .collect::<BTreeMap<PeerId, Vec<Signature>>>()
            .await;

        if signatures.len() == self.cfg.consensus.bitcoin_pks.to_num_peers().threshold() {
            dbtx.remove_entry(&UnsignedTxKey(txid)).await;

            dbtx.remove_by_prefix(&SignaturesTxidPrefix(txid)).await;

            self.finalize_tx(&mut unsigned, &signatures);

            dbtx.insert_new_entry(&UnconfirmedTxKey(txid), &unsigned)
                .await;

            // Nothing goes out until both halves of the batch are signed, since
            // the zero fee parent cannot be relayed without its child.
            broadcast_pending_batch(&self.btc_rpc, dbtx).await;
        }

        Ok(())
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

            info!(target: LOG_MODULE_WALLETV2, "Waiting for local bitcoin backend to sync to block count {block_count}");

            sleep(common::sleep_duration()).await;
        }
    }

    pub async fn consensus_block_count(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        let num_peers = self.cfg.consensus.bitcoin_pks.to_num_peers();

        let mut counts = dbtx
            .find_by_prefix(&BlockCountVotePrefix)
            .await
            .map(|entry| entry.1)
            .collect::<Vec<u64>>()
            .await;

        assert!(counts.len() <= num_peers.total());

        counts.sort_unstable();

        counts.reverse();

        assert!(counts.last() <= counts.first());

        // The block count we select guarantees that any threshold of correct peers can
        // increase the consensus block count and any consensus block count has been
        // confirmed by a threshold of peers.

        counts.get(num_peers.threshold() - 1).copied().unwrap_or(0)
    }

    pub async fn consensus_feerate(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<u64> {
        let num_peers = self.cfg.consensus.bitcoin_pks.to_num_peers();

        let mut rates = dbtx
            .find_by_prefix(&FeeRateVotePrefix)
            .await
            .filter_map(|entry| async move { entry.1 })
            .collect::<Vec<u64>>()
            .await;

        assert!(rates.len() <= num_peers.total());

        rates.sort_unstable();

        assert!(rates.first() <= rates.last());

        rates.get(num_peers.threshold() - 1).copied()
    }

    pub async fn consensus_fee(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        tx_vbytes: u64,
    ) -> Option<Amount> {
        // Batching leaves at most one federation transaction outstanding, so
        // there is no pending stack to lift and the fee is simply what this
        // request's own shape costs. The base feerate remains as a floor
        // against a catastrophic error in the feerate estimation.
        let feerate = self
            .consensus_feerate(dbtx)
            .await?
            .max(self.cfg.consensus.feerate_base);

        Some(Amount::from_sat(
            tx_vbytes.saturating_mul(feerate).saturating_div(1000),
        ))
    }

    pub async fn send_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_fee(dbtx, self.cfg.consensus.send_quote_vbytes())
            .await
    }

    pub async fn receive_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_fee(dbtx, self.cfg.consensus.receive_quote_vbytes())
            .await
    }

    fn descriptor(&self, tweak: &sha256::Hash) -> Wsh<secp256k1::PublicKey> {
        descriptor(&self.cfg.consensus.bitcoin_pks, tweak)
    }

    fn sign_tx(&self, unsigned_tx: &FederationTx) -> Vec<Signature> {
        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .map(|(index, utxo)| {
                let descriptor = self.descriptor(&utxo.tweak).ecdsa_sighash_script_code();

                let p2wsh_sighash = sighash_cache
                    .p2wsh_signature_hash(index, &descriptor, utxo.value, EcdsaSighashType::All)
                    .expect("Failed to compute P2WSH segwit sighash");

                let scalar = &Scalar::from_be_bytes(utxo.tweak.to_byte_array())
                    .expect("Hash is within field order");

                let sk = self
                    .cfg
                    .private
                    .bitcoin_sk
                    .add_tweak(scalar)
                    .expect("Failed to tweak bitcoin secret key");

                Secp256k1::new().sign_ecdsa(&p2wsh_sighash.into(), &sk)
            })
            .collect()
    }

    fn verify_signatures(
        &self,
        unsigned_tx: &FederationTx,
        signatures: &[Signature],
        pk: PublicKey,
    ) -> anyhow::Result<()> {
        ensure!(
            unsigned_tx.spent_tx_outs.len() == signatures.len(),
            "Incorrect number of signatures"
        );

        let mut sighash_cache = SighashCache::new(unsigned_tx.tx.clone());

        for ((index, utxo), signature) in unsigned_tx
            .spent_tx_outs
            .iter()
            .enumerate()
            .zip(signatures.iter())
        {
            let code = self.descriptor(&utxo.tweak).ecdsa_sighash_script_code();

            let p2wsh_sighash = sighash_cache
                .p2wsh_signature_hash(index, &code, utxo.value, EcdsaSighashType::All)
                .expect("Failed to compute P2WSH segwit sighash");

            let pk = tweak_public_key(&pk, &utxo.tweak);

            secp256k1::SECP256K1.verify_ecdsa(&p2wsh_sighash.into(), signature, &pk)?;
        }

        Ok(())
    }

    fn finalize_tx(
        &self,
        federation_tx: &mut FederationTx,
        signatures: &BTreeMap<PeerId, Vec<Signature>>,
    ) {
        // Inputs needing a signature are a prefix of the transaction's inputs;
        // a batch child's trailing anchor input is anyone-can-spend and keeps
        // the empty witness it was built with.
        assert!(federation_tx.spent_tx_outs.len() <= federation_tx.tx.input.len());

        for (index, utxo) in federation_tx.spent_tx_outs.iter().enumerate() {
            let satisfier: BTreeMap<PublicKey, bitcoin::ecdsa::Signature> = signatures
                .iter()
                .map(|(peer, sigs)| {
                    assert_eq!(sigs.len(), federation_tx.spent_tx_outs.len());

                    let pk = *self
                        .cfg
                        .consensus
                        .bitcoin_pks
                        .get(peer)
                        .expect("Failed to get public key of peer from config");

                    let pk = tweak_public_key(&pk, &utxo.tweak);

                    (pk, bitcoin::ecdsa::Signature::sighash_all(sigs[index]))
                })
                .collect();

            miniscript::Descriptor::Wsh(self.descriptor(&utxo.tweak))
                .satisfy(&mut federation_tx.tx.input[index], satisfier)
                .expect("Failed to satisfy descriptor");
        }
    }

    /// Resolves the bitcoin transaction id a peg-out ended up in, waiting for
    /// the batch carrying it to be built.
    ///
    /// Peg-outs are queued, so no transaction id exists at the moment consensus
    /// accepts one. Returning `None` in that window would make clients report a
    /// successful peg-out as a failure, so we wait instead. Only outpoints that
    /// correspond to a queued peg-out are waited on; anything else returns
    /// immediately, so a caller cannot hold a request open on a made-up
    /// outpoint.
    async fn await_tx_id(&self, outpoint: OutPoint) -> Option<Txid> {
        loop {
            let mut dbtx = self.db.begin_transaction_nc().await;

            if let Some(txid) = self.tx_id(&mut dbtx, outpoint).await {
                return Some(txid);
            }

            dbtx.get_value(&PendingSendIndexKey(outpoint)).await?;

            drop(dbtx);

            sleep(common::sleep_duration()).await;
        }
    }

    async fn tx_id(&self, dbtx: &mut DatabaseTransaction<'_>, outpoint: OutPoint) -> Option<Txid> {
        let index = dbtx.get_value(&TxInfoIndexKey(outpoint)).await?;

        dbtx.get_value(&TxInfoKey(index))
            .await
            .map(|entry| entry.txid)
    }

    async fn get_outputs(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        start_index: u64,
        end_index: u64,
    ) -> Vec<OutputInfo> {
        let spent: BTreeSet<u64> = dbtx
            .find_by_range(SpentOutputKey(start_index)..SpentOutputKey(end_index))
            .await
            .map(|entry| entry.0.0)
            .collect()
            .await;

        dbtx.find_by_range(OutputKey(start_index)..OutputKey(end_index))
            .await
            .filter_map(|entry| {
                std::future::ready(entry.1.1.script_pubkey.is_p2wsh().then(|| OutputInfo {
                    index: entry.0.0,
                    script: entry.1.1.script_pubkey,
                    value: entry.1.1.value,
                    spent: spent.contains(&entry.0.0),
                    outpoint: Some(entry.1.0),
                }))
            })
            .collect()
            .await
    }

    async fn pending_tx_chain(&self, dbtx: &mut DatabaseTransaction<'_>) -> Vec<TxInfo> {
        // A batch is a parent and a child on chain but one logical transaction
        // to users, and at most one is ever in flight.
        let n_pending = usize::from(dbtx.get_value(&PendingBatchKey).await.is_some());

        dbtx.find_by_prefix_sorted_descending(&TxInfoPrefix)
            .await
            .take(n_pending)
            .map(|entry| entry.1)
            .collect()
            .await
    }

    async fn tx_chain(&self, dbtx: &mut DatabaseTransaction<'_>) -> Vec<TxInfo> {
        dbtx.find_by_prefix(&TxInfoPrefix)
            .await
            .map(|entry| entry.1)
            .collect()
            .await
    }

    async fn total_txs(&self, dbtx: &mut DatabaseTransaction<'_>) -> u64 {
        dbtx.find_by_prefix_sorted_descending(&TxInfoPrefix)
            .await
            .next()
            .await
            .map_or(0, |entry| entry.0.0 + 1)
    }

    /// Get the network for UI display
    pub fn network_ui(&self) -> Network {
        self.cfg.consensus.network
    }

    /// Get the current federation wallet info for UI display
    pub async fn federation_wallet_ui(&self) -> Option<FederationWallet> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&FederationWalletKey)
            .await
    }

    /// Get the current consensus block count for UI display
    pub async fn consensus_block_count_ui(&self) -> u64 {
        self.consensus_block_count(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current consensus feerate for UI display
    pub async fn consensus_feerate_ui(&self) -> Option<u64> {
        self.consensus_feerate(&mut self.db.begin_transaction_nc().await)
            .await
            .map(|feerate| feerate / 1000)
    }

    /// Get the current send fee for UI display
    pub async fn send_fee_ui(&self) -> Option<Amount> {
        self.send_fee(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current receive fee for UI display
    pub async fn receive_fee_ui(&self) -> Option<Amount> {
        self.receive_fee(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current pending transaction info for UI display
    pub async fn pending_tx_chain_ui(&self) -> Vec<TxInfo> {
        self.pending_tx_chain(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Get the current transaction log for UI display
    pub async fn tx_chain_ui(&self) -> Vec<TxInfo> {
        self.tx_chain(&mut self.db.begin_transaction_nc().await)
            .await
    }

    /// Export recovery keys for federation shutdown. Returns None if the
    /// federation wallet has not been initialized yet.
    pub async fn recovery_keys_ui(&self) -> Option<(BTreeMap<PeerId, String>, String)> {
        let wallet = self.federation_wallet_ui().await?;

        let pks = self
            .cfg
            .consensus
            .bitcoin_pks
            .iter()
            .map(|(peer, pk)| (*peer, tweak_public_key(pk, &wallet.tweak).to_string()))
            .collect();

        let tweak = &Scalar::from_be_bytes(wallet.tweak.to_byte_array())
            .expect("Hash is within field order");

        let sk = self
            .cfg
            .private
            .bitcoin_sk
            .add_tweak(tweak)
            .expect("Failed to tweak bitcoin secret key");

        let sk = bitcoin::PrivateKey::new(sk, self.cfg.consensus.network).to_wif();

        Some((pks, sk))
    }
}
