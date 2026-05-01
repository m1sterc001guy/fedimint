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
mod taproot;

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Mutex;
use std::time::SystemTime;

use anyhow::{Context, anyhow, bail, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, Sequence, Transaction, TxIn, TxOut, Txid};
use common::config::WalletConfigConsensus;
use common::{
    OutputInfo, WalletCommonInit, WalletConsensusItem, WalletInput, WalletModuleTypes,
    WalletOutput, WalletOutputOutcome,
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
use fedimint_core::envs::{FM_ENABLE_MODULE_WALLETV2_ENV, is_env_var_set_opt};
use fedimint_core::module::audit::Audit;
use fedimint_core::module::{
    Amounts, ApiEndpoint, ApiVersion, CORE_CONSENSUS_VERSION, CoreConsensusVersion, InputMeta,
    ModuleConsensusVersion, ModuleInit, SupportedModuleApiVersions, TransactionItemAmounts,
    api_endpoint,
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
    FeeConsensus, WalletClientConfig, WalletConfig, WalletConfigPrivate, WalletDescriptor,
};
use fedimint_walletv2_common::endpoint_constants::{
    CONSENSUS_BLOCK_COUNT_ENDPOINT, CONSENSUS_FEERATE_ENDPOINT, FEDERATION_WALLET_ENDPOINT,
    OUTPUT_INFO_SLICE_ENDPOINT, PENDING_TRANSACTION_CHAIN_ENDPOINT, RECEIVE_FEE_ENDPOINT,
    SEND_FEE_ENDPOINT, TRANSACTION_CHAIN_ENDPOINT, TRANSACTION_ID_ENDPOINT,
};
use fedimint_walletv2_common::taproot::frost::{FrostPublicKeyPackage, FrostSigningCommitments};
use fedimint_walletv2_common::taproot::{descriptor_tr, tweak_xonly_public_key};
use fedimint_walletv2_common::{
    FederationWallet, MODULE_CONSENSUS_VERSION, TxInfo, WalletInputError, WalletOutputError,
    descriptor, is_potential_receive, tweak_public_key,
};
use frost_secp256k1_tr::Identifier;
use frost_secp256k1_tr::round1::SigningNonces;
use futures::StreamExt;
use miniscript::descriptor::Wsh;
use rand::rngs::OsRng;
use secp256k1::ecdsa::Signature;
use secp256k1::{PublicKey, Scalar, SecretKey, schnorr};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tracing::{debug, info};

use crate::db::{
    BlockCountVoteKey, BlockCountVotePrefix, FeeRateVoteKey, FeeRateVotePrefix,
    FrostAdvanceVoteAttemptPrefix, FrostAdvanceVoteKey, FrostAdvanceVoteTxidPrefix,
    FrostSignatureShareAttemptPrefix, FrostSignatureShareKey, FrostSignatureShareTxidPrefix,
    FrostSigningAttemptKey, FrostSigningAttemptTxidPrefix, FrostSigningCommitmentsKey,
    FrostSigningCommitmentsPeerPrefix, FrostSigningNoncesKey, FrostSigningNoncesPrefix,
    FrostSigningPackagesKey, FrostSigningPackagesTxidPrefix, SchnorrSignaturesPrefix, TxInfoKey,
    TxInfoPrefix, UnconfirmedTxKey, UnconfirmedTxPrefix, UnsignedTxKey, UnsignedTxPrefix,
};
use crate::taproot::frost::{
    FROST_NONCE_BUFFER_TARGET, FrostSigningNonces, apply_utxo_tweak_to_pubkey_package,
    local_advance_timeout, peer_id_to_identifier, spawn_initial_nonce_backfill,
    verify_signature_share,
};

/// Number of confirmations required for a transaction to be considered as
/// final by the federation. The block that mines the transaction does
/// not count towards the number of confirmations.
pub const CONFIRMATION_FINALITY_DELAY: u64 = 6;

/// Maximum number of blocks the consensus block count can advance in a single
/// consensus item to limit the work done in one `process_consensus_item` step.
const MAX_BLOCK_COUNT_INCREMENT: u64 = 5;

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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SpentTxOut {
    pub value: Amount,
    pub tweak: sha256::Hash,
}

async fn pending_txs_unordered(dbtx: &mut DatabaseTransaction<'_>) -> Vec<FederationTx> {
    let unsigned: Vec<FederationTx> = dbtx
        .find_by_prefix(&UnsignedTxPrefix)
        .await
        .map(|entry| entry.1)
        .collect()
        .await;

    let unconfirmed: Vec<FederationTx> = dbtx
        .find_by_prefix(&UnconfirmedTxPrefix)
        .await
        .map(|entry| entry.1)
        .collect()
        .await;

    unsigned.into_iter().chain(unconfirmed).collect()
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
                DbKeyPrefix::SchnorrSignatures => {
                    push_db_pair_items!(
                        dbtx,
                        SchnorrSignaturesPrefix,
                        SchnorrSignaturesKey,
                        Vec<schnorr::Signature>,
                        wallet,
                        "Wallet Schnorr Signatures"
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
                DbKeyPrefix::FrostSigningCommitments => {
                    todo!()
                }
                DbKeyPrefix::FrostSigningNonce => {
                    todo!()
                }
                DbKeyPrefix::FrostSignatureShare => {
                    todo!()
                }
                DbKeyPrefix::FrostSigningPackages => {
                    todo!()
                }
                DbKeyPrefix::FrostSigningAttempt => {
                    todo!()
                }
                DbKeyPrefix::FrostAdvanceVote => {
                    todo!()
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

    fn supported_api_versions(&self) -> SupportedModuleApiVersions {
        SupportedModuleApiVersions::from_raw(
            (CORE_CONSENSUS_VERSION.major, CORE_CONSENSUS_VERSION.minor),
            (
                MODULE_CONSENSUS_VERSION.major,
                MODULE_CONSENSUS_VERSION.minor,
            ),
            &[(0, 1)],
        )
    }

    fn is_enabled_by_default(&self) -> bool {
        is_env_var_set_opt(FM_ENABLE_MODULE_WALLETV2_ENV).unwrap_or(false)
    }

    fn get_documented_env_vars(&self) -> Vec<EnvVarDoc> {
        vec![EnvVarDoc {
            name: FM_ENABLE_MODULE_WALLETV2_ENV,
            description: "Set to 1/true to enable the WalletV2 module (experimental). Disabled by default.",
        }]
    }

    async fn init(&self, args: &ServerModuleInitArgs<Self>) -> anyhow::Result<Self::Module> {
        Ok(Wallet::new(
            args.cfg().to_typed()?,
            args.our_peer_id(),
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

        let (key_packages, internal_key, pubkey_package) =
            taproot::frost::trusted_setup(peers).expect("Could not execute trusted setup");
        let frost_pubkey_package = Some(FrostPublicKeyPackage(pubkey_package));

        bitcoin_sks
            .into_iter()
            .map(|(peer, bitcoin_sk)| {
                let frost_key_package = key_packages.get(&peer).cloned();
                let config = WalletConfig {
                    private: WalletConfigPrivate {
                        bitcoin_sk,
                        frost_key_package,
                    },
                    consensus: WalletConfigConsensus::new(
                        bitcoin_pks.clone(),
                        fee_consensus.clone(),
                        args.network,
                        args.use_taproot,
                        internal_key,
                        frost_pubkey_package.clone(),
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

        let (key_package, internal_key, pubkey_package) = taproot::frost::dkg(peers).await?;

        let config = WalletConfig {
            private: WalletConfigPrivate {
                bitcoin_sk,
                frost_key_package: Some(key_package),
            },
            consensus: WalletConfigConsensus::new(
                bitcoin_pks,
                fee_consensus,
                args.network,
                args.use_taproot,
                internal_key,
                Some(FrostPublicKeyPackage(pubkey_package)),
            ),
        };

        let descriptor = descriptor_tr(
            &config.consensus.bitcoin_pks,
            &sha256::Hash::all_zeros(),
            internal_key,
        );
        tracing::info!(target: LOG_MODULE_WALLETV2, "DKG finished. Wallet Descriptor: {descriptor}");

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
        let our_pk = self.cfg.private.bitcoin_sk.public_key(secp256k1::SECP256K1);

        let mut items: Vec<WalletConsensusItem> = match self.cfg.consensus.descriptor {
            WalletDescriptor::Wsh => {
                dbtx.find_by_prefix(&UnsignedTxPrefix)
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
                    .collect()
                    .await
            }
            WalletDescriptor::Tr => {
                dbtx.find_by_prefix(&UnsignedTxPrefix)
                    .await
                    .map(|(key, unsigned_tx)| {
                        let signatures = self.sign_tx_schnorr(&unsigned_tx);
                        self.verify_signatures_schnorr(&unsigned_tx, &signatures, our_pk)
                            .expect("Our signatures failed verification against our private key");
                        WalletConsensusItem::SchnorrSignatures(key.0, signatures)
                    })
                    .collect()
                    .await
            }
            WalletDescriptor::Frost(_) => Vec::new(),
        };

        if matches!(self.cfg.consensus.descriptor, WalletDescriptor::Frost(_)) {
            let my_commitments = dbtx
                .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(self.our_peer_id))
                .await
                .map(|c| c.0.frost_commitments)
                .collect::<HashSet<_>>()
                .await;

            let my_nonces = dbtx
                .find_by_prefix(&FrostSigningNoncesPrefix)
                .await
                .collect::<Vec<_>>()
                .await;

            // Snapshot the in-flight set: commitments we've already pushed to
            // a previous proposal but that haven't yet been finalized through
            // AlephBFT. Without this, the DB filter alone races with the
            // proposal cadence (~100ms) vs. consensus round-trip (~150–300ms)
            // and the same commitment goes out repeatedly.
            let in_flight_snapshot = self
                .in_flight_commitments
                .lock()
                .expect("in_flight_commitments mutex poisoned")
                .clone();

            let new_commitments: Vec<FrostSigningCommitments> = my_nonces
                .into_iter()
                .filter_map(|(commitment, _)| {
                    let c = commitment.0;
                    (!my_commitments.contains(&c) && !in_flight_snapshot.contains(&c)).then_some(c)
                })
                .collect();

            if !new_commitments.is_empty() {
                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    commitment_len = %new_commitments.len(),
                    "Added commitments to be broadcasted"
                );

                {
                    let mut in_flight = self
                        .in_flight_commitments
                        .lock()
                        .expect("in_flight_commitments mutex poisoned");
                    for c in &new_commitments {
                        in_flight.insert(c.clone());
                    }
                }

                items.extend(
                    new_commitments
                        .into_iter()
                        .map(WalletConsensusItem::FrostSigningCommitments),
                );
            }

            // Broadcast our pre-computed signature share for each active signing
            // session. We compute the share inline in `process_input` /
            // `process_output` when the unsigned tx is created and store it
            // locally at our own peer_id; here we surface it so the other
            // signers can aggregate. Receivers look up the (deterministic)
            // SigningPackage and the FederationTx in their own DB by txid.
            // The signing_session for each tx is read from FrostSigningAttemptKey
            // — set when the tx was created — so the choice of signers is
            // a per-tx fact, not a global constant.
            let txids = dbtx
                .find_by_prefix(&UnsignedTxPrefix)
                .await
                .map(|(key, _)| key.0)
                .collect::<Vec<_>>()
                .await;
            for txid in txids {
                // Find the latest attempt for this tx — attempts are
                // append-only, so the highest attempt number is the
                // current one. None means the tx hasn't reached the
                // FROST signing path yet (e.g. first peg-in, which only
                // inserts the FederationWalletKey).
                let Some((latest_attempt, attempt)) = dbtx
                    .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
                    .await
                    .map(|(k, v)| (k.attempt, v))
                    .collect::<Vec<_>>()
                    .await
                    .into_iter()
                    .max_by_key(|(att, _)| *att)
                else {
                    continue;
                };

                // If the current attempt has been waiting longer than our
                // local advance timeout, broadcast a vote to abandon it.
                // Any peer can vote, including non-session observers — they
                // can see whose share is missing from their own DB.
                let timer_expired = {
                    let mut map = self
                        .tx_attempt_first_seen
                        .lock()
                        .expect("tx_attempt_first_seen mutex poisoned");
                    let first_seen = map
                        .entry((txid, latest_attempt))
                        .or_insert_with(fedimint_core::time::now);
                    fedimint_core::time::now()
                        .duration_since(*first_seen)
                        .unwrap_or_default()
                        > local_advance_timeout()
                };
                if timer_expired {
                    let in_flight = self
                        .in_flight_advance_votes
                        .lock()
                        .expect("in_flight_advance_votes mutex poisoned")
                        .contains(&(txid, latest_attempt));
                    let already_voted = dbtx
                        .get_value(&FrostAdvanceVoteKey {
                            txid,
                            attempt: latest_attempt,
                            voter: self.our_peer_id,
                        })
                        .await
                        .is_some();
                    if !in_flight && !already_voted {
                        self.in_flight_advance_votes
                            .lock()
                            .expect("in_flight_advance_votes mutex poisoned")
                            .insert((txid, latest_attempt));
                        tracing::info!(
                            target: LOG_MODULE_WALLETV2,
                            ?txid,
                            attempt = latest_attempt,
                            "Broadcasting FROST advance vote for stuck signing session"
                        );
                        items.push(WalletConsensusItem::FrostAdvanceVote((
                            txid,
                            latest_attempt,
                        )));
                    }
                }

                if !attempt.signing_session.contains(&self.our_peer_id) {
                    continue;
                }
                let already_broadcast = self
                    .broadcast_signature_shares
                    .lock()
                    .expect("broadcast_signature_shares mutex poisoned")
                    .contains(&(txid, latest_attempt));
                if already_broadcast {
                    continue;
                }
                let key = FrostSignatureShareKey {
                    txid,
                    attempt: latest_attempt,
                    peer_id: self.our_peer_id,
                };
                if let Some(shares) = dbtx.get_value(&key).await {
                    self.broadcast_signature_shares
                        .lock()
                        .expect("broadcast_signature_shares mutex poisoned")
                        .insert((txid, latest_attempt));
                    tracing::info!(
                        target: LOG_MODULE_WALLETV2,
                        "Broadcasting our FROST signature share"
                    );
                    items.push(WalletConsensusItem::FrostSignatureShare((
                        txid,
                        latest_attempt,
                        shares,
                    )));
                }
            }
        }

        if let Some(status) = self.btc_rpc.status() {
            assert_eq!(status.network, self.cfg.consensus.network);

            let block_count_vote = status
                .block_count
                .saturating_sub(CONFIRMATION_FINALITY_DELAY);

            let consensus_block_count = self.consensus_block_count(dbtx).await;

            let block_count_vote = match consensus_block_count {
                0 => block_count_vote,
                _ => block_count_vote.min(consensus_block_count + MAX_BLOCK_COUNT_INCREMENT),
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
                ensure!(
                    self.cfg.consensus.descriptor == WalletDescriptor::Wsh,
                    "Received ECDSA signature on a Taproot Federation"
                );
                self.process_signatures(dbtx, txid, signatures, peer).await
            }
            WalletConsensusItem::SchnorrSignatures(txid, signatures) => {
                ensure!(
                    self.cfg.consensus.descriptor == WalletDescriptor::Tr,
                    "Received Schnorr Signature on a Segwit Federation"
                );
                self.process_signatures_schnorr(dbtx, txid, signatures, peer)
                    .await
            }
            WalletConsensusItem::FrostSigningCommitments(commitments) => {
                // Reject duplicates so they're not stored in `AcceptedItemKey`
                // and replayed on recovery. Mirrors the `Feerate` redundancy
                // handling.
                let was_present = dbtx
                    .insert_entry(
                        &FrostSigningCommitmentsKey {
                            peer_id: peer,
                            frost_commitments: commitments.clone(),
                        },
                        &(),
                    )
                    .await
                    .is_some();

                if was_present {
                    return Err(anyhow!("FROST signing commitment is redundant"));
                }

                let commitment_count = dbtx
                    .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(peer))
                    .await
                    .count()
                    .await;

                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    ?peer,
                    commitment_count,
                    target = FROST_NONCE_BUFFER_TARGET,
                    "Stored FROST signing commitment"
                );

                // Our own commitment has now been finalized — drop it from
                // the in-flight set so the next `consensus_proposal` can
                // freely propose new commitments without the race window.
                if peer == self.our_peer_id {
                    self.in_flight_commitments
                        .lock()
                        .expect("in_flight_commitments mutex poisoned")
                        .remove(&commitments);
                }

                // A fresh commitment may have unblocked a tx that was
                // waiting on commitment-buffer availability. Retry any
                // pending signings.
                self.try_progress_pending_signings(dbtx).await?;

                Ok(())
            }
            WalletConsensusItem::FrostSignatureShare((txid, attempt, signature_shares)) => {
                tracing::info!(target: LOG_MODULE_WALLETV2, ?peer, attempt, "Received signature shares for tx from peer");

                let Some(unsigned_tx) = dbtx.get_value(&UnsignedTxKey(txid)).await else {
                    tracing::info!(
                        target: LOG_MODULE_WALLETV2,
                        "Tx already finalized, skipping signature share..."
                    );
                    return Ok(());
                };

                // The wire `attempt` identifies which attempt this share
                // is for. Multiple attempts can coexist; we just need a
                // record for *this* one. No staleness check is needed —
                // late shares for old attempts are still mathematically
                // valid against the old attempt's stored signing_packages,
                // and any attempt reaching threshold finalizes the tx.
                let stored_attempt = dbtx
                    .get_value(&FrostSigningAttemptKey { txid, attempt })
                    .await
                    .ok_or_else(|| {
                        anyhow!(
                            "FROST signature share references a nonexistent attempt {attempt} of tx {txid}"
                        )
                    })?;
                ensure!(
                    stored_attempt.signing_session.contains(&peer),
                    "Peer {peer} broadcast a signature share but is not in the \
                     signing session for tx {txid} attempt {attempt}",
                );

                // Verify each per-input share before storing. Catches a malicious
                // or buggy peer here (where we can reject just their consensus
                // item) instead of at aggregation time, where one bad share
                // would otherwise blow up the whole session.
                ensure!(
                    matches!(self.cfg.consensus.descriptor, WalletDescriptor::Frost(_)),
                    "FrostSignatureShare on non-FROST federation",
                );
                let pubkey_package_base = self
                    .cfg
                    .consensus
                    .frost_pubkey_package
                    .as_ref()
                    .expect("FROST federation must have a frost_pubkey_package")
                    .0
                    .clone();
                ensure!(
                    signature_shares.signature_shares.len() == unsigned_tx.tx.input.len(),
                    "Wrong number of FROST signature shares from peer {peer}",
                );

                let signing_packages = dbtx
                    .get_value(&FrostSigningPackagesKey { txid, attempt })
                    .await
                    .ok_or_else(|| {
                        anyhow!(
                            "Missing FROST signing packages for tx {txid} attempt {attempt} \
                             — DB inconsistency"
                        )
                    })?;
                ensure!(
                    signing_packages.len() == unsigned_tx.tx.input.len(),
                    "Stored FROST signing packages count mismatch for tx {txid} attempt {attempt}",
                );

                for (input_index, share) in signature_shares.signature_shares.iter().enumerate() {
                    let utxo = &unsigned_tx.spent_tx_outs[input_index];
                    let merkle_root = self.tap_leaf_hash(&utxo.tweak).to_byte_array();
                    verify_signature_share(
                        &pubkey_package_base,
                        &utxo.tweak,
                        &merkle_root,
                        peer,
                        &signing_packages[input_index].0,
                        share,
                    )?;
                }

                // Reject re-broadcasts from *other* peers so they're stripped
                // from `AcceptedItemKey` and don't pollute logs. Our own
                // peer is special: `compute_and_store_frost_signature_shares`
                // already populated this key during process_input /
                // process_output (so `consensus_proposal` can find the share
                // to broadcast), and our broadcast then comes back here as
                // a no-op overwrite. If we returned `Err` here, the
                // broadcasting peer would strip its own share from its
                // accepted-items list while every other peer accepted it —
                // that's a federation-wide consensus divergence (mismatched
                // session headers).
                let was_present = dbtx
                    .insert_entry(
                        &FrostSignatureShareKey {
                            txid,
                            attempt,
                            peer_id: peer,
                        },
                        &signature_shares,
                    )
                    .await
                    .is_some();
                if was_present && peer != self.our_peer_id {
                    return Err(anyhow!(
                        "FROST signature share from peer {peer} for tx {txid} attempt {attempt} \
                         is redundant"
                    ));
                }

                // Lookup all signature shares for *this attempt only* — old
                // attempts' shares are still in the DB but live under a
                // different prefix and don't pollute the count.
                let shares = dbtx
                    .find_by_prefix(&FrostSignatureShareAttemptPrefix { txid, attempt })
                    .await
                    .collect::<Vec<_>>()
                    .await;
                let threshold = self.cfg.consensus.bitcoin_pks.to_num_peers().threshold();
                if shares.len() == threshold {
                    let pubkey_package = self
                        .cfg
                        .consensus
                        .frost_pubkey_package
                        .clone()
                        .ok_or_else(|| {
                            anyhow!("FROST federation must have a frost_pubkey_package")
                        })?
                        .0;

                    let mut final_sigs = Vec::with_capacity(unsigned_tx.tx.input.len());
                    for input_index in 0..unsigned_tx.tx.input.len() {
                        let utxo = &unsigned_tx.spent_tx_outs[input_index];
                        let signing_package = &signing_packages[input_index].0;

                        let shares_for_input = shares
                            .iter()
                            .map(|(k, v)| {
                                (
                                    peer_id_to_identifier(k.peer_id),
                                    v.signature_shares[input_index],
                                )
                            })
                            .collect::<BTreeMap<_, _>>();

                        let pubkey_package =
                            apply_utxo_tweak_to_pubkey_package(&pubkey_package, &utxo.tweak);
                        let merkle_root = self.tap_leaf_hash(&utxo.tweak).to_byte_array();

                        let final_sig = frost_secp256k1_tr::aggregate_with_tweak(
                            signing_package,
                            &shares_for_input,
                            &pubkey_package,
                            Some(&merkle_root),
                        )?;

                        tracing::info!(
                            target: LOG_MODULE_WALLETV2,
                            input_index,
                            "Aggregated FROST signature for input"
                        );

                        final_sigs.push(final_sig);
                    }

                    // Attach key-path witnesses, move tx unsigned → unconfirmed,
                    // clean up the per-peer share entries + cached signing
                    // packages + signing-attempt record + advance votes
                    // (across all attempts), and broadcast.
                    let mut unsigned = unsigned_tx;
                    taproot::frost::finalize_tx_frost(&mut unsigned, &final_sigs);

                    // All per-attempt state for this tx — across every
                    // attempt that ever ran — gets cleaned up here, since
                    // shares, packages, and attempt records are all keyed
                    // by `(txid, attempt)`.
                    dbtx.remove_entry(&UnsignedTxKey(txid)).await;
                    dbtx.remove_by_prefix(&FrostSignatureShareTxidPrefix(txid))
                        .await;
                    dbtx.remove_by_prefix(&FrostSigningPackagesTxidPrefix(txid))
                        .await;
                    dbtx.remove_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
                        .await;
                    dbtx.remove_by_prefix(&FrostAdvanceVoteTxidPrefix(txid))
                        .await;
                    dbtx.insert_new_entry(&UnconfirmedTxKey(txid), &unsigned)
                        .await;
                    // Drop in-memory broadcast guards for this tx — no more
                    // shares to broadcast and no more votes to file.
                    self.broadcast_signature_shares
                        .lock()
                        .expect("broadcast_signature_shares mutex poisoned")
                        .retain(|(t, _)| *t != txid);
                    self.tx_attempt_first_seen
                        .lock()
                        .expect("tx_attempt_first_seen mutex poisoned")
                        .retain(|(t, _), _| *t != txid);

                    if let Err(err) = self.btc_rpc.submit_transaction(unsigned.tx).await {
                        tracing::warn!(
                            target: LOG_MODULE_WALLETV2,
                            err = %err.fmt_compact_anyhow(),
                            "Error broadcasting finalized FROST transaction"
                        );
                    }
                } else {
                    tracing::info!(target: LOG_MODULE_WALLETV2, ?peer, len = %shares.len(), "Not enough shares for this transaction yet.");
                }

                Ok(())
            }
            WalletConsensusItem::FrostAdvanceVote((txid, attempt)) => {
                // Validate the wire `attempt` corresponds to a real attempt
                // in our DB. We don't reject votes for older attempts —
                // those are still real attempts whose data is preserved;
                // we just won't re-advance past the next one (see below).
                ensure!(
                    dbtx.get_value(&FrostSigningAttemptKey { txid, attempt })
                        .await
                        .is_some(),
                    "FROST advance vote references a nonexistent attempt {attempt} of tx {txid}",
                );

                // Dedup: each peer votes at most once per (txid, attempt).
                let was_present = dbtx
                    .insert_entry(
                        &FrostAdvanceVoteKey {
                            txid,
                            attempt,
                            voter: peer,
                        },
                        &(),
                    )
                    .await
                    .is_some();
                if was_present {
                    return Err(anyhow!("Duplicate FROST advance vote from peer {peer}"));
                }

                if peer == self.our_peer_id {
                    self.in_flight_advance_votes
                        .lock()
                        .expect("in_flight_advance_votes mutex poisoned")
                        .remove(&(txid, attempt));
                }

                tracing::info!(
                    target: LOG_MODULE_WALLETV2,
                    ?peer,
                    ?txid,
                    attempt,
                    "Recorded FROST advance vote"
                );

                // Tally votes for this (txid, attempt). Advance once `f+1`
                // distinct voters agree the session is stuck — that's the
                // smallest threshold at which Byzantine peers can't trigger
                // advance alone.
                let vote_count = dbtx
                    .find_by_prefix(&FrostAdvanceVoteAttemptPrefix { txid, attempt })
                    .await
                    .count()
                    .await;
                let advance_threshold =
                    self.cfg.consensus.bitcoin_pks.to_num_peers().max_evil() + 1;
                if vote_count < advance_threshold {
                    return Ok(());
                }

                // Idempotent advance: if `(txid, attempt + 1)` already
                // exists, the federation has already advanced — extra
                // votes for `attempt` are recorded for posterity but
                // don't trigger another advance. No teardown needed:
                // attempts are append-only and old data lives at its own
                // per-attempt prefix until tx finalization.
                let next_attempt = attempt + 1;
                let next_already_exists = dbtx
                    .get_value(&FrostSigningAttemptKey {
                        txid,
                        attempt: next_attempt,
                    })
                    .await
                    .is_some();
                if next_already_exists {
                    tracing::info!(
                        target: LOG_MODULE_WALLETV2,
                        ?txid,
                        attempt,
                        next_attempt,
                        "FROST advance threshold reached, but next attempt already exists"
                    );
                    return Ok(());
                }

                let unsigned_tx = dbtx
                    .get_value(&UnsignedTxKey(txid))
                    .await
                    .expect("active attempt implies UnsignedTxKey exists");

                // Append a new attempt at `attempt + 1`. Old attempt N's
                // shares, packages, and attempt record stay in their
                // per-attempt slots. Late shares for attempt N can still
                // arrive and contribute toward attempt N's threshold —
                // and any attempt that reaches threshold finalizes the
                // tx. Cleanup happens at finalization.
                //
                // If `compute_and_store` fails (typically because the
                // federation's commitment buffer is too thin to form a
                // viable session right now), don't propagate the error —
                // the vote was already recorded above. The next
                // FrostSigningCommitments processing will retry via
                // try_progress_pending_signings once buffers refill.
                match self
                    .compute_and_store_frost_signature_shares(dbtx, &unsigned_tx, next_attempt)
                    .await
                {
                    Ok(()) => {
                        let next_attempt_record = dbtx
                            .get_value(&FrostSigningAttemptKey {
                                txid,
                                attempt: next_attempt,
                            })
                            .await
                            .expect("compute_and_store just persisted this attempt");

                        tracing::info!(
                            target: LOG_MODULE_WALLETV2,
                            ?txid,
                            attempt,
                            next_attempt,
                            vote_count,
                            advance_threshold,
                            next_signing_session = ?next_attempt_record.signing_session,
                            "FROST advance threshold reached; built next attempt"
                        );
                    }
                    Err(err) => {
                        tracing::warn!(
                            target: LOG_MODULE_WALLETV2,
                            ?txid,
                            attempt,
                            next_attempt,
                            err = %err.fmt_compact_anyhow(),
                            "FROST advance threshold reached but couldn't build next attempt; will retry when commitments replenish"
                        );
                    }
                }

                Ok(())
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

        let tweaked_pubkey = self.script_pubkey_for(&input.tweak.consensus_hash());

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

        if let Some(wallet) = dbtx.remove_entry(&FederationWalletKey).await {
            // Assuming the first receive into the federation is made through a
            // standard transaction, its output value is over the P2WSH dust
            // limit. By induction so is this change value.
            let change_value = wallet
                .value
                .checked_add(output_value)
                .ok_or(WalletInputError::ArithmeticOverflow)?;

            let tx = Transaction {
                version: Version(2),
                lock_time: LockTime::ZERO,
                input: vec![
                    TxIn {
                        previous_output: wallet.outpoint,
                        script_sig: Default::default(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                    TxIn {
                        previous_output: tracked_outpoint,
                        script_sig: Default::default(),
                        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                        witness: bitcoin::Witness::new(),
                    },
                ],
                output: vec![TxOut {
                    value: change_value,
                    script_pubkey: self.script_pubkey_for(&wallet.consensus_hash()),
                }],
            };

            let txid = tx.compute_txid();

            dbtx.insert_new_entry(
                &FederationWalletKey,
                &FederationWallet {
                    value: change_value,
                    outpoint: bitcoin::OutPoint { txid, vout: 0 },
                    tweak: wallet.consensus_hash(),
                },
            )
            .await;

            let tx_index = self.total_txs(dbtx).await;

            let created = self.consensus_block_count(dbtx).await;

            dbtx.insert_new_entry(
                &TxInfoKey(tx_index),
                &TxInfo {
                    index: tx_index,
                    txid,
                    input: wallet.value,
                    output: change_value,
                    vbytes: self.cfg.consensus.receive_tx_vbytes,
                    fee: input.fee,
                    created,
                },
            )
            .await;

            let unsigned = FederationTx {
                tx,
                spent_tx_outs: vec![
                    SpentTxOut {
                        value: wallet.value,
                        tweak: wallet.tweak,
                    },
                    SpentTxOut {
                        value: tracked_output.value,
                        tweak: input.tweak.consensus_hash(),
                    },
                ],
                vbytes: self.cfg.consensus.receive_tx_vbytes,
                fee: input.fee,
            };

            dbtx.insert_new_entry(&UnsignedTxKey(txid), &unsigned).await;

            if matches!(self.cfg.consensus.descriptor, WalletDescriptor::Frost(_)) {
                if let Err(err) = self
                    .compute_and_store_frost_signature_shares(dbtx, &unsigned, 0)
                    .await
                {
                    // Tx is created without an attempt; the next
                    // FrostSigningCommitments processing will retry via
                    // try_progress_pending_signings once buffers refill.
                    tracing::warn!(
                        target: LOG_MODULE_WALLETV2,
                        ?txid,
                        err = %err.fmt_compact_anyhow(),
                        "Couldn't start initial FROST signing attempt for receive tx; will retry when commitments replenish"
                    );
                }
            }
        } else {
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

        let wallet = dbtx
            .remove_entry(&FederationWalletKey)
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

        let change_value = wallet
            .value
            .checked_sub(output_value)
            .ok_or(WalletOutputError::ArithmeticOverflow)?;

        if change_value < self.cfg.consensus.dust_limit {
            return Err(WalletOutputError::ChangeUnderDustLimit);
        }

        let script_pubkey = output
            .destination
            .script_pubkey()
            .ok_or(WalletOutputError::UnknownScriptVariant)?;

        let tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: wallet.outpoint,
                script_sig: Default::default(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![
                TxOut {
                    value: change_value,
                    script_pubkey: self.script_pubkey_for(&wallet.consensus_hash()),
                },
                TxOut {
                    value: output.value,
                    script_pubkey,
                },
            ],
        };

        let txid = tx.compute_txid();

        dbtx.insert_new_entry(
            &FederationWalletKey,
            &FederationWallet {
                value: change_value,
                outpoint: bitcoin::OutPoint { txid, vout: 0 },
                tweak: wallet.consensus_hash(),
            },
        )
        .await;

        let tx_index = self.total_txs(dbtx).await;

        let created = self.consensus_block_count(dbtx).await;

        dbtx.insert_new_entry(
            &TxInfoKey(tx_index),
            &TxInfo {
                index: tx_index,
                txid,
                input: wallet.value,
                output: change_value,
                vbytes: self.cfg.consensus.send_tx_vbytes,
                fee: output.fee,
                created,
            },
        )
        .await;

        dbtx.insert_new_entry(&TxInfoIndexKey(outpoint), &tx_index)
            .await;

        let unsigned = FederationTx {
            tx,
            spent_tx_outs: vec![SpentTxOut {
                value: wallet.value,
                tweak: wallet.tweak,
            }],
            vbytes: self.cfg.consensus.send_tx_vbytes,
            fee: output.fee,
        };

        dbtx.insert_new_entry(&UnsignedTxKey(txid), &unsigned).await;

        if matches!(self.cfg.consensus.descriptor, WalletDescriptor::Frost(_)) {
            if let Err(err) = self
                .compute_and_store_frost_signature_shares(dbtx, &unsigned, 0)
                .await
            {
                // Tx is created without an attempt; the next
                // FrostSigningCommitments processing will retry via
                // try_progress_pending_signings once buffers refill.
                tracing::warn!(
                    target: LOG_MODULE_WALLETV2,
                    ?txid,
                    err = %err.fmt_compact_anyhow(),
                    "Couldn't start initial FROST signing attempt for send tx; will retry when commitments replenish"
                );
            }
        }

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
            api_endpoint! {
                CONSENSUS_BLOCK_COUNT_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> u64 {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_block_count(&mut dbtx).await)
                }
            },
            api_endpoint! {
                CONSENSUS_FEERATE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<u64> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.consensus_feerate(&mut dbtx).await)
                }
            },
            api_endpoint! {
                FEDERATION_WALLET_ENDPOINT,
                ApiVersion::new(0, 0),
                async |_module: &Wallet, context, _params: ()| -> Option<FederationWallet> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(dbtx.get_value(&FederationWalletKey).await)
                }
            },
            api_endpoint! {
                SEND_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.send_fee(&mut dbtx).await)
                }
            },
            api_endpoint! {
                RECEIVE_FEE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Option<Amount> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.receive_fee(&mut dbtx).await)
                }
            },
            api_endpoint! {
                TRANSACTION_ID_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: OutPoint| -> Option<Txid> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.tx_id(&mut dbtx, params).await)
                }
            },
            api_endpoint! {
                OUTPUT_INFO_SLICE_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, params: (u64, u64)| -> Vec<OutputInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.get_outputs(&mut dbtx, params.0, params.1).await)
                }
            },
            api_endpoint! {
                PENDING_TRANSACTION_CHAIN_ENDPOINT,
                ApiVersion::new(0, 0),
                async |module: &Wallet, context, _params: ()| -> Vec<TxInfo> {
                    let db = context.db();
                    let mut dbtx = db.begin_transaction_nc().await;
                    Ok(module.pending_tx_chain(&mut dbtx).await)
                }
            },
            api_endpoint! {
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
}

#[derive(Debug)]
pub struct Wallet {
    cfg: WalletConfig,
    our_peer_id: PeerId,
    db: Database,
    btc_rpc: ServerBitcoinRpcMonitor,
    /// FROST commitments we've put into a `consensus_proposal` output but
    /// haven't yet seen come back through `process_consensus_item`. The DB
    /// filter on its own is racy: at 100ms proposal cadence, the same
    /// commitment can be re-submitted several times before AlephBFT
    /// finalizes the first copy. Tracking them in memory closes that
    /// window. Entries are cleared when our own commitment is processed.
    in_flight_commitments: Mutex<HashSet<FrostSigningCommitments>>,
    /// Wall-clock timestamp of when we first observed each `(txid, attempt)`
    /// locally. Used to fire a per-peer advance vote when the session has
    /// been waiting longer than `local_advance_timeout()`. Per-peer state;
    /// not consensus.
    tx_attempt_first_seen: Mutex<HashMap<(Txid, u32), SystemTime>>,
    /// Same in-flight pattern as `in_flight_commitments`, but for advance
    /// votes. Keeps us from re-broadcasting the same vote at every
    /// `consensus_proposal` tick before the first one has been finalized.
    in_flight_advance_votes: Mutex<HashSet<(Txid, u32)>>,
    /// `(Txid, attempt)` tuples for which we have broadcast our signature
    /// share at least once. Unlike `in_flight_commitments`, entries here
    /// are *not* cleared when our share comes back through
    /// `process_consensus_item` — the same per-attempt share never needs
    /// to be re-broadcast. Cleared only when the attempt advances or the
    /// tx finalizes.
    broadcast_signature_shares: Mutex<HashSet<(Txid, u32)>>,
}

impl Wallet {
    fn new(
        cfg: WalletConfig,
        our_peer_id: PeerId,
        db: &Database,
        task_group: &TaskGroup,
        btc_rpc: ServerBitcoinRpcMonitor,
    ) -> Wallet {
        Self::spawn_broadcast_unconfirmed_txs_task(btc_rpc.clone(), db.clone(), task_group);

        if let WalletDescriptor::Frost(_) = cfg.consensus.descriptor {
            let key_package = cfg
                .private
                .frost_key_package
                .clone()
                .expect("Frost key not generated");
            spawn_initial_nonce_backfill(db.clone(), task_group, key_package);
        }

        Wallet {
            cfg,
            our_peer_id,
            btc_rpc,
            db: db.clone(),
            in_flight_commitments: Mutex::new(HashSet::new()),
            tx_attempt_first_seen: Mutex::new(HashMap::new()),
            in_flight_advance_votes: Mutex::new(HashSet::new()),
            broadcast_signature_shares: Mutex::new(HashSet::new()),
        }
    }

    /// Take the first available `FrostSigningCommitments` for each peer in
    /// `signing_session` and remove them from the DB. Called by every peer
    /// (including non-session peers) so that DB state — and therefore the
    /// derived `SigningPackage` — stays in sync across the federation.
    pub(crate) async fn consume_session_commitments(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        signing_session: &[PeerId],
    ) -> anyhow::Result<BTreeMap<Identifier, FrostSigningCommitments>> {
        let mut commitments_map = BTreeMap::new();
        for peer_id in signing_session {
            let commitment = dbtx
                .find_by_prefix(&FrostSigningCommitmentsPeerPrefix(*peer_id))
                .await
                .next()
                .await
                .ok_or_else(|| anyhow!("No FROST commitments available for peer {peer_id}"))?;
            commitments_map.insert(
                peer_id_to_identifier(*peer_id),
                commitment.0.frost_commitments.clone(),
            );
            dbtx.remove_entry(&commitment.0).await;
        }
        Ok(commitments_map)
    }

    /// Look up our own `SigningNonces` matching our entry in
    /// `commitments_map` and remove it from the DB. Only signing-session
    /// peers should call this — for non-session peers our_peer_id won't be
    /// in the map.
    pub(crate) async fn consume_our_nonce(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
        commitments_map: &BTreeMap<Identifier, FrostSigningCommitments>,
    ) -> anyhow::Result<SigningNonces> {
        let our_commitment = commitments_map
            .get(&peer_id_to_identifier(self.our_peer_id))
            .ok_or_else(|| anyhow!("Our peer is not in the signing session"))?;
        let nonce = dbtx
            .remove_entry(&FrostSigningNoncesKey(our_commitment.clone()))
            .await
            .ok_or_else(|| {
                anyhow!("FROST nonce for our own commitment is missing — DB inconsistency")
            })?
            .0;

        // Inline 1:1 replacement: keep our local nonce buffer at
        // `FROST_NONCE_BUFFER_TARGET` invariantly. Local-only state, no
        // consensus implications.
        let key_package = self
            .cfg
            .private
            .frost_key_package
            .as_ref()
            .expect("FROST federation must have a frost_key_package");
        let (new_nonce, new_commitment) =
            frost_secp256k1_tr::round1::commit(key_package.signing_share(), &mut OsRng);
        dbtx.insert_new_entry(
            &FrostSigningNoncesKey(FrostSigningCommitments(new_commitment)),
            &FrostSigningNonces(new_nonce),
        )
        .await;

        Ok(nonce)
    }

    /// Walk all unsigned txs and (re)try to start signing wherever we
    /// previously couldn't because of a thin commitment buffer:
    ///
    /// - Tx with no attempt at all → try `compute_and_store(.., 0)` to create
    ///   attempt 0. This is the "sign-later" path for an `UnsignedTx` that was
    ///   created in `process_input` / `process_output` while commitments were
    ///   drained.
    /// - Tx whose latest attempt has reached the advance vote threshold but
    ///   doesn't yet have an `attempt + 1` record → try `compute_and_store(..,
    ///   latest + 1)`. This catches the case where the advance handler had to
    ///   defer attempt creation.
    ///
    /// Errors are logged at trace level — the next call (typically the
    /// next `FrostSigningCommitments` processing) will retry, so we don't
    /// want to spam logs while waiting for buffers to refill.
    pub(crate) async fn try_progress_pending_signings(
        &self,
        dbtx: &mut DatabaseTransaction<'_>,
    ) -> anyhow::Result<()> {
        let unsigned_txs: Vec<(Txid, FederationTx)> = dbtx
            .find_by_prefix(&UnsignedTxPrefix)
            .await
            .map(|(k, v)| (k.0, v))
            .collect()
            .await;

        let advance_threshold = self.cfg.consensus.bitcoin_pks.to_num_peers().max_evil() + 1;

        for (txid, unsigned_tx) in unsigned_txs {
            let latest_attempt: Option<u32> = dbtx
                .find_by_prefix(&FrostSigningAttemptTxidPrefix(txid))
                .await
                .map(|(k, _)| k.attempt)
                .collect::<Vec<_>>()
                .await
                .into_iter()
                .max();

            let target_attempt = match latest_attempt {
                None => Some(0),
                Some(latest) => {
                    let vote_count = dbtx
                        .find_by_prefix(&FrostAdvanceVoteAttemptPrefix {
                            txid,
                            attempt: latest,
                        })
                        .await
                        .count()
                        .await;
                    if vote_count >= advance_threshold {
                        Some(latest + 1)
                    } else {
                        None
                    }
                }
            };

            if let Some(target) = target_attempt {
                if let Err(err) = self
                    .compute_and_store_frost_signature_shares(dbtx, &unsigned_tx, target)
                    .await
                {
                    tracing::trace!(
                        target: LOG_MODULE_WALLETV2,
                        ?txid,
                        target_attempt = target,
                        err = %err.fmt_compact_anyhow(),
                        "Couldn't progress FROST signing for tx; will retry on next commitment"
                    );
                }
            }
        }

        Ok(())
    }

    fn spawn_broadcast_unconfirmed_txs_task(
        btc_rpc: ServerBitcoinRpcMonitor,
        db: Database,
        task_group: &TaskGroup,
    ) {
        task_group.spawn_cancellable("broadcast_unconfirmed_transactions", async move {
            loop {
                let unconfirmed_txs = db
                    .begin_transaction_nc()
                    .await
                    .find_by_prefix(&UnconfirmedTxPrefix)
                    .await
                    .map(|entry| entry.1)
                    .collect::<Vec<FederationTx>>()
                    .await;

                for unconfirmed_tx in unconfirmed_txs {
                    if let Err(err) = btc_rpc.submit_transaction(unconfirmed_tx.tx).await {
                        debug!(
                            target: LOG_MODULE_WALLETV2,
                            err = %err.fmt_compact_anyhow(),
                            "Error broadcasting unconfirmed transaction"
                        );
                    }
                }

                sleep(common::sleep_duration()).await;
            }
        });
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

        // We do not sync blocks that predate the federation itself.
        if old_consensus_block_count == 0 {
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

            for tx in block.txdata {
                dbtx.remove_entry(&UnconfirmedTxKey(tx.compute_txid()))
                    .await;

                // We maintain an append-only log of transaction outputs that pass
                // the probabilistic receive filter created since the federation was
                // established. This is downloaded by clients to detect pegins and
                // claim them by index.

                for (vout, tx_out) in tx.output.iter().enumerate() {
                    if is_potential_receive(&tx_out.script_pubkey, &pks_hash) {
                        let outpoint = bitcoin::OutPoint {
                            txid: tx.compute_txid(),
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
                    }
                }
            }
        }

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

            if let Err(err) = self.btc_rpc.submit_transaction(unsigned.tx).await {
                debug!(
                    target: LOG_MODULE_WALLETV2,
                    err = %err.fmt_compact_anyhow(),
                    "Error broadcasting finalized transaction"
                );
            }
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
        // The minimum feerate is a protection against a catastrophic error in the
        // feerate estimation and limits the length of the pending transaction stack.

        let pending_txs = pending_txs_unordered(dbtx).await;

        assert!(pending_txs.len() <= 32);

        let feerate = self
            .consensus_feerate(dbtx)
            .await?
            .max(self.cfg.consensus.feerate_base << pending_txs.len());

        let tx_fee = tx_vbytes.saturating_mul(feerate).saturating_div(1000);

        let stack_vbytes = pending_txs
            .iter()
            .map(|t| t.vbytes)
            .try_fold(tx_vbytes, u64::checked_add)
            .expect("Stack vbytes overflow with at most 32 pending txs");

        let stack_fee = stack_vbytes.saturating_mul(feerate).saturating_div(1000);

        // Deduct the fees already paid by currently pending transactions
        let stack_fee = pending_txs
            .iter()
            .map(|t| t.fee.to_sat())
            .fold(stack_fee, u64::saturating_sub);

        Some(Amount::from_sat(tx_fee.max(stack_fee)))
    }

    pub async fn send_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_fee(dbtx, self.cfg.consensus.send_tx_vbytes)
            .await
    }

    pub async fn receive_fee(&self, dbtx: &mut DatabaseTransaction<'_>) -> Option<Amount> {
        self.consensus_fee(dbtx, self.cfg.consensus.receive_tx_vbytes)
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
        assert_eq!(
            federation_tx.spent_tx_outs.len(),
            federation_tx.tx.input.len()
        );

        for (index, utxo) in federation_tx.spent_tx_outs.iter().enumerate() {
            let satisfier: BTreeMap<PublicKey, bitcoin::ecdsa::Signature> = signatures
                .iter()
                .map(|(peer, sigs)| {
                    assert_eq!(sigs.len(), federation_tx.tx.input.len());

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
                let matches = match self.cfg.consensus.descriptor {
                    WalletDescriptor::Wsh => entry.1.1.script_pubkey.is_p2wsh(),
                    WalletDescriptor::Tr | WalletDescriptor::Frost(_) => {
                        entry.1.1.script_pubkey.is_p2tr()
                    }
                };
                std::future::ready(matches.then(|| OutputInfo {
                    index: entry.0.0,
                    script: entry.1.1.script_pubkey,
                    value: entry.1.1.value,
                    spent: spent.contains(&entry.0.0),
                }))
            })
            .collect()
            .await
    }

    async fn pending_tx_chain(&self, dbtx: &mut DatabaseTransaction<'_>) -> Vec<TxInfo> {
        let n_pending = pending_txs_unordered(dbtx).await.len();

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
            .map(|(peer, pk)| {
                let tweaked = match self.cfg.consensus.descriptor {
                    WalletDescriptor::Wsh => tweak_public_key(pk, &wallet.tweak).to_string(),
                    WalletDescriptor::Tr | WalletDescriptor::Frost(_) => {
                        tweak_xonly_public_key(&pk.x_only_public_key().0, &wallet.tweak).to_string()
                    }
                };
                (*peer, tweaked)
            })
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
