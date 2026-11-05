#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]

pub mod api;
#[cfg(feature = "cli")]
mod cli;
pub mod db;

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use anyhow::{Context as _, anyhow, bail, ensure};
use api::StatechainFederationApi;
use bitcoin::address::NetworkUnchecked;
use bitcoin::{Address, Transaction};
use db::{
    DbKeyPrefix, LocalCoin, LocalCoinKey, LocalCoinPrefix, LocalCoinState, ReceiveKey,
    ReceiveKeyKey, ReceiveKeyPrefix,
};
use fedimint_api_client::api::DynModuleApi;
use fedimint_client_module::DynGlobalClientContext;
use fedimint_client_module::db::ClientModuleMigrationFn;
use fedimint_client_module::module::init::{ClientModuleInit, ClientModuleInitArgs};
use fedimint_client_module::module::recovery::NoModuleBackup;
use fedimint_client_module::module::{ClientContext, ClientModule};
use fedimint_client_module::sm::{Context, DynState, State, StateTransition};
use fedimint_client_module::transaction::{
    ClientInput, ClientInputBundle, ClientOutput, ClientOutputBundle, TransactionBuilder,
};
use fedimint_core::core::{IntoDynInstance, ModuleInstanceId, ModuleKind, OperationId};
use fedimint_core::db::{
    Database, DatabaseTransaction, DatabaseVersion, IDatabaseTransactionOpsCoreTyped,
};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{
    AmountUnit, Amounts, ApiVersion, CommonModuleInit, ModuleCommon, ModuleInit, MultiApiVersion,
};
use fedimint_core::task::sleep;
use fedimint_core::util::FmtCompact as _;
use fedimint_core::{Amount, NumPeersExt, OutPointRange, PeerId, apply, async_trait_maybe_send};
use fedimint_logging::LOG_CLIENT_MODULE_STATECHAIN;
pub use fedimint_statechain_common as common;
use fedimint_statechain_common::config::{StatechainClientConfig, StatechainParams};
use fedimint_statechain_common::crypto::{
    ROTATION_CONTEXT, SECRET_CONTEXT, SignSession, SigningKey, deal_tweak, decrypt_secret,
    encrypt_secret, encryption_context, generate_nonce, rotation_tweak, verify_signature,
};
use fedimint_statechain_common::{
    CoinId, CoinRecord, CoinStatus, Funding, NonceRequest, SignRequest, SigningPurpose,
    StatechainAddress, StatechainCommonInit, StatechainInput, StatechainInputV0,
    StatechainModuleTypes, StatechainOutput, StatechainOutputV0, txs,
};
use futures::StreamExt;
use futures::future::join_all;
use rand::rngs::OsRng;
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, PublicKey, SECP256K1, SecretKey};
use serde::{Deserialize, Serialize};
use strum::IntoEnumIterator;
use tracing::{debug, info};

/// How often signing is retried with other guardians after one misbehaved
const MAX_SIGNING_ATTEMPTS: usize = 3;

/// How long we wait for the guardians to finish a consensus step, such as a
/// coin's key generation, before giving up
const CONSENSUS_STEP_TIMEOUT: Duration = Duration::from_mins(5);

/// How long a key rotation waits for every guardian to announce its ephemeral
/// key before dealing to the threshold that did
const EPHEMERAL_KEYS_GRACE_PERIOD: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositInfo {
    pub coin: CoinId,
    /// The address to fund. Build the funding transaction but only broadcast it
    /// after `fund` has signed the coin's backup transactions.
    pub address: Address<NetworkUnchecked>,
}

/// The signed transactions of a unilateral exit. The exit transaction can be
/// broadcast once the node transaction has `timelock` confirmations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitTransactions {
    pub node_tx: Transaction,
    pub exit_tx: Transaction,
    pub timelock: u16,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClaimResult {
    pub claimed: Vec<CoinId>,
    /// Coins sent to us that we could not claim, with the reason
    pub failed: BTreeMap<CoinId, String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CoinInfo {
    pub coin: CoinId,
    pub local: Option<LocalCoin>,
    pub federation: Option<CoinRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatechainOperationMeta {
    pub action: String,
    pub coin: Option<CoinId>,
}

#[derive(Debug)]
pub struct StatechainClientModule {
    cfg: StatechainClientConfig,
    client_ctx: ClientContext<Self>,
    db: Database,
    module_api: DynModuleApi,
}

#[derive(Debug, Clone)]
pub struct StatechainClientContext;

impl Context for StatechainClientContext {
    const KIND: Option<ModuleKind> = Some(fedimint_statechain_common::KIND);
}

#[apply(async_trait_maybe_send!)]
impl ClientModule for StatechainClientModule {
    type Init = StatechainClientInit;
    type Common = StatechainModuleTypes;
    type Backup = NoModuleBackup;
    type ModuleStateMachineContext = StatechainClientContext;
    type States = StatechainStateMachine;

    fn context(&self) -> Self::ModuleStateMachineContext {
        StatechainClientContext
    }

    fn input_fee(
        &self,
        _amount: &Amounts,
        _input: &<Self::Common as ModuleCommon>::Input,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    fn output_fee(
        &self,
        _amount: &Amounts,
        _output: &<Self::Common as ModuleCommon>::Output,
    ) -> Option<Amounts> {
        Some(Amounts::ZERO)
    }

    #[cfg(feature = "cli")]
    async fn handle_cli_command(
        &self,
        args: &[std::ffi::OsString],
    ) -> Result<serde_json::Value, fedimint_client_module::error::ClientModuleError> {
        cli::handle_cli_command(self, args)
            .await
            .map_err(fedimint_client_module::error::ClientModuleError::other)
    }

    async fn get_balance(&self, _dbtx: &mut DatabaseTransaction<'_>, _unit: AmountUnit) -> Amount {
        // Statecoins are bitcoin UTXOs, not e-cash, and do not count towards
        // the federation balance.
        Amount::ZERO
    }
}

impl StatechainClientModule {
    pub fn params(&self) -> &StatechainParams {
        &self.cfg.params
    }

    fn threshold(&self) -> usize {
        self.module_api.all_peers().to_num_peers().threshold()
    }

    /// The consensus block count, which trails the chain tip by
    /// [`fedimint_statechain_common::BLOCK_COUNT_VOTE_DELAY`] blocks
    pub async fn block_count(&self) -> anyhow::Result<u64> {
        Ok(self.module_api.block_count().await?)
    }

    /// Creates a coin: the guardians generate its operator key and we learn
    /// the address to fund. Our exit transactions will pay to `exit_address`.
    pub async fn deposit(
        &self,
        exit_address: Address<NetworkUnchecked>,
    ) -> anyhow::Result<DepositInfo> {
        let exit_script = exit_address
            .require_network(self.params().network)?
            .script_pubkey();

        let user_sk = SecretKey::new(&mut OsRng);

        let range = self
            .submit(
                "deposit",
                None,
                Vec::new(),
                vec![StatechainOutputV0::Deposit {
                    user_pk: user_sk.public_key(SECP256K1),
                }],
            )
            .await?;

        // Our outputs precede any change outputs the primary module adds, so
        // the deposit is the transaction's first output.
        let coin = CoinId(fedimint_core::OutPoint {
            txid: range.txid(),
            out_idx: 0,
        });

        self.save_coin(
            coin,
            &LocalCoin {
                user_sk,
                exit_script,
                aggregate_pk: None,
                funding: None,
                level: 0,
                node_signature: None,
                exit_signature: None,
                state: LocalCoinState::Owned,
            },
        )
        .await;

        info!(target: LOG_CLIENT_MODULE_STATECHAIN, %coin, "Waiting for the guardians to generate the coin's key");

        let record = self
            .await_coin(coin, |record| record.status != CoinStatus::KeyGen)
            .await?;

        let aggregate_pk = record.aggregate_pk().context("The key generation failed")?;

        self.update_coin(coin, |local| local.aggregate_pk = Some(aggregate_pk))
            .await?;

        Ok(DepositInfo {
            coin,
            address: Address::from_script(&txs::coin_script(aggregate_pk), self.params().network)?
                .into_unchecked(),
        })
    }

    /// Registers the not yet broadcast `funding_tx` for a coin and co-signs
    /// the coin's node and exit transactions with the guardians. Only broadcast
    /// `funding_tx` once this returns: from then on the exit transactions can
    /// recover the funds without the guardians.
    pub async fn fund(&self, coin: CoinId, funding_tx: &Transaction) -> anyhow::Result<Funding> {
        let local = self.owned_coin(coin).await?;

        // A non-segwit input lets anyone change the funding txid before it
        // confirms, which would invalidate the pre-signed backups.
        ensure!(
            funding_tx
                .input
                .iter()
                .all(|input| input.script_sig.is_empty()),
            "Every input of the funding transaction must be a native segwit input"
        );

        let record = self.coin_record(coin).await?;
        let coin_script = record.coin_script().context("The coin has no key yet")?;

        let (vout, tx_out) = funding_tx
            .output
            .iter()
            .enumerate()
            .find(|(_, tx_out)| tx_out.script_pubkey == coin_script)
            .context("The funding transaction does not pay to the coin's address")?;

        let funding = Funding {
            outpoint: bitcoin::OutPoint {
                txid: funding_tx.compute_txid(),
                vout: u32::try_from(vout).expect("Bitcoin limits the output count"),
            },
            amount: tx_out.value,
        };

        match record.status {
            CoinStatus::AwaitingFunding => {
                self.submit(
                    "register-funding",
                    Some(coin),
                    vec![(
                        StatechainInputV0::RegisterFunding {
                            coin,
                            funding,
                            exit_script: local.exit_script.clone(),
                        },
                        local.user_sk,
                    )],
                    Vec::new(),
                )
                .await?;
            }
            // Resuming after an interruption
            _ if record.funding == Some(funding) => {}
            _ => bail!("The coin is already funded"),
        }

        let record = self.coin_record(coin).await?;

        let node_signature = self
            .sign(coin, &record, &local.user_sk, SigningPurpose::Node)
            .await?;

        let exit_signature = self
            .sign(
                coin,
                &record,
                &local.user_sk,
                SigningPurpose::Exit { level: 0 },
            )
            .await?;

        self.update_coin(coin, |local| {
            local.funding = Some(funding);
            local.node_signature = Some(node_signature);
            local.exit_signature = Some(exit_signature);
        })
        .await?;

        Ok(funding)
    }

    /// Waits until the federation has seen a coin's funding transaction become
    /// final and returns the coin's status.
    pub async fn await_deposit(&self, coin: CoinId) -> anyhow::Result<CoinStatus> {
        loop {
            let record = self.coin_record(coin).await?;

            match record.status {
                CoinStatus::KeyGen | CoinStatus::AwaitingFunding | CoinStatus::Unconfirmed => {
                    sleep(Duration::from_secs(1)).await;
                }
                status => return Ok(status),
            }
        }
    }

    /// Creates a statechain address for receiving coins whose exit
    /// transactions pay to `exit_address`.
    pub async fn receive_address(
        &self,
        exit_address: Address<NetworkUnchecked>,
    ) -> anyhow::Result<StatechainAddress> {
        let exit_script = exit_address
            .require_network(self.params().network)?
            .script_pubkey();

        let sk = SecretKey::new(&mut OsRng);
        let pubkey = sk.public_key(SECP256K1);

        let mut dbtx = self.db.begin_transaction().await;

        dbtx.insert_new_entry(
            &ReceiveKeyKey(pubkey),
            &ReceiveKey {
                sk,
                exit_script: exit_script.clone(),
            },
        )
        .await;

        dbtx.commit_tx().await;

        Ok(StatechainAddress {
            pubkey,
            exit_script,
        })
    }

    /// Sends a coin: locks it to `receiver`, co-signs the receiver's exit
    /// transaction, which has a shorter timelock than ours, and hands the coin
    /// key to an intermediate key only the receiver can decrypt.
    pub async fn send(&self, coin: CoinId, receiver: StatechainAddress) -> anyhow::Result<()> {
        let local = self.owned_coin(coin).await?;
        let record = self.coin_record(coin).await?;

        ensure!(
            record.user_pk == local.user_sk.public_key(SECP256K1),
            "The federation does not consider us the owner of this coin"
        );

        let node_signature = local
            .node_signature
            .context("We do not have the coin's node transaction signature")?;

        match &record.status {
            CoinStatus::Active => {
                self.submit(
                    "send",
                    Some(coin),
                    vec![(
                        StatechainInputV0::Send {
                            coin,
                            receiver: receiver.clone(),
                        },
                        local.user_sk,
                    )],
                    Vec::new(),
                )
                .await?;
            }
            // Resuming after an interruption
            CoinStatus::SendPending { receiver: pending } if *pending == receiver => {}
            status => bail!("The coin cannot be sent in its current state: {status:?}"),
        }

        let record = self.coin_record(coin).await?;
        let receiver_level = record.level + 1;

        let exit_signature = self
            .sign(
                coin,
                &record,
                &local.user_sk,
                SigningPurpose::Exit {
                    level: receiver_level,
                },
            )
            .await?;

        let intermediate_sk = SecretKey::new(&mut OsRng);

        let encrypted_secret = encrypt_secret(
            &encryption_context(coin, u64::from(receiver_level), SECRET_CONTEXT),
            &receiver.pubkey,
            &intermediate_sk,
            &mut OsRng,
        );

        self.rotate(coin, &local.user_sk, &intermediate_sk, |tweak| {
            StatechainInputV0::CompleteSend {
                coin,
                node_signature,
                exit_signature,
                intermediate_pk: intermediate_sk.public_key(SECP256K1),
                tweak,
                encrypted_secret,
            }
        })
        .await?;

        self.update_coin(coin, |local| {
            local.state = LocalCoinState::Sent { receiver }
        })
        .await?;

        Ok(())
    }

    /// Claims every coin sent to one of our statechain addresses. A coin that
    /// cannot be claimed is reported without stopping the others.
    pub async fn claim(&self) -> anyhow::Result<ClaimResult> {
        let receive_keys = self
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&ReceiveKeyPrefix)
            .await
            .map(|(key, receive_key)| (key.0, receive_key))
            .collect::<Vec<(PublicKey, ReceiveKey)>>()
            .await;

        let mut result = ClaimResult::default();

        for (pubkey, receive_key) in receive_keys {
            for coin in self.module_api.incoming(pubkey).await? {
                match self.claim_coin(coin, &receive_key).await {
                    Ok(()) => result.claimed.push(coin),
                    Err(err) => {
                        info!(
                            target: LOG_CLIENT_MODULE_STATECHAIN,
                            %coin,
                            err = %err.fmt_compact(),
                            "Could not claim statecoin"
                        );

                        result.failed.insert(coin, format!("{err:#}"));
                    }
                }
            }
        }

        Ok(result)
    }

    async fn claim_coin(&self, coin: CoinId, receive_key: &ReceiveKey) -> anyhow::Result<()> {
        let record = self.coin_record(coin).await?;

        let CoinStatus::AwaitingClaim {
            receiver,
            encrypted_secret,
        } = &record.status
        else {
            bail!("Coin {coin} is not awaiting a claim");
        };

        ensure!(receiver.pubkey == receive_key.sk.public_key(SECP256K1));
        ensure!(record.exit_script.as_ref() == Some(&receive_key.exit_script));

        let intermediate_sk = decrypt_secret(
            &encryption_context(coin, u64::from(record.level), SECRET_CONTEXT),
            encrypted_secret,
            &receive_key.sk,
        )
        .filter(|sk| sk.public_key(SECP256K1) == record.user_pk)
        .context("The sender's intermediate key does not decrypt to the coin's user key")?;

        // The published backups must let us exit before every previous owner.
        let aggregate_pk = record.aggregate_pk().context("The coin has no key")?;
        let node_signature = record.node_signature.context("No node signature")?;
        let exit_signature = record.exit_signature.context("No exit signature")?;

        for (purpose, signature) in [
            (SigningPurpose::Node, node_signature),
            (
                SigningPurpose::Exit {
                    level: record.level,
                },
                exit_signature,
            ),
        ] {
            let message = record.signing_tx(self.params(), purpose)?.sighash();

            ensure!(
                verify_signature(&aggregate_pk, &message, &signature),
                "The coin's published backup signatures are invalid"
            );
        }

        self.rotate(coin, &intermediate_sk, &receive_key.sk, |tweak| {
            StatechainInputV0::Claim { coin, tweak }
        })
        .await?;

        self.save_coin(
            coin,
            &LocalCoin {
                user_sk: receive_key.sk,
                exit_script: receive_key.exit_script.clone(),
                aggregate_pk: Some(aggregate_pk),
                funding: record.funding,
                level: record.level,
                node_signature: Some(node_signature),
                exit_signature: Some(exit_signature),
                state: LocalCoinState::Owned,
            },
        )
        .await;

        info!(target: LOG_CLIENT_MODULE_STATECHAIN, %coin, "Claimed statecoin");

        Ok(())
    }

    /// Cooperatively pegs a coin out to `address`, paying `fee` from the coin's
    /// value. The guardians broadcast the signed transaction.
    pub async fn peg_out(
        &self,
        coin: CoinId,
        address: Address<NetworkUnchecked>,
        fee: bitcoin::Amount,
    ) -> anyhow::Result<Transaction> {
        let destination = address
            .require_network(self.params().network)?
            .script_pubkey();

        let local = self.owned_coin(coin).await?;
        let record = self.coin_record(coin).await?;

        match &record.status {
            CoinStatus::Active => {
                self.submit(
                    "peg-out",
                    Some(coin),
                    vec![(
                        StatechainInputV0::PegOut {
                            coin,
                            destination: destination.clone(),
                            fee,
                        },
                        local.user_sk,
                    )],
                    Vec::new(),
                )
                .await?;
            }
            // Resuming after an interruption
            CoinStatus::PegOutPending {
                destination: pending_destination,
                fee: pending_fee,
            } if *pending_destination == destination && *pending_fee == fee => {}
            status => bail!("The coin cannot be pegged out in its current state: {status:?}"),
        }

        let record = self.coin_record(coin).await?;

        let signature = self
            .sign(coin, &record, &local.user_sk, SigningPurpose::PegOut)
            .await?;

        self.submit(
            "complete-peg-out",
            Some(coin),
            vec![(
                StatechainInputV0::CompletePegOut { coin, signature },
                local.user_sk,
            )],
            Vec::new(),
        )
        .await?;

        let tx = txs::with_signature(
            record.signing_tx(self.params(), SigningPurpose::PegOut)?.tx,
            &signature,
        );

        let txid = tx.compute_txid();

        self.update_coin(coin, |local| {
            local.state = LocalCoinState::PeggedOut { txid }
        })
        .await?;

        Ok(tx)
    }

    /// The signed node and exit transactions of a coin we own, built from local
    /// data only so that an exit never depends on the guardians.
    pub async fn exit_transactions(&self, coin: CoinId) -> anyhow::Result<ExitTransactions> {
        let local = self.owned_coin(coin).await?;

        let aggregate_pk = local.aggregate_pk.context("The coin has no key yet")?;
        let funding = local.funding.context("The coin is not funded")?;
        let node_signature = local.node_signature.context("No node signature")?;
        let exit_signature = local.exit_signature.context("No exit signature")?;

        let timelock = self
            .params()
            .exit_timelock(local.level)
            .context("The coin's exit timelock is exhausted")?;

        let coin_script = txs::coin_script(aggregate_pk);

        let node_tx = txs::node_tx(funding, coin_script.clone(), self.params().node_tx_fee)
            .context("The coin cannot cover the node transaction fee")?;

        let exit_tx = txs::exit_tx(
            &node_tx,
            timelock,
            local.exit_script.clone(),
            self.params().exit_tx_fee,
        )
        .context("The coin cannot cover the exit transaction fee")?;

        let node_prevout = bitcoin::TxOut {
            value: funding.amount,
            script_pubkey: coin_script,
        };

        ensure!(
            verify_signature(
                &aggregate_pk,
                &txs::key_spend_sighash(&node_tx, &node_prevout),
                &node_signature
            ),
            "Our node transaction signature is invalid"
        );

        ensure!(
            verify_signature(
                &aggregate_pk,
                &txs::key_spend_sighash(&exit_tx, &node_tx.output[0]),
                &exit_signature
            ),
            "Our exit transaction signature is invalid"
        );

        Ok(ExitTransactions {
            node_tx: txs::with_signature(node_tx, &node_signature),
            exit_tx: txs::with_signature(exit_tx, &exit_signature),
            timelock,
        })
    }

    /// Our view and the federation's view of a coin
    pub async fn coin_info(&self, coin: CoinId) -> anyhow::Result<CoinInfo> {
        Ok(CoinInfo {
            coin,
            local: self.local_coin(coin).await,
            federation: self.module_api.coin(coin).await?,
        })
    }

    /// The coins we hold or held, with the federation's view of each
    pub async fn list_coins(&self) -> anyhow::Result<Vec<CoinInfo>> {
        let coins = self
            .db
            .begin_transaction_nc()
            .await
            .find_by_prefix(&LocalCoinPrefix)
            .await
            .map(|(key, _)| key.0)
            .collect::<Vec<CoinId>>()
            .await;

        let mut infos = Vec::new();

        for coin in coins {
            infos.push(self.coin_info(coin).await?);
        }

        Ok(infos)
    }

    /// Runs a FROST signing session over `purpose` as its coordinator: collects
    /// nonces from a threshold of guardians, verifies each guardian's signature
    /// share and adds ours. Guardians that misbehave are left out of retries.
    async fn sign(
        &self,
        coin: CoinId,
        record: &CoinRecord,
        user_sk: &SecretKey,
        purpose: SigningPurpose,
    ) -> anyhow::Result<Signature> {
        ensure!(
            record.user_pk == user_sk.public_key(SECP256K1),
            "We do not hold the coin's current user key"
        );

        let aggregate_pk = record.aggregate_pk().context("The coin has no key yet")?;
        let message = record.signing_tx(self.params(), purpose)?.sighash();
        let key = SigningKey::new(&aggregate_pk);

        let mut excluded = BTreeSet::new();

        for attempt in 0..MAX_SIGNING_ATTEMPTS {
            let session = rand::random::<[u8; 32]>();

            let nonce_responses = join_all(
                record
                    .signers
                    .iter()
                    .filter(|peer| !excluded.contains(*peer))
                    .map(|peer| async move {
                        let response = self
                            .module_api
                            .nonce(*peer, NonceRequest::new(coin, session, purpose, user_sk))
                            .await;

                        (*peer, response)
                    }),
            )
            .await;

            let guardian_nonces = nonce_responses
                .into_iter()
                .filter_map(|(peer, response)| response.ok().map(|nonce| (peer, nonce)))
                .take(self.threshold())
                .collect::<BTreeMap<PeerId, _>>();

            ensure!(
                guardian_nonces.len() == self.threshold(),
                "Not enough guardians are available to sign"
            );

            let (user_secret_nonce, user_nonce) = generate_nonce(&mut OsRng);

            let sign_session = SignSession::new(key, message, &guardian_nonces, user_nonce);

            let request = SignRequest {
                coin,
                session,
                purpose,
                guardian_nonces: guardian_nonces.clone(),
                user_nonce,
            };

            let share_responses = join_all(guardian_nonces.keys().map(|peer| {
                let request = request.clone();

                async move { (*peer, self.module_api.sign(*peer, request).await) }
            }))
            .await;

            let mut shares = Vec::new();

            for (peer, response) in share_responses {
                match response {
                    Ok(share)
                        if sign_session.verify_guardian_share(
                            peer,
                            &record.operator_poly,
                            share,
                        ) =>
                    {
                        shares.push(share);
                    }
                    response => {
                        debug!(
                            target: LOG_CLIENT_MODULE_STATECHAIN,
                            %peer,
                            attempt,
                            error = ?response.err(),
                            "Guardian did not provide a valid signature share"
                        );

                        excluded.insert(peer);
                    }
                }
            }

            if shares.len() != self.threshold() {
                continue;
            }

            shares.push(sign_session.user_sign(user_sk, &user_secret_nonce));

            let signature = sign_session
                .combine(shares)
                .context("Invalid signature encoding")?;

            ensure!(
                verify_signature(&aggregate_pk, &message, &signature),
                "The combined signature is invalid"
            );

            return Ok(signature);
        }

        Err(anyhow!(
            "Signing failed after {MAX_SIGNING_ATTEMPTS} attempts"
        ))
    }

    /// Hands a coin's user key from `old_sk` to `new_sk` by dealing the tweak
    /// to the guardians' ephemeral keys in the input `make_input` builds,
    /// which is authorized by the key the federation expects for it.
    async fn rotate(
        &self,
        coin: CoinId,
        old_sk: &SecretKey,
        new_sk: &SecretKey,
        make_input: impl Fn(fedimint_statechain_common::TweakDeal) -> StatechainInputV0,
    ) -> anyhow::Result<()> {
        let tweak =
            rotation_tweak(old_sk, new_sk).context("The new user key equals the old one")?;

        let mut last_error = None;

        for _ in 0..MAX_SIGNING_ATTEMPTS {
            let record = self.coin_record(coin).await?;
            let ephemeral_keys = self.await_ephemeral_keys(coin, &record).await?;

            let deal = deal_tweak(
                &tweak,
                self.threshold(),
                &ephemeral_keys,
                &encryption_context(coin, record.epoch, ROTATION_CONTEXT),
                &mut OsRng,
            );

            let input = make_input(deal);

            let authorizing_sk = match &input {
                StatechainInputV0::Claim { .. } => new_sk,
                _ => old_sk,
            };

            match self
                .submit(
                    "rotate",
                    Some(coin),
                    vec![(input, *authorizing_sk)],
                    Vec::new(),
                )
                .await
            {
                Ok(_) => return Ok(()),
                // A guardian announcing its key after we fetched them rejects the
                // deal; fetch the keys again.
                Err(err) => last_error = Some(err),
            }
        }

        Err(last_error.expect("We attempted at least once"))
    }

    /// The ephemeral keys of the coin's current epoch. Waits for every signer
    /// to announce one for a grace period, then settles for a threshold.
    async fn await_ephemeral_keys(
        &self,
        coin: CoinId,
        record: &CoinRecord,
    ) -> anyhow::Result<BTreeMap<PeerId, PublicKey>> {
        let start = fedimint_core::time::now();

        loop {
            let keys = self.module_api.ephemeral_keys(coin).await?;

            let waited = fedimint_core::time::now()
                .duration_since(start)
                .unwrap_or_default();

            if keys.len() == record.signers.len()
                || (keys.len() >= self.threshold() && waited > EPHEMERAL_KEYS_GRACE_PERIOD)
            {
                return Ok(keys);
            }

            ensure!(
                waited < CONSENSUS_STEP_TIMEOUT,
                "The guardians did not announce their ephemeral keys"
            );

            sleep(Duration::from_millis(500)).await;
        }
    }

    /// Submits a transaction of statechain inputs and outputs and waits for
    /// the federation to accept it.
    async fn submit(
        &self,
        action: &str,
        coin: Option<CoinId>,
        inputs: Vec<(StatechainInputV0, SecretKey)>,
        outputs: Vec<StatechainOutputV0>,
    ) -> anyhow::Result<OutPointRange> {
        let operation_id = OperationId::new_random();

        let mut tx_builder = TransactionBuilder::new();

        if !inputs.is_empty() {
            let inputs = inputs
                .into_iter()
                .map(|(input, sk)| ClientInput {
                    input: StatechainInput::V0(input),
                    keys: vec![Keypair::from_secret_key(SECP256K1, &sk)],
                    amounts: Amounts::ZERO,
                })
                .collect();

            tx_builder = tx_builder.with_inputs(
                self.client_ctx
                    .make_client_inputs(ClientInputBundle::new_no_sm(inputs)),
            );
        }

        if !outputs.is_empty() {
            let outputs = outputs
                .into_iter()
                .map(|output| ClientOutput {
                    output: StatechainOutput::V0(output),
                    amounts: Amounts::ZERO,
                })
                .collect();

            tx_builder = tx_builder.with_outputs(
                self.client_ctx
                    .make_client_outputs(ClientOutputBundle::new_no_sm(outputs)),
            );
        }

        let meta = StatechainOperationMeta {
            action: action.to_string(),
            coin,
        };

        let range = self
            .client_ctx
            .finalize_and_submit_transaction(
                operation_id,
                StatechainCommonInit::KIND.as_str(),
                move |_| meta.clone(),
                tx_builder,
            )
            .await?;

        self.client_ctx
            .transaction_updates(operation_id)
            .await
            .await_tx_accepted(range.txid())
            .await
            .map_err(|err| anyhow!("The federation rejected the {action} transaction: {err}"))?;

        Ok(range)
    }

    async fn coin_record(&self, coin: CoinId) -> anyhow::Result<CoinRecord> {
        self.module_api
            .coin(coin)
            .await?
            .with_context(|| format!("The federation does not know coin {coin}"))
    }

    async fn await_coin(
        &self,
        coin: CoinId,
        condition: impl Fn(&CoinRecord) -> bool,
    ) -> anyhow::Result<CoinRecord> {
        let start = fedimint_core::time::now();

        loop {
            if let Some(record) = self.module_api.coin(coin).await?
                && condition(&record)
            {
                return Ok(record);
            }

            ensure!(
                fedimint_core::time::now()
                    .duration_since(start)
                    .unwrap_or_default()
                    < CONSENSUS_STEP_TIMEOUT,
                "Timed out waiting for the guardians"
            );

            sleep(Duration::from_millis(500)).await;
        }
    }

    async fn local_coin(&self, coin: CoinId) -> Option<LocalCoin> {
        self.db
            .begin_transaction_nc()
            .await
            .get_value(&LocalCoinKey(coin))
            .await
    }

    async fn owned_coin(&self, coin: CoinId) -> anyhow::Result<LocalCoin> {
        let local = self
            .local_coin(coin)
            .await
            .with_context(|| format!("We do not hold coin {coin}"))?;

        ensure!(
            local.state == LocalCoinState::Owned,
            "We no longer own coin {coin}"
        );

        Ok(local)
    }

    async fn save_coin(&self, coin: CoinId, local: &LocalCoin) {
        let mut dbtx = self.db.begin_transaction().await;

        dbtx.insert_entry(&LocalCoinKey(coin), local).await;

        dbtx.commit_tx().await;
    }

    async fn update_coin(
        &self,
        coin: CoinId,
        update: impl FnOnce(&mut LocalCoin),
    ) -> anyhow::Result<()> {
        let mut local = self
            .local_coin(coin)
            .await
            .with_context(|| format!("We do not hold coin {coin}"))?;

        update(&mut local);

        self.save_coin(coin, &local).await;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct StatechainClientInit;

impl ModuleInit for StatechainClientInit {
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
                    fedimint_core::push_db_pair_items!(
                        dbtx,
                        LocalCoinPrefix,
                        LocalCoinKey,
                        LocalCoin,
                        items,
                        "Coins"
                    );
                }
                DbKeyPrefix::ReceiveKey => {
                    fedimint_core::push_db_pair_items!(
                        dbtx,
                        ReceiveKeyPrefix,
                        ReceiveKeyKey,
                        ReceiveKey,
                        items,
                        "Receive Keys"
                    );
                }
            }
        }

        Box::new(items.into_iter())
    }
}

#[apply(async_trait_maybe_send!)]
impl ClientModuleInit for StatechainClientInit {
    type Module = StatechainClientModule;

    fn supported_api_versions(&self) -> MultiApiVersion {
        MultiApiVersion::try_from_iter([ApiVersion { major: 0, minor: 0 }])
            .expect("no version conflicts")
    }

    async fn init(
        &self,
        args: &ClientModuleInitArgs<Self>,
    ) -> Result<Self::Module, fedimint_client_module::error::ClientModuleError> {
        Ok(StatechainClientModule {
            cfg: args.cfg().clone(),
            client_ctx: args.context(),
            db: args.db().clone(),
            module_api: args.module_api().clone(),
        })
    }

    fn get_database_migrations(&self) -> BTreeMap<DatabaseVersion, ClientModuleMigrationFn> {
        BTreeMap::new()
    }
}

/// The module drives its operations directly instead of through state
/// machines, so it has none.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Decodable, Encodable)]
pub enum StatechainStateMachine {}

impl State for StatechainStateMachine {
    type ModuleContext = StatechainClientContext;

    fn transitions(
        &self,
        _context: &Self::ModuleContext,
        _global_context: &DynGlobalClientContext,
    ) -> Vec<StateTransition<Self>> {
        match *self {}
    }

    fn operation_id(&self) -> OperationId {
        match *self {}
    }
}

impl IntoDynInstance for StatechainStateMachine {
    type DynType = DynState;

    fn into_dyn(self, instance_id: ModuleInstanceId) -> Self::DynType {
        DynState::from_typed(instance_id, self)
    }
}
