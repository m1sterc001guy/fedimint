#![deny(clippy::pedantic)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::similar_names)]

//! A statechain module modeled on [Spark](https://docs.spark.money).
//!
//! A statecoin is a bitcoin UTXO locked to a single taproot key that is the
//! sum of two keys: one held by the coin's current owner and one shared among
//! the guardians as a FROST `t`-of-`n` key. Spending requires both halves, so
//! the guardians can never move a coin without its owner. Ownership moves off
//! chain by re-splitting the summed key between the guardians and the new
//! owner, after which the guardians delete their old shares; the previous
//! owner's half then no longer combines to anything. Pre-signed backup
//! transactions with decreasing relative timelocks let the current owner exit
//! to bitcoin without the guardians.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::str::FromStr;

use bitcoin::hashes::Hash as _;
use bitcoin::{ScriptBuf, Transaction, TxOut};
use config::{StatechainClientConfig, StatechainParams};
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{
    OutPoint, PeerId, TransactionId, extensible_associated_module_type,
    plugin_types_trait_impl_common,
};
use secp256k1::PublicKey;
use secp256k1::schnorr::Signature;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod config;
pub mod crypto;
pub mod endpoint_constants;
pub mod txs;

pub const KIND: ModuleKind = ModuleKind::from_static_str("statechain");

pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(1, 0);

/// Number of confirmations required for a deposit or a spend of a coin's
/// funding output to be considered final by the federation. The block that
/// mines the transaction does not count towards the number of confirmations.
pub const CONFIRMATION_FINALITY_DELAY: u64 = 6;

/// How many blocks a guardian's block count vote trails its bitcoin backend:
/// the finality delay plus one block of slack, as in the walletv2 module.
pub const BLOCK_COUNT_VOTE_DELAY: u64 = CONFIRMATION_FINALITY_DELAY + 1;

/// Identifies a statecoin by the federation transaction output that created
/// it.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Ord, PartialOrd, Encodable, Decodable)]
pub struct CoinId(pub OutPoint);

// Serialized as `<txid>:<output index>`, the form the CLI accepts.
impl Serialize for CoinId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for CoinId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for CoinId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for CoinId {
    type Err = ParseCoinIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (txid, out_idx) = s.split_once(':').ok_or(ParseCoinIdError)?;

        Ok(CoinId(OutPoint {
            txid: TransactionId::from_str(txid).map_err(|_| ParseCoinIdError)?,
            out_idx: out_idx.parse().map_err(|_| ParseCoinIdError)?,
        }))
    }
}

#[derive(Debug, Error)]
#[error("A coin id has the form <txid>:<output index>")]
pub struct ParseCoinIdError;

/// A statecoin's on-chain funding output.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct Funding {
    pub outpoint: bitcoin::OutPoint,
    pub amount: bitcoin::Amount,
}

/// Where a statecoin can be sent: the receiver's half of the coin key and the
/// script its exit transaction pays to.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StatechainAddress {
    pub pubkey: PublicKey,
    pub exit_script: ScriptBuf,
}

const STATECHAIN_ADDRESS_PREFIX: &str = "statechain";

impl fmt::Display for StatechainAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{STATECHAIN_ADDRESS_PREFIX}{}",
            self.consensus_encode_to_hex()
        )
    }
}

impl FromStr for StatechainAddress {
    type Err = ParseStatechainAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s
            .strip_prefix(STATECHAIN_ADDRESS_PREFIX)
            .ok_or(ParseStatechainAddressError)?;

        Self::consensus_decode_hex(
            hex,
            &fedimint_core::module::registry::ModuleRegistry::default(),
        )
        .map_err(|_| ParseStatechainAddressError)
    }
}

#[derive(Debug, Error)]
#[error("Invalid statechain address")]
pub struct ParseStatechainAddressError;

/// A scalar in its 32 byte big-endian encoding, as used for signature shares
/// and encrypted secret shares.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ScalarBytes(pub [u8; 32]);

/// A public FROST nonce: the commitments to a signer's two secret nonces.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct PublicNonce {
    pub hiding: PublicKey,
    pub binding: PublicKey,
}

/// Secret shares encrypted to a set of guardians' ephemeral keys with one
/// shared encryption nonce.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EncryptedShares {
    pub nonce: PublicKey,
    pub ciphertexts: BTreeMap<PeerId, ScalarBytes>,
}

/// A guardian's contribution to the distributed generation of a coin's
/// operator key (`SimplePedPop` with encrypted shares).
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DkgContribution {
    /// Feldman commitments to the contributor's secret polynomial
    pub commitments: Vec<PublicKey>,
    /// Proof of possession of the polynomial's constant term
    pub proof_of_possession: Signature,
    /// One share of the polynomial for every guardian
    pub shares: EncryptedShares,
}

/// A secret-shared tweak of a coin's operator key, dealt by the owner that
/// hands the coin's user key over. Each guardian adds its share to its key
/// share, which moves the operator key by the tweak while the commitments
/// let every guardian check that its share is consistent.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct TweakDeal {
    pub commitments: Vec<PublicKey>,
    pub shares: EncryptedShares,
}

/// A secret key encrypted to a single public key.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EncryptedSecret {
    pub nonce: PublicKey,
    pub ciphertext: ScalarBytes,
}

/// The lifecycle of a statecoin as agreed by the federation.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum CoinStatus {
    /// The guardians are generating the coin's operator key.
    KeyGen,
    /// The coin's address is known; its owner has yet to register the funding
    /// output.
    AwaitingFunding,
    /// The funding output is registered but not yet final on chain.
    Unconfirmed,
    /// The coin is funded and can be transferred or pegged out.
    Active,
    /// The owner is sending the coin to `receiver` and may now co-sign the
    /// receiver's lower-timelock exit transaction.
    SendPending { receiver: StatechainAddress },
    /// The coin's user key is an intermediate key that only the sender and
    /// `receiver` know; the receiver claims the coin by rotating it to its own
    /// key.
    AwaitingClaim {
        receiver: StatechainAddress,
        encrypted_secret: EncryptedSecret,
    },
    /// The owner is cooperatively signing a peg-out transaction.
    PegOutPending {
        destination: ScriptBuf,
        fee: bitcoin::Amount,
    },
    /// The signed peg-out transaction is being broadcast by the guardians.
    PegOutBroadcast { tx: Transaction },
    /// The node transaction was mined: a unilateral exit is in progress and
    /// the coin can no longer be transferred.
    Exiting,
    /// The funding output was spent by a transaction other than the node
    /// transaction, normally the peg-out.
    Closed { txid: bitcoin::Txid },
    /// The funding output mined with a different script or amount than
    /// registered, so the pre-signed backup transactions are invalid.
    Invalid,
}

/// The federation's view of a statecoin. All of it is public.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct CoinRecord {
    /// The current owner's half of the coin key
    pub user_pk: PublicKey,
    /// Counts the coin's key generations and rotations; the guardians'
    /// ephemeral encryption keys are announced per epoch.
    pub epoch: u64,
    /// The commitments to the polynomial that shares the operator key, empty
    /// until the key generation completes. Its constant term is the operator
    /// key.
    pub operator_poly: Vec<PublicKey>,
    /// The guardians that received a share of the operator key in the last key
    /// generation or rotation
    pub signers: BTreeSet<PeerId>,
    pub funding: Option<Funding>,
    /// The script the current owner's exit transaction pays to
    pub exit_script: Option<ScriptBuf>,
    /// The current owner's exit level; see [`StatechainParams::exit_timelock`]
    pub level: u16,
    /// The node transaction's signature, published with the first transfer
    pub node_signature: Option<Signature>,
    /// The signature of the current owner's exit transaction, published when
    /// the coin was sent to it
    pub exit_signature: Option<Signature>,
    pub status: CoinStatus,
}

/// What a signing session signs. The guardians derive the transaction itself
/// from the coin's consensus state and refuse purposes the state does not
/// allow.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum SigningPurpose {
    /// The node transaction that spends the funding output and starts the exit
    /// timelocks
    Node,
    /// The exit transaction of the owner at `level`
    Exit { level: u16 },
    /// The cooperative peg-out transaction
    PegOut,
}

/// A transaction to sign together with the output it spends.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SigningTx {
    pub tx: Transaction,
    pub prevout: TxOut,
}

impl SigningTx {
    pub fn sighash(&self) -> [u8; 32] {
        txs::key_spend_sighash(&self.tx, &self.prevout)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Error)]
pub enum SigningTxError {
    #[error("The coin's operator key has not been generated yet")]
    NoOperatorKey,
    #[error("The coin's funding output has not been registered yet")]
    NotFunded,
    #[error("The coin's state does not allow signing this transaction")]
    NotAllowed,
    #[error("The exit timelocks of this coin are exhausted")]
    TimelockExhausted,
    #[error("The coin's value cannot cover the transaction fees")]
    InsufficientValue,
}

impl CoinRecord {
    /// The operator key, the constant term of the operator polynomial
    pub fn operator_pk(&self) -> Option<PublicKey> {
        self.operator_poly.first().copied()
    }

    /// The internal taproot key of the coin: user key plus operator key. It is
    /// invariant under transfers.
    pub fn aggregate_pk(&self) -> Option<PublicKey> {
        self.user_pk.combine(&self.operator_pk()?).ok()
    }

    /// The script of the coin's funding output, which the node transaction's
    /// output reuses
    pub fn coin_script(&self) -> Option<ScriptBuf> {
        self.aggregate_pk().map(txs::coin_script)
    }

    /// Builds the transaction for `purpose` if the coin's state allows signing
    /// it. Guardians enforce this when producing signature shares; clients
    /// use it to derive the same transaction.
    pub fn signing_tx(
        &self,
        params: &StatechainParams,
        purpose: SigningPurpose,
    ) -> Result<SigningTx, SigningTxError> {
        let coin_script = self.coin_script().ok_or(SigningTxError::NoOperatorKey)?;
        let funding = self.funding.ok_or(SigningTxError::NotFunded)?;

        if matches!(self.status, CoinStatus::Closed { .. } | CoinStatus::Invalid) {
            return Err(SigningTxError::NotAllowed);
        }

        let funding_prevout = TxOut {
            value: funding.amount,
            script_pubkey: coin_script.clone(),
        };

        let node_tx = txs::node_tx(funding, coin_script, params.node_tx_fee)
            .ok_or(SigningTxError::InsufficientValue)?;

        match purpose {
            SigningPurpose::Node => Ok(SigningTx {
                tx: node_tx,
                prevout: funding_prevout,
            }),
            SigningPurpose::Exit { level } => {
                let exit_script = match &self.status {
                    CoinStatus::SendPending { receiver }
                        if Some(level) == self.level.checked_add(1) =>
                    {
                        receiver.exit_script.clone()
                    }
                    _ if level == self.level => {
                        self.exit_script.clone().ok_or(SigningTxError::NotFunded)?
                    }
                    _ => return Err(SigningTxError::NotAllowed),
                };

                let timelock = params
                    .exit_timelock(level)
                    .ok_or(SigningTxError::TimelockExhausted)?;

                let tx = txs::exit_tx(&node_tx, timelock, exit_script, params.exit_tx_fee)
                    .ok_or(SigningTxError::InsufficientValue)?;

                Ok(SigningTx {
                    tx,
                    prevout: node_tx.output[0].clone(),
                })
            }
            SigningPurpose::PegOut => {
                let CoinStatus::PegOutPending { destination, fee } = &self.status else {
                    return Err(SigningTxError::NotAllowed);
                };

                let tx = txs::pegout_tx(funding, destination.clone(), *fee)
                    .ok_or(SigningTxError::InsufficientValue)?;

                Ok(SigningTx {
                    tx,
                    prevout: funding_prevout,
                })
            }
        }
    }
}

/// Requests a fresh nonce from a guardian. The nonce is stored under `nonce_id`
/// until a signing session uses it; with ROAST a guardian's nonce is collected
/// before the session it ends up in is known. Only the coin's current user can
/// complete a signature, so only it may request nonces; the signature keeps
/// others from filling the guardians' nonce storage.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NonceRequest {
    pub coin: CoinId,
    pub nonce_id: [u8; 32],
    pub purpose: SigningPurpose,
    /// Signature of [`NonceRequest::message`] by the coin's user key
    pub signature: Signature,
}

impl NonceRequest {
    pub fn message(
        coin: CoinId,
        nonce_id: [u8; 32],
        purpose: SigningPurpose,
    ) -> secp256k1::Message {
        secp256k1::Message::from_digest(
            ("fedimint-statechain/nonce-request", coin, nonce_id, purpose)
                .consensus_hash::<bitcoin::hashes::sha256::Hash>()
                .to_byte_array(),
        )
    }

    pub fn new(
        coin: CoinId,
        nonce_id: [u8; 32],
        purpose: SigningPurpose,
        user_sk: &secp256k1::SecretKey,
    ) -> Self {
        let keypair = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, user_sk);

        Self {
            coin,
            nonce_id,
            purpose,
            signature: secp256k1::SECP256K1
                .sign_schnorr(&Self::message(coin, nonce_id, purpose), &keypair),
        }
    }

    pub fn verify(&self, user_pk: &PublicKey) -> bool {
        secp256k1::SECP256K1
            .verify_schnorr(
                &self.signature,
                &Self::message(self.coin, self.nonce_id, self.purpose),
                &user_pk.x_only_public_key().0,
            )
            .is_ok()
    }
}

/// Requests a guardian's signature share in a signing session. The nonces of
/// the participating guardians determine the signing set; `nonce_id` names the
/// receiving guardian's own nonce, which the share consumes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SignRequest {
    pub coin: CoinId,
    pub nonce_id: [u8; 32],
    pub purpose: SigningPurpose,
    pub guardian_nonces: BTreeMap<PeerId, PublicNonce>,
    pub user_nonce: PublicNonce,
}

#[derive(Debug)]
pub struct StatechainCommonInit;

impl CommonModuleInit for StatechainCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = StatechainClientConfig;

    fn decoder() -> Decoder {
        StatechainModuleTypes::decoder()
    }
}

pub struct StatechainModuleTypes;

plugin_types_trait_impl_common!(
    KIND,
    StatechainModuleTypes,
    StatechainClientConfig,
    StatechainInput,
    StatechainOutput,
    StatechainOutputOutcome,
    StatechainConsensusItem,
    StatechainInputError,
    StatechainOutputError
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum StatechainConsensusItem {
    /// A guardian's vote on the bitcoin block count
    BlockCount(u64),
    /// A guardian's ephemeral encryption key for a coin's current epoch
    EphemeralKey {
        coin: CoinId,
        epoch: u64,
        key: PublicKey,
    },
    /// A guardian's contribution to a coin's operator key generation
    DkgContribution {
        coin: CoinId,
        contribution: DkgContribution,
    },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

impl fmt::Display for StatechainConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatechainConsensusItem::BlockCount(count) => {
                write!(f, "Statechain Block Count {count}")
            }
            StatechainConsensusItem::EphemeralKey { coin, epoch, .. } => {
                write!(f, "Statechain Ephemeral Key for {coin} epoch {epoch}")
            }
            StatechainConsensusItem::DkgContribution { coin, .. } => {
                write!(f, "Statechain DKG Contribution for {coin}")
            }
            StatechainConsensusItem::Default { variant, .. } => {
                write!(f, "Unknown Statechain CI variant={variant}")
            }
        }
    }
}

extensible_associated_module_type!(
    StatechainInput,
    StatechainInputV0,
    UnknownStatechainInputVariantError
);

/// Inputs carry no value: statecoins are bitcoin UTXOs, not federation
/// e-cash. An input authorizes a change to a coin with the signature of the
/// key named in its [`fedimint_core::module::InputMeta`].
// Inputs are short-lived wire messages, so the size of the largest variant
// does not matter.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum StatechainInputV0 {
    /// Registers the (not yet broadcast) funding output and the depositor's
    /// exit script. Authorized by the coin's user key.
    RegisterFunding {
        coin: CoinId,
        funding: Funding,
        exit_script: ScriptBuf,
    },
    /// Locks the coin to `receiver`. Authorized by the coin's user key.
    Send {
        coin: CoinId,
        receiver: StatechainAddress,
    },
    /// Publishes the receiver's signed exit transaction and rotates the coin's
    /// user key to `intermediate_pk`, whose secret is encrypted to the
    /// receiver. Authorized by the coin's user key.
    CompleteSend {
        coin: CoinId,
        node_signature: Signature,
        exit_signature: Signature,
        intermediate_pk: PublicKey,
        tweak: TweakDeal,
        encrypted_secret: EncryptedSecret,
    },
    /// Rotates the coin's user key from the intermediate key to the receiver's
    /// key. Authorized by the receiver's key.
    Claim { coin: CoinId, tweak: TweakDeal },
    /// Locks the coin for a cooperative peg-out. Authorized by the coin's user
    /// key.
    PegOut {
        coin: CoinId,
        destination: ScriptBuf,
        fee: bitcoin::Amount,
    },
    /// Hands the signed peg-out transaction to the guardians for broadcast.
    /// Authorized by the coin's user key.
    CompletePegOut { coin: CoinId, signature: Signature },
}

impl StatechainInputV0 {
    pub fn coin(&self) -> CoinId {
        match self {
            StatechainInputV0::RegisterFunding { coin, .. }
            | StatechainInputV0::Send { coin, .. }
            | StatechainInputV0::CompleteSend { coin, .. }
            | StatechainInputV0::Claim { coin, .. }
            | StatechainInputV0::PegOut { coin, .. }
            | StatechainInputV0::CompletePegOut { coin, .. } => *coin,
        }
    }
}

impl fmt::Display for StatechainInputV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let action = match self {
            StatechainInputV0::RegisterFunding { .. } => "Register Funding",
            StatechainInputV0::Send { .. } => "Send",
            StatechainInputV0::CompleteSend { .. } => "Complete Send",
            StatechainInputV0::Claim { .. } => "Claim",
            StatechainInputV0::PegOut { .. } => "PegOut",
            StatechainInputV0::CompletePegOut { .. } => "Complete PegOut",
        };

        write!(f, "Statechain {action} for {}", self.coin())
    }
}

extensible_associated_module_type!(
    StatechainOutput,
    StatechainOutputV0,
    UnknownStatechainOutputVariantError
);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum StatechainOutputV0 {
    /// Creates a new coin with the given user key; the guardians then generate
    /// its operator key.
    Deposit { user_pk: PublicKey },
}

impl fmt::Display for StatechainOutputV0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatechainOutputV0::Deposit { .. } => write!(f, "Statechain Deposit"),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct StatechainOutputOutcome;

impl fmt::Display for StatechainOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "StatechainOutputOutcome")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum StatechainInputError {
    #[error("The statechain input version is not supported by this federation")]
    UnknownInputVariant(#[from] UnknownStatechainInputVariantError),
    #[error("The coin does not exist")]
    UnknownCoin,
    #[error("The coin's state does not allow this action")]
    InvalidCoinState,
    #[error("The funding output is already registered for another coin")]
    FundingAlreadyRegistered,
    #[error("The deposit is below the federation's minimum")]
    DepositTooSmall,
    #[error("The exit timelocks of this coin are exhausted; peg it out instead")]
    TimelockExhausted,
    #[error("A signature is invalid")]
    InvalidSignature,
    #[error("The tweak deal is malformed or does not match the key rotation")]
    InvalidTweak,
    #[error("The tweak deal does not match the guardians' ephemeral keys; retry")]
    EphemeralKeyMismatch,
    #[error("The transaction value cannot cover its fee")]
    InsufficientValue,
    #[error("The new user key equals the current one")]
    UnchangedUserKey,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum StatechainOutputError {
    #[error("The statechain output version is not supported by this federation")]
    UnknownOutputVariant(#[from] UnknownStatechainOutputVariantError),
}
