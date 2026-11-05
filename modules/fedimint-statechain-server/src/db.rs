use bitcoin::Transaction;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_statechain_common::{CoinId, CoinRecord, ScalarBytes, SigningPurpose};
use secp256k1::{PublicKey, SecretKey};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Coin = 0x40,
    OperatorShare = 0x41,
    EphemeralSecret = 0x42,
    EphemeralKey = 0x43,
    DkgContribution = 0x44,
    KeyGenCoin = 0x45,
    FundingOutpoint = 0x46,
    Incoming = 0x47,
    SigningNonce = 0x48,
    BlockCountVote = 0x49,
    PendingBroadcast = 0x4a,
    UnannouncedEphemeralKey = 0x4b,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// The federation's consensus view of every coin.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct CoinKey(pub CoinId);

#[derive(Debug, Encodable, Decodable)]
pub struct CoinPrefix;

impl_db_record!(
    key = CoinKey,
    value = CoinRecord,
    db_prefix = DbKeyPrefix::Coin,
    notify_on_modify = true,
);
impl_db_lookup!(key = CoinKey, query_prefix = CoinPrefix);

/// This guardian's share of a coin's operator key. Private, and replaced on
/// every rotation; a guardian that could not verify a dealt share has none.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct OperatorShareKey(pub CoinId);

#[derive(Debug, Encodable, Decodable)]
pub struct OperatorSharePrefix;

impl_db_record!(
    key = OperatorShareKey,
    value = ScalarBytes,
    db_prefix = DbKeyPrefix::OperatorShare,
);
impl_db_lookup!(key = OperatorShareKey, query_prefix = OperatorSharePrefix);

/// This guardian's ephemeral decryption key for a coin's epoch. Private, and
/// deleted as soon as the shares encrypted to it have been applied, so that the
/// ciphertexts kept in the consensus history become undecryptable.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct EphemeralSecretKey(pub CoinId, pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct EphemeralSecretPrefix;

impl_db_record!(
    key = EphemeralSecretKey,
    value = SecretKey,
    db_prefix = DbKeyPrefix::EphemeralSecret,
);
impl_db_lookup!(
    key = EphemeralSecretKey,
    query_prefix = EphemeralSecretPrefix
);

/// The ephemeral encryption keys the guardians announced for a coin's epoch.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct EphemeralKeyKey(pub CoinId, pub u64, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct EphemeralKeyPrefix;

#[derive(Debug, Encodable, Decodable)]
pub struct EphemeralKeyEpochPrefix(pub CoinId, pub u64);

impl_db_record!(
    key = EphemeralKeyKey,
    value = PublicKey,
    db_prefix = DbKeyPrefix::EphemeralKey,
);
impl_db_lookup!(
    key = EphemeralKeyKey,
    query_prefix = EphemeralKeyPrefix,
    query_prefix = EphemeralKeyEpochPrefix
);

/// The DKG contributions received for a coin whose key generation is running.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct DkgContributionKey(pub CoinId, pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct DkgContributionPrefix;

#[derive(Debug, Encodable, Decodable)]
pub struct DkgContributionCoinPrefix(pub CoinId);

impl_db_record!(
    key = DkgContributionKey,
    value = fedimint_statechain_common::DkgContribution,
    db_prefix = DbKeyPrefix::DkgContribution,
);
impl_db_lookup!(
    key = DkgContributionKey,
    query_prefix = DkgContributionPrefix,
    query_prefix = DkgContributionCoinPrefix
);

/// Index of the coins whose key generation is running, so proposals do not
/// have to scan every coin.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct KeyGenCoinKey(pub CoinId);

#[derive(Debug, Encodable, Decodable)]
pub struct KeyGenCoinPrefix;

impl_db_record!(
    key = KeyGenCoinKey,
    value = (),
    db_prefix = DbKeyPrefix::KeyGenCoin,
);
impl_db_lookup!(key = KeyGenCoinKey, query_prefix = KeyGenCoinPrefix);

/// Maps registered funding outputs to their coins for block scanning.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct FundingOutpointKey(pub bitcoin::OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct FundingOutpointPrefix;

impl_db_record!(
    key = FundingOutpointKey,
    value = CoinId,
    db_prefix = DbKeyPrefix::FundingOutpoint,
);
impl_db_lookup!(
    key = FundingOutpointKey,
    query_prefix = FundingOutpointPrefix
);

/// The coins waiting to be claimed by a receiver key.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct IncomingKey(pub PublicKey, pub CoinId);

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingPrefix;

#[derive(Debug, Encodable, Decodable)]
pub struct IncomingReceiverPrefix(pub PublicKey);

impl_db_record!(
    key = IncomingKey,
    value = (),
    db_prefix = DbKeyPrefix::Incoming,
);
impl_db_lookup!(
    key = IncomingKey,
    query_prefix = IncomingPrefix,
    query_prefix = IncomingReceiverPrefix
);

/// A secret FROST nonce handed out for a signing session. Removed when the
/// signature share is produced so that it can never be used twice.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct SigningNonceKey(pub CoinId, pub [u8; 32]);

#[derive(Debug, Encodable, Decodable)]
pub struct SigningNoncePrefix;

#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub struct StoredNonce {
    pub purpose: SigningPurpose,
    pub hiding: [u8; 32],
    pub binding: [u8; 32],
}

impl_db_record!(
    key = SigningNonceKey,
    value = StoredNonce,
    db_prefix = DbKeyPrefix::SigningNonce,
);
impl_db_lookup!(key = SigningNonceKey, query_prefix = SigningNoncePrefix);

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote,
);
impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

/// Signed peg-out transactions the guardians rebroadcast until they confirm.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct PendingBroadcastKey(pub bitcoin::Txid);

#[derive(Debug, Encodable, Decodable)]
pub struct PendingBroadcastPrefix;

impl_db_record!(
    key = PendingBroadcastKey,
    value = Transaction,
    db_prefix = DbKeyPrefix::PendingBroadcast,
);
impl_db_lookup!(
    key = PendingBroadcastKey,
    query_prefix = PendingBroadcastPrefix
);

/// Our ephemeral keys not yet announced in consensus, so that proposals do not
/// have to look at the ephemeral key of every coin.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct UnannouncedEphemeralKey(pub CoinId, pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct UnannouncedEphemeralKeyPrefix;

impl_db_record!(
    key = UnannouncedEphemeralKey,
    value = (),
    db_prefix = DbKeyPrefix::UnannouncedEphemeralKey,
);
impl_db_lookup!(
    key = UnannouncedEphemeralKey,
    query_prefix = UnannouncedEphemeralKeyPrefix
);
