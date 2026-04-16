use bitcoin::{TxOut, Txid};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{PeerId, impl_db_lookup, impl_db_record};
use fedimint_walletv2_common::TxInfo;
use secp256k1::ecdsa::Signature;
use secp256k1::schnorr;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::frost::{FrostSignatureShare, FrostSigningCommitments, FrostSigningNonces};
use crate::{FederationTx, FederationWallet};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Output = 0x30,
    SpentOutput = 0x31,
    BlockCountVote = 0x32,
    FeeRateVote = 0x33,
    TxLog = 0x34,
    TxInfoIndex = 0x35,
    UnsignedTx = 0x36,
    Signatures = 0x37,
    UnconfirmedTx = 0x38,
    FederationWallet = 0x39,
    SchnorrSignatures = 0x3a,
    FrostNoncePool = 0x3b,
    FrostCommitmentPool = 0x3c,
    FrostPoolSize = 0x3d,
    FrostPoolCursor = 0x3e,
    FrostAllocation = 0x3f,
    FrostShares = 0x40,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct OutputKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct OutputPrefix;

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct Output(pub bitcoin::OutPoint, pub TxOut);

impl_db_record!(
    key = OutputKey,
    value = Output,
    db_prefix = DbKeyPrefix::Output,
);

impl_db_lookup!(key = OutputKey, query_prefix = OutputPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct SpentOutputKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SpentOutputPrefix;

impl_db_record!(
    key = SpentOutputKey,
    value = (),
    db_prefix = DbKeyPrefix::SpentOutput
);

impl_db_lookup!(key = SpentOutputKey, query_prefix = SpentOutputPrefix);

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct FederationWalletPrefix;

#[derive(Clone, Debug, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct FederationWalletKey;

impl_db_record!(
    key = FederationWalletKey,
    value = FederationWallet,
    db_prefix = DbKeyPrefix::FederationWallet,
);

impl_db_lookup!(
    key = FederationWalletKey,
    query_prefix = FederationWalletPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct TxInfoKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TxInfoPrefix;

impl_db_record!(
    key = TxInfoKey,
    value = TxInfo,
    db_prefix = DbKeyPrefix::TxLog,
);

impl_db_lookup!(key = TxInfoKey, query_prefix = TxInfoPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct TxInfoIndexKey(pub fedimint_core::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct TxInfoIndexPrefix;

impl_db_record!(
    key = TxInfoIndexKey,
    value = u64,
    db_prefix = DbKeyPrefix::TxInfoIndex,
);

impl_db_lookup!(key = TxInfoIndexKey, query_prefix = TxInfoIndexPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTxKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTxPrefix;

impl_db_record!(
    key = UnsignedTxKey,
    value = FederationTx,
    db_prefix = DbKeyPrefix::UnsignedTx,
);

impl_db_lookup!(key = UnsignedTxKey, query_prefix = UnsignedTxPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct SignaturesKey(pub Txid, pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SignaturesTxidPrefix(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SignaturesPrefix;

impl_db_record!(
    key = SignaturesKey,
    value = Vec<Signature>,
    db_prefix = DbKeyPrefix::Signatures,
);

impl_db_lookup!(key = SignaturesKey, query_prefix = SignaturesTxidPrefix);

impl_db_lookup!(key = SignaturesKey, query_prefix = SignaturesPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct SchnorrSignaturesKey(pub Txid, pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SchnorrSignaturesTxidPrefix(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct SchnorrSignaturesPrefix;

impl_db_record!(
    key = SchnorrSignaturesKey,
    value = Vec<schnorr::Signature>,
    db_prefix = DbKeyPrefix::SchnorrSignatures,
);

impl_db_lookup!(
    key = SchnorrSignaturesKey,
    query_prefix = SchnorrSignaturesTxidPrefix
);

impl_db_lookup!(
    key = SchnorrSignaturesKey,
    query_prefix = SchnorrSignaturesPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnconfirmedTxKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnconfirmedTxPrefix;

impl_db_record!(
    key = UnconfirmedTxKey,
    value = FederationTx,
    db_prefix = DbKeyPrefix::UnconfirmedTx,
);

impl_db_lookup!(key = UnconfirmedTxKey, query_prefix = UnconfirmedTxPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct BlockCountVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockCountVotePrefix;

impl_db_record!(
    key = BlockCountVoteKey,
    value = u64,
    db_prefix = DbKeyPrefix::BlockCountVote
);

impl_db_lookup!(key = BlockCountVoteKey, query_prefix = BlockCountVotePrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FeeRateVoteKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FeeRateVotePrefix;

impl_db_record!(
    key = FeeRateVoteKey,
    value = Option<u64>,
    db_prefix = DbKeyPrefix::FeeRateVote
);

impl_db_lookup!(key = FeeRateVoteKey, query_prefix = FeeRateVotePrefix);

// ----- FROST signing pool -----

/// Our own FROST signing nonces, indexed by our local sequence number.
/// Must never be broadcast or leave this process.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FrostNoncePoolKey(pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostNoncePoolPrefix;

impl_db_record!(
    key = FrostNoncePoolKey,
    value = FrostSigningNonces,
    db_prefix = DbKeyPrefix::FrostNoncePool,
);

impl_db_lookup!(key = FrostNoncePoolKey, query_prefix = FrostNoncePoolPrefix);

/// Every signing peer's FROST commitments, indexed by `(peer, seq)`.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FrostCommitmentPoolKey(pub PeerId, pub u64);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostCommitmentPoolPeerPrefix(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostCommitmentPoolPrefix;

impl_db_record!(
    key = FrostCommitmentPoolKey,
    value = FrostSigningCommitments,
    db_prefix = DbKeyPrefix::FrostCommitmentPool,
);

impl_db_lookup!(
    key = FrostCommitmentPoolKey,
    query_prefix = FrostCommitmentPoolPeerPrefix
);

impl_db_lookup!(
    key = FrostCommitmentPoolKey,
    query_prefix = FrostCommitmentPoolPrefix
);

/// Cumulative number of commitments a peer has deposited into the pool.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FrostPoolSizeKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostPoolSizePrefix;

impl_db_record!(
    key = FrostPoolSizeKey,
    value = u64,
    db_prefix = DbKeyPrefix::FrostPoolSize,
);

impl_db_lookup!(key = FrostPoolSizeKey, query_prefix = FrostPoolSizePrefix);

/// Cumulative number of commitments consumed from a peer's pool by signing
/// sessions.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FrostPoolCursorKey(pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostPoolCursorPrefix;

impl_db_record!(
    key = FrostPoolCursorKey,
    value = u64,
    db_prefix = DbKeyPrefix::FrostPoolCursor,
);

impl_db_lookup!(
    key = FrostPoolCursorKey,
    query_prefix = FrostPoolCursorPrefix
);

/// Sequence numbers allocated to a specific transaction's inputs. The
/// per-peer allocation is the same for every signing peer (cursors advance
/// in lockstep on the consensus log), so a single `Vec<u64>` per txid
/// suffices.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FrostAllocationKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostAllocationPrefix;

impl_db_record!(
    key = FrostAllocationKey,
    value = Vec<u64>,
    db_prefix = DbKeyPrefix::FrostAllocation,
);

impl_db_lookup!(
    key = FrostAllocationKey,
    query_prefix = FrostAllocationPrefix
);

/// Received FROST signature shares, per-input per-peer.
#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct FrostSharesKey(pub Txid, pub PeerId);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostSharesTxidPrefix(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct FrostSharesPrefix;

impl_db_record!(
    key = FrostSharesKey,
    value = Vec<FrostSignatureShare>,
    db_prefix = DbKeyPrefix::FrostShares,
);

impl_db_lookup!(key = FrostSharesKey, query_prefix = FrostSharesTxidPrefix);

impl_db_lookup!(key = FrostSharesKey, query_prefix = FrostSharesPrefix);
