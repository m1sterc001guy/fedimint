use bitcoin::ScriptBuf;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use fedimint_statechain_common::{CoinId, CoinRecord, Funding, StatechainAddress};
use secp256k1::schnorr::Signature;
use secp256k1::{PublicKey, SecretKey};
use serde::Serialize;
use strum_macros::EnumIter;

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Coin = 0x01,
    ReceiveKey = 0x02,
    LastCoinRecord = 0x03,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Everything needed to exit a coin unilaterally, kept locally so that an exit
/// works while the guardians are unreachable.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct LocalCoin {
    /// Our half of the coin key
    #[serde(skip_serializing)]
    pub user_sk: SecretKey,
    /// Where our exit transaction pays to
    pub exit_script: ScriptBuf,
    /// The coin's aggregate key, once its operator key exists
    pub aggregate_pk: Option<PublicKey>,
    pub funding: Option<Funding>,
    /// Our exit level, which determines our exit timelock
    pub level: u16,
    pub node_signature: Option<Signature>,
    pub exit_signature: Option<Signature>,
    pub state: LocalCoinState,
}

#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub enum LocalCoinState {
    /// We own the coin
    Owned,
    /// We sent the coin to `receiver`
    Sent { receiver: StatechainAddress },
    /// We pegged the coin out with the transaction `txid`
    PeggedOut { txid: bitcoin::Txid },
}

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct LocalCoinKey(pub CoinId);

#[derive(Debug, Encodable, Decodable)]
pub struct LocalCoinPrefix;

impl_db_record!(
    key = LocalCoinKey,
    value = LocalCoin,
    db_prefix = DbKeyPrefix::Coin,
);
impl_db_lookup!(key = LocalCoinKey, query_prefix = LocalCoinPrefix);

/// A key we handed out in a statechain address to receive coins.
#[derive(Debug, Clone, Eq, PartialEq, Encodable, Decodable, Serialize)]
pub struct ReceiveKey {
    #[serde(skip_serializing)]
    pub sk: SecretKey,
    pub exit_script: ScriptBuf,
}

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct ReceiveKeyKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct ReceiveKeyPrefix;

impl_db_record!(
    key = ReceiveKeyKey,
    value = ReceiveKey,
    db_prefix = DbKeyPrefix::ReceiveKey,
);
impl_db_lookup!(key = ReceiveKeyKey, query_prefix = ReceiveKeyPrefix);

/// The last record of a coin we fetched from the guardians, shown while they
/// are unreachable.
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct LastCoinRecordKey(pub CoinId);

#[derive(Debug, Encodable, Decodable)]
pub struct LastCoinRecordPrefix;

impl_db_record!(
    key = LastCoinRecordKey,
    value = CoinRecord,
    db_prefix = DbKeyPrefix::LastCoinRecord,
);
impl_db_lookup!(key = LastCoinRecordKey, query_prefix = LastCoinRecordPrefix);
