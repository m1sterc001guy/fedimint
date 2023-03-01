use bitcoin::{BlockHash, Txid};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record};
use secp256k1::ecdsa::Signature;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::{
    PendingTransaction, RoundConsensus, SpendableUTXO, UnsignedTransaction, WalletOutputOutcome,
};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    BlockHash = 0x30,
    Utxo = 0x31,
    RoundConsensus = 0x32,
    UnsignedTransaction = 0x34,
    PendingTransaction = 0x35,
    PegOutTxSigCi = 0x36,
    PegOutBitcoinOutPoint = 0x37,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct BlockHashKey(pub BlockHash);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct BlockHashKeyPrefix;

impl_db_record!(
    key = BlockHashKey,
    value = (),
    db_prefix = DbKeyPrefix::BlockHash,
);
impl_db_lookup!(key = BlockHashKey, query_prefix = BlockHashKeyPrefix);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UTXOKey(pub bitcoin::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UTXOPrefixKey;

impl_db_record!(
    key = UTXOKey,
    value = SpendableUTXO,
    db_prefix = DbKeyPrefix::Utxo,
);
impl_db_lookup!(key = UTXOKey, query_prefix = UTXOPrefixKey);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct RoundConsensusKey;

impl_db_record!(
    key = RoundConsensusKey,
    value = RoundConsensus,
    db_prefix = DbKeyPrefix::RoundConsensus,
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct UnsignedTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct UnsignedTransactionPrefixKey;

impl_db_record!(
    key = UnsignedTransactionKey,
    value = UnsignedTransaction,
    db_prefix = DbKeyPrefix::UnsignedTransaction,
);
impl_db_lookup!(
    key = UnsignedTransactionKey,
    query_prefix = UnsignedTransactionPrefixKey
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PendingTransactionKey(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PendingTransactionPrefixKey;

impl_db_record!(
    key = PendingTransactionKey,
    value = PendingTransaction,
    db_prefix = DbKeyPrefix::PendingTransaction,
);
impl_db_lookup!(
    key = PendingTransactionKey,
    query_prefix = PendingTransactionPrefixKey
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutTxSignatureCI(pub Txid);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutTxSignatureCIPrefix;

impl_db_record!(
    key = PegOutTxSignatureCI,
    value = Vec<Signature>,
    db_prefix = DbKeyPrefix::PegOutTxSigCi,
);
impl_db_lookup!(
    key = PegOutTxSignatureCI,
    query_prefix = PegOutTxSignatureCIPrefix
);

#[derive(Clone, Debug, Encodable, Decodable, Serialize)]
pub struct PegOutBitcoinTransaction(pub fedimint_core::OutPoint);

#[derive(Clone, Debug, Encodable, Decodable)]
pub struct PegOutBitcoinTransactionPrefix;

impl_db_record!(
    key = PegOutBitcoinTransaction,
    value = WalletOutputOutcome,
    db_prefix = DbKeyPrefix::PegOutBitcoinOutPoint,
);
impl_db_lookup!(
    key = PegOutBitcoinTransaction,
    query_prefix = PegOutBitcoinTransactionPrefix
);

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::env;
    use std::path::Path;

    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_WALLET;
    use fedimint_core::db::apply_migrations;
    use fedimint_core::module::DynModuleGen;
    use fedimint_testing::apply_to_databases;
    use futures::StreamExt;
    use strum::IntoEnumIterator;

    use crate::db::{
        BlockHashKeyPrefix, DbKeyPrefix, PegOutBitcoinTransactionPrefix, PegOutTxSignatureCIPrefix,
        PendingTransactionPrefixKey, RoundConsensusKey, UTXOPrefixKey,
        UnsignedTransactionPrefixKey,
    };
    use crate::WalletGen;

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_wallet_database_migration() {
        // Only run the database migration test if the database backup directory
        // environment variable has been defined
        let backup_dir = env::var("FM_TEST_DB_BACKUP_DIR");
        if let Ok(backup_dir) = backup_dir {
            let mut migrated_values = BTreeMap::new();
            apply_to_databases(
                Path::new(&backup_dir),
                |db| async move {
                    // First apply all of the database migrations so that the data can be properly
                    // read.
                    let module = DynModuleGen::from(WalletGen);
                    let isolated_db = db.new_isolated(LEGACY_HARDCODED_INSTANCE_ID_WALLET);
                    apply_migrations(
                        &isolated_db,
                        module.module_kind().to_string(),
                        module.database_version(),
                        module.get_database_migrations(),
                    )
                    .await
                    .expect("Error applying migrations to temp database");

                    // Verify that all of the data from the wallet namespace can be read. If a
                    // database migration failed or was not properly supplied,
                    // this will fail.
                    let mut migrated_pairs: BTreeMap<u8, usize> = BTreeMap::new();
                    let mut dbtx = isolated_db.begin_transaction().await;

                    for prefix in DbKeyPrefix::iter() {
                        match prefix {
                            DbKeyPrefix::BlockHash => {
                                let blocks = dbtx
                                    .find_by_prefix(&BlockHashKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_blocks = blocks.len();
                                for block in blocks {
                                    block.expect("Error deserializing BlockHash");
                                }
                                migrated_pairs.insert(DbKeyPrefix::BlockHash as u8, num_blocks);
                            }
                            DbKeyPrefix::PegOutBitcoinOutPoint => {
                                let outpoints = dbtx
                                    .find_by_prefix(&PegOutBitcoinTransactionPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_outpoints = outpoints.len();
                                for outpoint in outpoints {
                                    outpoint.expect("Error deserializing OutPoint");
                                }
                                migrated_pairs.insert(
                                    DbKeyPrefix::PegOutBitcoinOutPoint as u8,
                                    num_outpoints,
                                );
                            }
                            DbKeyPrefix::PegOutTxSigCi => {
                                let sigs = dbtx
                                    .find_by_prefix(&PegOutTxSignatureCIPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_sigs = sigs.len();
                                for sig in sigs {
                                    sig.expect("Error deserializing PegOutTxSignatureCI");
                                }
                                migrated_pairs.insert(DbKeyPrefix::PegOutTxSigCi as u8, num_sigs);
                            }
                            DbKeyPrefix::PendingTransaction => {
                                let pending_txs = dbtx
                                    .find_by_prefix(&PendingTransactionPrefixKey)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_txs = pending_txs.len();
                                for tx in pending_txs {
                                    tx.expect("Error deserializing PendingTransaction");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::PendingTransaction as u8, num_txs);
                            }
                            DbKeyPrefix::RoundConsensus => {
                                let round = dbtx
                                    .get_value(&RoundConsensusKey)
                                    .await
                                    .expect("Error deserializing RoundConsensus");
                                migrated_pairs.insert(
                                    DbKeyPrefix::RoundConsensus as u8,
                                    round.is_some() as usize,
                                );
                            }
                            DbKeyPrefix::UnsignedTransaction => {
                                let unsigned_txs = dbtx
                                    .find_by_prefix(&UnsignedTransactionPrefixKey)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_txs = unsigned_txs.len();
                                for tx in unsigned_txs {
                                    tx.expect("Error deserializing UnsignedTransaction");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::UnsignedTransaction as u8, num_txs);
                            }
                            DbKeyPrefix::Utxo => {
                                let utxos = dbtx
                                    .find_by_prefix(&UTXOPrefixKey)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_utxos = utxos.len();
                                for utxo in utxos {
                                    utxo.expect("Error deserializing UTXO");
                                }
                                migrated_pairs.insert(DbKeyPrefix::Utxo as u8, num_utxos);
                            }
                        }
                    }

                    migrated_pairs
                },
                &mut migrated_values,
            )
            .await;

            // Verify that all records were able to be read at least once. This guarantees
            // that, over the supplied database backup directory, at least one
            // record was read per record type.
            for (_, value) in migrated_values {
                assert!(value > 0);
            }
        }
    }
}
