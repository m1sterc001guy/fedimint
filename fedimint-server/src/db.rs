use std::fmt::Debug;

use fedimint_core::db::{DatabaseVersion, MigrationMap, MODULE_GLOBAL_PREFIX};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::epoch::{SerdeSignature, SignedEpochOutcome};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId, TransactionId};
use serde::Serialize;
use strum_macros::EnumIter;

use crate::consensus::AcceptedTransaction;

pub const GLOBAL_DATABASE_VERSION: DatabaseVersion = DatabaseVersion(0);

#[repr(u8)]
#[derive(Clone, EnumIter, Debug, Ord, PartialOrd, Eq, PartialEq)]
pub enum DbKeyPrefix {
    AcceptedTransaction = 0x02,
    DropPeer = 0x03,
    RejectedTransaction = 0x04,
    EpochHistory = 0x05,
    LastEpoch = 0x06,
    ClientConfigSignature = 0x07,
    Module = MODULE_GLOBAL_PREFIX,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AcceptedTransactionKey(pub TransactionId);

#[derive(Debug, Encodable, Decodable)]
pub struct AcceptedTransactionKeyPrefix;

impl_db_record!(
    key = AcceptedTransactionKey,
    value = AcceptedTransaction,
    db_prefix = DbKeyPrefix::AcceptedTransaction,
);
impl_db_lookup!(
    key = AcceptedTransactionKey,
    query_prefix = AcceptedTransactionKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct RejectedTransactionKey(pub TransactionId);

#[derive(Debug, Encodable, Decodable)]
pub struct RejectedTransactionKeyPrefix;

impl_db_record!(
    key = RejectedTransactionKey,
    value = String,
    db_prefix = DbKeyPrefix::RejectedTransaction,
);
impl_db_lookup!(
    key = RejectedTransactionKey,
    query_prefix = RejectedTransactionKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct DropPeerKey(pub PeerId);

#[derive(Debug, Encodable, Decodable)]
pub struct DropPeerKeyPrefix;

impl_db_record!(
    key = DropPeerKey,
    value = (),
    db_prefix = DbKeyPrefix::DropPeer,
);
impl_db_lookup!(key = DropPeerKey, query_prefix = DropPeerKeyPrefix);

#[derive(Debug, Copy, Clone, Encodable, Decodable, Serialize)]
pub struct EpochHistoryKey(pub u64);

#[derive(Debug, Encodable, Decodable)]
pub struct EpochHistoryKeyPrefix;

impl_db_record!(
    key = EpochHistoryKey,
    value = SignedEpochOutcome,
    db_prefix = DbKeyPrefix::EpochHistory,
);
impl_db_lookup!(key = EpochHistoryKey, query_prefix = EpochHistoryKeyPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LastEpochKey;

impl_db_record!(
    key = LastEpochKey,
    value = EpochHistoryKey,
    db_prefix = DbKeyPrefix::LastEpoch
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ClientConfigSignatureKey;

#[derive(Debug, Encodable, Decodable)]
pub struct ClientConfigSignatureKeyPrefix;

impl_db_record!(
    key = ClientConfigSignatureKey,
    value = SerdeSignature,
    db_prefix = DbKeyPrefix::ClientConfigSignature,
);
impl_db_lookup!(
    key = ClientConfigSignatureKey,
    query_prefix = ClientConfigSignatureKeyPrefix
);

pub fn get_global_database_migrations<'a>() -> MigrationMap<'a> {
    MigrationMap::new()
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::env;
    use std::path::Path;

    use fedimint_core::db::apply_migrations;
    use fedimint_testing::apply_to_databases;
    use futures::StreamExt;
    use strum::IntoEnumIterator;

    use crate::db::{
        get_global_database_migrations, AcceptedTransactionKeyPrefix,
        ClientConfigSignatureKeyPrefix, DbKeyPrefix, DropPeerKeyPrefix, EpochHistoryKeyPrefix,
        LastEpochKey, RejectedTransactionKeyPrefix, GLOBAL_DATABASE_VERSION,
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_global_database_migration() {
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
                    apply_migrations(
                        &db,
                        "Global".to_string(),
                        GLOBAL_DATABASE_VERSION,
                        get_global_database_migrations(),
                    )
                    .await
                    .expect("Error applying migrations to temp database");

                    // Verify that all of the data from the global namespace can be read. If a
                    // database migration failed or was not properly supplied,
                    // this will fail.
                    let mut migrated_pairs: BTreeMap<u8, usize> = BTreeMap::new();
                    let mut dbtx = db.begin_transaction().await;

                    for prefix in DbKeyPrefix::iter() {
                        match prefix {
                            DbKeyPrefix::AcceptedTransaction => {
                                let accepted_transactions = dbtx
                                    .find_by_prefix(&AcceptedTransactionKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_accepted_transactions = accepted_transactions.len();
                                for tx in accepted_transactions {
                                    tx.expect("Error deserializing AcceptedTransaction");
                                }
                                migrated_pairs.insert(
                                    DbKeyPrefix::AcceptedTransaction as u8,
                                    num_accepted_transactions,
                                );
                            }
                            DbKeyPrefix::DropPeer => {
                                let dropped_peers = dbtx
                                    .find_by_prefix(&DropPeerKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_dropped_peers = dropped_peers.len();
                                for peer in dropped_peers {
                                    peer.expect("Error deserializing DroppedPeer");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::DropPeer as u8, num_dropped_peers);
                            }
                            DbKeyPrefix::RejectedTransaction => {
                                let rejected_transactions = dbtx
                                    .find_by_prefix(&RejectedTransactionKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_rejected_transactions = rejected_transactions.len();
                                for tx in rejected_transactions {
                                    tx.expect("Error deserializing RejectedTransaction");
                                }
                                migrated_pairs.insert(
                                    DbKeyPrefix::RejectedTransaction as u8,
                                    num_rejected_transactions,
                                );
                            }
                            DbKeyPrefix::EpochHistory => {
                                let epoch_history = dbtx
                                    .find_by_prefix(&EpochHistoryKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_epochs = epoch_history.len();
                                for history in epoch_history {
                                    history.expect("Error deserializing EpochHistory");
                                }
                                migrated_pairs.insert(DbKeyPrefix::EpochHistory as u8, num_epochs);
                            }
                            DbKeyPrefix::LastEpoch => {
                                let last_epoch = dbtx.get_value(&LastEpochKey).await;
                                migrated_pairs.insert(
                                    DbKeyPrefix::LastEpoch as u8,
                                    last_epoch.expect("Error deserializing LastEpoch").is_some()
                                        as usize,
                                );
                            }
                            DbKeyPrefix::ClientConfigSignature => {
                                let client_config_sigs = dbtx
                                    .find_by_prefix(&ClientConfigSignatureKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_sigs = client_config_sigs.len();
                                for sig in client_config_sigs {
                                    sig.expect("Error deserializing ClientConfigSignature");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::ClientConfigSignature as u8, num_sigs);
                            }
                            // Module prefix is reserved for modules, no migration testing is needed
                            DbKeyPrefix::Module => {}
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
