use std::time::SystemTime;

use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, Amount, OutPoint, PeerId};
use serde::{Deserialize, Serialize};
use strum_macros::EnumIter;

use crate::{MintOutputBlindSignatures, MintOutputSignatureShare, Nonce};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    NoteNonce = 0x10,
    ProposedPartialSig = 0x11,
    ReceivedPartialSig = 0x12,
    OutputOutcome = 0x13,
    MintAuditItem = 0x14,
    EcashBackup = 0x15,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct NonceKey(pub Nonce);

#[derive(Debug, Encodable, Decodable)]
pub struct NonceKeyPrefix;

impl_db_record!(
    key = NonceKey,
    value = (),
    db_prefix = DbKeyPrefix::NoteNonce,
);
impl_db_lookup!(key = NonceKey, query_prefix = NonceKeyPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposedPartialSignatureKey {
    pub out_point: OutPoint, // tx + output idx
}

#[derive(Debug, Encodable, Decodable)]
pub struct ProposedPartialSignaturesKeyPrefix;

impl_db_record!(
    key = ProposedPartialSignatureKey,
    value = MintOutputSignatureShare,
    db_prefix = DbKeyPrefix::ProposedPartialSig,
);
impl_db_lookup!(
    key = ProposedPartialSignatureKey,
    query_prefix = ProposedPartialSignaturesKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ReceivedPartialSignatureKey {
    pub request_id: OutPoint, // tx + output idx
    pub peer_id: PeerId,
}

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignaturesKeyPrefix;

#[derive(Debug, Encodable, Decodable)]
pub struct ReceivedPartialSignatureKeyOutputPrefix {
    pub request_id: OutPoint, // tx + output idx
}

impl_db_record!(
    key = ReceivedPartialSignatureKey,
    value = MintOutputSignatureShare,
    db_prefix = DbKeyPrefix::ReceivedPartialSig,
);
impl_db_lookup!(
    key = ReceivedPartialSignatureKey,
    query_prefix = ReceivedPartialSignaturesKeyPrefix,
    query_prefix = ReceivedPartialSignatureKeyOutputPrefix
);

/// Transaction id and output index identifying an output outcome
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct OutputOutcomeKey(pub OutPoint);

#[derive(Debug, Encodable, Decodable)]
pub struct OutputOutcomeKeyPrefix;

impl_db_record!(
    key = OutputOutcomeKey,
    value = MintOutputBlindSignatures,
    db_prefix = DbKeyPrefix::OutputOutcome,
);
impl_db_lookup!(
    key = OutputOutcomeKey,
    query_prefix = OutputOutcomeKeyPrefix
);

/// Represents the amounts of issued (signed) and redeemed (verified) notes for
/// auditing
#[derive(Debug, Clone, Encodable, Decodable, Serialize)]
pub enum MintAuditItemKey {
    Issuance(OutPoint),
    IssuanceTotal,
    Redemption(NonceKey),
    RedemptionTotal,
}

#[derive(Debug, Encodable, Decodable)]
pub struct MintAuditItemKeyPrefix;

impl_db_record!(
    key = MintAuditItemKey,
    value = Amount,
    db_prefix = DbKeyPrefix::MintAuditItem,
);
impl_db_lookup!(
    key = MintAuditItemKey,
    query_prefix = MintAuditItemKeyPrefix
);

/// Key used to store user's ecash backups
#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct EcashBackupKey(pub secp256k1_zkp::XOnlyPublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct EcashBackupKeyPrefix;

impl_db_record!(
    key = EcashBackupKey,
    value = ECashUserBackupSnapshot,
    db_prefix = DbKeyPrefix::EcashBackup,
);
impl_db_lookup!(key = EcashBackupKey, query_prefix = EcashBackupKeyPrefix);

/// User's backup, received at certain time, containing encrypted payload
#[derive(Debug, Clone, PartialEq, Eq, Encodable, Decodable, Serialize, Deserialize)]
pub struct ECashUserBackupSnapshot {
    pub timestamp: SystemTime,
    #[serde(with = "fedimint_core::hex::serde")]
    pub data: Vec<u8>,
}

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::env;
    use std::path::Path;

    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_MINT;
    use fedimint_core::db::apply_migrations;
    use fedimint_core::module::DynModuleGen;
    use fedimint_testing::apply_to_databases;
    use futures::StreamExt;
    use strum::IntoEnumIterator;

    use crate::db::{
        DbKeyPrefix, EcashBackupKeyPrefix, MintAuditItemKeyPrefix, NonceKeyPrefix,
        OutputOutcomeKeyPrefix, ProposedPartialSignaturesKeyPrefix,
        ReceivedPartialSignaturesKeyPrefix,
    };
    use crate::MintGen;

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_mint_database_migration() {
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
                    let module = DynModuleGen::from(MintGen);
                    let isolated_db = db.new_isolated(LEGACY_HARDCODED_INSTANCE_ID_MINT);
                    apply_migrations(
                        &isolated_db,
                        module.module_kind().to_string(),
                        module.database_version(),
                        module.get_database_migrations(),
                    )
                    .await
                    .expect("Error applying migrations to temp database");

                    // Verify that all of the data from the mint namespace can be read. If a
                    // database migration failed or was not properly supplied,
                    // this will fail.
                    let mut migrated_pairs: BTreeMap<u8, usize> = BTreeMap::new();
                    let mut dbtx = isolated_db.begin_transaction().await;

                    for prefix in DbKeyPrefix::iter() {
                        match prefix {
                            DbKeyPrefix::EcashBackup => {
                                let backups = dbtx
                                    .find_by_prefix(&EcashBackupKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_backups = backups.len();
                                for backup in backups {
                                    backup.expect("Error deserializing EcashBackup");
                                }
                                migrated_pairs.insert(DbKeyPrefix::EcashBackup as u8, num_backups);
                            }
                            DbKeyPrefix::MintAuditItem => {
                                let items = dbtx
                                    .find_by_prefix(&MintAuditItemKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_items = items.len();
                                for item in items {
                                    item.expect("Error deserializing MintAuditItem");
                                }
                                migrated_pairs.insert(DbKeyPrefix::MintAuditItem as u8, num_items);
                            }
                            DbKeyPrefix::NoteNonce => {
                                let notes = dbtx
                                    .find_by_prefix(&NonceKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_notes = notes.len();
                                for note in notes {
                                    note.expect("Error deserializing NoteNonce");
                                }
                                migrated_pairs.insert(DbKeyPrefix::NoteNonce as u8, num_notes);
                            }
                            DbKeyPrefix::OutputOutcome => {
                                let outcomes = dbtx
                                    .find_by_prefix(&OutputOutcomeKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_outcomes = outcomes.len();
                                for outcome in outcomes {
                                    outcome.expect("Error deserializing OutputOutcome");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::OutputOutcome as u8, num_outcomes);
                            }
                            DbKeyPrefix::ProposedPartialSig => {
                                let proposed_partial_sigs = dbtx
                                    .find_by_prefix(&ProposedPartialSignaturesKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_sigs = proposed_partial_sigs.len();
                                for sig in proposed_partial_sigs {
                                    sig.expect("Error deserializing ProposedPartialSignature");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::ProposedPartialSig as u8, num_sigs);
                            }
                            DbKeyPrefix::ReceivedPartialSig => {
                                let received_partial_sigs = dbtx
                                    .find_by_prefix(&ReceivedPartialSignaturesKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_sigs = received_partial_sigs.len();
                                for sig in received_partial_sigs {
                                    sig.expect("Error deserializing ReceivedPartialSignature");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::ReceivedPartialSig as u8, num_sigs);
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
