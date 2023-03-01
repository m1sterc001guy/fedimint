use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, OutPoint, PeerId};
use secp256k1::PublicKey;
use serde::Serialize;
use strum_macros::EnumIter;

use crate::contracts::incoming::IncomingContractOffer;
use crate::contracts::{ContractId, PreimageDecryptionShare};
use crate::{ContractAccount, LightningGateway, LightningOutputOutcome};

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Contract = 0x40,
    Offer = 0x41,
    ProposeDecryptionShare = 0x42,
    AgreedDecryptionShare = 0x43,
    ContractUpdate = 0x44,
    LightningGateway = 0x45,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Copy, Encodable, Decodable, Serialize)]
pub struct ContractKey(pub ContractId);

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractKeyPrefix;

impl_db_record!(
    key = ContractKey,
    value = ContractAccount,
    db_prefix = DbKeyPrefix::Contract,
);
impl_db_lookup!(key = ContractKey, query_prefix = ContractKeyPrefix);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ContractUpdateKey(pub OutPoint);

#[derive(Debug, Clone, Copy, Encodable, Decodable)]
pub struct ContractUpdateKeyPrefix;

impl_db_record!(
    key = ContractUpdateKey,
    value = LightningOutputOutcome,
    db_prefix = DbKeyPrefix::ContractUpdate,
);
impl_db_lookup!(
    key = ContractUpdateKey,
    query_prefix = ContractUpdateKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct OfferKey(pub bitcoin_hashes::sha256::Hash);

#[derive(Debug, Encodable, Decodable)]
pub struct OfferKeyPrefix;

impl_db_record!(
    key = OfferKey,
    value = IncomingContractOffer,
    db_prefix = DbKeyPrefix::Offer,
);
impl_db_lookup!(key = OfferKey, query_prefix = OfferKeyPrefix);

// TODO: remove redundancy
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct ProposeDecryptionShareKey(pub ContractId);

/// Our preimage decryption shares that still need to be broadcasted
#[derive(Debug, Encodable)]
pub struct ProposeDecryptionShareKeyPrefix;

impl_db_record!(
    key = ProposeDecryptionShareKey,
    value = PreimageDecryptionShare,
    db_prefix = DbKeyPrefix::ProposeDecryptionShare,
);
impl_db_lookup!(
    key = ProposeDecryptionShareKey,
    query_prefix = ProposeDecryptionShareKeyPrefix
);

/// Preimage decryption shares we received
#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct AgreedDecryptionShareKey(pub ContractId, pub PeerId);

/// Preimage decryption shares we received
#[derive(Debug, Encodable)]
pub struct AgreedDecryptionShareKeyPrefix;

impl_db_record!(
    key = AgreedDecryptionShareKey,
    value = PreimageDecryptionShare,
    db_prefix = DbKeyPrefix::AgreedDecryptionShare,
);
impl_db_lookup!(
    key = AgreedDecryptionShareKey,
    query_prefix = AgreedDecryptionShareKeyPrefix
);

#[derive(Debug, Encodable, Decodable, Serialize)]
pub struct LightningGatewayKey(pub PublicKey);

#[derive(Debug, Encodable, Decodable)]
pub struct LightningGatewayKeyPrefix;

impl_db_record!(
    key = LightningGatewayKey,
    value = LightningGateway,
    db_prefix = DbKeyPrefix::LightningGateway,
);
impl_db_lookup!(
    key = LightningGatewayKey,
    query_prefix = LightningGatewayKeyPrefix
);

#[cfg(test)]
mod fedimint_migration_tests {
    use std::collections::BTreeMap;
    use std::env;
    use std::path::Path;

    use fedimint_core::core::LEGACY_HARDCODED_INSTANCE_ID_LN;
    use fedimint_core::db::apply_migrations;
    use fedimint_core::module::DynModuleGen;
    use fedimint_testing::apply_to_databases;
    use futures::StreamExt;
    use strum::IntoEnumIterator;

    use crate::db::{
        AgreedDecryptionShareKeyPrefix, ContractKeyPrefix, ContractUpdateKeyPrefix, DbKeyPrefix,
        LightningGatewayKeyPrefix, ProposeDecryptionShareKeyPrefix,
    };
    use crate::LightningGen;

    #[tokio::test(flavor = "multi_thread")]
    async fn verify_lightning_database_migration() {
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
                    let module = DynModuleGen::from(LightningGen);
                    let isolated_db = db.new_isolated(LEGACY_HARDCODED_INSTANCE_ID_LN);
                    apply_migrations(
                        &isolated_db,
                        module.module_kind().to_string(),
                        module.database_version(),
                        module.get_database_migrations(),
                    )
                    .await
                    .expect("Error applying migrations to temp database");

                    // Verify that all of the data from the lightning namespace can be read. If a
                    // database migration failed or was not properly supplied,
                    // this will fail.
                    let mut migrated_pairs: BTreeMap<u8, usize> = BTreeMap::new();
                    let mut dbtx = isolated_db.begin_transaction().await;

                    for prefix in DbKeyPrefix::iter() {
                        match prefix {
                            DbKeyPrefix::Contract => {
                                let contracts = dbtx
                                    .find_by_prefix(&ContractKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_contracts = contracts.len();
                                for contract in contracts {
                                    contract.expect("Error deserializing contract");
                                }
                                migrated_pairs.insert(DbKeyPrefix::Contract as u8, num_contracts);
                            }
                            DbKeyPrefix::AgreedDecryptionShare => {
                                let agreed_decryption_shares = dbtx
                                    .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_shares = agreed_decryption_shares.len();
                                for share in agreed_decryption_shares {
                                    share.expect("Error deserializing AgreedDecryptionShare");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::AgreedDecryptionShare as u8, num_shares);
                            }
                            DbKeyPrefix::ContractUpdate => {
                                let contract_updates = dbtx
                                    .find_by_prefix(&ContractUpdateKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_updates = contract_updates.len();
                                for update in contract_updates {
                                    update.expect("Error deserializing ContractUpdate");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::ContractUpdate as u8, num_updates);
                            }
                            DbKeyPrefix::LightningGateway => {
                                let gateways = dbtx
                                    .find_by_prefix(&LightningGatewayKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_gateways = gateways.len();
                                for gateway in gateways {
                                    gateway.expect("Error deserializing LightningGateway");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::LightningGateway as u8, num_gateways);
                            }
                            DbKeyPrefix::Offer => {
                                // TODO: Offers are temporary database entries
                                // that are removed once a contract is created,
                                // therefore currently it is not expected that
                                // the backup databases will have any offer
                                // record.
                            }
                            DbKeyPrefix::ProposeDecryptionShare => {
                                let proposed_decryption_shares = dbtx
                                    .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                                    .await
                                    .collect::<Vec<_>>()
                                    .await;
                                let num_shares = proposed_decryption_shares.len();
                                for share in proposed_decryption_shares {
                                    share.expect("Error deserializing ProposeDecryptionShare");
                                }
                                migrated_pairs
                                    .insert(DbKeyPrefix::ProposeDecryptionShare as u8, num_shares);
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
