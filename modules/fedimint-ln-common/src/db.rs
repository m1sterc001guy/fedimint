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
    use std::env;
    use std::path::Path;
    use std::str::FromStr;
    use std::time::SystemTime;

    use bitcoin_hashes::Hash;
    use fedimint_core::db::{apply_migrations, Database};
    use fedimint_core::module::DynServerModuleGen;
    use fedimint_core::{OutPoint, TransactionId};
    use fedimint_testing::{open_temp_db, validate_migrations};
    use futures::StreamExt;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use rand::rngs::OsRng;
    use rand::RngCore;
    use strum::IntoEnumIterator;
    use threshold_crypto::{DecryptionShare, G1Projective};
    use url::Url;

    use super::{
        AgreedDecryptionShareKey, ContractKey, ContractUpdateKey, LightningGatewayKey, OfferKey,
        ProposeDecryptionShareKey,
    };
    use crate::contracts::incoming::{
        FundedIncomingContract, IncomingContract, IncomingContractOffer, OfferId,
    };
    use crate::contracts::{
        self, ContractId, DecryptedPreimage, EncryptedPreimage, Preimage, PreimageDecryptionShare,
    };
    use crate::db::{
        AgreedDecryptionShareKeyPrefix, ContractKeyPrefix, ContractUpdateKeyPrefix, DbKeyPrefix,
        LightningGatewayKeyPrefix, OfferKeyPrefix, ProposeDecryptionShareKeyPrefix,
    };
    use crate::{ContractAccount, LightningGateway, LightningGen, LightningOutputOutcome};

    const STRING_64: &str = "0123456789012345678901234567890101234567890123456789012345678901";
    const BYTE_8: [u8; 8] = [0, 1, 2, 3, 4, 5, 6, 7];
    const BYTE_32: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
        0, 1,
    ];

    async fn create_db_with_v0_data(db: Database) -> anyhow::Result<()> {
        let mut dbtx = db.begin_transaction().await;
        let contract_id = ContractId::from_str(STRING_64).unwrap();
        let amount = fedimint_core::Amount { msats: 1000 };
        let preimage1 = Preimage(BYTE_32);
        let preimage2 = Preimage(BYTE_32);
        let threshold_key = threshold_crypto::PublicKey::from(G1Projective::identity());
        let (_, pk) = secp256k1::generate_keypair(&mut OsRng);
        let incoming_contract = IncomingContract {
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(preimage1, &threshold_key),
            decrypted_preimage: DecryptedPreimage::Some(preimage2),
            gateway_key: pk.x_only_public_key().0,
        };
        let out_point = OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        };
        let contract = contracts::FundedContract::Incoming(FundedIncomingContract {
            contract: incoming_contract,
            out_point,
        });
        let acct = ContractAccount { amount, contract };
        dbtx.insert_new_entry(&ContractKey(contract_id), &acct)
            .await
            .expect("Error inserting ContractAccount");
        // TODO: Need to insert OutgoingContract here too

        let preimage = Preimage(BYTE_32);
        let offer = IncomingContractOffer {
            amount: fedimint_core::Amount { msats: 1000 },
            hash: secp256k1::hashes::sha256::Hash::hash(&BYTE_8),
            encrypted_preimage: EncryptedPreimage::new(preimage, &threshold_key),
            expiry_time: None,
        };
        let offer_key = OfferKey(offer.hash);
        dbtx.insert_new_entry(&offer_key, &offer)
            .await
            .expect("Error inserting Offer");

        let contract_update_key = ContractUpdateKey(OutPoint {
            txid: TransactionId::all_zeros(),
            out_idx: 0,
        });
        let lightning_output_outcome = LightningOutputOutcome::Offer {
            id: OfferId::from_str(STRING_64).unwrap(),
        };
        dbtx.insert_new_entry(&contract_update_key, &lightning_output_outcome)
            .await
            .expect("Error inserting ContractUpdate");

        let propose_decryption_share_key = ProposeDecryptionShareKey(contract_id);
        let dec_share: DecryptionShare = Standard.sample(&mut OsRng);
        let preimage_decryption_share = PreimageDecryptionShare(dec_share);
        dbtx.insert_new_entry(&propose_decryption_share_key, &preimage_decryption_share)
            .await
            .expect("Error insert ProposeDecryptionShare");

        let agreed_decryption_share_key = AgreedDecryptionShareKey(contract_id, 0.into());
        dbtx.insert_new_entry(&agreed_decryption_share_key, &preimage_decryption_share)
            .await
            .expect("Error inserting AgreedDecryptionShareKey");

        let lightning_gateway_key = LightningGatewayKey(pk);
        let gateway = LightningGateway {
            mint_channel_id: 100,
            mint_pub_key: pk.x_only_public_key().0,
            node_pub_key: pk,
            api: Url::parse("http://example.com")
                .expect("Could not parse URL to generate GatewayClientConfig API endpoint"),
            route_hints: vec![],
            valid_until: SystemTime::now(),
        };
        dbtx.insert_new_entry(&lightning_gateway_key, &gateway)
            .await
            .expect("Error inserting LightningGateway");

        dbtx.commit_tx()
            .await
            .expect("Error committing to database");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepare_migration_snapshots() {
        if let Ok(parent_dir) = env::var("FM_TEST_DB_BACKUP_DIR") {
            let dir_v0 =
                Path::new(&parent_dir).join(format!("lightning-{}-{}", "v0", OsRng.next_u64()));
            create_db_with_v0_data(open_temp_db(&dir_v0))
                .await
                .expect("Error preparing temporary database");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_migrations() {
        if let Ok(parent_dir) = env::var("FM_TEST_DB_BACKUP_DIR") {
            validate_migrations(Path::new(&parent_dir), |db| async move {
                let module = DynServerModuleGen::from(LightningGen);
                apply_migrations(
                    &db,
                    module.module_kind().to_string(),
                    module.database_version(),
                    module.get_database_migrations(),
                )
                .await
                .expect("Error applying migrations to temp database");

                // Verify that all of the data from the lightning namespace can be read. If a
                // database migration failed or was not properly supplied,
                // this will fail.
                let mut dbtx = db.begin_transaction().await;

                for prefix in DbKeyPrefix::iter() {
                    match prefix {
                        DbKeyPrefix::Contract => {
                            let contracts = dbtx
                                .find_by_prefix(&ContractKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_contracts = contracts.len();
                            assert!(num_contracts > 0, "validate_migrations was not able to read any contracts");
                            for contract in contracts {
                                contract.expect("Error reading contract");
                            }
                        }
                        DbKeyPrefix::AgreedDecryptionShare => {
                            let agreed_decryption_shares = dbtx
                                .find_by_prefix(&AgreedDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = agreed_decryption_shares.len();
                            assert!(num_shares > 0, "validate_migrations was not able to read any AgreedDecryptionShares");
                            for share in agreed_decryption_shares {
                                share.expect("Error reading AgreedDecryptionShare");
                            }
                        }
                        DbKeyPrefix::ContractUpdate => {
                            let contract_updates = dbtx
                                .find_by_prefix(&ContractUpdateKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_updates = contract_updates.len();
                            assert!(num_updates > 0, "validate_migrations was not able to read any ContractUpdates");
                            for update in contract_updates {
                                update.expect("Error reading ContractUpdate");
                            }
                        }
                        DbKeyPrefix::LightningGateway => {
                            let gateways = dbtx
                                .find_by_prefix(&LightningGatewayKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_gateways = gateways.len();
                            assert!(num_gateways > 0, "validate_migrations was not able to read any LightningGateways");
                            for gateway in gateways {
                                gateway.expect("Error reading LightningGateway");
                            }
                        }
                        DbKeyPrefix::Offer => {
                            let offers = dbtx.find_by_prefix(&OfferKeyPrefix).await.collect::<Vec<_>>().await;
                            let num_offers = offers.len();
                            assert!(num_offers > 0, "validate_migrations was not able to read any Offers");
                            for offer in offers {
                                offer.expect("Error reading Offer");
                            }
                        }
                        DbKeyPrefix::ProposeDecryptionShare => {
                            let proposed_decryption_shares = dbtx
                                .find_by_prefix(&ProposeDecryptionShareKeyPrefix)
                                .await
                                .collect::<Vec<_>>()
                                .await;
                            let num_shares = proposed_decryption_shares.len();
                            assert!(num_shares > 0, "validate_migrations was not able to read any ProposeDecryptionShares");
                            for share in proposed_decryption_shares {
                                share.expect("Error reading ProposeDecryptionShare");
                            }
                        }
                    }
                }
            }).await;
        }
    }
}
