use std::{collections::BTreeMap, path::PathBuf};

use erased_serde::Serialize;
use fedimint_api::{
    core::ModuleKind,
    db::DatabaseTransaction,
    encoding::Encodable,
    module::{DynModuleGen, __reexports::serde_json},
};
use fedimint_ln::LightningGen;
use fedimint_mint::{db as MintRange, MintGen};
use fedimint_rocksdb::RocksDbReadOnly;
use fedimint_server::config::ModuleInitRegistry;
use fedimint_server::db as ConsensusRange;
use fedimint_wallet::WalletGen;
use fedimintd::SALT_FILE;
use strum::IntoEnumIterator;

macro_rules! push_db_pair_items {
    ($dbtx:ident, $prefix_type:expr, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
        let db_items = $dbtx.find_by_prefix(&$prefix_type).await;
        let mut items: Vec<($key_type, $value_type)> = Vec::new();
        for item in db_items {
            items.push(item.unwrap());
        }
        $map.insert($key_literal.to_string(), Box::new(items));
    };
}

#[derive(Debug, serde::Serialize)]
struct SerdeWrapper(#[serde(with = "hex::serde")] Vec<u8>);

impl SerdeWrapper {
    fn from_encodable<T: Encodable>(e: T) -> SerdeWrapper {
        let mut bytes = vec![];
        e.consensus_encode(&mut bytes)
            .expect("Write to vec can't fail");
        SerdeWrapper(bytes)
    }
}

macro_rules! push_db_pair_items_no_serde {
    ($dbtx:ident, $prefix_type:expr, $key_type:ty, $value_type:ty, $map:ident, $key_literal:literal) => {
        let db_items = $dbtx.find_by_prefix(&$prefix_type).await;
        let mut items: Vec<($key_type, SerdeWrapper)> = Vec::new();
        for item in db_items {
            let (k, v) = item.unwrap();
            items.push((k, SerdeWrapper::from_encodable(v)));
        }
        $map.insert($key_literal.to_string(), Box::new(items));
    };
}

macro_rules! push_db_key_items {
    ($dbtx:ident, $prefix_type:expr, $key_type:ty, $map:ident, $key_literal:literal) => {
        let db_items = $dbtx.find_by_prefix(&$prefix_type).await;
        let mut items: Vec<$key_type> = Vec::new();
        for item in db_items {
            items.push(item.unwrap().0);
        }
        $map.insert($key_literal.to_string(), Box::new(items));
    };
}

/// Structure to hold the deserialized structs from the database.
/// Also includes metadata on which sections of the database to read.
pub struct DatabaseDump<'a> {
    serialized: BTreeMap<String, Box<dyn Serialize>>,
    read_only: DatabaseTransaction<'a>,
    modules: Vec<String>,
    prefixes: Vec<String>,
    include_all_prefixes: bool,
    module_id_map: BTreeMap<ModuleKind, u16>,
}

impl<'a> DatabaseDump<'a> {
    pub fn new(
        cfg_dir: PathBuf,
        data_dir: String,
        password: Option<String>,
        modules: Vec<String>,
        prefixes: Vec<String>,
    ) -> DatabaseDump<'a> {
        let read_only = match RocksDbReadOnly::open_read_only(data_dir) {
            Ok(db) => db,
            Err(_) => {
                panic!("Error reading RocksDB database. Quitting...");
            }
        };

        let module_inits = ModuleInitRegistry::from(vec![
            DynModuleGen::from(WalletGen),
            DynModuleGen::from(MintGen),
            DynModuleGen::from(LightningGen),
        ]);

        let salt_path = cfg_dir.join(SALT_FILE);
        let key = fedimintd::encrypt::get_key(password, salt_path).unwrap();
        let cfg = fedimintd::read_server_configs(&key, cfg_dir.clone()).unwrap();
        let decoders = module_inits.decoders(cfg.iter_module_instances()).unwrap();
        let dbtx = DatabaseTransaction::new(Box::new(read_only), decoders);

        // Build a module map that maps the ModuleKind -> ModuleInstanceId for fast lookups of module instances.
        // TODO: Use vector to support multiple instantiations of the same kind
        let module_map: BTreeMap<ModuleKind, u16> = cfg
            .iter_module_instances()
            .map(|(id, kind)| (kind.clone(), id))
            .collect();

        for (kind, id) in &module_map {
            println!("Available module kind: {} module id: {}", kind, id);
        }

        DatabaseDump {
            serialized: BTreeMap::new(),
            read_only: dbtx,
            modules: modules,
            prefixes: prefixes,
            include_all_prefixes: true,
            module_id_map: module_map,
        }
    }
}

impl<'a> DatabaseDump<'a> {
    /// Prints the contents of the BTreeMap to a pretty JSON string
    fn print_database(&self) {
        let json = serde_json::to_string_pretty(&self.serialized).unwrap();
        println!("{}", json);
    }

    /// Iterates through all the specified ranges in the database and retrieves the
    /// data for each range. Prints serialized contents at the end.
    pub async fn dump_database(&mut self) {
        for range in self.modules.clone() {
            match range.as_str() {
                "consensus" => {
                    self.get_consensus_data().await;
                }
                "mint" => {
                    let module_id = self.module_id_map.get(&ModuleKind::from("mint")).unwrap();
                    self.get_mint_data(module_id.clone()).await;
                }
                /*
                "wallet" => {
                    self.get_wallet_data().await;
                }
                "lightning" => {
                    self.get_lightning_data().await;
                }
                "mintclient" => {
                    self.get_mint_client_data().await;
                }
                "lightningclient" => {
                    self.get_ln_client_data().await;
                }
                "walletclient" => {
                    self.get_wallet_client_data().await;
                }
                "client" => {
                    self.get_client_data().await;
                }
                */
                _ => {}
            }
        }

        self.print_database();
    }

    /// Iterates through each of the prefixes within the consensus range and retrieves
    /// the corresponding data.
    async fn get_consensus_data(&mut self) {
        let mut consensus: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        let dbtx = &mut self.read_only;

        for table in ConsensusRange::DbKeyPrefix::iter() {
            //filter_prefixes!(table, self);

            match table {
                ConsensusRange::DbKeyPrefix::ProposedTransaction => {
                    push_db_pair_items_no_serde!(
                        dbtx,
                        ConsensusRange::ProposedTransactionKeyPrefix,
                        ConsensusRange::ProposedTransactionKey,
                        fedimint_core::transaction::Transaction,
                        consensus,
                        "Pending Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::AcceptedTransaction => {
                    push_db_pair_items_no_serde!(
                        dbtx,
                        ConsensusRange::AcceptedTransactionKeyPrefix,
                        ConsensusRange::AcceptedTransactionKey,
                        fedimint_server::consensus::AcceptedTransaction,
                        consensus,
                        "Accepted Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::DropPeer => {
                    push_db_key_items!(
                        dbtx,
                        ConsensusRange::DropPeerKeyPrefix,
                        ConsensusRange::DropPeerKey,
                        consensus,
                        "Dropped Peers"
                    );
                }
                ConsensusRange::DbKeyPrefix::RejectedTransaction => {
                    push_db_pair_items!(
                        dbtx,
                        ConsensusRange::RejectedTransactionKeyPrefix,
                        ConsensusRange::RejectedTransactionKey,
                        String,
                        consensus,
                        "Rejected Transactions"
                    );
                }
                ConsensusRange::DbKeyPrefix::EpochHistory => {
                    push_db_pair_items_no_serde!(
                        dbtx,
                        ConsensusRange::EpochHistoryKeyPrefix,
                        ConsensusRange::EpochHistoryKey,
                        fedimint_core::epoch::EpochHistory,
                        consensus,
                        "Epoch History"
                    );
                }
                ConsensusRange::DbKeyPrefix::LastEpoch => {
                    let last_epoch = dbtx.get_value(&ConsensusRange::LastEpochKey).await.unwrap();
                    if let Some(last_epoch) = last_epoch {
                        consensus.insert("LastEpoch".to_string(), Box::new(last_epoch));
                    }
                }
                // Module is a global prefix for all module data
                ConsensusRange::DbKeyPrefix::Module => {}
            }
        }

        self.serialized
            .insert("Consensus".to_string(), Box::new(consensus));
    }

    /// Iterates through each of the prefixes within the mint range and retrieves
    /// the corresponding data.
    async fn get_mint_data(&mut self, module_instance_id: u16) {
        let mut mint: BTreeMap<String, Box<dyn Serialize>> = BTreeMap::new();
        let mut dbtx = self.read_only.with_module_prefix(module_instance_id);
        for table in MintRange::DbKeyPrefix::iter() {
            //filter_prefixes!(table, self);

            match table {
                MintRange::DbKeyPrefix::CoinNonce => {
                    push_db_key_items!(
                        dbtx,
                        MintRange::NonceKeyPrefix,
                        MintRange::NonceKey,
                        mint,
                        "Used Coins"
                    );
                }
                MintRange::DbKeyPrefix::MintAuditItem => {
                    push_db_pair_items!(
                        dbtx,
                        MintRange::MintAuditItemKeyPrefix,
                        MintRange::MintAuditItemKey,
                        fedimint_api::Amount,
                        mint,
                        "Mint Audit Items"
                    );
                }
                MintRange::DbKeyPrefix::OutputOutcome => {
                    push_db_pair_items!(
                        dbtx,
                        MintRange::OutputOutcomeKeyPrefix,
                        MintRange::OutputOutcomeKey,
                        fedimint_mint::OutputOutcome,
                        mint,
                        "Output Outcomes"
                    );
                }
                MintRange::DbKeyPrefix::ProposedPartialSig => {
                    push_db_pair_items!(
                        dbtx,
                        MintRange::ProposedPartialSignaturesKeyPrefix,
                        MintRange::ProposedPartialSignatureKey,
                        fedimint_mint::OutputConfirmationSignatures,
                        mint,
                        "Proposed Signature Shares"
                    );
                }
                MintRange::DbKeyPrefix::ReceivedPartialSig => {
                    push_db_pair_items!(
                        dbtx,
                        MintRange::ReceivedPartialSignaturesKeyPrefix,
                        MintRange::ReceivedPartialSignatureKey,
                        fedimint_mint::OutputConfirmationSignatures,
                        mint,
                        "Received Signature Shares"
                    );
                }
                MintRange::DbKeyPrefix::EcashBackup => {
                    push_db_pair_items!(
                        dbtx,
                        MintRange::EcashBackupKeyPrefix,
                        MintRange::EcashBackupKey,
                        fedimint_mint::db::ECashUserBackupSnapshot,
                        mint,
                        "User Ecash Backup"
                    );
                }
            }
        }

        self.serialized.insert("Mint".to_string(), Box::new(mint));
    }
}
