use std::path::Path;

use anyhow::Result;
use async_trait::async_trait;
use fedimint_api::db::PrefixIter;
use fedimint_api::db::{IDatabase, IDatabaseTransaction};
use fedimint_api::task::TaskGroup;
pub use rocksdb;
use rocksdb::{OptimisticTransactionDB, OptimisticTransactionOptions, WriteOptions};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::warn;

#[derive(Debug)]
enum DatabaseRequest {
    InsertEntry,
}

#[derive(Debug)]
enum DatabaseResponse {
    Ok,
}

#[derive(Debug)]
pub struct RocksDb(rocksdb::OptimisticTransactionDB);

pub struct RocksDbReadOnly(rocksdb::DB);

pub struct RocksDbTransaction<'a> {
    //inner_tx: rocksdb::Transaction<'a, rocksdb::OptimisticTransactionDB>,
    async_tx: AsyncDatabaseTransaction<'a>,
}

struct AsyncDatabaseTransaction<'a> {
    inner_tx: rocksdb::Transaction<'a, rocksdb::OptimisticTransactionDB>,
    sender: Sender<DatabaseRequest>,
    receiver: Receiver<DatabaseResponse>,
}

impl RocksDb {
    pub fn open(db_path: impl AsRef<Path>) -> Result<RocksDb, rocksdb::Error> {
        let db: rocksdb::OptimisticTransactionDB =
            rocksdb::OptimisticTransactionDB::<rocksdb::SingleThreaded>::open_default(&db_path)?;
        Ok(RocksDb(db))
    }

    pub fn inner(&self) -> &rocksdb::OptimisticTransactionDB {
        &self.0
    }
}

impl RocksDbReadOnly {
    pub fn open_read_only(db_path: impl AsRef<Path>) -> Result<RocksDbReadOnly, rocksdb::Error> {
        let opts = rocksdb::Options::default();
        let db = rocksdb::DB::open_for_read_only(&opts, db_path, false)?;
        Ok(RocksDbReadOnly(db))
    }
}

impl From<rocksdb::OptimisticTransactionDB> for RocksDb {
    fn from(db: OptimisticTransactionDB) -> Self {
        RocksDb(db)
    }
}

impl From<RocksDb> for rocksdb::OptimisticTransactionDB {
    fn from(db: RocksDb) -> Self {
        db.0
    }
}

impl<'a> AsyncDatabaseTransaction<'a> {
    pub async fn new(
        inner_tx: rocksdb::Transaction<'a, rocksdb::OptimisticTransactionDB>,
    ) -> AsyncDatabaseTransaction<'a> {
        let (incoming_sender, mut incoming_receiver) = mpsc::channel::<DatabaseRequest>(100);
        let (outgoing_sender, outgoing_receiver) = mpsc::channel::<DatabaseResponse>(100);
        let mut tg = TaskGroup::new();
        tg.spawn("tx_thread", |task_handle| async move {
            println!("Starting tx thread");
            // TODO: Either sleep or change to recv
            while let Ok(msg) = incoming_receiver.try_recv() {
                match msg {
                    DatabaseRequest::InsertEntry => {
                        println!("Received InsertEntry");
                        outgoing_sender
                            .send(DatabaseResponse::Ok)
                            .await
                            .expect("Error sending database response");
                    }
                }
            }
        })
        .await;

        AsyncDatabaseTransaction {
            sender: incoming_sender,
            inner_tx,
            receiver: outgoing_receiver,
        }
    }
}

#[async_trait]
impl IDatabase for RocksDb {
    async fn begin_transaction<'a>(&'a self) -> Box<dyn IDatabaseTransaction<'a> + Send + 'a> {
        let mut optimistic_options = OptimisticTransactionOptions::default();
        optimistic_options.set_snapshot(true);
        let inner_tx = self
            .0
            .transaction_opt(&WriteOptions::default(), &optimistic_options);
        let mut rocksdb_tx = RocksDbTransaction {
            //inner_tx: self.0
            //    .transaction_opt(&WriteOptions::default(), &optimistic_options),
            async_tx: AsyncDatabaseTransaction::new(inner_tx).await,
        };
        rocksdb_tx.set_tx_savepoint().await;
        Box::new(rocksdb_tx)
    }
}

#[async_trait]
impl<'a> IDatabaseTransaction<'a> for RocksDbTransaction<'a> {
    async fn raw_insert_bytes(&mut self, key: &[u8], value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        println!("Sending InsertEntry");
        self.async_tx
            .sender
            .send(DatabaseRequest::InsertEntry)
            .await?;
        println!("Waiting for response to tx thread");
        match self.async_tx.receiver.recv().await {
            Some(DatabaseResponse::Ok) => {
                println!("Received Ok Response");
            }
            _ => {
                println!("Received None Response");
            }
        }
        //let val = self.inner_tx.get(key).unwrap();
        //self.inner_tx.put(key, value)?;
        //Ok(val)
        Ok(None)
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        //Ok(self.inner_tx.snapshot().get(key)?)
        Ok(None)
    }

    async fn raw_remove_entry(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        //let val = self.inner_tx.get(key).unwrap();
        //self.inner_tx.delete(key)?;
        //Ok(val)
        Ok(None)
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixIter<'_> {
        /*
        let prefix = key_prefix.to_vec();
        let mut options = rocksdb::ReadOptions::default();
        options.set_iterate_range(rocksdb::PrefixRange(prefix.clone()));
        let iter = self.inner_tx.snapshot().iterator_opt(
            rocksdb::IteratorMode::From(&prefix, rocksdb::Direction::Forward),
            options,
        );
        Box::new(
            iter.map_while(move |res| {
                let (key_bytes, value_bytes) = res.expect("DB error");
                key_bytes
                    .starts_with(&prefix)
                    .then_some((key_bytes, value_bytes))
            })
            .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
            .map(Ok),
        )
        */
        Box::new(vec![].into_iter())
    }

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        //self.inner_tx.commit()?;
        Ok(())
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        /*
        match self.inner_tx.rollback_to_savepoint() {
            Ok(()) => {}
            _ => {
                warn!("Rolling back database transaction without a set savepoint");
            }
        }
        */
    }

    async fn set_tx_savepoint(&mut self) {
        //self.inner_tx.set_savepoint();
    }
}

#[async_trait]
impl IDatabaseTransaction<'_> for RocksDbReadOnly {
    async fn raw_insert_bytes(&mut self, _key: &[u8], _value: Vec<u8>) -> Result<Option<Vec<u8>>> {
        panic!("Cannot insert into a read only transaction");
    }

    async fn raw_get_bytes(&mut self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.0.get(key)?)
    }

    async fn raw_remove_entry(&mut self, _key: &[u8]) -> Result<Option<Vec<u8>>> {
        panic!("Cannot remove from a read only transaction");
    }

    async fn raw_find_by_prefix(&mut self, key_prefix: &[u8]) -> PrefixIter<'_> {
        let prefix = key_prefix.to_vec();
        Box::new(
            self.0
                .prefix_iterator(prefix.clone())
                .map_while(move |res| {
                    let (key_bytes, value_bytes) = res.expect("DB error");
                    key_bytes
                        .starts_with(&prefix)
                        .then_some((key_bytes, value_bytes))
                })
                .map(|(key_bytes, value_bytes)| (key_bytes.to_vec(), value_bytes.to_vec()))
                .map(Ok),
        )
    }

    async fn commit_tx(self: Box<Self>) -> Result<()> {
        panic!("Cannot commit a read only transaction");
    }

    async fn rollback_tx_to_savepoint(&mut self) {
        panic!("Cannot rollback a read only transaction");
    }

    async fn set_tx_savepoint(&mut self) {
        panic!("Cannot set a savepoint in a read only transaction");
    }
}

#[cfg(test)]
mod fedimint_rocksdb_tests {
    use std::time::Duration;

    use fedimint_api::task::TaskGroup;
    use fedimint_api::{db::Database, module::registry::ModuleDecoderRegistry};
    use tokio::sync::mpsc;

    use crate::RocksDb;
    use crate::{AsyncDatabaseTransaction, DatabaseRequest};

    fn open_temp_db(temp_path: &str) -> Database {
        let path = tempfile::Builder::new()
            .prefix(temp_path)
            .tempdir()
            .unwrap();

        Database::new(
            RocksDb::open(path).unwrap(),
            ModuleDecoderRegistry::default(),
        )
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_insert_elements() {
        fedimint_api::db::verify_insert_elements(open_temp_db("fcb-rocksdb-test-insert-elements"))
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_nonexisting() {
        fedimint_api::db::verify_remove_nonexisting(open_temp_db(
            "fcb-rocksdb-test-remove-nonexisting",
        ))
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_existing() {
        fedimint_api::db::verify_remove_existing(open_temp_db("fcb-rocksdb-test-remove-existing"))
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_read_own_writes() {
        fedimint_api::db::verify_read_own_writes(open_temp_db("fcb-rocksdb-test-read-own-writes"))
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_dirty_reads() {
        fedimint_api::db::verify_prevent_dirty_reads(open_temp_db(
            "fcb-rocksdb-test-prevent-dirty-reads",
        ))
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_find_by_prefix() {
        fedimint_api::db::verify_find_by_prefix(open_temp_db("fcb-rocksdb-test-find-by-prefix"))
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_commit() {
        fedimint_api::db::verify_commit(open_temp_db("fcb-rocksdb-test-commit")).await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_prevent_nonrepeatable_reads() {
        fedimint_api::db::verify_prevent_nonrepeatable_reads(open_temp_db(
            "fcb-rocksdb-test-prevent-nonrepeatable-reads",
        ))
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_rollback_to_savepoint() {
        fedimint_api::db::verify_rollback_to_savepoint(open_temp_db(
            "fcb-rocksdb-test-rollback-to-savepoint",
        ))
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_phantom_entry() {
        fedimint_api::db::verify_phantom_entry(open_temp_db("fcb-rocksdb-test-phantom-entry"))
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_write_conflict() {
        fedimint_api::db::expect_write_conflict(open_temp_db("fcb-rocksdb-test-write-conflict"))
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_dbtx_remove_by_prefix() {
        fedimint_api::db::verify_remove_by_prefix(open_temp_db(
            "fcb-rocksdb-test-remove-by-prefix",
        ))
        .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_module_dbtx() {
        fedimint_api::db::verify_module_prefix(open_temp_db("fcb-rocksdb-test-module-prefix"))
            .await;
    }

    #[test_log::test(tokio::test)]
    async fn test_module_db() {
        let module_instance_id = 1;
        let path = tempfile::Builder::new()
            .prefix("fcb-rocksdb-test-module-db-prefix")
            .tempdir()
            .unwrap();

        let module_db = Database::new(
            RocksDb::open(path).unwrap(),
            ModuleDecoderRegistry::default(),
        );

        fedimint_api::db::verify_module_db(
            open_temp_db("fcb-rocksdb-test-module-db"),
            module_db.new_isolated(module_instance_id),
        )
        .await;
    }

    #[test_log::test()]
    #[should_panic(expected = "Cannot isolate and already isolated database.")]
    fn test_cannot_isolate_already_isolated_db() {
        let module_instance_id = 1;
        let db = open_temp_db("rocksdb-test-already-isolated").new_isolated(module_instance_id);

        // try to isolate the database again
        let module_instance_id = 2;
        db.new_isolated(module_instance_id);
    }

    #[test_log::test(tokio::test)]
    async fn test_channel() {
        fedimint_api::db::test_channel(open_temp_db("rocksdb-channel")).await;
        fedimint_api::task::sleep(Duration::from_secs(5)).await;
    }
}
