use std::path::PathBuf;

use anyhow::Result;
use bitcoin_hashes::hex::ToHex;
use bytes::Bytes;
use clap::{Parser, Subcommand};
use fedimint_api::db::Database;
use fedimint_api::module::registry::ModuleDecoderRegistry;

use crate::dump::DatabaseDump;

mod dump;

fn csv_vec_parser(input: &str) -> Result<Vec<String>, String> {
    let vec = input
        .split(',')
        .map(|s| s.to_string().to_lowercase())
        .collect::<Vec<String>>();
    Ok(vec)
}

#[derive(Debug, Clone, Parser)]
struct Options {
    database: String,
    #[command(subcommand)]
    command: DbCommand,
}

#[derive(Debug, Clone, Subcommand)]
enum DbCommand {
    List {
        #[arg(value_parser = hex_parser)]
        prefix: Bytes,
    },
    Write {
        #[arg(value_parser = hex_parser)]
        key: Bytes,
        #[arg(value_parser = hex_parser)]
        value: Bytes,
    },
    Delete {
        #[arg(value_parser = hex_parser)]
        prefix: Bytes,
    },
    Dump {
        cfg_dir: PathBuf,
        #[arg(required = false)]
        modules: String,
        #[arg(required = false)]
        prefix: String,
        #[arg(env = "FM_PASSWORD")]
        password: Option<String>,
    },
}

fn hex_parser(hex: &str) -> Result<Bytes> {
    let bytes: Vec<u8> = bitcoin_hashes::hex::FromHex::from_hex(hex)?;
    Ok(bytes.into())
}

async fn open_db(path: &str) -> Result<Database> {
    let rocksdb = fedimint_rocksdb::RocksDb::open(path)?;
    Ok(Database::new(rocksdb, ModuleDecoderRegistry::default()))
}

fn print_kv(key: &[u8], value: &[u8]) {
    println!("{} {}", key.to_hex(), value.to_hex());
}

#[tokio::main]
async fn main() {
    let options: Options = Options::parse();

    match options.command {
        DbCommand::List { prefix } => {
            let db = open_db(&options.database).await.expect("Failed to open DB");
            let mut dbtx = db.begin_transaction().await;
            let prefix_iter = dbtx.raw_find_by_prefix(&prefix).await;
            for db_res in prefix_iter {
                let (key, value) = db_res.expect("DB error");
                print_kv(&key, &value);
            }
        }
        DbCommand::Write { key, value } => {
            let db = open_db(&options.database).await.expect("Failed to open DB");
            let mut dbtx = db.begin_transaction().await;
            dbtx.raw_insert_bytes(&key, value.into())
                .await
                .expect("DB error");
            dbtx.commit_tx().await.expect("DB Error");
        }
        DbCommand::Delete { prefix: key } => {
            let db = open_db(&options.database).await.expect("Failed to open DB");
            let mut dbtx = db.begin_transaction().await;
            dbtx.raw_remove_entry(&key).await.expect("DB error");
            dbtx.commit_tx().await.expect("DB Error");
        }
        DbCommand::Dump {
            cfg_dir,
            modules,
            prefix,
            password,
        } => {
            let mut dbdump = DatabaseDump::new(
                cfg_dir,
                options.database,
                password,
                vec!["consensus".to_string()],
                vec![],
            );
            dbdump.dump_database().await;
        }
    }
}
