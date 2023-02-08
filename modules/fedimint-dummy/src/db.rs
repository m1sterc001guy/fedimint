use fedimint_api::db::{Database, DatabaseKeyPrefixConst, DatabaseVersion, DatabaseVersionKey};
use fedimint_api::encoding::{Decodable, Encodable};
use futures::StreamExt;
use serde::Serialize;
use strum_macros::EnumIter;

pub const DATABASE_VERSION: DatabaseVersion = DatabaseVersion(1);

pub async fn migrate_dummy_db_version_0(db: &Database) -> Result<DatabaseVersion, anyhow::Error> {
    let mut read_dbtx = db.begin_transaction().await;
    let mut write_dbtx = db.begin_transaction().await;

    let example_keys_v1 = read_dbtx
        .find_by_prefix(&ExampleKeyPrefixV1)
        .await
        .map(|res| res.unwrap())
        .collect::<Vec<_>>()
        .await;
    write_dbtx.remove_by_prefix(&ExampleKeyPrefixV1).await?;
    for (key, _) in example_keys_v1 {
        let key_v2 = ExampleKey(key.0, format!("Example String"));
        write_dbtx.insert_new_entry(&key_v2, &()).await?;
    }

    let new_version = DatabaseVersion(2);
    write_dbtx
        .insert_entry(&DatabaseVersionKey, &new_version)
        .await?;

    write_dbtx.commit_tx().await?;
    tracing::info!(
        "Dummy module successfully migrated to version {}",
        new_version.clone()
    );
    Ok(new_version)
}

#[repr(u8)]
#[derive(Clone, EnumIter, Debug)]
pub enum DbKeyPrefix {
    Example = 0x80,
}

impl std::fmt::Display for DbKeyPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ExampleKeyV1(pub u64);

impl DatabaseKeyPrefixConst for ExampleKeyV1 {
    const DB_PREFIX: u8 = DbKeyPrefix::Example as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct ExampleKeyPrefixV1;

impl DatabaseKeyPrefixConst for ExampleKeyPrefixV1 {
    const DB_PREFIX: u8 = DbKeyPrefix::Example as u8;
    type Key = ExampleKeyV1;
    type Value = ();
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ExampleKey(pub u64, pub String);

impl DatabaseKeyPrefixConst for ExampleKey {
    const DB_PREFIX: u8 = DbKeyPrefix::Example as u8;
    type Key = Self;
    type Value = ();
}

#[derive(Debug, Encodable, Decodable)]
pub struct ExampleKeyPrefix;

impl DatabaseKeyPrefixConst for ExampleKeyPrefix {
    const DB_PREFIX: u8 = DbKeyPrefix::Example as u8;
    type Key = ExampleKey;
    type Value = ();
}
