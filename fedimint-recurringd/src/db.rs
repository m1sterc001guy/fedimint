use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::impl_db_record;
use fedimint_lnv2_common::recurring::{PaymentCodeId, PaymentCodeRootKey};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
enum DbKeyPrefix {
    PaymentCodes = 0x00,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeEntry {
    pub root_key: PaymentCodeRootKey,
    pub federation_id: FederationId,
    pub payment_code: String,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Encodable, Decodable)]
pub struct PaymentCodeKey(pub PaymentCodeId);

impl_db_record!(
    key = PaymentCodeKey,
    value = PaymentCodeEntry,
    db_prefix = DbKeyPrefix::PaymentCodes
);
