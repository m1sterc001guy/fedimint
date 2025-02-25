use std::fmt::{Display, Formatter};
use std::str::FromStr;

use bitcoin::hashes::sha256;
use bitcoin::secp256k1::PublicKey;
use fedimint_core::BitcoinHash;
use fedimint_core::config::FederationId;
use fedimint_core::encoding::{Decodable, Encodable};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecurringPaymentRegistrationRequest {
    pub federation_id: FederationId,
    pub payment_code_root_key: PaymentCodeRootKey,
}

#[derive(Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecurringPaymentRegistrationResponse {
    pub recurring_payment_code: String,
}

#[derive(
    Debug,
    Clone,
    Copy,
    PartialOrd,
    Ord,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct PaymentCodeRootKey(pub PublicKey);

impl PaymentCodeRootKey {
    pub fn to_payment_code_id(&self) -> PaymentCodeId {
        PaymentCodeId(sha256::Hash::hash(&self.0.serialize()))
    }
}

#[derive(
    Debug, Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Serialize, Deserialize, Encodable, Decodable,
)]
pub struct PaymentCodeId(sha256::Hash);

impl Display for PaymentCodeId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for PaymentCodeId {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(sha256::Hash::from_str(s)?))
    }
}
