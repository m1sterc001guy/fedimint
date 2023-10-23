use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::{impl_db_lookup, impl_db_record, PeerId};
use resolvr_common::{ResolvrNonceKeyPair, ResolvrSignatureShare, UnsignedEvent};
use serde::Serialize;

#[repr(u8)]
#[derive(Clone, Debug)]
pub enum DbKeyPrefix {
    Nonce = 0x01,
    SignatureShare = 0x02,
    MessageNonceRequest = 0x03,
    MessageSignRequest = 0x04,
}

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ResolvrNonceKey(pub UnsignedEvent, pub PeerId);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ResolvrNonceKeyMessagePrefix(pub UnsignedEvent);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ResolvrNonceKeyPrefix;

impl_db_record!(
    key = ResolvrNonceKey,
    value = ResolvrNonceKeyPair,
    db_prefix = DbKeyPrefix::Nonce
);

impl_db_lookup!(
    key = ResolvrNonceKey,
    query_prefix = ResolvrNonceKeyPrefix,
    query_prefix = ResolvrNonceKeyMessagePrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ResolvrSignatureShareKey(pub UnsignedEvent, pub PeerId);

impl_db_record!(
    key = ResolvrSignatureShareKey,
    value = ResolvrSignatureShare,
    db_prefix = DbKeyPrefix::SignatureShare
);

impl_db_lookup!(
    key = ResolvrSignatureShareKey,
    query_prefix = ResolvrSignatureShareKeyPrefix,
    query_prefix = ResolvrSignatureShareKeyMessagePrefix
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ResolvrSignatureShareKeyMessagePrefix(pub UnsignedEvent);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct ResolvrSignatureShareKeyPrefix;

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct MessageNonceRequest;

impl_db_record!(
    key = MessageNonceRequest,
    value = UnsignedEvent,
    db_prefix = DbKeyPrefix::MessageNonceRequest
);

#[derive(Debug, Clone, Encodable, Decodable, Eq, PartialEq, Hash, Serialize)]
pub struct MessageSignRequest;

impl_db_record!(
    key = MessageSignRequest,
    value = UnsignedEvent,
    db_prefix = DbKeyPrefix::MessageSignRequest
);
