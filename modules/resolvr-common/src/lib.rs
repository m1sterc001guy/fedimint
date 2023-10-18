use core::hash::Hash;
use std::fmt;

use config::ResolvrClientConfig;
use fedimint_core::core::{Decoder, ModuleKind};
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleInstanceId;
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::plugin_types_trait_impl_common;
use schnorr_fun::fun::marker::{Public, Zero};
use schnorr_fun::fun::Scalar;
use schnorr_fun::musig::NonceKeyPair;
use serde::{Deserialize, Serialize};

pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("resolvr");

/// Modules are non-compatible with older versions
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion(0);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum ResolvrConsensusItem {
    Nonce(String, ResolvrNonceKeyPair),
    FrostSigShare(String, ResolvrSignatureShare),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ResolvrInput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ResolvrOutput;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct ResolvrOutputOutcome;

pub struct ResolvrModuleTypes;

plugin_types_trait_impl_common!(
    ResolvrModuleTypes,
    ResolvrClientConfig,
    ResolvrInput,
    ResolvrOutput,
    ResolvrOutputOutcome,
    ResolvrConsensusItem
);

#[derive(Debug)]
pub struct ResolvrCommonGen;

impl CommonModuleInit for ResolvrCommonGen {
    const CONSENSUS_VERSION: ModuleConsensusVersion = CONSENSUS_VERSION;

    const KIND: ModuleKind = KIND;

    type ClientConfig = ResolvrClientConfig;

    fn decoder() -> Decoder {
        ResolvrModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for ResolvrClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResolvrClientConfig")
    }
}

impl fmt::Display for ResolvrInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResolvrInput")
    }
}

impl fmt::Display for ResolvrOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResolvrOutput")
    }
}

impl fmt::Display for ResolvrOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResolvrOutputOutcome")
    }
}

impl fmt::Display for ResolvrConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ResolvrConsensusItem")
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Deserialize)]
pub struct ResolvrNonceKeyPair(pub NonceKeyPair);

impl Hash for ResolvrNonceKeyPair {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let mut bytes = Vec::new();
        self.consensus_encode(&mut bytes).unwrap();
        state.write(&bytes);
    }
}

impl Eq for ResolvrNonceKeyPair {}

impl Encodable for ResolvrNonceKeyPair {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for ResolvrNonceKeyPair {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let mut bytes = [0; 64];
        r.read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode ResolvrNonceKeyPair"))?;
        match NonceKeyPair::from_bytes(bytes) {
            Some(nonce_keypair) => Ok(ResolvrNonceKeyPair(nonce_keypair)),
            None => Err(DecodeError::from_str(
                "Failed to create NonceKeyPair from bytes",
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Deserialize, Eq, Hash)]
pub struct ResolvrSignatureShare(pub Scalar<Public, Zero>);

impl Encodable for ResolvrSignatureShare {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let bytes = self.0.to_bytes();
        writer.write(&bytes)?;
        Ok(bytes.len())
    }
}

impl Decodable for ResolvrSignatureShare {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let mut bytes = [0; 32];
        r.read_exact(&mut bytes)
            .map_err(|_| DecodeError::from_str("Failed to decode ResolvrSignatureShare"))?;
        match Scalar::from_bytes(bytes) {
            Some(share) => Ok(ResolvrSignatureShare(share)),
            None => Err(DecodeError::from_str(
                "Failed to create ResolvrSignatureShare from bytes",
            )),
        }
    }
}
