use std::io::ErrorKind;

use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::{plugin_types_trait_impl_config, PeerId};
use schnorr_fun::frost::FrostKey;
use schnorr_fun::fun::marker::{Normal, Secret};
use schnorr_fun::fun::Scalar;
use serde::{Deserialize, Serialize};

use crate::ResolvrCommonGen;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrGenParams {
    pub local: ResolvrGenParamsLocal,
    pub consensus: ResolvrGenParamsConsensus,
}

impl Default for ResolvrGenParams {
    fn default() -> Self {
        Self {
            local: ResolvrGenParamsLocal {},
            consensus: ResolvrGenParamsConsensus { threshold: 3 },
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrGenParamsLocal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrGenParamsConsensus {
    pub threshold: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrConfig {
    pub local: ResolvrConfigLocal,
    pub private: ResolvrConfigPrivate,
    pub consensus: ResolvrConfigConsensus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable, Hash)]
pub struct ResolvrClientConfig;

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct ResolvrConfigLocal;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrConfigConsensus {
    pub threshold: u32,
    pub frost_key: FrostKey<Normal>,
}

// TODO: How do we save the FrostKey from DKG??
impl Encodable for ResolvrConfigConsensus {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        let threshold_bytes = self.threshold.to_le_bytes();
        let frost_key_bytes = bincode::serialize(&self.frost_key).map_err(|_| {
            std::io::Error::new(ErrorKind::Other, format!("Error serializing FrostKey"))
        })?;
        writer.write(&threshold_bytes.as_slice())?;
        writer.write(&frost_key_bytes.as_slice())?;
        Ok(threshold_bytes.len() + frost_key_bytes.len())
    }
}

impl Decodable for ResolvrConfigConsensus {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        let mut threshold_bytes = [0; 4]; // Assuming u32 threshold
        r.read_exact(&mut threshold_bytes)
            .map_err(|_| DecodeError::from_str("Failed to read threshold bytes"))?;
        let threshold = u32::from_le_bytes(threshold_bytes);

        // Now, you need to read and deserialize the FrostKey
        let mut frost_key_bytes = Vec::new();
        r.read_to_end(&mut frost_key_bytes)
            .map_err(|_| DecodeError::from_str("Failed to read FrostKey bytes"))?;
        let frost_key: FrostKey<Normal> = bincode::deserialize(&frost_key_bytes)
            .map_err(|_| DecodeError::from_str("Error deserializing FrostKey"))?;

        // Create and return the ResolvrConfigConsensus
        Ok(ResolvrConfigConsensus {
            threshold,
            frost_key,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrConfigPrivate {
    pub my_secret_share: Scalar<Secret>,
    pub my_peer_id: PeerId,
}

plugin_types_trait_impl_config!(
    ResolvrCommonGen,
    ResolvrGenParams,
    ResolvrGenParamsLocal,
    ResolvrGenParamsConsensus,
    ResolvrConfig,
    ResolvrConfigLocal,
    ResolvrConfigPrivate,
    ResolvrConfigConsensus,
    ResolvrClientConfig
);
