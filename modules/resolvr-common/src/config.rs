use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
use schnorr_fun::frost::FrostKey;
use schnorr_fun::fun::bincode::Encode;
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

#[derive(Clone, Debug, Serialize, Deserialize, Encodable, Decodable)]
pub struct ResolvrConfigConsensus {
    pub threshold: u32,
    //pub frost_key: FrostKey<Normal>,
}

// TODO: How do we save the FrostKey from DKG??
/*
impl Encodable for ResolvrConfigConsensus {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<usize, std::io::Error> {
        self.frost_key.into_xonly_key().encode(writer);
        todo!()
    }
}

impl Decodable for ResolvrConfigConsensus {
    fn consensus_decode<R: std::io::Read>(
        r: &mut R,
        _modules: &fedimint_core::module::registry::ModuleDecoderRegistry,
    ) -> Result<Self, fedimint_core::encoding::DecodeError> {
        todo!()
    }
}
*/

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrConfigPrivate {
    pub my_secret_share: Scalar<Secret>,
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
