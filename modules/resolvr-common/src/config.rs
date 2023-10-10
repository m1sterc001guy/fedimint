use fedimint_core::core::ModuleKind;
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::plugin_types_trait_impl_config;
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResolvrConfigPrivate;

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
