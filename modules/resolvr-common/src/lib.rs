use std::fmt;

use config::ResolvrClientConfig;
use fedimint_core::core::{Decoder, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::registry::ModuleInstanceId;
use fedimint_core::module::{CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::plugin_types_trait_impl_common;
use serde::{Deserialize, Serialize};

pub mod config;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("resolvr");

/// Modules are non-compatible with older versions
pub const CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion(0);

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum ResolvrConsensusItem {}

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
